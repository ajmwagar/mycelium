use std::collections::BTreeSet;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::topology::VlanId;
use crate::{ActionPlan, PlanBlocker};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AllocationValue {
    Vlan {
        id: VlanId,
    },
    Subnet {
        network: IpAddr,
        prefix: u8,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        gateway: Option<IpAddr>,
    },
}

impl AllocationValue {
    pub fn canonical(&self) -> String {
        match self {
            Self::Vlan { id } => format!("vlan:{}", id.0),
            Self::Subnet {
                network, prefix, ..
            } => format!("subnet:{network}/{prefix}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllocationStrategy {
    ImportedObservation,
    LowestFree,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllocationBasis {
    pub strategy: AllocationStrategy,
    #[serde(default)]
    pub sources: BTreeSet<String>,
}

/// Durable generated state. Intent can be renamed and placement can move;
/// this identity and allocation remain stable until an explicit migration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllocationReceipt {
    pub resource: String,
    pub identity: String,
    pub site: String,
    pub allocation: AllocationValue,
    pub basis: AllocationBasis,
    pub generation: u64,
}

/// Stable logical ownership of one or more allocation receipts. Placement and
/// vendor configuration are intentionally absent and re-derived elsewhere.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogicalNetwork {
    pub identity: String,
    pub name: String,
    pub site: String,
    pub receipt_ids: BTreeSet<String>,
    pub generation: u64,
}

impl LogicalNetwork {
    pub fn adopted(
        site: impl Into<String>,
        name: impl Into<String>,
        receipt_ids: BTreeSet<String>,
    ) -> Self {
        let site = site.into();
        let name = name.into();
        Self {
            identity: stable_identity(&format!("network|{site}|{name}"))
                .replacen("alloc-", "net-", 1),
            name,
            site,
            receipt_ids,
            generation: 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkDriftState {
    InSync,
    Drifted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkDriftReport {
    pub network: LogicalNetwork,
    pub state: NetworkDriftState,
    pub missing_receipts: BTreeSet<String>,
    pub missing_allocations: BTreeSet<String>,
    pub gateway_mismatches: BTreeSet<String>,
    pub known_members: BTreeSet<String>,
    pub evidence_sources: BTreeSet<String>,
}

impl NetworkDriftReport {
    /// Derive a vendor-neutral plan from evidence. Driver actions are only
    /// added when a concrete managed binding exists; missing facts block.
    pub fn action_plan(&self) -> ActionPlan {
        let mut plan = ActionPlan::new(format!("network:{}", self.network.identity));
        plan.desired_revision = Some(format!("generation:{}", self.network.generation));
        for receipt in &self.missing_receipts {
            plan.blockers.push(PlanBlocker {
                code: "missing_allocation_receipt".into(),
                message: format!("allocation receipt {receipt} is unavailable"),
                resource: Some(receipt.clone()),
            });
        }
        for allocation in &self.missing_allocations {
            plan.blockers.push(PlanBlocker {
                code: "allocation_not_observed".into(),
                message: format!("desired allocation {allocation} is not observed"),
                resource: Some(allocation.clone()),
            });
        }
        for mismatch in &self.gateway_mismatches {
            plan.blockers.push(PlanBlocker {
                code: "gateway_mismatch".into(),
                message: mismatch.clone(),
                resource: Some(self.network.identity.clone()),
            });
        }
        if plan.blockers.is_empty() && self.known_members.is_empty() {
            plan.blockers.push(PlanBlocker {
                code: "no_managed_bindings".into(),
                message: "network has no managed device bindings from which to derive actions"
                    .into(),
                resource: Some(self.network.identity.clone()),
            });
        }
        plan
    }
}

impl AllocationReceipt {
    pub fn imported(
        site: impl Into<String>,
        allocation: AllocationValue,
        sources: BTreeSet<String>,
    ) -> Self {
        let site = site.into();
        let canonical = allocation.canonical();
        let identity = stable_identity(&format!("{site}|{canonical}"));
        Self {
            resource: format!("imported/{site}/{}", canonical.replace(':', "/")),
            identity,
            site,
            allocation,
            basis: AllocationBasis {
                strategy: AllocationStrategy::ImportedObservation,
                sources,
            },
            generation: 1,
        }
    }
}

fn stable_identity(input: &str) -> String {
    // FNV-1a is deliberately specified here rather than relying on Rust's
    // process/version-dependent DefaultHasher.
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("alloc-{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imported_identity_is_deterministic_and_site_scoped() {
        let allocation = AllocationValue::Vlan { id: VlanId(30) };
        let first = AllocationReceipt::imported("home", allocation.clone(), BTreeSet::new());
        let second = AllocationReceipt::imported("home", allocation.clone(), BTreeSet::new());
        let elsewhere = AllocationReceipt::imported("lab", allocation, BTreeSet::new());
        assert_eq!(first.identity, second.identity);
        assert_ne!(first.identity, elsewhere.identity);
        assert_eq!(first.generation, 1);
    }

    #[test]
    fn adopted_network_identity_survives_receipt_order() {
        let first = LogicalNetwork::adopted(
            "home",
            "cctv",
            BTreeSet::from(["alloc-b".into(), "alloc-a".into()]),
        );
        let second = LogicalNetwork::adopted(
            "home",
            "cctv",
            BTreeSet::from(["alloc-a".into(), "alloc-b".into()]),
        );
        assert_eq!(first.identity, second.identity);
    }

    #[test]
    fn network_plan_fails_loudly_without_a_managed_binding() {
        let network = LogicalNetwork::adopted("home", "cctv", BTreeSet::new());
        let report = NetworkDriftReport {
            network,
            state: NetworkDriftState::InSync,
            missing_receipts: BTreeSet::new(),
            missing_allocations: BTreeSet::new(),
            gateway_mismatches: BTreeSet::new(),
            known_members: BTreeSet::new(),
            evidence_sources: BTreeSet::new(),
        };
        let plan = report.action_plan();
        assert!(!plan.ready_to_apply());
        assert_eq!(plan.blockers[0].code, "no_managed_bindings");
    }
}
