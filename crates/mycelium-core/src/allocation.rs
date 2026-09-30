use std::collections::BTreeSet;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::topology::VlanId;

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
}
