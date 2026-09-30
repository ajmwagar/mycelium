//! Translate a deliberately partial SNMP snapshot into the shared action plan.
//!
//! Absence is only interpreted as absence when the corresponding coverage bit
//! is true. This prevents an incomplete MIB walk from becoming a delete plan.

use std::collections::BTreeMap;

use mycelium_core::{
    ActionPlan, ActionRisk, Params, PlanBlocker, PlannedAction, Value, VerificationPredicate,
    VerificationSpec, ID_SWITCH_OBSERVE, ID_VLAN_ASSIGN, ID_VLAN_CREATE,
};
use mycelium_network_types::{ObservationCoverage, PortId};
use serde::{Deserialize, Serialize};

use crate::FastpathIntent;

pub const SNMP_SWITCH_STATE_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SnmpCoverage {
    pub vlan_inventory: bool,
    pub vlan_names: bool,
    pub interface_pvids: bool,
    pub interface_membership: bool,
    pub management_vlan: bool,
    pub lag_membership: bool,
}

impl SnmpCoverage {
    pub fn semantic(&self) -> ObservationCoverage {
        let mut coverage = ObservationCoverage::empty();
        for (present, capability) in [
            (self.vlan_inventory, ObservationCoverage::VLAN_INVENTORY),
            (self.vlan_names, ObservationCoverage::VLAN_NAMES),
            (self.interface_pvids, ObservationCoverage::PORT_PVIDS),
            (
                self.interface_membership,
                ObservationCoverage::VLAN_MEMBERSHIP,
            ),
            (self.management_vlan, ObservationCoverage::MANAGEMENT_VLAN),
            (self.lag_membership, ObservationCoverage::LAG_MEMBERSHIP),
        ] {
            if present {
                coverage = coverage.with(capability);
            }
        }
        coverage
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnmpVlanState {
    pub id: u16,
    pub name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnmpInterfaceState {
    #[serde(default)]
    pub port_id: PortId,
    pub name: String,
    pub pvid: Option<u16>,
    #[serde(default)]
    pub included_vlans: std::collections::BTreeSet<u16>,
    #[serde(default)]
    pub tagged_vlans: std::collections::BTreeSet<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnmpSwitchState {
    pub schema_version: u32,
    pub model_family: Option<String>,
    pub firmware_version: Option<String>,
    pub coverage: SnmpCoverage,
    #[serde(default)]
    pub vlans: BTreeMap<u16, SnmpVlanState>,
    #[serde(default)]
    pub interfaces: BTreeMap<String, SnmpInterfaceState>,
}

impl SnmpSwitchState {
    pub fn plan(&self, device: &str, desired: &FastpathIntent) -> ActionPlan {
        let mut plan = ActionPlan::new(format!("device:{device}"));
        let coverage = self.coverage.semantic();

        if !model_families_match(
            desired.model_family.as_deref(),
            self.model_family.as_deref(),
        ) {
            plan.blockers.push(blocker(
                "model_family_mismatch",
                format!(
                    "desired model {:?} does not match observed model {:?}",
                    desired.model_family, self.model_family
                ),
                None,
            ));
        }
        if !desired.opaque.is_empty() {
            plan.blockers.push(blocker(
                "unsupported_desired_statements",
                format!(
                    "{} desired statements are not normalized",
                    desired.opaque.len()
                ),
                None,
            ));
        }

        if coverage.contains(ObservationCoverage::VLAN_INVENTORY) {
            for (id, desired_vlan) in &desired.vlans {
                let observed = self.vlans.get(id);
                let name_differs = coverage.contains(ObservationCoverage::VLAN_NAMES)
                    && observed.and_then(|vlan| vlan.name.as_ref()) != desired_vlan.name.as_ref();
                if observed.is_none() {
                    let mut params = Params::from_iter([("id".into(), Value::Int(*id as i64))]);
                    if let Some(name) = &desired_vlan.name {
                        params.insert("name".into(), Value::Str(name.clone()));
                    }
                    plan.actions.push(action(
                        device,
                        ID_VLAN_CREATE,
                        params,
                        observed.map(vlan_value),
                        vlan_value(&SnmpVlanState {
                            id: *id,
                            name: desired_vlan.name.clone(),
                        }),
                    ));
                } else if name_differs {
                    plan.blockers.push(blocker(
                        "vlan_name_update_unsupported",
                        "the shared capability contract does not yet define VLAN renames".into(),
                        Some(format!("vlan:{id}")),
                    ));
                }
            }
        } else if !desired.vlans.is_empty() {
            plan.blockers.push(blocker(
                "vlan_inventory_unobserved",
                "SNMP did not establish VLAN inventory; refusing to infer missing VLANs".into(),
                None,
            ));
        }

        for (name, desired_interface) in &desired.interfaces {
            if let Some(pvid) = desired_interface.pvid {
                if coverage.contains(ObservationCoverage::PORT_PVIDS) {
                    let observed = self.interfaces.get(name).and_then(|state| state.pvid);
                    if observed != Some(pvid) {
                        plan.actions.push(action(
                            device,
                            ID_VLAN_ASSIGN,
                            Params::from_iter([
                                ("port".into(), Value::Str(name.clone())),
                                ("vlan".into(), Value::Int(pvid as i64)),
                                ("tagged".into(), Value::Bool(false)),
                            ]),
                            observed.map(|id| Value::Int(id as i64)),
                            Value::Int(pvid as i64),
                        ));
                    }
                } else {
                    plan.blockers.push(blocker(
                        "interface_pvid_unobserved",
                        "SNMP did not establish the interface PVID".into(),
                        Some(name.clone()),
                    ));
                }
            }
            if coverage.contains(ObservationCoverage::VLAN_MEMBERSHIP) {
                if let Some(observed) = self.interfaces.get(name) {
                    for vlan in desired_interface
                        .included_vlans
                        .difference(&observed.included_vlans)
                    {
                        let tagged = desired_interface.tagged_vlans.contains(vlan);
                        let duplicates_pvid_action = !tagged
                            && desired_interface.pvid == Some(*vlan)
                            && observed.pvid != Some(*vlan);
                        if !duplicates_pvid_action {
                            plan.actions.push(action(
                                device,
                                ID_VLAN_ASSIGN,
                                Params::from_iter([
                                    ("port".into(), Value::Str(name.clone())),
                                    ("vlan".into(), Value::Int(*vlan as i64)),
                                    ("tagged".into(), Value::Bool(tagged)),
                                ]),
                                None,
                                interface_membership_value(name, *vlan, tagged),
                            ));
                        }
                    }
                    let extras = observed
                        .included_vlans
                        .difference(&desired_interface.included_vlans)
                        .copied()
                        .collect::<Vec<_>>();
                    if !extras.is_empty() {
                        plan.blockers.push(blocker(
                            "interface_membership_removal_unsupported",
                            format!("removing VLAN memberships {extras:?} is not yet modeled"),
                            Some(name.clone()),
                        ));
                    }
                }
            } else if !desired_interface.included_vlans.is_empty()
                || !desired_interface.tagged_vlans.is_empty()
            {
                plan.blockers.push(blocker(
                    "interface_membership_unobserved",
                    "tagged/untagged VLAN membership is not covered by this SNMP snapshot".into(),
                    Some(name.clone()),
                ));
            }
        }

        if desired.management_vlan.is_some()
            && !coverage.contains(ObservationCoverage::MANAGEMENT_VLAN)
        {
            plan.blockers.push(blocker(
                "management_vlan_unobserved",
                "the standard Q-BRIDGE snapshot cannot prove the management VLAN".into(),
                None,
            ));
        }

        if !desired.lags.is_empty()
            || desired.stack != Default::default()
            || !desired.voice_ouis.is_empty()
        {
            plan.blockers.push(blocker(
                "fastpath_state_unobserved",
                "LAG, stack, or voice-OUI intent requires a FASTPATH configuration observation"
                    .into(),
                None,
            ));
        }
        if !plan.actions.is_empty() {
            plan.blockers.push(blocker(
                "apply_transport_unavailable",
                "NETGEAR actions are dry-run only until an apply transport and postcondition verifier are installed".into(),
                Some(device.into()),
            ));
        }
        plan
    }
}

fn action(
    device: &str,
    capability: &str,
    params: Params,
    before: Option<Value>,
    expected_after: Value,
) -> PlannedAction {
    PlannedAction {
        device: device.into(),
        capability: capability.into(),
        params,
        risk: ActionRisk::Disruptive,
        before,
        expected_after: Some(expected_after.clone()),
        verification: VerificationSpec {
            capability: ID_SWITCH_OBSERVE.into(),
            params: Params::new(),
            predicate: VerificationPredicate::Contains {
                expected: expected_after,
            },
        },
    }
}

fn vlan_value(vlan: &SnmpVlanState) -> Value {
    Value::Map(Params::from_iter([
        ("id".into(), Value::Int(vlan.id as i64)),
        (
            "name".into(),
            vlan.name.clone().map(Value::Str).unwrap_or(Value::Null),
        ),
    ]))
}

fn interface_membership_value(name: &str, vlan: u16, tagged: bool) -> Value {
    Value::Map(Params::from_iter([
        ("name".into(), Value::Str(name.into())),
        ("vlan".into(), Value::Int(vlan as i64)),
        ("tagged".into(), Value::Bool(tagged)),
    ]))
}

fn blocker(code: &str, message: String, resource: Option<String>) -> PlanBlocker {
    PlanBlocker {
        code: code.into(),
        message,
        resource,
    }
}

fn model_families_match(desired: Option<&str>, observed: Option<&str>) -> bool {
    let (Some(desired), Some(observed)) = (desired, observed) else {
        return true;
    };
    let family = desired.split('_').next().unwrap_or(desired);
    family.len() == observed.len()
        && family
            .chars()
            .zip(observed.chars())
            .all(|(expected, actual)| expected.eq_ignore_ascii_case(&actual) || expected == 'x')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FastpathConfig, FastpathIntent};

    fn desired(source: &str) -> FastpathIntent {
        FastpathIntent::normalize(&FastpathConfig::parse(source).unwrap()).unwrap()
    }

    fn observed() -> SnmpSwitchState {
        SnmpSwitchState {
            schema_version: SNMP_SWITCH_STATE_SCHEMA_VERSION,
            model_family: Some("GS7xxTS_TPS".into()),
            firmware_version: None,
            coverage: SnmpCoverage {
                vlan_inventory: true,
                vlan_names: true,
                interface_pvids: true,
                interface_membership: false,
                management_vlan: false,
                lag_membership: false,
            },
            vlans: BTreeMap::new(),
            interfaces: BTreeMap::new(),
        }
    }

    #[test]
    fn emits_shared_actions_but_blocks_live_apply() {
        let desired = desired("0x4e470x010x00GS7xxTS_TPS 5.3.0.31 0x0\nvlan database\nvlan 20\nexit\ninterface 1/g1\nvlan pvid 20\nexit\n");
        let plan = observed().plan("netgear-pris", &desired);
        assert_eq!(plan.actions.len(), 2);
        assert_eq!(plan.actions[0].capability, ID_VLAN_CREATE);
        assert_eq!(plan.actions[1].capability, ID_VLAN_ASSIGN);
        assert!(plan
            .blockers
            .iter()
            .any(|b| b.code == "apply_transport_unavailable"));
        assert!(!plan.ready_to_apply());
    }

    #[test]
    fn incomplete_inventory_never_implies_absence() {
        let desired =
            desired("0x4e470x010x00GS7xxTS_TPS 5.3.0.31 0x0\nvlan database\nvlan 20\nexit\n");
        let mut state = observed();
        state.coverage.vlan_inventory = false;
        let plan = state.plan("netgear-pris", &desired);
        assert!(plan.actions.is_empty());
        assert!(plan
            .blockers
            .iter()
            .any(|b| b.code == "vlan_inventory_unobserved"));
    }

    #[test]
    fn fastpath_family_matches_concrete_snmp_model() {
        assert!(model_families_match(Some("GS7xxTS_TPS"), Some("GS728TS")));
        assert!(!model_families_match(Some("GS7xxTS_TPS"), Some("GS108T")));
    }
}
