use crate::{
    DiagnosticLevel, FastpathIntent, InterfaceIntent, LagIntent, StackIntent, VlanIntent, VoiceOui,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const PLAN_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReconcileOptions {
    /// Destructive convergence is deliberately opt-in. Without it, objects
    /// present only on the target become blockers rather than delete steps.
    pub allow_deletes: bool,
    /// Cross-platform migration is expected, but must be explicitly declared
    /// so unrelated switches cannot accidentally be reconciled.
    pub allow_model_mismatch: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconciliationPlan {
    pub schema_version: u32,
    pub source_model: Option<String>,
    pub source_firmware: Option<String>,
    pub target_model: Option<String>,
    pub target_firmware: Option<String>,
    pub ready_to_apply: bool,
    pub steps: Vec<PlanStep>,
    pub blockers: Vec<Blocker>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanStep {
    pub sequence: usize,
    pub operation: PlanOperation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum PlanOperation {
    CreateVlan {
        desired: VlanIntent,
    },
    UpdateVlan {
        before: VlanIntent,
        desired: VlanIntent,
    },
    DeleteVlan {
        before: VlanIntent,
    },
    SetManagementVlan {
        before: Option<u16>,
        desired: Option<u16>,
    },
    ConfigureInterface {
        name: String,
        before: Option<InterfaceIntent>,
        desired: InterfaceIntent,
    },
    CreateLag {
        desired: LagIntent,
    },
    UpdateLag {
        before: LagIntent,
        desired: LagIntent,
    },
    DeleteLag {
        before: LagIntent,
    },
    ConfigureStack {
        before: StackIntent,
        desired: StackIntent,
    },
    ConfigureVoiceOuis {
        before: Vec<VoiceOui>,
        desired: Vec<VoiceOui>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blocker {
    pub code: String,
    pub message: String,
}

impl ReconciliationPlan {
    pub fn build(
        desired: &FastpathIntent,
        observed: &FastpathIntent,
        options: ReconcileOptions,
    ) -> Self {
        let mut operations = Vec::new();
        let mut blockers = Vec::new();

        for diagnostic in &desired.diagnostics {
            if diagnostic.level == DiagnosticLevel::Error {
                blockers.push(Blocker {
                    code: "invalid_desired_intent".to_owned(),
                    message: diagnostic.message.clone(),
                });
            }
        }
        if !desired.opaque.is_empty() {
            blockers.push(Blocker {
                code: "unsupported_desired_statements".to_owned(),
                message: format!(
                    "{} desired statements require an explicit migration policy",
                    desired.opaque.len()
                ),
            });
        }
        if desired.model_family != observed.model_family && !options.allow_model_mismatch {
            blockers.push(Blocker {
                code: "model_family_mismatch".to_owned(),
                message: format!(
                    "source model {:?} does not match target model {:?}",
                    desired.model_family, observed.model_family
                ),
            });
        }

        // Create/update VLAN objects before referring to them elsewhere.
        for (id, vlan) in &desired.vlans {
            match observed.vlans.get(id) {
                None => operations.push(PlanOperation::CreateVlan {
                    desired: vlan.clone(),
                }),
                Some(before) if before != vlan => operations.push(PlanOperation::UpdateVlan {
                    before: before.clone(),
                    desired: vlan.clone(),
                }),
                Some(_) => {}
            }
        }

        if desired.management_vlan != observed.management_vlan {
            operations.push(PlanOperation::SetManagementVlan {
                before: observed.management_vlan,
                desired: desired.management_vlan,
            });
        }

        for (name, interface) in &desired.interfaces {
            let before = observed.interfaces.get(name);
            if before != Some(interface) {
                operations.push(PlanOperation::ConfigureInterface {
                    name: name.clone(),
                    before: before.cloned(),
                    desired: interface.clone(),
                });
            }
        }
        let extra_interfaces: BTreeSet<_> = observed
            .interfaces
            .keys()
            .filter(|name| !desired.interfaces.contains_key(*name))
            .cloned()
            .collect();
        if !extra_interfaces.is_empty() {
            blockers.push(Blocker {
                code: "unmapped_target_interfaces".to_owned(),
                message: format!(
                    "target has interfaces absent from desired intent: {}",
                    extra_interfaces.into_iter().collect::<Vec<_>>().join(", ")
                ),
            });
        }

        for (id, lag) in &desired.lags {
            match observed.lags.get(id) {
                None => operations.push(PlanOperation::CreateLag {
                    desired: lag.clone(),
                }),
                Some(before) if before != lag => operations.push(PlanOperation::UpdateLag {
                    before: before.clone(),
                    desired: lag.clone(),
                }),
                Some(_) => {}
            }
        }

        if desired.stack != observed.stack {
            operations.push(PlanOperation::ConfigureStack {
                before: observed.stack.clone(),
                desired: desired.stack.clone(),
            });
        }
        if desired.voice_ouis != observed.voice_ouis {
            operations.push(PlanOperation::ConfigureVoiceOuis {
                before: observed.voice_ouis.clone(),
                desired: desired.voice_ouis.clone(),
            });
        }

        let extra_lags: Vec<_> = observed
            .lags
            .iter()
            .filter(|(id, _)| !desired.lags.contains_key(*id))
            .map(|(_, lag)| lag.clone())
            .collect();
        let extra_vlans: Vec<_> = observed
            .vlans
            .iter()
            .filter(|(id, _)| !desired.vlans.contains_key(*id))
            .map(|(_, vlan)| vlan.clone())
            .collect();
        if options.allow_deletes {
            operations.extend(
                extra_lags
                    .into_iter()
                    .map(|before| PlanOperation::DeleteLag { before }),
            );
            // VLAN deletion is last so no still-needed port/LAG can reference it.
            operations.extend(
                extra_vlans
                    .into_iter()
                    .map(|before| PlanOperation::DeleteVlan { before }),
            );
        } else if !extra_lags.is_empty() || !extra_vlans.is_empty() {
            blockers.push(Blocker {
                code: "deletions_require_opt_in".to_owned(),
                message: format!(
                    "target-only state requires explicit deletion permission: {} VLAN(s), {} LAG(s)",
                    extra_vlans.len(),
                    extra_lags.len()
                ),
            });
        }

        let steps = operations
            .into_iter()
            .enumerate()
            .map(|(index, operation)| PlanStep {
                sequence: index + 1,
                operation,
            })
            .collect();
        Self {
            schema_version: PLAN_SCHEMA_VERSION,
            source_model: desired.model_family.clone(),
            source_firmware: desired.firmware_version.clone(),
            target_model: observed.model_family.clone(),
            target_firmware: observed.firmware_version.clone(),
            ready_to_apply: blockers.is_empty(),
            steps,
            blockers,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FastpathConfig;

    fn intent(config: &str) -> FastpathIntent {
        FastpathIntent::normalize(&FastpathConfig::parse(config).unwrap()).unwrap()
    }

    const HEADER: &str = "0x4e470x010x00GS7xxTS_TPS 5.3.0.31 0x00000000\n";

    #[test]
    fn identical_state_is_idempotent() {
        let state = intent(&format!("{HEADER}vlan database\nvlan 10\nexit\n"));
        let plan = ReconciliationPlan::build(&state, &state, ReconcileOptions::default());
        assert!(plan.ready_to_apply);
        assert!(plan.steps.is_empty());
        assert!(plan.blockers.is_empty());
    }

    #[test]
    fn orders_vlan_creation_before_interface_configuration() {
        let desired = intent(&format!(
            "{HEADER}vlan database\nvlan 10\nexit\ninterface 1/g1\nvlan pvid 10\nvlan participation include 10\nexit\n"
        ));
        let observed = intent(HEADER);
        let plan = ReconciliationPlan::build(&desired, &observed, ReconcileOptions::default());
        assert!(plan.ready_to_apply);
        assert!(matches!(
            plan.steps[0].operation,
            PlanOperation::CreateVlan { .. }
        ));
        assert!(matches!(
            plan.steps[1].operation,
            PlanOperation::ConfigureInterface { .. }
        ));
    }

    #[test]
    fn target_only_state_is_blocked_without_delete_opt_in() {
        let desired = intent(HEADER);
        let observed = intent(&format!("{HEADER}vlan database\nvlan 20\nexit\n"));
        let plan = ReconciliationPlan::build(&desired, &observed, ReconcileOptions::default());
        assert!(!plan.ready_to_apply);
        assert!(plan
            .blockers
            .iter()
            .any(|blocker| blocker.code == "deletions_require_opt_in"));
        assert!(plan.steps.is_empty());
    }

    #[test]
    fn explicit_delete_opt_in_places_deletes_last() {
        let desired = intent(&format!("{HEADER}vlan database\nvlan 10\nexit\n"));
        let observed = intent(&format!("{HEADER}vlan database\nvlan 20\nexit\n"));
        let plan = ReconciliationPlan::build(
            &desired,
            &observed,
            ReconcileOptions {
                allow_deletes: true,
                ..ReconcileOptions::default()
            },
        );
        assert!(plan.ready_to_apply);
        assert!(matches!(
            plan.steps[0].operation,
            PlanOperation::CreateVlan { .. }
        ));
        assert!(matches!(
            plan.steps[1].operation,
            PlanOperation::DeleteVlan { .. }
        ));
    }
}
