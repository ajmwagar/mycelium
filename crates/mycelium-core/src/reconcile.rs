//! Vendor-neutral reconciliation plans.
//!
//! Drivers may use richer internal representations, but plans crossing the
//! core boundary are expressed as declared capability calls plus explicit
//! postconditions. Execution remains owned by [`crate::Device::invoke`], so a
//! planner cannot create a second, ungated mutation path.

use serde::{Deserialize, Serialize};

use crate::{Params, Value};

pub const ACTION_PLAN_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionRisk {
    Low,
    Disruptive,
    Destructive,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VerificationSpec {
    /// Read-only capability invoked after the action.
    pub capability: String,
    #[serde(default)]
    pub params: Params,
    pub predicate: VerificationPredicate,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VerificationPredicate {
    /// The verification capability only needs to complete successfully.
    Succeeds,
    /// Its structured output must exactly equal this value.
    Equals { expected: Value },
    /// Its structured output must contain this value. Collection-specific
    /// semantics belong to the verifier, not to vendor drivers.
    Contains { expected: Value },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PlannedAction {
    pub device: String,
    pub capability: String,
    #[serde(default)]
    pub params: Params,
    pub risk: ActionRisk,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_after: Option<Value>,
    pub verification: VerificationSpec,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanBlocker {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ActionPlan {
    pub schema_version: u32,
    pub scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desired_revision: Option<String>,
    #[serde(default)]
    pub actions: Vec<PlannedAction>,
    #[serde(default)]
    pub blockers: Vec<PlanBlocker>,
}

impl ActionPlan {
    pub fn new(scope: impl Into<String>) -> Self {
        Self {
            schema_version: ACTION_PLAN_SCHEMA_VERSION,
            scope: scope.into(),
            desired_revision: None,
            actions: Vec::new(),
            blockers: Vec::new(),
        }
    }

    /// Readiness is derived from blockers so it cannot drift from the facts.
    pub fn ready_to_apply(&self) -> bool {
        self.blockers.is_empty()
    }
}

pub fn verification_matches(actual: &Value, predicate: &VerificationPredicate) -> bool {
    match predicate {
        VerificationPredicate::Succeeds => true,
        VerificationPredicate::Equals { expected } => actual == expected,
        VerificationPredicate::Contains { expected } => value_contains(actual, expected),
    }
}

fn value_contains(actual: &Value, expected: &Value) -> bool {
    if actual == expected {
        return true;
    }
    match (actual, expected) {
        (Value::List(actual), Value::List(expected)) => expected
            .iter()
            .all(|expected| actual.iter().any(|actual| value_contains(actual, expected))),
        (Value::List(values), _) => values.iter().any(|value| value_contains(value, expected)),
        (Value::Map(actual), Value::Map(expected)) => expected.iter().all(|(key, value)| {
            actual
                .get(key)
                .is_some_and(|actual| value_contains(actual, value))
        }),
        (Value::Map(values), _) => values.values().any(|value| value_contains(value, expected)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_is_derived_from_blockers() {
        let mut plan = ActionPlan::new("site:titan");
        assert!(plan.ready_to_apply());
        plan.blockers.push(PlanBlocker {
            code: "management_path_unavailable".into(),
            message: "cannot verify recovery access".into(),
            resource: Some("deckard".into()),
        });
        assert!(!plan.ready_to_apply());
    }

    #[test]
    fn plan_round_trips_as_versioned_data() {
        let mut plan = ActionPlan::new("device:netgear-titan");
        plan.actions.push(PlannedAction {
            device: "netgear-titan".into(),
            capability: "vlan.assign".into(),
            params: Params::from_iter([("id".into(), Value::Int(20))]),
            risk: ActionRisk::Disruptive,
            before: None,
            expected_after: Some(Value::Int(20)),
            verification: VerificationSpec {
                capability: "vlan.list".into(),
                params: Params::new(),
                predicate: VerificationPredicate::Contains {
                    expected: Value::Int(20),
                },
            },
        });

        let json = serde_json::to_string(&plan).unwrap();
        let restored: ActionPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, plan);
    }

    #[test]
    fn verification_contains_supports_nested_structured_values() {
        let actual = Value::List(vec![Value::Map(Params::from_iter([
            ("id".into(), Value::Int(30)),
            ("name".into(), Value::Str("cctv".into())),
        ]))]);
        let predicate = VerificationPredicate::Contains {
            expected: Value::Map(Params::from_iter([("id".into(), Value::Int(30))])),
        };
        assert!(verification_matches(&actual, &predicate));
    }
}
