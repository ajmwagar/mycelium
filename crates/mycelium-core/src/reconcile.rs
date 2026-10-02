//! Vendor-neutral reconciliation plans.
//!
//! Drivers may use richer internal representations, but plans crossing the
//! core boundary are expressed as declared capability calls plus explicit
//! postconditions. Execution remains owned by [`crate::Device::invoke`], so a
//! planner cannot create a second, ungated mutation path.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Params, Value};

pub const ACTION_PLAN_SCHEMA_VERSION: u32 = 1;

/// One unambiguous execution mode. CLI compatibility flags are normalized to
/// this type at the protocol boundary and never reach the executor separately.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionMode {
    Plan,
    Apply,
}

impl ExecutionMode {
    pub fn from_legacy_flags(write: bool, dry_run: bool) -> Result<Self, String> {
        match (write, dry_run) {
            (true, true) => Err("--write and --dry-run are mutually exclusive".into()),
            (true, false) => Ok(Self::Apply),
            (false, true) => Ok(Self::Plan),
            (false, false) => Err("choose --write to apply or --dry-run to plan".into()),
        }
    }
}

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

    /// Content identity independent of JSON object insertion order. This is
    /// the review/apply boundary and the durable receipt key.
    pub fn digest(&self) -> String {
        canonical_digest(self)
    }

    pub fn action_id(&self, index: usize) -> Option<String> {
        let action = self.actions.get(index)?;
        let value = serde_json::to_value(action).ok()?;
        let mut hash = Sha256::new();
        hash.update(self.digest().as_bytes());
        hash.update((index as u64).to_be_bytes());
        hash.update(canonical_json(&value).as_bytes());
        Some(format!("{:x}", hash.finalize()))
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StateChangePlan {
    pub schema_version: u32,
    pub operation: String,
    pub scope: String,
    pub desired: serde_json::Value,
}

impl StateChangePlan {
    pub fn new(
        operation: impl Into<String>,
        scope: impl Into<String>,
        desired: serde_json::Value,
    ) -> Self {
        Self {
            schema_version: 1,
            operation: operation.into(),
            scope: scope.into(),
            desired,
        }
    }
    pub fn digest(&self) -> String {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StateChangeReceipt {
    pub schema_version: u32,
    pub change_digest: String,
    pub operation: String,
    pub scope: String,
    pub mode: ExecutionMode,
    pub state: ExecutionState,
    pub started_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionState {
    Planned,
    Running,
    Succeeded,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ActionReceipt {
    pub action_id: String,
    pub device: String,
    pub capability: String,
    pub state: ExecutionState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    pub schema_version: u32,
    pub plan_digest: String,
    pub scope: String,
    pub mode: ExecutionMode,
    pub state: ExecutionState,
    pub started_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<u64>,
    pub actions: Vec<ActionReceipt>,
}

fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "null".into(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Number(value) => value.to_string(),
        serde_json::Value::String(value) => {
            serde_json::to_string(value).expect("string serializes")
        }
        serde_json::Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        serde_json::Value::Object(values) => {
            let mut fields = values.iter().collect::<Vec<_>>();
            fields.sort_by(|(left, _), (right, _)| left.cmp(right));
            format!(
                "{{{}}}",
                fields
                    .into_iter()
                    .map(|(key, value)| format!(
                        "{}:{}",
                        serde_json::to_string(key).expect("key serializes"),
                        canonical_json(value)
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
    }
}

pub fn canonical_digest<T: Serialize>(value: &T) -> String {
    let value = serde_json::to_value(value).expect("digest input is serializable");
    let mut hash = Sha256::new();
    hash.update(canonical_json(&value).as_bytes());
    format!("{:x}", hash.finalize())
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

    #[test]
    fn execution_flags_cannot_be_ambiguous() {
        assert_eq!(
            ExecutionMode::from_legacy_flags(true, false),
            Ok(ExecutionMode::Apply)
        );
        assert_eq!(
            ExecutionMode::from_legacy_flags(false, true),
            Ok(ExecutionMode::Plan)
        );
        assert!(ExecutionMode::from_legacy_flags(true, true).is_err());
        assert!(ExecutionMode::from_legacy_flags(false, false).is_err());
    }

    #[test]
    fn plan_and_action_identity_is_stable() {
        let mut plan = ActionPlan::new("test");
        plan.actions.push(PlannedAction {
            device: "node".into(),
            capability: "test.apply".into(),
            params: Params::from_iter([("b".into(), Value::Int(2)), ("a".into(), Value::Int(1))]),
            risk: ActionRisk::Low,
            before: None,
            expected_after: None,
            verification: VerificationSpec {
                capability: "test.read".into(),
                params: Params::new(),
                predicate: VerificationPredicate::Succeeds,
            },
        });
        assert_eq!(plan.digest(), plan.digest());
        assert_eq!(plan.action_id(0), plan.action_id(0));
        assert_eq!(plan.digest().len(), 64);
    }

    #[test]
    fn state_change_identity_is_canonical() {
        let left = StateChangePlan::new(
            "network.adopt",
            "network:cctv",
            serde_json::json!({"b": 2, "a": 1}),
        );
        let right = StateChangePlan::new(
            "network.adopt",
            "network:cctv",
            serde_json::json!({"a": 1, "b": 2}),
        );
        assert_eq!(left.digest(), right.digest());
    }
}
