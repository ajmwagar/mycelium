//! The sole executor for vendor-neutral changes crossing the daemon boundary.

use mycelium_core::{
    verification_matches, ActionPlan, ActionReceipt, ExecContext, ExecutionMode, ExecutionReceipt,
    ExecutionState, Inventory, MyceliumError, Result,
};

pub(crate) async fn execute(
    inventory: &Inventory,
    plan: &ActionPlan,
    mode: ExecutionMode,
) -> Result<ExecutionReceipt> {
    if !plan.ready_to_apply() {
        return Err(MyceliumError::Validation(format!(
            "action plan has {} blocker(s)",
            plan.blockers.len()
        )));
    }
    preflight(inventory, plan)?;
    let started_at = now();
    let mut receipt = ExecutionReceipt {
        schema_version: 1,
        plan_digest: plan.digest(),
        scope: plan.scope.clone(),
        mode,
        state: if mode == ExecutionMode::Plan {
            ExecutionState::Planned
        } else {
            ExecutionState::Running
        },
        started_at,
        finished_at: None,
        actions: plan
            .actions
            .iter()
            .enumerate()
            .map(|(index, action)| ActionReceipt {
                action_id: plan.action_id(index).expect("existing action has identity"),
                device: action.device.clone(),
                capability: action.capability.clone(),
                state: ExecutionState::Planned,
                output: None,
                verification: None,
                error: None,
            })
            .collect(),
    };
    persist(&receipt)?;

    for (index, action) in plan.actions.iter().enumerate() {
        let device = inventory.get(&action.device)?;
        let context = ExecContext {
            capability: action.capability.clone(),
            allow_writes: mode == ExecutionMode::Apply,
            dry_run: mode == ExecutionMode::Plan,
        };
        let applied = match device
            .invoke(&context, &action.capability, action.params.clone())
            .await
        {
            Ok(value) if value.ok => value,
            Ok(value) => {
                return fail(
                    &mut receipt,
                    index,
                    value.message.unwrap_or_else(|| "action failed".into()),
                );
            }
            Err(error) => return fail(&mut receipt, index, error.to_string()),
        };
        receipt.actions[index].output = Some(applied.output);
        if mode == ExecutionMode::Plan {
            receipt.actions[index].state = ExecutionState::Planned;
            persist(&receipt)?;
            continue;
        }
        receipt.actions[index].state = ExecutionState::Running;
        persist(&receipt)?;
        let verified = match device
            .invoke(
                &ExecContext::readonly(&action.verification.capability),
                &action.verification.capability,
                action.verification.params.clone(),
            )
            .await
        {
            Ok(value)
                if value.ok
                    && verification_matches(&value.output, &action.verification.predicate) =>
            {
                value
            }
            Ok(_) => {
                return fail(
                    &mut receipt,
                    index,
                    format!("postcondition failed after `{}`", action.capability),
                )
            }
            Err(error) => {
                return fail(&mut receipt, index, format!("verification failed: {error}"))
            }
        };
        receipt.actions[index].verification = Some(verified.output);
        receipt.actions[index].state = ExecutionState::Succeeded;
        persist(&receipt)?;
    }
    receipt.finished_at = Some(now());
    receipt.state = if mode == ExecutionMode::Plan {
        ExecutionState::Planned
    } else {
        ExecutionState::Succeeded
    };
    persist(&receipt)?;
    Ok(receipt)
}

fn preflight(inventory: &Inventory, plan: &ActionPlan) -> Result<()> {
    for action in &plan.actions {
        let capabilities = inventory.capabilities(&action.device)?;
        let mutation = capabilities
            .iter()
            .find(|capability| capability.id == action.capability)
            .ok_or_else(|| MyceliumError::UnknownCapability(action.capability.clone()))?;
        mutation
            .spec
            .validate(&action.params)
            .map_err(MyceliumError::Validation)?;
        let verification = capabilities
            .iter()
            .find(|capability| capability.id == action.verification.capability)
            .ok_or_else(|| {
                MyceliumError::UnknownCapability(action.verification.capability.clone())
            })?;
        if verification.spec.mutation {
            return Err(MyceliumError::Validation(format!(
                "verification capability `{}` must be read-only",
                action.verification.capability
            )));
        }
        verification
            .spec
            .validate(&action.verification.params)
            .map_err(MyceliumError::Validation)?;
    }
    Ok(())
}

fn fail(receipt: &mut ExecutionReceipt, index: usize, error: String) -> Result<ExecutionReceipt> {
    receipt.state = ExecutionState::Failed;
    receipt.finished_at = Some(now());
    receipt.actions[index].state = ExecutionState::Failed;
    receipt.actions[index].error = Some(error.clone());
    persist(receipt)?;
    Err(MyceliumError::Device {
        exit_code: 1,
        stderr: format!(
            "execution {} failed at action {}: {error}",
            receipt.plan_digest, receipt.actions[index].action_id
        ),
    })
}

fn persist(receipt: &ExecutionReceipt) -> Result<()> {
    let dir = receipts_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!(
        "{}-{}.json",
        receipt.plan_digest, receipt.started_at
    ));
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    std::fs::write(
        &temporary,
        serde_json::to_vec_pretty(receipt)
            .map_err(|error| MyceliumError::Parse(error.to_string()))?,
    )?;
    std::fs::rename(temporary, path)?;
    Ok(())
}

#[cfg(not(test))]
fn receipts_dir() -> std::path::PathBuf {
    crate::execution_receipts_dir()
}

#[cfg(test)]
fn receipts_dir() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("mycelium-execution-tests-{}", std::process::id()))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(crate) fn list_receipts() -> Result<Vec<serde_json::Value>> {
    let mut receipts = Vec::new();
    let Ok(entries) = std::fs::read_dir(receipts_dir()) else {
        return Ok(receipts);
    };
    for entry in entries {
        let entry = entry?;
        if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        receipts.push(
            serde_json::from_slice(&std::fs::read(entry.path())?)
                .map_err(|error| MyceliumError::Parse(error.to_string()))?,
        );
    }
    receipts.sort_by_key(|receipt| std::cmp::Reverse(receipt["started_at"].as_u64().unwrap_or(0)));
    Ok(receipts)
}
