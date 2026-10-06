//! Durable transaction boundary for mutations of Mycelium-owned state.

use mycelium_core::{
    ExecutionMode, ExecutionState, MyceliumError, Result, StateChangePlan, StateChangeReceipt,
};

pub struct StateChangeTransaction {
    receipt: StateChangeReceipt,
}

impl StateChangeTransaction {
    pub fn begin(plan: StateChangePlan, mode: ExecutionMode) -> Result<Self> {
        let now = now();
        let receipt = StateChangeReceipt {
            schema_version: 1,
            change_digest: plan.digest(),
            operation: plan.operation,
            scope: plan.scope,
            mode,
            state: if mode == ExecutionMode::Plan {
                ExecutionState::Planned
            } else {
                ExecutionState::Running
            },
            started_at: now,
            finished_at: None,
            result: None,
            error: None,
        };
        persist(&receipt)?;
        Ok(Self { receipt })
    }

    pub fn mode(&self) -> ExecutionMode {
        self.receipt.mode
    }

    pub fn finish(mut self, result: serde_json::Value) -> Result<StateChangeReceipt> {
        self.receipt.result = Some(result);
        self.receipt.finished_at = Some(now());
        self.receipt.state = if self.receipt.mode == ExecutionMode::Plan {
            ExecutionState::Planned
        } else {
            ExecutionState::Succeeded
        };
        persist(&self.receipt)?;
        Ok(self.receipt)
    }

    pub fn fail(mut self, error: impl Into<String>) -> Result<StateChangeReceipt> {
        let error = error.into();
        self.receipt.error = Some(error.clone());
        self.receipt.finished_at = Some(now());
        self.receipt.state = ExecutionState::Failed;
        persist(&self.receipt)?;
        Err(MyceliumError::Validation(format!(
            "state change {} failed: {error}",
            self.receipt.change_digest
        )))
    }
}

pub(crate) fn mode_from_flags(write: bool, dry_run: bool) -> Result<ExecutionMode> {
    ExecutionMode::from_legacy_flags(write, dry_run).map_err(|error| {
        if !write && !dry_run {
            MyceliumError::WritesNotPermitted(error)
        } else {
            MyceliumError::Validation(error)
        }
    })
}

fn persist(receipt: &StateChangeReceipt) -> Result<()> {
    let dir = receipts_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!(
        "state-{}-{}.json",
        receipt.change_digest, receipt.started_at
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
    std::env::temp_dir().join(format!(
        "mycelium-state-change-tests-{}",
        std::process::id()
    ))
}
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
