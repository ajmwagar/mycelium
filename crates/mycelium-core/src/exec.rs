use serde::{Deserialize, Serialize};

/// Context handed to [`crate::device::Device::exec`] for every unit of work.
///
/// The write/dry-run gates live here so they can be threaded from the CLI
/// all the way down to the transport — a driver cannot "forget" to honor
/// them, and a plugin host API enforces the same gates before touching
/// the wire (secure by default, tenet #9/self-validating).
#[derive(Clone, Debug)]
pub struct ExecContext {
    /// Capability id being executed (for error messages and logging).
    pub capability: String,
    /// Session opted into state-changing operations.
    pub allow_writes: bool,
    /// Compute/validate everything, apply nothing.
    pub dry_run: bool,
}

impl ExecContext {
    pub fn readonly(capability: impl Into<String>) -> Self {
        Self { capability: capability.into(), allow_writes: false, dry_run: false }
    }

    /// Refuse to proceed when this capability mutates state but writes are
    /// not permitted. Called by every honest driver/plugin host.
    pub fn gate(&self, mutation: bool) -> Result<(), crate::MyceliumError> {
        if mutation && !self.allow_writes {
            return Err(crate::MyceliumError::WritesNotPermitted(self.capability.clone()));
        }
        Ok(())
    }
}

/// Raw result of running command(s) on an appliance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecOutcome {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl ExecOutcome {
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }
}
