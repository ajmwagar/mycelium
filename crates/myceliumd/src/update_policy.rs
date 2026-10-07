use serde::{Deserialize, Serialize};
use std::path::Path;

/// Missing policy uses defaults; corrupt or unreadable policy is never absence.
pub fn read(path: &Path) -> Result<Option<UpdatePolicy>, String> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("read update policy: {error}")),
    };
    let policy: UpdatePolicy = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse update policy: {error}"))?;
    policy.validate()?;
    Ok(Some(policy))
}

/// Distribution follows local desired policy, even when activation is disabled.
/// The environment is only the bootstrap default before a policy exists.
pub fn distribution_channel(path: &Path, fallback: &str) -> Result<String, String> {
    let policy = read(path)?.unwrap_or_else(|| UpdatePolicy {
        channel: fallback.to_owned(),
        ..Default::default()
    });
    policy.validate()?;
    Ok(policy.channel)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdatePolicy {
    pub enabled: bool,
    pub channel: String,
    pub minimum_age_secs: u64,
    pub rollout_window_secs: u64,
    pub retry_backoff_secs: u64,
}

impl Default for UpdatePolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            channel: "canary".into(),
            minimum_age_secs: 900,
            rollout_window_secs: 1800,
            retry_backoff_secs: 3600,
        }
    }
}

impl UpdatePolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.channel.trim().is_empty()
            || self
                .channel
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
        {
            return Err("update channel contains unsafe characters".into());
        }
        if self.minimum_age_secs < 60 {
            return Err("automatic update minimum age must be at least 60 seconds".into());
        }
        if self.retry_backoff_secs < 300 {
            return Err("automatic update retry backoff must be at least 5 minutes".into());
        }
        if self.rollout_window_secs < 300 {
            return Err("automatic update rollout window must be at least 5 minutes".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_channel_controls_fetching_without_enabling_activation() {
        let root = std::env::temp_dir().join(format!("mycelium-channel-{}-{}",
            std::process::id(), std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("update-policy.json");
        assert_eq!(distribution_channel(&path, "canary").unwrap(), "canary");
        let policy = UpdatePolicy { channel: "fungos-qemu-test".into(), ..Default::default() };
        std::fs::write(&path, serde_json::to_vec(&policy).unwrap()).unwrap();
        assert_eq!(distribution_channel(&path, "canary").unwrap(), "fungos-qemu-test");
        assert!(!read(&path).unwrap().unwrap().enabled);
        std::fs::write(&path, b"not JSON").unwrap();
        assert!(distribution_channel(&path, "canary").is_err());
        assert!(read(&path).is_err());
        let invalid = UpdatePolicy { minimum_age_secs: 1, ..policy };
        std::fs::write(&path, serde_json::to_vec(&invalid).unwrap()).unwrap();
        assert!(distribution_channel(&path, "canary").is_err());
        assert!(read(&root).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn defaults_are_disabled_and_conservative() {
        let policy = UpdatePolicy::default();
        assert!(!policy.enabled);
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn unsafe_or_impatient_policies_fail() {
        let mut policy = UpdatePolicy::default();
        policy.channel = "canary; reboot".into();
        assert!(policy.validate().is_err());
        policy.channel = "canary".into();
        policy.minimum_age_secs = 1;
        assert!(policy.validate().is_err());
    }
}
