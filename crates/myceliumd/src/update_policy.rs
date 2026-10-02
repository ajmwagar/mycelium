use serde::{Deserialize, Serialize};

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
