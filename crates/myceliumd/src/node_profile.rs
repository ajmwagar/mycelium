//! Local runtime-profile intent. This is not an image installer, permission
//! grant, or scheduler: package placement uses the existing software policy.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeIntent {
    pub node_id: String,
    pub profile: String,
    #[serde(default)]
    pub hostname: Option<String>,
    pub software_policy: crate::software::SoftwarePolicy,
    /// Reconcile existing local SSH policy from converged signed grants.
    #[serde(default)]
    pub reconcile_ssh: bool,
}

impl NodeIntent {
    pub fn validate(&self) -> Result<(), String> {
        if self.node_id.len() != 64
            || !self
                .node_id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err("node intent requires a stable lowercase peer ID".into());
        }
        if !matches!(
            self.profile.as_str(),
            "base" | "edge" | "headless-edge" | "compute" | "cloud"
        ) {
            return Err("unsupported runtime profile".into());
        }
        if let Some(hostname) = &self.hostname {
            validate_hostname(hostname)?;
        }
        self.software_policy.validate()
    }
}

pub fn validate_hostname(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 63
        || !value.as_bytes()[0].is_ascii_alphanumeric()
        || !value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
        || !value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(
            "hostname must be a lowercase DNS label (1-63 letters, digits or internal hyphens)"
                .into(),
        );
    }
    Ok(())
}

pub fn path() -> std::path::PathBuf {
    crate::home_dir().join("node-intent.json")
}

pub fn read() -> Result<Option<NodeIntent>, Box<dyn std::error::Error + Send + Sync>> {
    match std::fs::read(path()) {
        Ok(bytes) => {
            let intent: NodeIntent = serde_json::from_slice(&bytes)?;
            intent.validate()?;
            Ok(Some(intent))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

pub fn write(intent: &NodeIntent) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    intent.validate()?;
    let path = path();
    let temporary = path.with_extension("json.staging");
    std::fs::write(&temporary, serde_json::to_vec_pretty(intent)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(temporary, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn names_cannot_be_commands_or_unstable_aliases() {
        for name in [
            "",
            "-bad",
            "bad-",
            "UPPER",
            "two words",
            "a;reboot",
            "host.local",
            "../etc",
        ] {
            assert!(validate_hostname(name).is_err(), "{name}");
        }
        validate_hostname("edge-lab-01").unwrap();
    }
    #[test]
    fn profile_is_metadata_not_an_access_grant() {
        let mut intent = NodeIntent {
            node_id: "a".repeat(64),
            profile: "edge".into(),
            hostname: None,
            software_policy: crate::software::SoftwarePolicy {
                schema_version: 1,
                defaults: Default::default(),
                rules: vec![],
            },
            reconcile_ssh: false,
        };
        intent.validate().unwrap();
        intent.profile = "network-admin".into();
        assert!(intent.validate().is_err());
        intent.profile = "base".into();
        intent.node_id = "my-host".into();
        assert!(intent.validate().is_err());
    }
}
