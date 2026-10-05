#![forbid(unsafe_code)]

//! Versioned provider-neutral contracts for machine birth.
//!
//! This crate contains declared state and pure validation only. PXE, cloud
//! APIs, topology, enrollment authorities, artifact serving, and execution
//! belong to providers that consume these contracts.

use std::collections::{BTreeMap, BTreeSet};

pub use mycelium_network_types::MacAddress;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const BOOT_CONTRACT_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootMachineSelector {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<MacAddress>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_uuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tpm_public_key_digest: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootIntentMode {
    InstallOnce,
    Always,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecureBootPolicy {
    Required,
    Preferred,
    Disabled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TangPolicy {
    pub threshold: usize,
    pub endpoints: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootSecurityPolicy {
    pub secure_boot: SecureBootPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tang: Option<TangPolicy>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootPostInstall {
    #[serde(default)]
    pub enroll_mycelium: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mycelium_role: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootIntentV1 {
    pub schema_version: u32,
    pub machine: String,
    pub selector: BootMachineSelector,
    pub profile: String,
    pub mode: BootIntentMode,
    pub network: String,
    pub security: BootSecurityPolicy,
    #[serde(default)]
    pub post_install: BootPostInstall,
}

impl BootIntentV1 {
    pub fn validate(&self) -> Result<(), BootContractError> {
        validate_version(self.schema_version)?;
        require_text("machine", &self.machine)?;
        require_text("profile", &self.profile)?;
        require_text("network", &self.network)?;
        if self.selector.mac.is_none()
            && optional_text_is_empty(self.selector.system_uuid.as_deref())
            && optional_text_is_empty(self.selector.tpm_public_key_digest.as_deref())
        {
            return Err(BootContractError::MissingMachineIdentity);
        }
        if let Some(digest) = &self.selector.tpm_public_key_digest {
            validate_sha256("selector.tpm_public_key_digest", digest)?;
        }
        if let Some(tang) = &self.security.tang {
            if tang.threshold == 0 || tang.threshold > tang.endpoints.len() {
                return Err(BootContractError::InvalidTangThreshold {
                    threshold: tang.threshold,
                    endpoints: tang.endpoints.len(),
                });
            }
            if tang.endpoints.iter().collect::<BTreeSet<_>>().len() != tang.endpoints.len() {
                return Err(BootContractError::DuplicateTangEndpoint);
            }
            for endpoint in &tang.endpoints {
                validate_endpoint("security.tang.endpoints", endpoint, &["http", "https"])?;
            }
        }
        if self.post_install.mycelium_role.is_some() && !self.post_install.enroll_mycelium {
            return Err(BootContractError::RoleWithoutEnrollment);
        }
        Ok(())
    }

    pub fn digest(&self) -> String {
        canonical_digest(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootFirmware {
    Uefi,
    Bios,
    RaspberryPi,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootArtifactKind {
    Bootloader,
    Kernel,
    Initrd,
    RootFilesystem,
    Installer,
    Signature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootArtifact {
    pub url: String,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootProfileV1 {
    pub schema_version: u32,
    pub id: String,
    pub architecture: String,
    pub firmware: BootFirmware,
    pub artifacts: BTreeMap<BootArtifactKind, BootArtifact>,
    #[serde(default)]
    pub kernel_arguments: Vec<String>,
}

impl BootProfileV1 {
    pub fn validate(&self) -> Result<(), BootContractError> {
        validate_version(self.schema_version)?;
        require_text("id", &self.id)?;
        require_text("architecture", &self.architecture)?;
        if self.artifacts.is_empty() {
            return Err(BootContractError::MissingArtifacts);
        }
        for (kind, artifact) in &self.artifacts {
            let schemes: &[&str] = if *kind == BootArtifactKind::Bootloader {
                &["http", "https", "tftp"]
            } else {
                &["http", "https"]
            };
            validate_endpoint("artifact.url", &artifact.url, schemes)?;
            validate_sha256("artifact.sha256", &artifact.sha256)?;
        }
        if self
            .kernel_arguments
            .iter()
            .any(|argument| argument.trim().is_empty())
        {
            return Err(BootContractError::EmptyField("kernel_arguments"));
        }
        Ok(())
    }

    pub fn digest(&self) -> String {
        canonical_digest(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootReceiptState {
    Planned,
    Booting,
    Installed,
    Enrolled,
    Verified,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootReceiptV1 {
    pub schema_version: u32,
    pub machine: String,
    pub intent_digest: String,
    pub profile_digest: String,
    pub state: BootReceiptState,
    pub observed_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mycelium_peer_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl BootReceiptV1 {
    pub fn validate(&self) -> Result<(), BootContractError> {
        validate_version(self.schema_version)?;
        require_text("machine", &self.machine)?;
        validate_sha256("intent_digest", &self.intent_digest)?;
        validate_sha256("profile_digest", &self.profile_digest)?;
        if self.state == BootReceiptState::Failed {
            require_text("error", self.error.as_deref().unwrap_or_default())?;
        } else if self.error.is_some() {
            return Err(BootContractError::ErrorOnSuccessfulReceipt);
        }
        if matches!(
            self.state,
            BootReceiptState::Enrolled | BootReceiptState::Verified
        ) {
            require_text(
                "mycelium_peer_id",
                self.mycelium_peer_id.as_deref().unwrap_or_default(),
            )?;
        }
        Ok(())
    }

    pub fn digest(&self) -> String {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BootContractError {
    UnsupportedSchemaVersion(u32),
    EmptyField(&'static str),
    MissingMachineIdentity,
    MissingArtifacts,
    InvalidSha256(&'static str),
    InvalidEndpoint { field: &'static str, value: String },
    InvalidTangThreshold { threshold: usize, endpoints: usize },
    DuplicateTangEndpoint,
    RoleWithoutEnrollment,
    ErrorOnSuccessfulReceipt,
}

impl std::fmt::Display for BootContractError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedSchemaVersion(version) => {
                write!(
                    formatter,
                    "unsupported boot contract schema version {version}"
                )
            }
            Self::EmptyField(field) => {
                write!(formatter, "boot contract field `{field}` cannot be empty")
            }
            Self::MissingMachineIdentity => write!(
                formatter,
                "boot intent requires a MAC, system UUID, or TPM public-key digest"
            ),
            Self::MissingArtifacts => {
                write!(formatter, "boot profile requires at least one artifact")
            }
            Self::InvalidSha256(field) => write!(
                formatter,
                "boot contract field `{field}` must be a lowercase SHA-256 digest"
            ),
            Self::InvalidEndpoint { field, value } => write!(
                formatter,
                "boot contract field `{field}` contains unsupported endpoint `{value}`"
            ),
            Self::InvalidTangThreshold {
                threshold,
                endpoints,
            } => write!(
                formatter,
                "Tang threshold {threshold} is invalid for {endpoints} endpoint(s)"
            ),
            Self::DuplicateTangEndpoint => write!(formatter, "Tang endpoints must be unique"),
            Self::RoleWithoutEnrollment => write!(
                formatter,
                "a Mycelium role requires post-install enrollment"
            ),
            Self::ErrorOnSuccessfulReceipt => {
                write!(formatter, "only failed boot receipts may contain an error")
            }
        }
    }
}

impl std::error::Error for BootContractError {}

fn validate_version(version: u32) -> Result<(), BootContractError> {
    if version == BOOT_CONTRACT_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(BootContractError::UnsupportedSchemaVersion(version))
    }
}

fn require_text(field: &'static str, value: &str) -> Result<(), BootContractError> {
    if value.trim().is_empty() {
        Err(BootContractError::EmptyField(field))
    } else {
        Ok(())
    }
}

fn optional_text_is_empty(value: Option<&str>) -> bool {
    value.is_none_or(|value| value.trim().is_empty())
}

fn validate_sha256(field: &'static str, digest: &str) -> Result<(), BootContractError> {
    if digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(BootContractError::InvalidSha256(field))
    }
}

fn validate_endpoint(
    field: &'static str,
    endpoint: &str,
    schemes: &[&str],
) -> Result<(), BootContractError> {
    let valid = endpoint
        .split_once("://")
        .is_some_and(|(scheme, rest)| schemes.contains(&scheme) && !rest.is_empty());
    if valid && !endpoint.chars().any(char::is_whitespace) {
        Ok(())
    } else {
        Err(BootContractError::InvalidEndpoint {
            field,
            value: endpoint.to_owned(),
        })
    }
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

fn canonical_digest<T: Serialize>(value: &T) -> String {
    let value = serde_json::to_value(value).expect("digest input is serializable");
    let mut hash = Sha256::new();
    hash.update(canonical_json(&value).as_bytes());
    format!("{:x}", hash.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn portable_contract_round_trip_is_stable() {
        let intent = BootIntentV1 {
            schema_version: BOOT_CONTRACT_SCHEMA_VERSION,
            machine: "node-1".into(),
            selector: BootMachineSelector {
                mac: Some(MacAddress([0x02, 0, 0, 0, 0, 1])),
                ..BootMachineSelector::default()
            },
            profile: "fungos-base-amd64".into(),
            mode: BootIntentMode::InstallOnce,
            network: "site-a".into(),
            security: BootSecurityPolicy {
                secure_boot: SecureBootPolicy::Preferred,
                tang: None,
            },
            post_install: BootPostInstall::default(),
        };
        intent.validate().unwrap();
        let encoded = serde_json::to_string(&intent).unwrap();
        assert!(encoded.contains("02:00:00:00:00:01"));
        assert_eq!(
            serde_json::from_str::<BootIntentV1>(&encoded).unwrap(),
            intent
        );
        assert_eq!(intent.digest(), intent.digest());
    }

    #[test]
    fn non_bootloader_tftp_is_rejected() {
        let profile = BootProfileV1 {
            schema_version: BOOT_CONTRACT_SCHEMA_VERSION,
            id: "unsafe".into(),
            architecture: "amd64".into(),
            firmware: BootFirmware::Uefi,
            artifacts: BTreeMap::from([(
                BootArtifactKind::Kernel,
                BootArtifact {
                    url: "tftp://192.0.2.1/vmlinuz".into(),
                    sha256: SHA.into(),
                },
            )]),
            kernel_arguments: vec![],
        };
        assert!(matches!(
            profile.validate(),
            Err(BootContractError::InvalidEndpoint { .. })
        ));
    }
}
