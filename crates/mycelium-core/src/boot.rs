//! Deterministic early-boot network and NBDE planning.
//!
//! The planner only reasons over observed topology. It does not probe, mutate
//! routing, or execute Clevis: those belong to drivers and an explicitly
//! write-gated enrollment workflow.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use serde::{Deserialize, Serialize};

use crate::{canonical_digest, ipv4_in_cidr, MacAddress, Segment, TopoNode, Topology};

pub const BOOT_CONTRACT_SCHEMA_VERSION: u32 = 1;

/// Stable evidence used to associate a physical machine with a boot intent.
/// At least one hardware identity must be present; a hostname alone is not a
/// safe selector for unattended provisioning.
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

/// Provider-neutral desired state for one machine's next network boot.
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

/// Immutable profile data consumed by any provisioning implementation.
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

/// Durable evidence from provisioning. It references immutable digests rather
/// than embedding an intent or profile that could later diverge.
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
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedSchemaVersion(version) => {
                write!(f, "unsupported boot contract schema version {version}")
            }
            Self::EmptyField(field) => write!(f, "boot contract field `{field}` cannot be empty"),
            Self::MissingMachineIdentity => write!(
                f,
                "boot intent requires a MAC, system UUID, or TPM public-key digest"
            ),
            Self::MissingArtifacts => write!(f, "boot profile requires at least one artifact"),
            Self::InvalidSha256(field) => write!(
                f,
                "boot contract field `{field}` must be a lowercase SHA-256 digest"
            ),
            Self::InvalidEndpoint { field, value } => write!(
                f,
                "boot contract field `{field}` contains unsupported endpoint `{value}`"
            ),
            Self::InvalidTangThreshold {
                threshold,
                endpoints,
            } => write!(
                f,
                "Tang threshold {threshold} is invalid for {endpoints} endpoint(s)"
            ),
            Self::DuplicateTangEndpoint => write!(f, "Tang endpoints must be unique"),
            Self::RoleWithoutEnrollment => {
                write!(f, "a Mycelium role requires post-install enrollment")
            }
            Self::ErrorOnSuccessfulReceipt => {
                write!(f, "only failed boot receipts may contain an error")
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootReachability {
    Direct,
    Routed,
    Unverified,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootTarget {
    pub endpoint: String,
    pub address: IpAddr,
    pub reachability: BootReachability,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_segment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_segment: Option<String>,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootPath {
    pub device: String,
    pub source_addresses: Vec<IpAddr>,
    pub targets: Vec<BootTarget>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NbdePlan {
    pub device: String,
    pub threshold: usize,
    pub endpoints: Vec<BootTarget>,
    pub reachable: usize,
    pub viable: bool,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BootPlanError {
    DeviceNotFound(String),
    AmbiguousDevice(String),
    InvalidEndpoint(String),
    InvalidThreshold { threshold: usize, endpoints: usize },
}

impl std::fmt::Display for BootPlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DeviceNotFound(device) => write!(f, "device `{device}` is absent from topology"),
            Self::AmbiguousDevice(device) => write!(f, "device selector `{device}` is ambiguous"),
            Self::InvalidEndpoint(endpoint) => {
                write!(f, "endpoint `{endpoint}` must contain an IP address")
            }
            Self::InvalidThreshold {
                threshold,
                endpoints,
            } => write!(
                f,
                "threshold {threshold} is invalid for {endpoints} endpoint(s)"
            ),
        }
    }
}

impl std::error::Error for BootPlanError {}

impl Topology {
    pub fn boot_path(&self, device: &str, endpoints: &[String]) -> Result<BootPath, BootPlanError> {
        let node = self.resolve_node(device)?;
        let source_addresses = node.ips.keys().copied().collect::<Vec<_>>();
        let source_segments = matching_segments(self, node);
        let mut targets = Vec::with_capacity(endpoints.len());

        for endpoint in endpoints {
            let address = endpoint_ip(endpoint)
                .ok_or_else(|| BootPlanError::InvalidEndpoint(endpoint.clone()))?;
            let target_segments = self
                .segments
                .values()
                .filter(|segment| segment_contains(segment, address))
                .collect::<Vec<_>>();

            let direct = source_segments
                .iter()
                .find(|source| target_segments.iter().any(|target| source.id == target.id));
            let (reachability, source_segment, target_segment, reason) = if let Some(segment) =
                direct
            {
                (
                    BootReachability::Direct,
                    Some(segment.id.clone()),
                    Some(segment.id.clone()),
                    "endpoint shares an observed boot segment".to_owned(),
                )
            } else if let (Some(source), Some(target)) = (
                source_segments.iter().find(|segment| segment.gw.is_some()),
                target_segments.first(),
            ) {
                (
                    BootReachability::Routed,
                    Some(source.id.clone()),
                    Some(target.id.clone()),
                    "source has a gateway and target is on an observed segment; initramfs route/firewall still requires verification".to_owned(),
                )
            } else {
                (
                    BootReachability::Unverified,
                    source_segments.first().map(|segment| segment.id.clone()),
                    target_segments.first().map(|segment| segment.id.clone()),
                    "topology does not prove an early-boot path".to_owned(),
                )
            };
            targets.push(BootTarget {
                endpoint: endpoint.clone(),
                address,
                reachability,
                source_segment,
                target_segment,
                reason,
            });
        }

        Ok(BootPath {
            device: node.id.clone(),
            source_addresses,
            targets,
        })
    }

    pub fn nbde_plan(
        &self,
        device: &str,
        endpoints: &[String],
        threshold: usize,
    ) -> Result<NbdePlan, BootPlanError> {
        if threshold == 0 || threshold > endpoints.len() {
            return Err(BootPlanError::InvalidThreshold {
                threshold,
                endpoints: endpoints.len(),
            });
        }
        let path = self.boot_path(device, endpoints)?;
        let reachable = path
            .targets
            .iter()
            .filter(|target| target.reachability != BootReachability::Unverified)
            .count();
        let mut warnings = path
            .targets
            .iter()
            .filter(|target| target.reachability == BootReachability::Routed)
            .map(|target| {
                format!(
                    "{} is routed; verify initramfs addressing, gateway, and firewall policy",
                    target.endpoint
                )
            })
            .collect::<Vec<_>>();
        if reachable < threshold {
            warnings.push(format!(
                "only {reachable} of {} endpoints have an observed path; threshold is {threshold}",
                endpoints.len()
            ));
        }
        Ok(NbdePlan {
            device: path.device,
            threshold,
            endpoints: path.targets,
            reachable,
            viable: reachable >= threshold,
            warnings,
        })
    }

    fn resolve_node(&self, selector: &str) -> Result<&TopoNode, BootPlanError> {
        if let Some(node) = self.nodes.get(selector) {
            return Ok(node);
        }
        let selector_ip = selector.parse::<IpAddr>().ok();
        let matches = self
            .nodes
            .values()
            .filter(|node| {
                node.hostnames.contains(&selector.to_lowercase())
                    || selector_ip.is_some_and(|ip| node.ips.contains_key(&ip))
            })
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [] => Err(BootPlanError::DeviceNotFound(selector.to_owned())),
            [node] => Ok(node),
            _ => Err(BootPlanError::AmbiguousDevice(selector.to_owned())),
        }
    }
}

fn matching_segments<'a>(topology: &'a Topology, node: &TopoNode) -> Vec<&'a Segment> {
    topology
        .segments
        .values()
        .filter(|segment| {
            node.ips
                .keys()
                .any(|address| segment_contains(segment, *address))
        })
        .collect()
}

fn segment_contains(segment: &Segment, address: IpAddr) -> bool {
    segment
        .subnet
        .is_some_and(|(network, prefix)| ipv4_in_cidr(address, network, prefix))
}

fn endpoint_ip(endpoint: &str) -> Option<IpAddr> {
    let authority = endpoint
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(endpoint)
        .split('/')
        .next()?;
    if let Ok(address) = authority.parse() {
        return Some(address);
    }
    authority
        .rsplit_once(':')
        .and_then(|(host, _)| host.parse().ok())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::{IpRecord, SegmentKind};

    const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn boot_intent() -> BootIntentV1 {
        BootIntentV1 {
            schema_version: BOOT_CONTRACT_SCHEMA_VERSION,
            machine: "radioman-pi".into(),
            selector: BootMachineSelector {
                mac: Some(MacAddress([0xdc, 0xa6, 0x32, 0x01, 0x02, 0x03])),
                ..BootMachineSelector::default()
            },
            profile: "fpl-linux-arm64".into(),
            mode: BootIntentMode::InstallOnce,
            network: "wagar-house".into(),
            security: BootSecurityPolicy {
                secure_boot: SecureBootPolicy::Preferred,
                tang: Some(TangPolicy {
                    threshold: 1,
                    endpoints: vec!["http://192.168.20.8:7500".into()],
                }),
            },
            post_install: BootPostInstall {
                enroll_mycelium: true,
                mycelium_role: Some("managed-node".into()),
            },
        }
    }

    fn boot_profile() -> BootProfileV1 {
        BootProfileV1 {
            schema_version: BOOT_CONTRACT_SCHEMA_VERSION,
            id: "fpl-linux-arm64".into(),
            architecture: "aarch64".into(),
            firmware: BootFirmware::RaspberryPi,
            artifacts: BTreeMap::from([
                (
                    BootArtifactKind::Kernel,
                    BootArtifact {
                        url: "https://genesis.example/kernel".into(),
                        sha256: SHA_A.into(),
                    },
                ),
                (
                    BootArtifactKind::Initrd,
                    BootArtifact {
                        url: "https://genesis.example/initrd".into(),
                        sha256: SHA_B.into(),
                    },
                ),
            ]),
            kernel_arguments: vec!["console=ttyAMA0".into()],
        }
    }

    fn topology() -> Topology {
        let host_ip = "192.168.20.50".parse().unwrap();
        Topology {
            nodes: BTreeMap::from([(
                "server".into(),
                TopoNode {
                    id: "server".into(),
                    ips: BTreeMap::from([(
                        host_ip,
                        IpRecord {
                            addr: host_ip,
                            prefix: Some(24),
                            vlan: None,
                            origins: BTreeSet::new(),
                        },
                    )]),
                    hostnames: BTreeSet::from(["compute-1".into()]),
                    ..TopoNode::default()
                },
            )]),
            segments: BTreeMap::from([
                (
                    "boot".into(),
                    Segment {
                        id: "boot".into(),
                        kind: SegmentKind::Vlan,
                        subnet: Some(("192.168.20.0".parse().unwrap(), 24)),
                        gw: Some("192.168.20.1".parse().unwrap()),
                        ..Segment::default()
                    },
                ),
                (
                    "services".into(),
                    Segment {
                        id: "services".into(),
                        kind: SegmentKind::Vlan,
                        subnet: Some(("192.168.99.0".parse().unwrap(), 24)),
                        gw: Some("192.168.99.1".parse().unwrap()),
                        ..Segment::default()
                    },
                ),
            ]),
            ..Topology::default()
        }
    }

    #[test]
    fn classifies_direct_routed_and_unknown_paths() {
        let endpoints = vec![
            "http://192.168.20.8:7500".into(),
            "http://192.168.99.8:7500".into(),
            "http://10.4.0.8:7500".into(),
        ];
        let path = topology().boot_path("compute-1", &endpoints).unwrap();
        assert_eq!(path.targets[0].reachability, BootReachability::Direct);
        assert_eq!(path.targets[1].reachability, BootReachability::Routed);
        assert_eq!(path.targets[2].reachability, BootReachability::Unverified);
    }

    #[test]
    fn nbde_threshold_fails_loud_when_topology_cannot_support_it() {
        let endpoints = vec![
            "http://192.168.20.8:7500".into(),
            "http://10.4.0.8:7500".into(),
        ];
        let plan = topology().nbde_plan("server", &endpoints, 2).unwrap();
        assert!(!plan.viable);
        assert_eq!(plan.reachable, 1);
        assert!(!plan.warnings.is_empty());
    }

    #[test]
    fn rejects_dns_until_early_boot_dns_is_modeled() {
        let error = topology()
            .boot_path("server", &["http://tang.local:7500".into()])
            .unwrap_err();
        assert!(matches!(error, BootPlanError::InvalidEndpoint(_)));
    }

    #[test]
    fn boot_contracts_round_trip_and_have_stable_digests() {
        let intent = boot_intent();
        let profile = boot_profile();
        intent.validate().unwrap();
        profile.validate().unwrap();

        let encoded = serde_json::to_string(&intent).unwrap();
        let decoded: BootIntentV1 = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, intent);
        assert_eq!(decoded.digest(), intent.digest());

        let profile_value = serde_json::to_value(&profile).unwrap();
        let reordered = serde_json::Value::Object(
            profile_value
                .as_object()
                .unwrap()
                .iter()
                .rev()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        );
        let decoded: BootProfileV1 = serde_json::from_value(reordered).unwrap();
        assert_eq!(decoded.digest(), profile.digest());
    }

    #[test]
    fn boot_intent_rejects_unsafe_or_incomplete_identity_policy() {
        let mut intent = boot_intent();
        intent.selector = BootMachineSelector::default();
        assert_eq!(
            intent.validate(),
            Err(BootContractError::MissingMachineIdentity)
        );

        intent = boot_intent();
        intent.security.tang.as_mut().unwrap().threshold = 2;
        assert!(matches!(
            intent.validate(),
            Err(BootContractError::InvalidTangThreshold { .. })
        ));

        intent = boot_intent();
        intent.post_install.enroll_mycelium = false;
        assert_eq!(
            intent.validate(),
            Err(BootContractError::RoleWithoutEnrollment)
        );

        intent = boot_intent();
        intent.security.tang.as_mut().unwrap().endpoints = vec![
            "http://192.168.20.8:7500".into(),
            "http://192.168.20.8:7500".into(),
        ];
        assert_eq!(
            intent.validate(),
            Err(BootContractError::DuplicateTangEndpoint)
        );
    }

    #[test]
    fn boot_profile_rejects_unpinned_artifacts() {
        let mut profile = boot_profile();
        profile
            .artifacts
            .get_mut(&BootArtifactKind::Kernel)
            .unwrap()
            .sha256 = "latest".into();
        assert_eq!(
            profile.validate(),
            Err(BootContractError::InvalidSha256("artifact.sha256"))
        );

        let mut profile = boot_profile();
        profile
            .artifacts
            .get_mut(&BootArtifactKind::Kernel)
            .unwrap()
            .url = "tftp://192.168.20.8/kernel".into();
        assert!(matches!(
            profile.validate(),
            Err(BootContractError::InvalidEndpoint { .. })
        ));

        let kernel = profile.artifacts.remove(&BootArtifactKind::Kernel).unwrap();
        profile
            .artifacts
            .insert(BootArtifactKind::Bootloader, kernel);
        profile.validate().unwrap();
    }

    #[test]
    fn receipt_requires_enrollment_evidence_and_failure_details() {
        let intent = boot_intent();
        let profile = boot_profile();
        let mut receipt = BootReceiptV1 {
            schema_version: BOOT_CONTRACT_SCHEMA_VERSION,
            machine: intent.machine.clone(),
            intent_digest: intent.digest(),
            profile_digest: profile.digest(),
            state: BootReceiptState::Enrolled,
            observed_at: 42,
            mycelium_peer_id: None,
            error: None,
        };
        assert_eq!(
            receipt.validate(),
            Err(BootContractError::EmptyField("mycelium_peer_id"))
        );
        receipt.mycelium_peer_id = Some("peer:radioman-pi".into());
        receipt.validate().unwrap();

        receipt.state = BootReceiptState::Failed;
        receipt.mycelium_peer_id = None;
        assert_eq!(
            receipt.validate(),
            Err(BootContractError::EmptyField("error"))
        );
        receipt.error = Some("installer exited".into());
        receipt.validate().unwrap();
    }
}
