//! Generic desired software placement and safe binary activation.
//!
//! Package manifests authorize immutable bytes. Placement rules consume only
//! derived node facts. Activation is deliberately constrained to Mycelium's
//! own state directory; service lifecycle is a separate driver boundary.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use mycelium_peer_protocol::{sha256_hex, HardwareKind, PackageManifest, Platform};
use serde::{Deserialize, Serialize};

use crate::peer::PeerView;

type AnyError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftwarePolicy {
    pub schema_version: u16,
    #[serde(default)]
    pub defaults: SoftwareDefaults,
    #[serde(default)]
    pub rules: Vec<PlacementRule>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftwareDefaults {
    #[serde(default)]
    pub updates: UpdatePolicy,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum UpdatePolicy {
    Manual,
    Automatic {
        #[serde(default = "default_minimum_age")]
        minimum_cache_age_secs: u64,
        #[serde(default = "default_rollout_window")]
        rollout_window_secs: u64,
        #[serde(default = "default_retry_backoff")]
        retry_backoff_secs: u64,
    },
}

impl Default for UpdatePolicy {
    fn default() -> Self {
        Self::Manual
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementRule {
    pub name: String,
    #[serde(default)]
    pub selector: FactSelector,
    pub packages: Vec<DesiredPackage>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactSelector {
    /// Every fact must be present. Empty means every enrolled node.
    #[serde(default)]
    pub all: BTreeSet<String>,
    /// No listed fact may be present.
    #[serde(default)]
    pub none: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesiredPackage {
    pub name: String,
    #[serde(default = "default_channel")]
    pub channel: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updates: Option<UpdatePolicy>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SoftwareAssignment {
    pub node_id: String,
    pub hostname: String,
    pub package: String,
    pub channel: String,
    pub updates: UpdatePolicy,
    pub rules: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ActivatedPackage {
    pub name: String,
    pub version: String,
    pub target: String,
    pub digest: String,
    pub executable: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageState {
    AwaitingManifest,
    AwaitingArtifact,
    Ready,
    Current,
    Updated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageStatus {
    pub package: String,
    pub channel: String,
    pub installed_version: Option<String>,
    pub desired_version: Option<String>,
    pub state: PackageState,
    pub updates: UpdatePolicy,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AutomaticState {
    #[serde(default)]
    pub last_attempts: BTreeMap<String, u64>,
}

fn default_channel() -> String {
    "stable".into()
}

fn default_minimum_age() -> u64 {
    900
}
fn default_rollout_window() -> u64 {
    1800
}
fn default_retry_backoff() -> u64 {
    3600
}

pub fn read_policy(path: &Path) -> Result<SoftwarePolicy, AnyError> {
    let policy: SoftwarePolicy = serde_json::from_slice(&std::fs::read(path)?)?;
    policy.validate()?;
    Ok(policy)
}

pub fn write_policy(source: &Path) -> Result<SoftwarePolicy, AnyError> {
    let policy = read_policy(source)?;
    let destination = crate::software_policy_path();
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = destination.with_extension("json.tmp");
    std::fs::write(&temporary, serde_json::to_vec_pretty(&policy)?)?;
    std::fs::rename(temporary, destination)?;
    Ok(policy)
}

impl SoftwarePolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1 {
            return Err(format!(
                "unsupported software policy schema {}",
                self.schema_version
            ));
        }
        let mut names = BTreeSet::new();
        for rule in &self.rules {
            validate_label("rule", &rule.name)?;
            if !names.insert(rule.name.as_str()) {
                return Err(format!("duplicate software rule `{}`", rule.name));
            }
            if rule.packages.is_empty() {
                return Err(format!("software rule `{}` has no packages", rule.name));
            }
            if !rule.selector.all.is_disjoint(&rule.selector.none) {
                return Err(format!(
                    "software rule `{}` requires and excludes the same fact",
                    rule.name
                ));
            }
            for package in &rule.packages {
                validate_label("package", &package.name)?;
                validate_label("channel", &package.channel)?;
                validate_update_policy(package.updates.as_ref().unwrap_or(&self.defaults.updates))?;
            }
        }
        Ok(())
    }
}

pub fn plan(
    policy: &SoftwarePolicy,
    peers: &[PeerView],
) -> Result<Vec<SoftwareAssignment>, String> {
    policy.validate()?;
    let mut assignments = BTreeMap::<(String, String), SoftwareAssignment>::new();
    for peer in peers {
        let Some(hello) = &peer.hello else { continue };
        let facts = facts(peer);
        for rule in &policy.rules {
            if !rule.selector.all.is_subset(&facts) || !rule.selector.none.is_disjoint(&facts) {
                continue;
            }
            for package in &rule.packages {
                let key = (hello.node_id.clone(), package.name.clone());
                let assignment = assignments
                    .entry(key)
                    .or_insert_with(|| SoftwareAssignment {
                        node_id: hello.node_id.clone(),
                        hostname: hello.hostname.clone(),
                        package: package.name.clone(),
                        channel: package.channel.clone(),
                        updates: package
                            .updates
                            .clone()
                            .unwrap_or_else(|| policy.defaults.updates.clone()),
                        rules: BTreeSet::new(),
                    });
                if assignment.channel != package.channel {
                    return Err(format!(
                        "conflicting channels for package `{}` on `{}`: `{}` and `{}`",
                        package.name, hello.hostname, assignment.channel, package.channel
                    ));
                }
                let updates = package
                    .updates
                    .clone()
                    .unwrap_or_else(|| policy.defaults.updates.clone());
                if assignment.updates != updates {
                    return Err(format!(
                        "conflicting update policies for package `{}` on `{}`",
                        package.name, hello.hostname
                    ));
                }
                assignment.rules.insert(rule.name.clone());
            }
        }
    }
    Ok(assignments.into_values().collect())
}

pub fn facts(peer: &PeerView) -> BTreeSet<String> {
    let mut facts = BTreeSet::new();
    let Some(hello) = &peer.hello else {
        return facts;
    };
    facts.insert(format!("platform.{}", platform_name(&hello.platform)));
    facts.insert(format!("arch.{}", hello.architecture));
    facts.insert(format!("site.{}", hello.site));
    facts.insert(format!("host.{}", hello.hostname));
    facts.extend(hello.capabilities.iter().cloned());
    if let Some(snapshot) = &peer.hardware {
        for device in &snapshot.devices {
            facts.extend(device.capabilities.iter().cloned());
            if matches!(device.kind, HardwareKind::Accelerator) {
                facts.insert("resource.gpu".into());
            }
        }
    }
    facts
}

pub fn select<'a>(
    manifests: &'a [PackageManifest],
    name: &str,
    channel: &str,
    targets: &[String],
) -> Option<&'a PackageManifest> {
    manifests
        .iter()
        .filter(|item| {
            item.name == name && item.channel == channel && targets.contains(&item.target)
        })
        .max_by(|left, right| {
            compare_versions(&left.version, &right.version).then_with(|| {
                let preference = |item: &PackageManifest| {
                    targets
                        .iter()
                        .position(|target| target == &item.target)
                        .map(|index| targets.len() - index)
                        .unwrap_or_default()
                };
                preference(left).cmp(&preference(right))
            })
        })
}

pub fn reconcile(
    assignments: &[SoftwareAssignment],
    manifests: &[PackageManifest],
    targets: &[String],
    write: bool,
) -> Result<Vec<PackageStatus>, AnyError> {
    let mut statuses = Vec::new();
    for assignment in assignments {
        let installed_version = installed_version(&assignment.package);
        let Some(manifest) = select(manifests, &assignment.package, &assignment.channel, targets)
        else {
            statuses.push(status(
                assignment,
                installed_version,
                None,
                PackageState::AwaitingManifest,
            ));
            continue;
        };
        if installed_version.as_deref() == Some(manifest.version.as_str()) {
            statuses.push(status(
                assignment,
                installed_version,
                Some(manifest.version.clone()),
                PackageState::Current,
            ));
            continue;
        }
        if !crate::artifacts_dir()
            .join(&manifest.artifact_digest)
            .is_file()
        {
            statuses.push(status(
                assignment,
                installed_version,
                Some(manifest.version.clone()),
                PackageState::AwaitingArtifact,
            ));
            continue;
        }
        if write {
            activate(manifest)?;
        }
        statuses.push(status(
            assignment,
            installed_version,
            Some(manifest.version.clone()),
            if write {
                PackageState::Updated
            } else {
                PackageState::Ready
            },
        ));
    }
    if write {
        write_statuses(&statuses)?;
    }
    Ok(statuses)
}

fn status(
    assignment: &SoftwareAssignment,
    installed_version: Option<String>,
    desired_version: Option<String>,
    state: PackageState,
) -> PackageStatus {
    PackageStatus {
        package: assignment.package.clone(),
        channel: assignment.channel.clone(),
        installed_version,
        desired_version,
        state,
        updates: assignment.updates.clone(),
    }
}

fn installed_version(name: &str) -> Option<String> {
    std::fs::read_link(crate::software_dir().join(name).join("current"))
        .ok()
        .and_then(|path| {
            path.file_name()
                .map(|value| value.to_string_lossy().into_owned())
        })
}

fn write_statuses(statuses: &[PackageStatus]) -> Result<(), AnyError> {
    let path = crate::software_state_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("json.tmp");
    std::fs::write(&temporary, serde_json::to_vec_pretty(statuses)?)?;
    std::fs::rename(temporary, path)?;
    Ok(())
}

pub fn persist_statuses(statuses: &[PackageStatus]) -> Result<(), AnyError> {
    write_statuses(statuses)
}

pub fn read_statuses() -> Vec<PackageStatus> {
    std::fs::read(crate::software_state_path())
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

pub fn automatic_assignments(
    assignments: Vec<SoftwareAssignment>,
    manifests: &[PackageManifest],
    targets: &[String],
    node_id: &str,
    now: u64,
    state: &mut AutomaticState,
) -> Vec<SoftwareAssignment> {
    assignments
        .into_iter()
        .filter(|assignment| {
            let UpdatePolicy::Automatic {
                minimum_cache_age_secs,
                rollout_window_secs,
                retry_backoff_secs,
            } = assignment.updates
            else {
                return false;
            };
            let Some(installed) = installed_version(&assignment.package) else {
                return false;
            };
            let Some(manifest) =
                select(manifests, &assignment.package, &assignment.channel, targets)
            else {
                return false;
            };
            if compare_versions(&manifest.version, &installed) != Ordering::Greater {
                return false;
            }
            let Ok(metadata) =
                std::fs::metadata(crate::artifacts_dir().join(&manifest.artifact_digest))
            else {
                return false;
            };
            let cached_at = metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|value| value.as_secs())
                .unwrap_or(now);
            let digest = sha256_hex(format!("{node_id}\0{}", assignment.package).as_bytes());
            let offset =
                u64::from_str_radix(&digest[..16], 16).unwrap_or_default() % rollout_window_secs;
            let eligible_at = cached_at
                .saturating_add(minimum_cache_age_secs)
                .saturating_add(offset);
            let retry_at = state
                .last_attempts
                .get(&assignment.package)
                .copied()
                .unwrap_or_default()
                .saturating_add(retry_backoff_secs);
            if now < eligible_at || now < retry_at {
                return false;
            }
            state.last_attempts.insert(assignment.package.clone(), now);
            true
        })
        .collect()
}

pub fn read_automatic_state() -> AutomaticState {
    std::fs::read(crate::software_automatic_state_path())
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

pub fn write_automatic_state(state: &AutomaticState) -> Result<(), AnyError> {
    let path = crate::software_automatic_state_path();
    let temporary = path.with_extension("json.tmp");
    std::fs::write(&temporary, serde_json::to_vec_pretty(state)?)?;
    std::fs::rename(temporary, path)?;
    Ok(())
}

fn compare_versions(left: &str, right: &str) -> Ordering {
    let numeric = |value: &str| {
        value
            .split('.')
            .map(str::parse::<u64>)
            .collect::<Result<Vec<_>, _>>()
    };
    match (numeric(left), numeric(right)) {
        (Ok(left), Ok(right)) => left.cmp(&right),
        _ => left.cmp(right),
    }
}

pub fn activate(manifest: &PackageManifest) -> Result<ActivatedPackage, AnyError> {
    activate_from(manifest, &crate::artifacts_dir(), &crate::software_dir())
}

fn activate_from(
    manifest: &PackageManifest,
    artifacts: &Path,
    software: &Path,
) -> Result<ActivatedPackage, AnyError> {
    manifest
        .verify()
        .map_err(|error| format!("package signature: {error}"))?;
    validate_label("package", &manifest.name)?;
    validate_label("version", &manifest.version)?;
    let artifact = artifacts.join(&manifest.artifact_digest);
    let bytes = std::fs::read(&artifact).map_err(|error| {
        format!(
            "package artifact {} is not cached: {error}",
            manifest.artifact_digest
        )
    })?;
    if bytes.len() as u64 != manifest.artifact_size
        || sha256_hex(&bytes) != manifest.artifact_digest
    {
        return Err("cached package artifact does not match signed manifest".into());
    }
    let release_dir = software
        .join(&manifest.name)
        .join("releases")
        .join(&manifest.version);
    std::fs::create_dir_all(&release_dir)?;
    let executable = release_dir.join(&manifest.name);
    let temporary = release_dir.join(format!(".{}.tmp-{}", manifest.name, std::process::id()));
    std::fs::write(&temporary, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o755))?;
    }
    std::fs::rename(&temporary, &executable)?;
    let package_dir = software.join(&manifest.name);
    let current_tmp = package_dir.join(format!(".current-{}", std::process::id()));
    #[cfg(unix)]
    std::os::unix::fs::symlink(Path::new("releases").join(&manifest.version), &current_tmp)?;
    #[cfg(not(unix))]
    return Err("package activation is not implemented on this platform".into());
    let current = package_dir.join("current");
    std::fs::rename(current_tmp, current)?;
    Ok(ActivatedPackage {
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        target: manifest.target.clone(),
        digest: manifest.artifact_digest.clone(),
        executable,
    })
}

fn platform_name(platform: &Platform) -> &'static str {
    match platform {
        Platform::Linux => "linux",
        Platform::Darwin => "darwin",
    }
}

fn validate_label(kind: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
    {
        return Err(format!("{kind} contains unsafe characters"));
    }
    Ok(())
}

fn validate_update_policy(policy: &UpdatePolicy) -> Result<(), String> {
    if let UpdatePolicy::Automatic {
        minimum_cache_age_secs,
        rollout_window_secs,
        retry_backoff_secs,
    } = policy
    {
        if *minimum_cache_age_secs < 60 || *rollout_window_secs < 300 || *retry_backoff_secs < 300 {
            return Err("automatic updates require minimum cache age >= 60s, rollout window >= 300s, and retry backoff >= 300s".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mycelium_peer_protocol::PeerHello;

    fn peer(
        hostname: &str,
        platform: Platform,
        architecture: &str,
        capabilities: &[&str],
    ) -> PeerView {
        PeerView {
            origin: hostname.into(),
            hello: Some(PeerHello {
                node_id: hostname.into(),
                protocol_version: 1,
                site: "wagar-house".into(),
                hostname: hostname.into(),
                platform,
                architecture: architecture.into(),
                daemon_version: "test".into(),
                capabilities: capabilities.iter().map(|v| (*v).into()).collect(),
            }),
            health: None,
            hardware: None,
            transports: vec![],
            last_seen: 1,
        }
    }

    #[test]
    fn rules_are_derived_from_facts_and_merge_without_duplicates() {
        let policy = SoftwarePolicy {
            schema_version: 1,
            defaults: SoftwareDefaults::default(),
            rules: vec![
                PlacementRule {
                    name: "global".into(),
                    selector: FactSelector::default(),
                    packages: vec![DesiredPackage {
                        name: "unibus".into(),
                        channel: "stable".into(),
                        updates: None,
                    }],
                },
                PlacementRule {
                    name: "pi".into(),
                    selector: FactSelector {
                        all: BTreeSet::from(["node.raspberry-pi".into()]),
                        none: BTreeSet::new(),
                    },
                    packages: vec![DesiredPackage {
                        name: "isochrone".into(),
                        channel: "stable".into(),
                        updates: None,
                    }],
                },
            ],
        };
        let assignments = plan(
            &policy,
            &[
                peer("pi", Platform::Linux, "aarch64", &["node.raspberry-pi"]),
                peer("mac", Platform::Darwin, "aarch64", &[]),
            ],
        )
        .unwrap();
        assert_eq!(assignments.len(), 3);
        assert!(assignments
            .iter()
            .any(|item| item.hostname == "pi" && item.package == "isochrone"));
    }

    #[test]
    fn conflicting_channels_fail_loudly() {
        let policy = SoftwarePolicy {
            schema_version: 1,
            defaults: SoftwareDefaults::default(),
            rules: vec![
                PlacementRule {
                    name: "a".into(),
                    selector: FactSelector::default(),
                    packages: vec![DesiredPackage {
                        name: "unibus".into(),
                        channel: "stable".into(),
                        updates: None,
                    }],
                },
                PlacementRule {
                    name: "b".into(),
                    selector: FactSelector::default(),
                    packages: vec![DesiredPackage {
                        name: "unibus".into(),
                        channel: "canary".into(),
                        updates: None,
                    }],
                },
            ],
        };
        assert!(
            plan(&policy, &[peer("pi", Platform::Linux, "aarch64", &[])])
                .unwrap_err()
                .contains("conflicting channels")
        );
    }

    #[test]
    fn package_selection_compares_numeric_versions() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let package = |version: &str| {
            PackageManifest::sign(
                &key,
                "unibus".into(),
                version.into(),
                "stable".into(),
                "aarch64-apple-darwin".into(),
                version.as_bytes(),
            )
            .unwrap()
        };
        let packages = vec![package("1.9.0"), package("1.10.0")];
        assert_eq!(
            select(
                &packages,
                "unibus",
                "stable",
                &["aarch64-apple-darwin".into()]
            )
            .unwrap()
            .version,
            "1.10.0"
        );
    }

    #[test]
    fn activation_verifies_bytes_and_switches_current_atomically() {
        let root =
            std::env::temp_dir().join(format!("mycelium-software-test-{}", std::process::id()));
        let artifacts = root.join("artifacts");
        let software = root.join("software");
        std::fs::create_dir_all(&artifacts).unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let package = PackageManifest::sign(
            &key,
            "unibus".into(),
            "1.0.0".into(),
            "stable".into(),
            "aarch64-apple-darwin".into(),
            b"binary",
        )
        .unwrap();
        std::fs::write(artifacts.join(&package.artifact_digest), b"binary").unwrap();
        let activated = activate_from(&package, &artifacts, &software).unwrap();
        assert_eq!(std::fs::read(activated.executable).unwrap(), b"binary");
        assert_eq!(
            std::fs::read_link(software.join("unibus/current")).unwrap(),
            Path::new("releases/1.0.0")
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn documented_policy_resolves_package_specific_updates() {
        let policy: SoftwarePolicy =
            serde_json::from_str(include_str!("../../../docs/examples/software-policy.json"))
                .unwrap();
        policy.validate().unwrap();
        assert_eq!(policy.defaults.updates, UpdatePolicy::Manual);
        let assignments = plan(
            &policy,
            &[peer("gpu", Platform::Linux, "aarch64", &["resource.gpu"])],
        )
        .unwrap();
        let yggdrasil = assignments
            .iter()
            .find(|item| item.package == "yggdrasil")
            .unwrap();
        assert!(matches!(
            yggdrasil.updates,
            UpdatePolicy::Automatic {
                minimum_cache_age_secs: 900,
                ..
            }
        ));
    }

    #[test]
    fn legacy_policy_defaults_to_manual_updates() {
        let policy: SoftwarePolicy = serde_json::from_str(
            r#"{"schema_version":1,"rules":[{"name":"base","packages":[{"name":"unibus"}]}]}"#,
        )
        .unwrap();
        let assignments = plan(&policy, &[peer("node", Platform::Linux, "aarch64", &[])]).unwrap();
        assert_eq!(assignments[0].updates, UpdatePolicy::Manual);
    }
}
