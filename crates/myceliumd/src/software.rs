//! Generic desired software placement and safe binary activation.
//!
//! Package manifests authorize immutable bytes. Placement rules consume only
//! derived node facts. Activation is deliberately constrained to Mycelium's
//! own state directory; service lifecycle is a separate driver boundary.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use mycelium_peer_protocol::{sha256_hex, HardwareKind, PackageManifest, Platform};
use serde::{Deserialize, Serialize};

use crate::peer::PeerView;

type AnyError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftwarePolicy {
    pub schema_version: u16,
    #[serde(default)]
    pub automatic: AutomaticPolicy,
    #[serde(default)]
    pub rules: Vec<PlacementRule>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutomaticPolicy {
    pub enabled: bool,
    pub minimum_cache_age_secs: u64,
    pub rollout_window_secs: u64,
    pub retry_backoff_secs: u64,
}

impl Default for AutomaticPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            minimum_cache_age_secs: 900,
            rollout_window_secs: 1800,
            retry_backoff_secs: 3600,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AutomaticState {
    #[serde(default)]
    pub last_attempts: BTreeMap<String, u64>,
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
    #[serde(default)]
    pub lifecycle: LifecyclePolicy,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum LifecyclePolicy {
    /// Install and atomically select the binary, but do not start it.
    #[default]
    Staged,
    /// Maintain a per-user service through the native OS supervisor.
    UserService {
        #[serde(default)]
        args: Vec<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SoftwareAssignment {
    pub node_id: String,
    pub hostname: String,
    pub package: String,
    pub channel: String,
    pub lifecycle: LifecyclePolicy,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconcileAction {
    Current,
    AwaitingManifest,
    AwaitingArtifact,
    Repair,
    Repaired,
    Activate,
    Activated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReconcileItem {
    pub package: String,
    pub channel: String,
    pub installed_version: Option<String>,
    pub desired_version: Option<String>,
    pub action: ReconcileAction,
    pub lifecycle: LifecyclePolicy,
}

fn default_channel() -> String {
    "stable".into()
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
        if self.automatic.minimum_cache_age_secs < 60
            || self.automatic.rollout_window_secs < 300
            || self.automatic.retry_backoff_secs < 300
        {
            return Err("automatic software policy requires minimum cache age >= 60s, rollout window >= 300s, and retry backoff >= 300s".into());
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
                if let LifecyclePolicy::UserService { args } = &package.lifecycle {
                    if args.len() > 64
                        || args.iter().any(|arg| {
                            arg.len() > 4096
                                || arg
                                    .chars()
                                    .any(|character| matches!(character, '\0' | '\n' | '\r'))
                        })
                    {
                        return Err(format!(
                            "software rule `{}` has unsafe service arguments",
                            rule.name
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

pub fn automatic_assignments(
    assignments: Vec<SoftwareAssignment>,
    manifests: &[PackageManifest],
    targets: &[String],
    policy: &AutomaticPolicy,
    node_id: &str,
    now: u64,
    state: &mut AutomaticState,
) -> Vec<SoftwareAssignment> {
    if !policy.enabled {
        return Vec::new();
    }
    assignments
        .into_iter()
        .filter(|assignment| {
            let Some(installed) = installed_version(&assignment.package) else {
                return false;
            };
            let Some(manifest) =
                select(manifests, &assignment.package, &assignment.channel, targets)
            else {
                return false;
            };
            if manifest.version == installed
                && !lifecycle_healthy(&assignment.package, &assignment.lifecycle)
            {
                let retry_at = state
                    .last_attempts
                    .get(&assignment.package)
                    .copied()
                    .unwrap_or_default()
                    .saturating_add(policy.retry_backoff_secs);
                if now < retry_at {
                    return false;
                }
                state.last_attempts.insert(assignment.package.clone(), now);
                return true;
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
                .map(|duration| duration.as_secs())
                .unwrap_or(now);
            if !automatic_eligible(
                &installed,
                &manifest.version,
                cached_at,
                state.last_attempts.get(&assignment.package).copied(),
                policy,
                node_id,
                &assignment.package,
                now,
            ) {
                return false;
            }
            state.last_attempts.insert(assignment.package.clone(), now);
            true
        })
        .collect()
}

fn automatic_eligible(
    installed: &str,
    desired: &str,
    cached_at: u64,
    last_attempt: Option<u64>,
    policy: &AutomaticPolicy,
    node_id: &str,
    package: &str,
    now: u64,
) -> bool {
    if compare_versions(desired, installed) != Ordering::Greater {
        return false;
    }
    let identity = format!("{node_id}\0{package}");
    let digest = sha256_hex(identity.as_bytes());
    let offset =
        u64::from_str_radix(&digest[..16], 16).unwrap_or_default() % policy.rollout_window_secs;
    let eligible_at = cached_at
        .saturating_add(policy.minimum_cache_age_secs)
        .saturating_add(offset);
    let retry_at = last_attempt
        .unwrap_or_default()
        .saturating_add(policy.retry_backoff_secs);
    now >= eligible_at && now >= retry_at
}

pub fn read_automatic_state() -> AutomaticState {
    std::fs::read(crate::software_automatic_state_path())
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

pub fn write_automatic_state(state: &AutomaticState) -> Result<(), AnyError> {
    let path = crate::software_automatic_state_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("json.tmp");
    std::fs::write(&temporary, serde_json::to_vec_pretty(state)?)?;
    std::fs::rename(temporary, path)?;
    Ok(())
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
                        lifecycle: package.lifecycle.clone(),
                        rules: BTreeSet::new(),
                    });
                if assignment.channel != package.channel {
                    return Err(format!(
                        "conflicting channels for package `{}` on `{}`: `{}` and `{}`",
                        package.name, hello.hostname, assignment.channel, package.channel
                    ));
                }
                if assignment.lifecycle != package.lifecycle {
                    return Err(format!(
                        "conflicting lifecycle policies for package `{}` on `{}`",
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

pub fn reconcile(
    assignments: &[SoftwareAssignment],
    manifests: &[PackageManifest],
    targets: &[String],
    write: bool,
) -> Result<Vec<ReconcileItem>, AnyError> {
    let mut report = Vec::new();
    for assignment in assignments {
        let installed_version = installed_version(&assignment.package);
        let Some(manifest) = select(manifests, &assignment.package, &assignment.channel, targets)
        else {
            report.push(ReconcileItem {
                package: assignment.package.clone(),
                channel: assignment.channel.clone(),
                installed_version,
                desired_version: None,
                action: ReconcileAction::AwaitingManifest,
                lifecycle: assignment.lifecycle.clone(),
            });
            continue;
        };
        if installed_version.as_deref() == Some(manifest.version.as_str()) {
            let healthy = lifecycle_healthy(&assignment.package, &assignment.lifecycle);
            if write && !healthy {
                apply_lifecycle(&assignment.package, &assignment.lifecycle)?;
            }
            report.push(ReconcileItem {
                package: assignment.package.clone(),
                channel: assignment.channel.clone(),
                installed_version,
                desired_version: Some(manifest.version.clone()),
                action: if healthy {
                    ReconcileAction::Current
                } else if write {
                    ReconcileAction::Repaired
                } else {
                    ReconcileAction::Repair
                },
                lifecycle: assignment.lifecycle.clone(),
            });
            continue;
        }
        if !crate::artifacts_dir()
            .join(&manifest.artifact_digest)
            .is_file()
        {
            report.push(ReconcileItem {
                package: assignment.package.clone(),
                channel: assignment.channel.clone(),
                installed_version,
                desired_version: Some(manifest.version.clone()),
                action: ReconcileAction::AwaitingArtifact,
                lifecycle: assignment.lifecycle.clone(),
            });
            continue;
        }
        if write {
            activate_with_lifecycle(manifest, &assignment.lifecycle)?;
        }
        report.push(ReconcileItem {
            package: assignment.package.clone(),
            channel: assignment.channel.clone(),
            installed_version,
            desired_version: Some(manifest.version.clone()),
            action: if write {
                ReconcileAction::Activated
            } else {
                ReconcileAction::Activate
            },
            lifecycle: assignment.lifecycle.clone(),
        });
    }
    Ok(report)
}

fn installed_version(name: &str) -> Option<String> {
    std::fs::read_link(crate::software_dir().join(name).join("current"))
        .ok()
        .and_then(|path| {
            path.file_name()
                .map(|value| value.to_string_lossy().into_owned())
        })
}

fn activate_with_lifecycle(
    manifest: &PackageManifest,
    lifecycle: &LifecyclePolicy,
) -> Result<ActivatedPackage, AnyError> {
    let current = crate::software_dir().join(&manifest.name).join("current");
    let previous = std::fs::read_link(&current).ok();
    let activated = activate(manifest)?;
    if let Err(error) = apply_lifecycle(&manifest.name, lifecycle) {
        restore_current(&current, previous.as_deref())?;
        let rollback = if previous.is_some() {
            apply_lifecycle(&manifest.name, lifecycle)
        } else {
            disable_lifecycle(&manifest.name, lifecycle)
        };
        return match rollback {
            Ok(()) => Err(format!("package `{}` failed health check and was rolled back: {error}", manifest.name).into()),
            Err(rollback) => Err(format!("package `{}` failed health check ({error}); rollback service also failed: {rollback}", manifest.name).into()),
        };
    }
    Ok(activated)
}

fn restore_current(current: &Path, previous: Option<&Path>) -> Result<(), AnyError> {
    let temporary = current.with_extension(format!("rollback-{}", std::process::id()));
    if let Some(previous) = previous {
        #[cfg(unix)]
        std::os::unix::fs::symlink(previous, &temporary)?;
        #[cfg(not(unix))]
        return Err("package rollback is not implemented on this platform".into());
        std::fs::rename(temporary, current)?;
    } else if current.symlink_metadata().is_ok() {
        std::fs::remove_file(current)?;
    }
    Ok(())
}

fn apply_lifecycle(name: &str, lifecycle: &LifecyclePolicy) -> Result<(), AnyError> {
    match lifecycle {
        LifecyclePolicy::Staged => Ok(()),
        LifecyclePolicy::UserService { args } => apply_user_service(name, args),
    }
}

fn lifecycle_healthy(name: &str, lifecycle: &LifecyclePolicy) -> bool {
    match lifecycle {
        LifecyclePolicy::Staged => true,
        LifecyclePolicy::UserService { .. } => user_service_healthy(name),
    }
}

#[cfg(target_os = "linux")]
fn user_service_healthy(name: &str) -> bool {
    Command::new("systemctl")
        .args([
            "--user",
            "is-active",
            "--quiet",
            &format!("mycelium-package-{name}.service"),
        ])
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(target_os = "macos")]
fn user_service_healthy(name: &str) -> bool {
    let Ok(uid) = command_output("id", &["-u"]) else {
        return false;
    };
    let Ok(output) = command_output(
        "launchctl",
        &[
            "print",
            &format!("gui/{uid}/dev.fpl.mycelium.package.{name}"),
        ],
    ) else {
        return false;
    };
    output.lines().any(|line| line.trim() == "state = running")
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn user_service_healthy(_name: &str) -> bool {
    false
}

fn disable_lifecycle(name: &str, lifecycle: &LifecyclePolicy) -> Result<(), AnyError> {
    match lifecycle {
        LifecyclePolicy::Staged => Ok(()),
        LifecyclePolicy::UserService { .. } => disable_user_service(name),
    }
}

#[cfg(target_os = "linux")]
fn disable_user_service(name: &str) -> Result<(), AnyError> {
    command_ok(
        "systemctl",
        &[
            "--user",
            "disable",
            "--now",
            &format!("mycelium-package-{name}.service"),
        ],
    )
}

#[cfg(target_os = "macos")]
fn disable_user_service(name: &str) -> Result<(), AnyError> {
    let uid = command_output("id", &["-u"])?;
    command_ok(
        "launchctl",
        &[
            "bootout",
            &format!("gui/{uid}/dev.fpl.mycelium.package.{name}"),
        ],
    )
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn disable_user_service(_name: &str) -> Result<(), AnyError> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_user_service(name: &str, args: &[String]) -> Result<(), AnyError> {
    let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
    let unit_dir = PathBuf::from(home).join(".config/systemd/user");
    std::fs::create_dir_all(&unit_dir)?;
    let executable = crate::software_dir().join(name).join("current").join(name);
    let command = std::iter::once(executable.to_string_lossy().into_owned())
        .chain(args.iter().cloned())
        .map(|value| systemd_quote(&value))
        .collect::<Vec<_>>()
        .join(" ");
    let unit = format!("[Unit]\nDescription=Mycelium managed package {name}\n\n[Service]\nExecStart={command}\nRestart=on-failure\nRestartSec=5s\n\n[Install]\nWantedBy=default.target\n");
    let unit_name = format!("mycelium-package-{name}.service");
    std::fs::write(unit_dir.join(&unit_name), unit)?;
    command_ok("systemctl", &["--user", "daemon-reload"])?;
    command_ok("systemctl", &["--user", "enable", "--now", &unit_name])?;
    command_ok("systemctl", &["--user", "restart", &unit_name])?;
    command_ok("systemctl", &["--user", "is-active", &unit_name])?;
    std::thread::sleep(std::time::Duration::from_secs(2));
    command_ok("systemctl", &["--user", "is-active", &unit_name])
}

#[cfg(target_os = "macos")]
fn apply_user_service(name: &str, args: &[String]) -> Result<(), AnyError> {
    let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
    let agents = PathBuf::from(home).join("Library/LaunchAgents");
    std::fs::create_dir_all(&agents)?;
    let label = format!("dev.fpl.mycelium.package.{name}");
    let path = agents.join(format!("{label}.plist"));
    let executable = crate::software_dir().join(name).join("current").join(name);
    let arguments = std::iter::once(executable.to_string_lossy().into_owned())
        .chain(args.iter().cloned())
        .map(|value| format!("<string>{}</string>", xml_escape(&value)))
        .collect::<String>();
    let log = crate::software_dir().join(name).join("service.log");
    let plist = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>{label}</string><key>ProgramArguments</key><array>{arguments}</array><key>KeepAlive</key><true/><key>StandardOutPath</key><string>{log}</string><key>StandardErrorPath</key><string>{log}</string></dict></plist>\n", log = xml_escape(&log.to_string_lossy()));
    std::fs::write(&path, plist)?;
    let uid = command_output("id", &["-u"])?;
    let domain = format!("gui/{uid}");
    let _ = Command::new("launchctl")
        .args(["bootout", &format!("{domain}/{label}")])
        .status();
    command_ok(
        "launchctl",
        &["bootstrap", &domain, &path.to_string_lossy()],
    )?;
    command_ok(
        "launchctl",
        &["kickstart", "-k", &format!("{domain}/{label}")],
    )?;
    launchd_running(&domain, &label)?;
    std::thread::sleep(std::time::Duration::from_secs(2));
    launchd_running(&domain, &label)
}

#[cfg(target_os = "macos")]
fn launchd_running(domain: &str, label: &str) -> Result<(), AnyError> {
    let output = command_output("launchctl", &["print", &format!("{domain}/{label}")])?;
    if output.lines().any(|line| line.trim() == "state = running") {
        Ok(())
    } else {
        Err(format!("launchd job `{label}` is not running").into())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn apply_user_service(_name: &str, _args: &[String]) -> Result<(), AnyError> {
    Err("managed user services are unsupported on this platform".into())
}

fn command_ok(program: &str, args: &[&str]) -> Result<(), AnyError> {
    let status = Command::new(program).args(args).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("`{program} {}` exited with {status}", args.join(" ")).into())
    }
}

#[cfg(target_os = "macos")]
fn command_output(program: &str, args: &[&str]) -> Result<String, AnyError> {
    let output = Command::new(program).args(args).output()?;
    if !output.status.success() {
        return Err(format!(
            "`{program} {}` exited with {}",
            args.join(" "),
            output.status
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

#[cfg(target_os = "linux")]
fn systemd_quote(value: &str) -> String {
    format!(
        "\"{}\"",
        value
            .replace('%', "%%")
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
    )
}

#[cfg(target_os = "macos")]
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
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
            automatic: AutomaticPolicy::default(),
            rules: vec![
                PlacementRule {
                    name: "global".into(),
                    selector: FactSelector::default(),
                    packages: vec![DesiredPackage {
                        name: "unibus".into(),
                        channel: "stable".into(),
                        lifecycle: LifecyclePolicy::default(),
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
                        lifecycle: LifecyclePolicy::default(),
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
            automatic: AutomaticPolicy::default(),
            rules: vec![
                PlacementRule {
                    name: "a".into(),
                    selector: FactSelector::default(),
                    packages: vec![DesiredPackage {
                        name: "unibus".into(),
                        channel: "stable".into(),
                        lifecycle: LifecyclePolicy::default(),
                    }],
                },
                PlacementRule {
                    name: "b".into(),
                    selector: FactSelector::default(),
                    packages: vec![DesiredPackage {
                        name: "unibus".into(),
                        channel: "canary".into(),
                        lifecycle: LifecyclePolicy::default(),
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
    fn automatic_rollout_requires_upgrade_soak_and_backoff() {
        let policy = AutomaticPolicy {
            enabled: true,
            minimum_cache_age_secs: 100,
            rollout_window_secs: 300,
            retry_backoff_secs: 500,
        };
        let identity = "node\0unibus";
        let digest = sha256_hex(identity.as_bytes());
        let offset = u64::from_str_radix(&digest[..16], 16).unwrap() % 300;
        let ready = 1_000 + 100 + offset;
        assert!(!automatic_eligible(
            "1.0.0", "1.0.0", 1_000, None, &policy, "node", "unibus", ready
        ));
        assert!(!automatic_eligible(
            "1.0.0",
            "1.1.0",
            1_000,
            None,
            &policy,
            "node",
            "unibus",
            ready - 1
        ));
        assert!(automatic_eligible(
            "1.0.0", "1.1.0", 1_000, None, &policy, "node", "unibus", ready
        ));
        assert!(!automatic_eligible(
            "1.0.0",
            "1.1.0",
            1_000,
            Some(ready),
            &policy,
            "node",
            "unibus",
            ready + 499
        ));
    }

    #[test]
    fn conflicting_lifecycle_policies_fail_loudly() {
        let policy = SoftwarePolicy {
            schema_version: 1,
            automatic: AutomaticPolicy::default(),
            rules: vec![
                PlacementRule {
                    name: "stage".into(),
                    selector: FactSelector::default(),
                    packages: vec![DesiredPackage {
                        name: "unibus".into(),
                        channel: "stable".into(),
                        lifecycle: LifecyclePolicy::Staged,
                    }],
                },
                PlacementRule {
                    name: "run".into(),
                    selector: FactSelector::default(),
                    packages: vec![DesiredPackage {
                        name: "unibus".into(),
                        channel: "stable".into(),
                        lifecycle: LifecyclePolicy::UserService { args: vec![] },
                    }],
                },
            ],
        };
        assert!(
            plan(&policy, &[peer("pi", Platform::Linux, "aarch64", &[])])
                .unwrap_err()
                .contains("conflicting lifecycle")
        );
    }
}
