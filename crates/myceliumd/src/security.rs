use std::collections::BTreeMap;
#[cfg(any(target_os = "linux", test))]
use std::collections::BTreeSet;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use mycelium_peer_protocol::{
    sha256_hex, ComplianceSummary, PeerHello, SecurityEvent, SecurityEventBatch, SecurityPosture,
    MAX_SECURITY_EVENTS,
};
#[cfg(any(target_os = "linux", test))]
use mycelium_peer_protocol::{SecurityFinding, SecuritySeverity};

type AnyError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationState {
    Planned,
    Applied,
    Verified,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemediationPlan {
    pub schema_version: u16,
    pub digest: String,
    pub script_digest: String,
    pub evidence_digest: String,
    pub content: String,
    pub profile: String,
    pub created_at: u64,
    pub state: RemediationState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub(crate) struct StigScan<'a> {
    pub content: &'a str,
    pub profile: &'a str,
    pub remediation_plan: bool,
}

pub(crate) fn collect(
    hello: &PeerHello,
    stig: Option<StigScan<'_>>,
) -> Result<(SecurityPosture, SecurityEventBatch), AnyError> {
    let observed_at = super::peer::now();
    let mut scanners = BTreeMap::new();
    #[allow(unused_mut)]
    let mut findings = Vec::new();
    #[allow(unused_mut)]
    let mut updates = 0;
    let mut compliance = Vec::new();

    #[cfg(target_os = "linux")]
    {
        scanners.insert("package_updates".into(), "available".into());
        match bounded_output("apt", &["list", "--upgradable"], Duration::from_secs(15)) {
            Ok(output) => {
                for line in output
                    .lines()
                    .filter(|line| line.contains(" upgradable from: "))
                {
                    updates += 1;
                    if findings.len() >= mycelium_peer_protocol::MAX_SECURITY_FINDINGS {
                        break;
                    }
                    if let Some(finding) = apt_finding(line) {
                        findings.push(finding);
                    }
                }
            }
            Err(error) => {
                scanners.insert("package_updates".into(), format!("error:{error}"));
            }
        }
        scanners.insert(
            "cve".into(),
            tool_status("trivy", &["--version"], Duration::from_secs(3)),
        );
        scanners.insert(
            "disa_stig".into(),
            tool_status("oscap", &["--version"], Duration::from_secs(3)),
        );
    }
    #[cfg(target_os = "macos")]
    {
        scanners.insert(
            "package_updates".into(),
            "manual_scan_required:softwareupdate".into(),
        );
        scanners.insert("cve".into(), "unsupported".into());
        scanners.insert("disa_stig".into(), "unsupported".into());
    }
    if let Some(spec) = stig {
        compliance.push(run_stig(&mut scanners, spec)?);
    }

    let posture = SecurityPosture {
        schema_version: 1,
        node_id: hello.node_id.clone(),
        hostname: hello.hostname.clone(),
        site: hello.site.clone(),
        observed_at,
        platform: format!("{:?}", hello.platform).to_lowercase(),
        os_version: os_version(),
        security_updates_available: updates,
        reboot_required: cfg!(target_os = "linux")
            && std::path::Path::new("/var/run/reboot-required").exists(),
        scanners,
        findings,
        compliance,
    };
    let events = posture
        .findings
        .iter()
        .take(MAX_SECURITY_EVENTS)
        .map(|finding| SecurityEvent {
            id: finding.id.clone(),
            observed_at,
            category: finding.category.clone(),
            action: "detected".into(),
            outcome: "open".into(),
            severity: finding.severity.clone(),
            message: finding.title.clone(),
            fields: [
                ("source".into(), finding.source.clone()),
                (
                    "component".into(),
                    finding.component.clone().unwrap_or_default(),
                ),
            ]
            .into(),
        })
        .collect();
    let batch = SecurityEventBatch {
        schema_version: 1,
        node_id: hello.node_id.clone(),
        hostname: hello.hostname.clone(),
        site: hello.site.clone(),
        observed_at,
        events,
    };
    Ok((posture, batch))
}

#[cfg(any(target_os = "linux", test))]
fn apt_finding(line: &str) -> Option<SecurityFinding> {
    let (package, rest) = line.split_once('/')?;
    let fields = rest.split_whitespace().collect::<Vec<_>>();
    let fixed = fields.get(1).map(|value| (*value).to_owned());
    let installed = fields
        .windows(2)
        .find(|window| window[0] == "from:")
        .map(|window| window[1].trim_end_matches(']').to_owned());
    let security = line.to_ascii_lowercase().contains("security");
    let title = format!(
        "{} update available for {package}",
        if security { "Security" } else { "Package" }
    );
    Some(SecurityFinding {
        id: sha256_hex(
            format!("apt:{package}:{}", fixed.as_deref().unwrap_or("unknown")).as_bytes(),
        ),
        source: "apt".into(),
        category: if security { "vulnerability" } else { "update" }.into(),
        severity: if security {
            SecuritySeverity::Medium
        } else {
            SecuritySeverity::Informational
        },
        title,
        component: Some(package.into()),
        installed_version: installed,
        fixed_version: fixed,
        references: BTreeSet::new(),
    })
}

#[cfg(target_os = "linux")]
fn tool_status(command: &str, args: &[&str], timeout: Duration) -> String {
    match bounded_output(command, args, timeout) {
        Ok(_) => "available".into(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => "unavailable".into(),
        Err(error) => format!("error:{error}"),
    }
}

fn run_stig(
    scanners: &mut BTreeMap<String, String>,
    spec: StigScan<'_>,
) -> Result<ComplianceSummary, AnyError> {
    if !std::path::Path::new(spec.content).is_file() {
        return Err(format!("STIG content does not exist: {}", spec.content).into());
    }
    let evidence_dir = crate::home_dir().join("security/evidence");
    std::fs::create_dir_all(&evidence_dir)?;
    let scan_id = sha256_hex(format!("{}:{}", spec.content, spec.profile).as_bytes());
    let temporary = evidence_dir.join(format!("{scan_id}.tmp.xml"));
    let temporary_text = temporary.to_string_lossy().into_owned();
    bounded_output_status(
        "oscap",
        &[
            "xccdf",
            "eval",
            "--profile",
            spec.profile,
            "--results",
            &temporary_text,
            spec.content,
        ],
        Duration::from_secs(15 * 60),
        &[0, 2],
    )
    .map_err(|error| format!("OpenSCAP STIG evaluation failed: {error}"))?;
    let evidence = std::fs::read(&temporary)?;
    let digest = sha256_hex(&evidence);
    let final_path = evidence_dir.join(format!("{digest}.xml"));
    std::fs::rename(&temporary, &final_path)?;
    let text = String::from_utf8_lossy(&evidence);
    let (passed, failed, errors, not_applicable) = compliance_counts(&text);
    if spec.remediation_plan {
        if passed + failed + errors == 0 {
            return Err(format!(
                "STIG profile `{}` is not applicable to this host; refusing to generate a remediation plan",
                spec.profile
            )
            .into());
        }
        let plan = evidence_dir.join(format!("{digest}.remediation.sh"));
        let plan_text = plan.to_string_lossy().into_owned();
        let evidence_text = final_path.to_string_lossy().into_owned();
        bounded_output(
            "oscap",
            &[
                "xccdf",
                "generate",
                "fix",
                "--profile",
                spec.profile,
                "--fix-type",
                "bash",
                "--output",
                &plan_text,
                &evidence_text,
            ],
            Duration::from_secs(60),
        )
        .map_err(|error| format!("OpenSCAP remediation plan generation failed: {error}"))?;
        scanners.insert(
            "disa_stig_remediation".into(),
            format!("planned:{}", sha256_hex(&std::fs::read(plan)?)),
        );
        persist_remediation_plan(spec.content, spec.profile, &digest)?;
    }
    scanners.insert(
        "disa_stig".into(),
        if passed + failed + errors == 0 {
            "not_applicable"
        } else {
            "completed"
        }
        .into(),
    );
    Ok(ComplianceSummary {
        profile: spec.profile.into(),
        passed,
        failed,
        errors,
        not_applicable,
        evidence_digest: Some(digest),
    })
}

fn plans_dir() -> std::path::PathBuf {
    crate::home_dir().join("security/plans")
}

fn persist_remediation_plan(
    content: &str,
    profile: &str,
    evidence_digest: &str,
) -> Result<RemediationPlan, AnyError> {
    let script_path = crate::home_dir()
        .join("security/evidence")
        .join(format!("{evidence_digest}.remediation.sh"));
    let script_digest = sha256_hex(&std::fs::read(&script_path)?);
    let digest = sha256_hex(
        format!("remediation:v1:{evidence_digest}:{script_digest}:{profile}").as_bytes(),
    );
    let plan = RemediationPlan {
        schema_version: 1,
        digest: digest.clone(),
        script_digest,
        evidence_digest: evidence_digest.into(),
        content: content.into(),
        profile: profile.into(),
        created_at: super::peer::now(),
        state: RemediationState::Planned,
        applied_at: None,
        verified_at: None,
        error: None,
    };
    std::fs::create_dir_all(plans_dir())?;
    write_plan(&plan)?;
    Ok(plan)
}

fn plan_path(digest: &str) -> Result<std::path::PathBuf, AnyError> {
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("remediation plan digest must be 64 hexadecimal characters".into());
    }
    Ok(plans_dir().join(format!("{digest}.json")))
}

fn write_plan(plan: &RemediationPlan) -> Result<(), AnyError> {
    let path = plan_path(&plan.digest)?;
    let temporary = path.with_extension("json.tmp");
    std::fs::write(&temporary, serde_json::to_vec_pretty(plan)?)?;
    std::fs::rename(temporary, path)?;
    Ok(())
}

pub(crate) fn remediation_plans() -> Result<Vec<RemediationPlan>, AnyError> {
    let mut plans = Vec::new();
    let Ok(entries) = std::fs::read_dir(plans_dir()) else {
        return Ok(plans);
    };
    for entry in entries {
        let entry = entry?;
        if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        plans.push(serde_json::from_slice(&std::fs::read(entry.path())?)?);
    }
    plans.sort_by_key(|plan: &RemediationPlan| std::cmp::Reverse(plan.created_at));
    Ok(plans)
}

pub(crate) fn apply_remediation(digest: &str) -> Result<RemediationPlan, AnyError> {
    let path = plan_path(digest)?;
    let mut plan: RemediationPlan = serde_json::from_slice(&std::fs::read(path)?)?;
    if plan.digest != digest {
        return Err("remediation plan identity does not match its filename".into());
    }
    if plan.state != RemediationState::Planned && plan.state != RemediationState::Failed {
        return Err(format!("remediation plan is already {:?}", plan.state).into());
    }
    let script_path = crate::home_dir()
        .join("security/evidence")
        .join(format!("{}.remediation.sh", plan.evidence_digest));
    let script = std::fs::read(&script_path)?;
    if sha256_hex(&script) != plan.script_digest {
        return Err("remediation script digest does not match the reviewed plan".into());
    }
    match bounded_output_status(
        "bash",
        &[script_path.to_string_lossy().as_ref()],
        Duration::from_secs(30 * 60),
        &[0],
    ) {
        Ok(_) => {
            plan.state = RemediationState::Applied;
            plan.applied_at = Some(super::peer::now());
            plan.error = None;
        }
        Err(error) => {
            plan.state = RemediationState::Failed;
            plan.error = Some(error.to_string());
        }
    }
    write_plan(&plan)?;
    Ok(plan)
}

pub(crate) fn verify_remediation(digest: &str) -> Result<RemediationPlan, AnyError> {
    let path = plan_path(digest)?;
    let mut plan: RemediationPlan = serde_json::from_slice(&std::fs::read(path)?)?;
    if plan.state != RemediationState::Applied {
        return Err("only an applied remediation plan can be verified".into());
    }
    let mut scanners = BTreeMap::new();
    let summary = run_stig(
        &mut scanners,
        StigScan {
            content: &plan.content,
            profile: &plan.profile,
            remediation_plan: false,
        },
    )?;
    if summary.failed == 0 && summary.errors == 0 && summary.passed > 0 {
        plan.state = RemediationState::Verified;
        plan.verified_at = Some(super::peer::now());
        plan.error = None;
    } else {
        plan.state = RemediationState::Failed;
        plan.error = Some(format!(
            "post-remediation scan has {} failed and {} error rules",
            summary.failed, summary.errors
        ));
    }
    write_plan(&plan)?;
    Ok(plan)
}

fn compliance_counts(text: &str) -> (u32, u32, u32, u32) {
    let count = |result: &str| text.matches(&format!(">{result}</result>")).count() as u32;
    (
        count("pass"),
        count("fail"),
        count("error"),
        count("notapplicable") + count("notchecked"),
    )
}

fn bounded_output(command: &str, args: &[&str], timeout: Duration) -> std::io::Result<String> {
    bounded_output_status(command, args, timeout, &[0])
}

fn bounded_output_status(
    command: &str,
    args: &[&str],
    timeout: Duration,
    allowed_codes: &[i32],
) -> std::io::Result<String> {
    let mut child = Command::new(command)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()?;
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            let output = child.wait_with_output()?;
            if !status
                .code()
                .is_some_and(|code| allowed_codes.contains(&code))
            {
                return Err(std::io::Error::other(format!("exited {status}")));
            }
            return String::from_utf8(output.stdout)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error));
        }
        if started.elapsed() >= timeout {
            child.kill()?;
            let _ = child.wait();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "timed out",
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn os_version() -> Option<String> {
    #[cfg(target_os = "linux")]
    return std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("PRETTY_NAME="))
                .map(|value| value.trim_matches('"').to_owned())
        });
    #[cfg(target_os = "macos")]
    return bounded_output(
        "/usr/bin/sw_vers",
        &["-productVersion"],
        Duration::from_secs(3),
    )
    .ok()
    .map(|value| value.trim().to_owned());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apt_update_becomes_stable_normalized_finding() {
        let line = "openssl/bookworm-security 3.0.17 amd64 [upgradable from: 3.0.16]";
        let finding = apt_finding(line).unwrap();
        assert_eq!(finding.component.as_deref(), Some("openssl"));
        assert_eq!(finding.category, "vulnerability");
        assert_eq!(finding.fixed_version.as_deref(), Some("3.0.17"));
        assert_eq!(finding.installed_version.as_deref(), Some("3.0.16"));
    }

    #[test]
    fn xccdf_result_counts_keep_not_applicable_visible() {
        let xml = "<result>pass</result><result>fail</result><result>notapplicable</result><result>notchecked</result>";
        assert_eq!(compliance_counts(xml), (1, 1, 0, 2));
    }

    #[test]
    fn remediation_plan_digest_is_path_safe() {
        assert!(plan_path("../oops").is_err());
        assert!(plan_path(&"a".repeat(64)).is_ok());
    }
}
