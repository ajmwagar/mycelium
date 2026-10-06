//! Explicit local lifecycle composition. The common state-change plan/receipt
//! pins identity and preconditions; software and SSH retain their own owners.
use mycelium_core::{canonical_digest, ExecutionMode, StateChangePlan};
use myceliumd::{
    client::Client, node_profile::NodeIntent, protocol::Request,
    state_change::StateChangeTransaction,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{fs, path::Path, process::Command};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Observed {
    hostname: String,
    static_hostname: String,
    software_policy_digest: Option<String>,
    intent_digest: Option<String>,
    ssh: Option<Value>,
    placement: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Change {
    intent: NodeIntent,
    before: Observed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedPlan {
    digest: String,
    plan: StateChangePlan,
}

pub async fn run(args: &[String]) -> Result<Vec<String>, String> {
    let action = args.first().map(String::as_str).unwrap_or("status");
    let mut client = Client::connect().await.map_err(|e| e.to_string())?;
    let observed = client
        .call(&Request::NodeObserve)
        .await
        .map_err(|e| e.to_string())?;
    let node_id = observed["hello"]["node_id"]
        .as_str()
        .ok_or("daemon has no stable identity")?
        .to_owned();
    match action {
        "status" => {
            exact_args(args, &["status", "--json"])?;
            let software = client
                .call(&Request::SoftwareStatus)
                .await
                .map_err(|e| e.to_string())?;
            Ok(vec![json!({"node": observed, "software": software,
                "note": "software status is retained; use software reconcile --dry-run for live health"}).to_string()])
        }
        "plan" => {
            if args.len() < 2 || args.len() > 3 || args.get(2).is_some_and(|arg| arg != "--json") {
                return Err("node plan needs INTENT.json [--json]".into());
            }
            let intent: NodeIntent = read_json(Path::new(&args[1]))?;
            validate_target(&intent, &node_id)?;
            require_linux()?;
            let before = observe(&intent, &mut client).await?;
            let plan = StateChangePlan::new(
                "node.reconcile",
                &node_id,
                serde_json::to_value(Change { intent, before }).map_err(|e| e.to_string())?,
            );
            Ok(vec![serde_json::to_string_pretty(&SavedPlan {
                digest: plan.digest(),
                plan,
            })
            .map_err(|e| e.to_string())?])
        }
        "apply" => {
            let mut plan_path = None;
            let mut write = false;
            let mut dry_run = false;
            let mut index = 1;
            while index < args.len() {
                match args[index].as_str() {
                    "--plan" if plan_path.is_none() => {
                        index += 1;
                        plan_path = Some(args.get(index).ok_or("--plan needs a file")?);
                    }
                    "--write" if !write => write = true,
                    "--dry-run" if !dry_run => dry_run = true,
                    "--json" => {}
                    other => return Err(format!("unknown node apply argument {other}")),
                }
                index += 1;
            }
            if write == dry_run {
                return Err("node apply requires exactly one of --write or --dry-run".into());
            }
            let saved: SavedPlan =
                read_json(Path::new(plan_path.ok_or("node apply needs --plan FILE")?))?;
            let change = validate_plan(&saved, &node_id)?;
            require_linux()?;
            if observe(&change.intent, &mut client).await? != change.before {
                return Err(
                    "node plan preconditions changed; generate and review a fresh plan".into(),
                );
            }
            if dry_run {
                return Ok(vec![
                    json!({"dry_run": true, "digest": saved.digest, "change": change}).to_string(),
                ]);
            }
            crate::ssh_access::require_root("node reconciliation")?;
            require_ready(&change.before.placement)?;
            let lock = fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .open(myceliumd::home_dir().join("node-reconcile.lock"))
                .map_err(|e| e.to_string())?;
            lock.try_lock()
                .map_err(|_| "another node reconciliation is running")?;
            // Recheck after acquiring the write lock, before any mutation.
            if observe(&change.intent, &mut client).await? != change.before {
                return Err("node plan changed while waiting for its write lock".into());
            }
            let transaction = StateChangeTransaction::begin(saved.plan, ExecutionMode::Apply)
                .map_err(|e| e.to_string())?;
            let result = apply(&change.intent, &mut client).await;
            match result {
                Ok(result) => Ok(vec![serde_json::to_string_pretty(
                    &transaction.finish(result).map_err(|e| e.to_string())?,
                )
                .map_err(|e| e.to_string())?]),
                Err(error) => Err(transaction.fail(error).unwrap_err().to_string()),
            }
        }
        other => Err(format!("unknown node action {other}")),
    }
}

fn require_linux() -> Result<(), String> {
    if cfg!(target_os = "linux") {
        Ok(())
    } else {
        Err("node reconciliation currently supports Linux/systemd; run it on the intended peer via mycelium ssh".into())
    }
}

fn exact_args(args: &[String], allowed: &[&str]) -> Result<(), String> {
    if args.iter().any(|arg| !allowed.contains(&arg.as_str())) {
        Err("unexpected node status argument".into())
    } else {
        Ok(())
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let metadata = fs::metadata(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    if metadata.len() > 1024 * 1024 {
        return Err("node intent/plan exceeds 1 MiB".into());
    }
    serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?)
        .map_err(|e| format!("parse {}: {e}", path.display()))
}

fn validate_target(intent: &NodeIntent, node_id: &str) -> Result<(), String> {
    intent.validate()?;
    if intent.node_id != node_id {
        return Err("node intent belongs to another peer".into());
    }
    Ok(())
}

fn validate_plan(saved: &SavedPlan, node_id: &str) -> Result<Change, String> {
    if saved.plan.schema_version != 1
        || saved.plan.operation != "node.reconcile"
        || saved.plan.scope != node_id
        || saved.digest != saved.plan.digest()
    {
        return Err("node plan digest, operation or peer identity does not match".into());
    }
    let change: Change =
        serde_json::from_value(saved.plan.desired.clone()).map_err(|e| e.to_string())?;
    validate_target(&change.intent, node_id)?;
    Ok(change)
}

fn output(program: &str, args: &[&str]) -> Result<String, String> {
    let result = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("{program}: {e}"))?;
    if !result.status.success() {
        return Err(format!(
            "{program} failed: {}",
            String::from_utf8_lossy(&result.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&result.stdout).trim().to_owned())
}

async fn ssh_status(client: &mut Client) -> Result<Value, String> {
    let state = client
        .call(&Request::AccessList)
        .await
        .map_err(|e| e.to_string())?;
    let status = crate::ssh_access::run(&["host-policy".into(), "status".into()], &state)?;
    let mut status: Value = serde_json::from_str(status.first().ok_or("missing SSH status")?)
        .map_err(|e| e.to_string())?;
    if status["access_view_ready"] != true {
        return Err("signed SSH access records have not converged".into());
    }
    let ca_path = status["policy"]["ca_public"]
        .as_str()
        .ok_or("SSH policy has no CA public path")?;
    let ca_digest =
        mycelium_peer_protocol::sha256_hex(&fs::read(ca_path).map_err(|e| e.to_string())?);
    status["ca_public_digest"] = json!(ca_digest);
    Ok(status)
}

fn require_ready(placement: &Value) -> Result<(), String> {
    for package in placement.as_array().ok_or("invalid planned placement")? {
        let digest = package["manifest"]["digest"]
            .as_str()
            .ok_or("placement is awaiting a compatible signed package manifest")?;
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("invalid planned artifact digest".into());
        }
        if !myceliumd::artifacts_dir().join(digest).is_file() {
            return Err(format!("package artifact {digest} is not cached; wait for signed distribution before applying the node plan"));
        }
    }
    Ok(())
}

async fn observe(intent: &NodeIntent, client: &mut Client) -> Result<Observed, String> {
    let software_policy_digest =
        match myceliumd::software::read_policy(&myceliumd::software_policy_path()) {
            Ok(policy) => Some(canonical_digest(&policy)),
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                None
            }
            Err(error) => return Err(error.to_string()),
        };
    Ok(Observed {
        hostname: output("hostname", &["-s"])?,
        static_hostname: output("hostnamectl", &["--static"])?,
        software_policy_digest,
        intent_digest: myceliumd::node_profile::read()
            .map_err(|e| e.to_string())?
            .map(|intent| canonical_digest(&intent)),
        ssh: if intent.reconcile_ssh {
            Some(ssh_status(client).await?)
        } else {
            None
        },
        placement: placement(intent, client).await?,
    })
}

async fn placement(intent: &NodeIntent, client: &mut Client) -> Result<Value, String> {
    let peers: Vec<myceliumd::peer::PeerView> = serde_json::from_value(
        client
            .call(&Request::PeerList)
            .await
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let mut peer = peers
        .into_iter()
        .find(|peer| {
            peer.hello
                .as_ref()
                .is_some_and(|hello| hello.node_id == intent.node_id)
        })
        .ok_or("local peer observation is unavailable")?;
    let hello = peer.hello.as_mut().ok_or("local peer identity missing")?;
    hello.hostname = intent
        .hostname
        .clone()
        .unwrap_or(output("hostname", &["-s"])?);
    hello
        .capabilities
        .retain(|fact| !fact.starts_with("profile."));
    hello
        .capabilities
        .push(format!("profile.{}", intent.profile));
    let assignments = myceliumd::software::plan(&intent.software_policy, &[peer])?;
    if assignments.is_empty() && !intent.software_policy.rules.is_empty() {
        return Err("software policy selects no packages for the desired node/profile/hostname; use stable node.ID selectors rather than the old hostname".into());
    }
    let manifests: Vec<mycelium_peer_protocol::PackageManifest> = serde_json::from_value(
        client
            .call(&Request::PackageList)
            .await
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let targets = mycelium_peer_protocol::local_compatible_targets();
    Ok(Value::Array(assignments.iter().map(|assignment| {
        let manifest = myceliumd::software::select(&manifests, &assignment.package, &assignment.channel, &targets);
        json!({"assignment": assignment, "manifest": manifest.map(|manifest| json!({
            "version": manifest.version, "digest": manifest.artifact_digest, "target": manifest.target
        }))})
    }).collect()))
}

async fn apply(intent: &NodeIntent, client: &mut Client) -> Result<Value, String> {
    // Desired state persists even if a later independent operation fails.
    // The common receipt reports failure; do not claim cross-domain atomicity.
    let policy_path = myceliumd::home_dir().join("node-software-policy.staging.json");
    fs::write(
        &policy_path,
        serde_json::to_vec_pretty(&intent.software_policy).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    // The existing CLI owner also installs the native automatic-update timer
    // when requested; calling its RPC alone would miss that behavior.
    crate::software(&[
        "policy".into(),
        "set".into(),
        policy_path.to_string_lossy().into_owned(),
        "--write".into(),
        "--json".into(),
    ])
    .await
    .map_err(|e| e.to_string())?;
    fs::remove_file(policy_path).map_err(|e| e.to_string())?;
    myceliumd::node_profile::write(intent).map_err(|e| e.to_string())?;
    if let Some(hostname) = &intent.hostname {
        if output("hostname", &["-s"])? != *hostname
            || output("hostnamectl", &["--static"])? != *hostname
        {
            output(
                "hostnamectl",
                &["set-hostname", "--static", "--transient", hostname],
            )?;
        }
        if output("hostname", &["-s"])? != *hostname
            || output("hostnamectl", &["--static"])? != *hostname
        {
            return Err("hostname postcondition failed".into());
        }
    }
    let hello = client
        .call(&Request::NodeRefresh { write: true })
        .await
        .map_err(|e| e.to_string())?;
    if hello["node_id"] != intent.node_id {
        return Err("peer identity changed during reconciliation".into());
    }
    let software = client
        .call(&Request::SoftwareReconcile {
            write: true,
            dry_run: false,
        })
        .await
        .map_err(|e| e.to_string())?;
    let ssh = if intent.reconcile_ssh {
        let state = client
            .call(&Request::AccessList)
            .await
            .map_err(|e| e.to_string())?;
        Some(crate::ssh_access::run(
            &["host-policy".into(), "reconcile".into(), "--write".into()],
            &state,
        )?)
    } else {
        None
    };
    // Pending manifests/artifacts are not a successful reconciliation.
    if software
        .as_array()
        .ok_or("invalid software reconciliation report")?
        .iter()
        .any(|package| !matches!(package["state"].as_str(), Some("current" | "updated")))
    {
        return Err(format!("software placement remains pending: {software}"));
    }
    Ok(json!({"profile": intent.profile, "hello": hello, "software": software, "ssh": ssh}))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> SavedPlan {
        let intent = NodeIntent {
            node_id: "a".repeat(64),
            profile: "edge".into(),
            hostname: Some("edge-test".into()),
            software_policy: myceliumd::software::SoftwarePolicy {
                schema_version: 1,
                defaults: Default::default(),
                rules: vec![],
            },
            reconcile_ssh: false,
        };
        let before = Observed {
            hostname: "old".into(),
            static_hostname: "old".into(),
            software_policy_digest: None,
            intent_digest: None,
            ssh: None,
            placement: json!([]),
        };
        let plan = StateChangePlan::new(
            "node.reconcile",
            intent.node_id.clone(),
            serde_json::to_value(Change { intent, before }).unwrap(),
        );
        SavedPlan {
            digest: plan.digest(),
            plan,
        }
    }
    #[test]
    fn plans_bind_identity_and_exact_intent() {
        let saved = fixture();
        validate_plan(&saved, &"a".repeat(64)).unwrap();
        assert!(validate_plan(&saved, &"b".repeat(64)).is_err());
        let mut tampered = saved.clone();
        tampered.plan.desired["intent"]["hostname"] = json!("different");
        assert!(validate_plan(&tampered, &"a".repeat(64)).is_err());
    }
    #[test]
    fn plans_reject_unknown_fields_and_unexpected_operations() {
        let mut saved = fixture();
        saved.plan.operation = "shell.exec".into();
        saved.digest = saved.plan.digest();
        assert!(validate_plan(&saved, &"a".repeat(64)).is_err());
        let mut saved = fixture();
        saved.plan.desired["command"] = json!("reboot");
        saved.digest = saved.plan.digest();
        assert!(validate_plan(&saved, &"a".repeat(64)).is_err());
    }
    #[test]
    fn pending_or_malformed_artifacts_fail_before_actions() {
        assert!(require_ready(&json!([{"manifest": null}])).is_err());
        assert!(require_ready(&json!([{"manifest": {"digest": "../secrets"}}])).is_err());
        require_ready(&json!([])).unwrap();
    }
}
