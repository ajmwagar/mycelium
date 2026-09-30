//! mycelium CLI: a thin, scriptable client over myceliumd's Unix socket.
//!
//! Argument parsing is hand-rolled (tenet #11: no clap until its weight is
//! earned). `--json` on every read command for pipelines; mutations need
//! explicit `--write`, and `--dry-run` always shows the plan instead of
//! applying it.

use mycelium_core::{
    ActionPlan, ActionRisk, BootReachability, NbdePlan, Topology, ID_SWITCH_OBSERVE,
};
use mycelium_driver_netgear_fastpath::{FastpathConfig, FastpathIntent, SnmpSwitchState};
use myceliumd::client::{Client, ClientError};
use myceliumd::protocol::Request;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(|a| a.as_str()) {
        Some("_serve") => {
            // hidden: run the daemon in this process (used by autostart)
            let rt = tokio::runtime::Runtime::new().expect("runtime");
            rt.block_on(myceliumd::rpc::serve())
                .map(|_| Vec::new())
                .map_err(ClientError::Io)
        }
        Some(other) => rt_block(run(other, &args[1..])),
        None => Ok(usage()),
    };
    match result {
        Ok(lines) => {
            for line in lines {
                println!("{line}");
            }
        }
        Err(e) => {
            eprintln!("mycelium: {e}");
            std::process::exit(if matches!(e, ClientError::Rpc { .. }) {
                2
            } else {
                1
            });
        }
    }
}

fn rt_block<'a, F>(fut: F) -> Result<Vec<String>, ClientError>
where
    F: std::future::Future<Output = Result<Vec<String>, ClientError>> + 'a,
{
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    rt.block_on(fut)
}

fn usage() -> Vec<String> {
    USAGE.lines().map(str::to_owned).collect()
}

const USAGE: &str = "\
mycelium — control plane for your network appliances

usage:
  mycelium daemon status|start|stop
  mycelium drivers
  mycelium add <host[:port]> [--driver NAME] [--user U] [--password-env VAR] [--key PATH]
  mycelium devices [--json]
  mycelium describe <id> [--json]
  mycelium call <id> <capability> [--param k=v ...] [--write] [--dry-run]
  mycelium plan switch <id> --desired <startup-config> [--json]
  mycelium scan
  mycelium topology [--json]
  mycelium map [--json]
  mycelium annotate <node> [--name NAME] [--kind KIND] --write [--dry-run]
  mycelium boot-path <device> --target <IP-or-URL>... [--json]
  mycelium nbde plan <device> --tang <IP-or-URL>... --threshold N [--json]
  mycelium tunnel <target>:<port> [--via DEVICE] [--local-port N] [--write] [--json]
  mycelium console <device> [--json]
  mycelium remove <id>

environment:
  MYCELIUM_HOME     state dir (default ~/.mycelium)
  MYCELIUM_SOCKET   override socket path
  MYCELIUM_NO_AUTOSTART=1  never spawn the daemon implicitly
";

struct Flags {
    json: bool,
    write: bool,
    dry_run: bool,
    driver: Option<String>,
    user: Option<String>,
    password_env: Option<String>,
    key: Option<String>,
    params: Vec<(String, String)>,
    targets: Vec<String>,
    tang: Vec<String>,
    threshold: Option<usize>,
    via: Option<String>,
    local_port: Option<u16>,
    name: Option<String>,
    kind: Option<String>,
    desired: Option<String>,
    rest: Vec<String>,
}

fn parse_flags(args: &[String]) -> Flags {
    let mut f = Flags {
        json: false,
        write: false,
        dry_run: false,
        driver: None,
        user: None,
        password_env: None,
        key: None,
        params: Vec::new(),
        targets: Vec::new(),
        tang: Vec::new(),
        threshold: None,
        via: None,
        local_port: None,
        name: None,
        kind: None,
        desired: None,
        rest: Vec::new(),
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => f.json = true,
            "--write" => f.write = true,
            "--dry-run" => f.dry_run = true,
            "--driver" => {
                i += 1;
                f.driver = args.get(i).cloned();
            }
            "--user" => {
                i += 1;
                f.user = args.get(i).cloned();
            }
            "--password-env" => {
                i += 1;
                f.password_env = args.get(i).cloned();
            }
            "--key" => {
                i += 1;
                f.key = args.get(i).cloned();
            }
            "--param" => {
                i += 1;
                if let Some(kv) = args.get(i) {
                    if let Some((k, v)) = kv.split_once('=') {
                        f.params.push((k.to_owned(), v.to_owned()));
                    } else {
                        eprintln!("mycelium: --param expects k=v, got {kv}");
                    }
                }
            }
            "--target" => {
                i += 1;
                if let Some(target) = args.get(i) {
                    f.targets.push(target.clone());
                }
            }
            "--tang" => {
                i += 1;
                if let Some(endpoint) = args.get(i) {
                    f.tang.push(endpoint.clone());
                }
            }
            "--threshold" => {
                i += 1;
                f.threshold = args.get(i).and_then(|value| value.parse().ok());
            }
            "--via" => {
                i += 1;
                f.via = args.get(i).cloned();
            }
            "--local-port" => {
                i += 1;
                f.local_port = args.get(i).and_then(|value| value.parse().ok());
            }
            "--name" => {
                i += 1;
                f.name = args.get(i).cloned();
            }
            "--kind" => {
                i += 1;
                f.kind = args.get(i).cloned();
            }
            "--desired" => {
                i += 1;
                f.desired = args.get(i).cloned();
            }
            other => f.rest.push(other.to_owned()),
        }
        i += 1;
    }
    f
}

async fn run(cmd: &str, args: &[String]) -> Result<Vec<String>, ClientError> {
    match cmd {
        "daemon" => daemon(args).await,
        "help" | "--help" | "-h" => Ok(usage()),
        "drivers" => {
            let mut c = connect().await?;
            let v = c.call(&Request::Drivers).await?;
            if parse_flags(args).json {
                return Ok(vec![v.to_string()]);
            }
            Ok(vec!["drivers:".into()]
                .into_iter()
                .chain(
                    v.as_array()
                        .unwrap_or(&vec![])
                        .iter()
                        .map(|d| format!("  {}", d.as_str().unwrap_or("?"))),
                )
                .collect())
        }
        "add" => {
            let f = parse_flags(args);
            let target = f.rest.first().ok_or(err_usage("add needs a host"))?;
            let mut c = connect().await?;
            let v = c
                .call(&Request::DeviceAdd {
                    target: target.clone(),
                    driver: f.driver,
                    username: f.user,
                    password_env: f.password_env,
                    key_path: f.key,
                })
                .await?;
            Ok(render_added(&v))
        }
        "devices" => {
            let f = parse_flags(args);
            let mut c = connect().await?;
            let v = c.call(&Request::DeviceList).await?;
            if f.json {
                return Ok(vec![v.to_string()]);
            }
            Ok(render_devices(&v))
        }
        "describe" => {
            let f = parse_flags(args);
            let id = f.rest.first().ok_or(err_usage("describe needs an id"))?;
            let mut c = connect().await?;
            let v = c.call(&Request::DeviceDescribe { id: id.clone() }).await?;
            if f.json {
                return Ok(vec![v.to_string()]);
            }
            Ok(render_describe(id, &v))
        }
        "call" => {
            let f = parse_flags(args);
            let mut it = f.rest.iter();
            let id = it.next().ok_or(err_usage("call needs <id> <capability>"))?;
            let cap = it.next().ok_or(err_usage("call needs <id> <capability>"))?;
            let mut params = serde_json::Map::new();
            for (k, v) in &f.params {
                params.insert(k.clone(), coerce(v));
            }
            let mut c = connect().await?;
            let v = c
                .call(&Request::DeviceCall {
                    id: id.clone(),
                    capability: cap.clone(),
                    params,
                    write: f.write,
                    dry_run: f.dry_run,
                })
                .await?;
            Ok(render_call(&v))
        }
        "plan" => plan(args).await,
        "scan" => {
            let f = parse_flags(args);
            let mut c = connect().await?;
            let v = c.call(&Request::Scan).await?;
            if f.json {
                return Ok(vec![v.to_string()]);
            }
            Ok(render_scan(&v))
        }
        "topology" | "map" => {
            let f = parse_flags(args);
            let mut c = connect().await?;
            let v = c.call(&Request::Topology).await?;
            if f.json {
                return Ok(vec![v.to_string()]);
            }
            let topo: Topology = serde_json::from_value(v)
                .map_err(|e| err_usage(&format!("bad topology json: {e}")))?;
            Ok(render_topology(&topo))
        }
        "annotate" => {
            let f = parse_flags(args);
            let selector = f
                .rest
                .first()
                .ok_or(err_usage("annotate needs a node selector"))?;
            let mut client = connect().await?;
            let value = client
                .call(&Request::TopologyAnnotate {
                    selector: selector.clone(),
                    name: f.name,
                    kind: f.kind,
                    write: f.write,
                    dry_run: f.dry_run,
                })
                .await?;
            if f.json {
                Ok(vec![value.to_string()])
            } else if value["dry_run"].as_bool() == Some(true) {
                Ok(vec![format!("DRY RUN: {value}")])
            } else {
                Ok(vec![format!(
                    "annotated {} name={} kind={}",
                    value["node"].as_str().unwrap_or("?"),
                    value["name"].as_str().unwrap_or("-"),
                    value["kind"].as_str().unwrap_or("-")
                )])
            }
        }
        "boot-path" => {
            let f = parse_flags(args);
            let device = f
                .rest
                .first()
                .ok_or(err_usage("boot-path needs a device"))?;
            if f.targets.is_empty() {
                return Err(err_usage("boot-path needs at least one --target"));
            }
            let topo = fetch_topology().await?;
            let path = topo
                .boot_path(device, &f.targets)
                .map_err(|error| err_usage(&error.to_string()))?;
            if f.json {
                Ok(vec![
                    serde_json::to_string(&path).map_err(|e| err_usage(&e.to_string()))?
                ])
            } else {
                Ok(render_boot_path(&path))
            }
        }
        "nbde" => nbde(args).await,
        "tunnel" => tunnel(args).await,
        "console" => console(args).await,
        "remove" => {
            let f = parse_flags(args);
            let id = f.rest.first().ok_or(err_usage("remove needs an id"))?;
            let mut c = connect().await?;
            c.call(&Request::DeviceRemove { id: id.clone() }).await?;
            Ok(vec![format!("removed {id}")])
        }
        other => Err(err_usage(&format!(
            "unknown command `{other}` (see `mycelium`)"
        ))),
    }
}

async fn console(args: &[String]) -> Result<Vec<String>, ClientError> {
    let f = parse_flags(args);
    let id = f
        .rest
        .first()
        .ok_or(err_usage("console needs a device id"))?;
    let mut client = connect().await?;
    let plan = client
        .call(&Request::ConsolePlan { id: id.clone() })
        .await?;
    if f.json {
        return Ok(vec![plan.to_string()]);
    }
    run_console(&plan)?;
    Ok(vec!["console closed".into()])
}

fn run_console(plan: &serde_json::Value) -> Result<(), ClientError> {
    if plan["kind"].as_str() != Some("ilo4_textcons") {
        return Err(err_usage("daemon returned an unsupported console kind"));
    }
    let host = plan["host"]
        .as_str()
        .ok_or(err_usage("console plan has no host"))?;
    let username = plan["username"]
        .as_str()
        .ok_or(err_usage("console plan has no username"))?;
    let password_name = plan["password_env"]
        .as_str()
        .ok_or(err_usage("console plan has no password environment"))?;
    let password = std::env::var(password_name).map_err(|_| {
        err_usage(&format!(
            "{password_name} is not exported; source the credential environment first"
        ))
    })?;
    let destination = format!("{username}@{host}");
    let script = r#"
set timeout 20
spawn sshpass -e ssh -tt -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o KexAlgorithms=+diffie-hellman-group14-sha1 -o HostKeyAlgorithms=+ssh-rsa -- [lindex $argv 0]
expect {
  -re {hpiLO->} { send -- "textcons\r" }
  timeout { puts stderr "timed out waiting for iLO CLI"; exit 3 }
  eof { puts stderr "iLO disconnected before console start"; exit 4 }
}
set timeout -1
interact
"#;
    let status = std::process::Command::new("expect")
        .args(["-c", script, &destination])
        .env("SSHPASS", password)
        .status()
        .map_err(|error| err_usage(&format!("could not launch console: {error}")))?;
    if !status.success() {
        return Err(err_usage(&format!("console exited with {status}")));
    }
    Ok(())
}

async fn tunnel(args: &[String]) -> Result<Vec<String>, ClientError> {
    let f = parse_flags(args);
    let destination = f
        .rest
        .first()
        .ok_or(err_usage("tunnel needs <target>:<port>"))?;
    let (target, remote_port) = destination
        .rsplit_once(':')
        .and_then(|(host, port)| port.parse::<u16>().ok().map(|port| (host, port)))
        .ok_or(err_usage("tunnel destination must be <IP>:<port>"))?;
    let local_port = f.local_port.unwrap_or(remote_port);
    let mut client = connect().await?;
    let plan = client
        .call(&Request::TunnelPlan {
            target: target.to_owned(),
            remote_port,
            local_port,
            via: f.via,
        })
        .await?;
    if f.json {
        return Ok(vec![plan.to_string()]);
    }
    if !f.write {
        return Ok(render_tunnel_plan(&plan));
    }
    run_tunnel(&plan)?;
    Ok(vec!["tunnel closed".into()])
}

fn run_tunnel(plan: &serde_json::Value) -> Result<(), ClientError> {
    let args = plan["ssh_args"]
        .as_array()
        .ok_or(err_usage("daemon returned invalid tunnel argv"))?
        .iter()
        .map(|arg| {
            arg.as_str()
                .map(str::to_owned)
                .ok_or(err_usage("invalid SSH argument"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let password_env = plan["hop"]["password_env"].as_str();
    let mut command = if password_env.is_some() {
        let mut command = std::process::Command::new("sshpass");
        command.arg("-e").arg("ssh");
        command
    } else {
        std::process::Command::new("ssh")
    };
    if let Some(name) = password_env {
        let password = std::env::var(name).map_err(|_| {
            err_usage(&format!(
                "{name} is not exported; source the credential environment first"
            ))
        })?;
        command.env("SSHPASS", password);
    }
    let status = command
        .args(args)
        .status()
        .map_err(|error| err_usage(&format!("could not run SSH: {error}")))?;
    if !status.success() {
        return Err(err_usage(&format!("SSH tunnel exited with {status}")));
    }
    Ok(())
}

async fn fetch_topology() -> Result<Topology, ClientError> {
    let mut client = connect().await?;
    let value = client.call(&Request::Topology).await?;
    serde_json::from_value(value).map_err(|error| err_usage(&format!("bad topology json: {error}")))
}

async fn nbde(args: &[String]) -> Result<Vec<String>, ClientError> {
    let Some("plan") = args.first().map(String::as_str) else {
        return Err(err_usage(
            "usage: mycelium nbde plan <device> --tang URL... --threshold N",
        ));
    };
    let f = parse_flags(&args[1..]);
    let device = f
        .rest
        .first()
        .ok_or(err_usage("nbde plan needs a device"))?;
    if f.tang.is_empty() {
        return Err(err_usage("nbde plan needs at least one --tang endpoint"));
    }
    let threshold = f
        .threshold
        .ok_or(err_usage("nbde plan needs --threshold N"))?;
    let plan = fetch_topology()
        .await?
        .nbde_plan(device, &f.tang, threshold)
        .map_err(|error| err_usage(&error.to_string()))?;
    if f.json {
        Ok(vec![
            serde_json::to_string(&plan).map_err(|e| err_usage(&e.to_string()))?
        ])
    } else {
        Ok(render_nbde_plan(&plan))
    }
}

async fn plan(args: &[String]) -> Result<Vec<String>, ClientError> {
    let flags = parse_flags(args);
    if flags.rest.first().map(String::as_str) != Some("switch") {
        return Err(err_usage(
            "usage: mycelium plan switch <id> --desired <startup-config> [--json]",
        ));
    }
    let device = flags
        .rest
        .get(1)
        .ok_or(err_usage("plan switch needs a device id"))?;
    let desired_path = flags
        .desired
        .ok_or(err_usage("plan switch needs --desired <startup-config>"))?;
    let source = std::fs::read_to_string(&desired_path)?;
    let config = FastpathConfig::parse(&source)
        .map_err(|error| err_usage(&format!("cannot parse {desired_path}: {error}")))?;
    let desired = FastpathIntent::normalize(&config)
        .map_err(|error| err_usage(&format!("cannot normalize {desired_path}: {error}")))?;

    let mut client = connect().await?;
    let response = client
        .call(&Request::DeviceCall {
            id: device.clone(),
            capability: ID_SWITCH_OBSERVE.into(),
            params: serde_json::Map::new(),
            write: false,
            dry_run: false,
        })
        .await?;
    let observed: SnmpSwitchState = serde_json::from_value(response["result"]["output"].clone())
        .map_err(|error| err_usage(&format!("invalid switch observation: {error}")))?;
    let plan = observed.plan(device, &desired);
    if flags.json {
        Ok(vec![serde_json::to_string(&plan).map_err(|error| {
            err_usage(&format!("cannot serialize plan: {error}"))
        })?])
    } else {
        Ok(render_switch_plan(&plan))
    }
}

async fn daemon(args: &[String]) -> Result<Vec<String>, ClientError> {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("status");
    match sub {
        "start" => {
            match Client::try_connect().await {
                Ok(_) => return Ok(vec!["myceliumd already running".into()]),
                Err(ClientError::Connect(_)) => {}
                Err(e) => return Err(e),
            }
            Client::spawn_daemon()?;
            // confirm it came up
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                match Client::try_connect().await {
                    Ok(_) => {
                        return Ok(vec![format!(
                            "myceliumd up on {}",
                            myceliumd::socket_path().display()
                        )])
                    }
                    Err(_) if std::time::Instant::now() > deadline => {
                        return Err(ClientError::DaemonUnresponsive)
                    }
                    Err(_) => {}
                }
            }
        }
        "stop" => {
            let mut c = Client::try_connect().await?;
            c.request(&Request::Shutdown).await.ok();
            Ok(vec!["myceliumd stopped".into()])
        }
        "status" => match Client::try_connect().await {
            Ok(mut c) => {
                let v = c.call(&Request::Hello).await?;
                Ok(vec![format!(
                    "myceliumd v{} pid {} socket {}",
                    v["version"].as_str().unwrap_or("?"),
                    v["pid"].to_string(),
                    v["socket"].as_str().unwrap_or("?"),
                )])
            }
            Err(ClientError::Connect(_)) => Ok(vec!["myceliumd not running".into()]),
            Err(e) => Err(e),
        },
        other => Err(err_usage(&format!("unknown daemon subcommand `{other}`"))),
    }
}

async fn connect() -> Result<Client, ClientError> {
    Client::connect().await
}

fn err_usage(msg: &str) -> ClientError {
    ClientError::Protocol(msg.to_owned())
}

fn coerce(v: &str) -> serde_json::Value {
    match v {
        "true" => serde_json::Value::Bool(true),
        "false" => serde_json::Value::Bool(false),
        _ => match v.parse::<i64>() {
            Ok(i) => serde_json::Value::from(i),
            Err(_) => {
                if v.starts_with('{') || v.starts_with('[') {
                    serde_json::from_str(v).unwrap_or_else(|_| serde_json::json!(v))
                } else {
                    serde_json::json!(v)
                }
            }
        },
    }
}

// ---- renderers ----------------------------------------------------------

fn render_added(v: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(devs) = v["devices"].as_array() {
        for d in devs {
            let id = d["id"].as_str().unwrap_or("?");
            let meta = &d["meta"];
            out.push(format!(
                "added {id}  ({} {} {}, driver {})",
                meta["kind"].as_str().unwrap_or("?"),
                meta["vendor"].as_str().unwrap_or("?"),
                meta["model"].as_str().unwrap_or("?"),
                meta["driver"].as_str().unwrap_or("?"),
            ));
        }
    }
    out
}

fn render_devices(v: &serde_json::Value) -> Vec<String> {
    let mut out = vec![format!(
        "{:<28} {:<12} {:<22} {:<16} driver",
        "id", "kind", "model", "address"
    )];
    if let Some(arr) = v.as_array() {
        for d in arr {
            out.push(format!(
                "{:<28} {:<12} {:<22} {:<16} {}",
                d["id"].as_str().unwrap_or("?"),
                d["kind"].as_str().unwrap_or("?"),
                d["model"]
                    .as_str()
                    .or(d["hostname"].as_str())
                    .unwrap_or("-"),
                d["address"].as_str().unwrap_or("?"),
                d["driver"].as_str().unwrap_or("?"),
            ));
        }
    }
    out
}

fn render_describe(id: &str, v: &serde_json::Value) -> Vec<String> {
    let mut out = vec![format!("capabilities of {id}:")];
    if let Some(arr) = v.as_array() {
        for c in arr {
            let cid = c["id"].as_str().unwrap_or("?");
            let desc = c["spec"]["description"].as_str().unwrap_or("");
            let mut params = String::new();
            for p in c["spec"]["params"].as_array().unwrap_or(&vec![]) {
                params.push_str(&format!(
                    " <{}:{}>",
                    p["name"].as_str().unwrap_or("?"),
                    p["ty"].as_str().unwrap_or("string")
                ));
            }
            let m = if c["spec"]["mutation"].as_bool().unwrap_or(false) {
                " [write]"
            } else {
                ""
            };
            out.push(format!("  {cid}{m}{params}  — {desc}"));
        }
    }
    out
}

fn render_call(v: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    let res = &v["result"];
    let dry = res["dry_run"].as_bool().unwrap_or(false);
    let ok = res["ok"].as_bool().unwrap_or(true);
    if dry {
        out.push("DRY RUN — planned commands (nothing applied):".into());
    } else if !ok {
        out.push(format!(
            "device error: {}",
            res["message"].as_str().unwrap_or("?")
        ));
    }
    match &res["output"] {
        serde_json::Value::String(s) => {
            for line in s.lines() {
                out.push(line.to_owned());
            }
        }
        serde_json::Value::Array(items) => {
            if dry {
                for cmd in items {
                    out.push(format!("  {}", cmd.as_str().unwrap_or("?")));
                }
            } else {
                out.push(serde_json::to_string_pretty(items).unwrap_or_default());
            }
        }
        other => out.push(serde_json::to_string_pretty(other).unwrap_or_default()),
    }
    if let Some(m) = res["message"].as_str().filter(|m| ok && !m.is_empty()) {
        out.push(format!("note: {m}"));
    }
    out
}

fn render_scan(v: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    let r = &v["report"];
    out.push(format!(
        "scan: {} new nodes, {} updated, {} segments | {} device(s) total, {} node(s), {} segment(s)",
        r["new_nodes"].as_i64().unwrap_or(0),
        r["updated_nodes"].as_i64().unwrap_or(0),
        r["merged_segments"].as_i64().unwrap_or(0),
        v["nodes"].as_i64().unwrap_or(0),
        v["nodes"].as_i64().unwrap_or(0),
        v["segments"].as_i64().unwrap_or(0),
    ));
    if let Some(c) = r["conflicts"].as_array() {
        for conflict in c {
            out.push(format!(
                "CONFLICT: {}",
                serde_json::to_string(conflict).unwrap_or_default()
            ));
        }
    }
    if let Some(w) = v["warnings"].as_array() {
        for warn in w {
            out.push(format!("warning: {}", warn.as_str().unwrap_or("?")));
        }
    }
    out
}

fn render_topology(topo: &Topology) -> Vec<String> {
    let mut out = Vec::new();
    out.push("segments:".into());
    for seg in topo.segments.values() {
        let subnet = seg
            .subnet
            .map(|(ip, pfx)| format!(" {ip}/{pfx}"))
            .unwrap_or_default();
        let gw = seg.gw.map(|g| format!(" gw {g}")).unwrap_or_default();
        out.push(format!(
            "  {:<18} {:<14}{subnet}{gw}  [{}]",
            seg.id,
            seg.domain_name.clone().unwrap_or_default(),
            seg.origins
                .iter()
                .map(|o| o.split(':').next().unwrap_or("?"))
                .collect::<Vec<_>>()
                .join(","),
        ));
    }
    out.push("appliances:".into());
    for node in topo.nodes.values().filter(|n| n.device) {
        let label = node.annotation.name.as_deref().unwrap_or(&node.id);
        let kind = node
            .annotation
            .kind
            .as_deref()
            .map(|kind| format!(" kind={kind}"))
            .unwrap_or_default();
        let ips = node
            .ips
            .keys()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
        out.push(format!(
            "  {:<28} ports={} ips={}{}",
            label,
            node.ports.len(),
            ips,
            format_args!("{kind}{}", render_lans(topo, node))
        ));
        render_device_links(&mut out, node);
        render_services(&mut out, node);
        render_overlays(&mut out, node);
    }
    out.push(format!(
        "hosts: {}",
        topo.nodes.values().filter(|n| !n.device).count()
    ));
    for node in topo.nodes.values().filter(|n| !n.device) {
        let names = if let Some(name) = &node.annotation.name {
            name.clone()
        } else if node.hostnames.is_empty() {
            "-".to_owned()
        } else {
            node.hostnames.iter().cloned().collect::<Vec<_>>().join(",")
        };
        let ips = node
            .ips
            .keys()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let kind = node
            .annotation
            .kind
            .as_deref()
            .map(|kind| format!(" kind={kind}"))
            .unwrap_or_default();
        out.push(format!(
            "  {:<20} {:<20} {names}  [{ips}]{kind}{}",
            node.mac
                .map(|m| m.to_string())
                .unwrap_or_else(|| "no-mac".into()),
            node.id,
            render_lans(topo, node)
        ));
        for link in node.ports.values().filter_map(|link| link.b.as_ref()) {
            out.push(format!("    └─ {}", link));
        }
        render_services(&mut out, node);
        render_overlays(&mut out, node);
    }
    if !topo.leases.is_empty() {
        out.push("leases:".into());
        for l in &topo.leases {
            out.push(format!(
                "  {:<16} {:<20} {}",
                l.ip,
                l.mac,
                l.hostname.clone().unwrap_or_else(|| "-".into())
            ));
        }
    }
    if !topo.conflicts.is_empty() {
        out.push(format!("CONFLICTS: {}", topo.conflicts.len()));
        for c in &topo.conflicts {
            out.push(format!("  {c:?}"));
        }
    }
    out
}

fn render_device_links(out: &mut Vec<String>, node: &mycelium_core::TopoNode) {
    for (name, link) in node.ports.iter().filter(|(_, link)| {
        !matches!(
            link.medium,
            Some(mycelium_core::LinkMedium::Virtual | mycelium_core::LinkMedium::Loopback)
        )
    }) {
        let medium = link
            .medium
            .map(|medium| format!("{medium:?}").to_ascii_lowercase())
            .unwrap_or_else(|| "unknown".into());
        let speed = link
            .speed_mbps
            .map(|speed| format!("{speed} Mbps"))
            .unwrap_or_else(|| "unknown speed".into());
        let duplex = link
            .duplex
            .map(|duplex| format!(" {duplex:?}").to_ascii_lowercase())
            .unwrap_or_default();
        out.push(format!(
            "    ├─ {name}: {medium}, {speed}{duplex}, {:?}",
            link.state
        ));
    }
}

fn render_services(out: &mut Vec<String>, node: &mycelium_core::TopoNode) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    for service in node.services.values() {
        if service.name == "unknown" {
            continue;
        }
        let age = now.saturating_sub(service.observed_at);
        let state = if age > 300 {
            format!("STALE {}m", age / 60)
        } else {
            format!("{:?}", service.state).to_ascii_uppercase()
        };
        out.push(format!(
            "    └─ {}:{}/{}  {}  {}",
            service.name,
            service.port,
            service.transport,
            state,
            service.product.as_deref().unwrap_or("unidentified")
        ));
    }
}

fn render_lans(topo: &Topology, node: &mycelium_core::TopoNode) -> String {
    let lans =
        topo.segments
            .values()
            .filter(|segment| {
                let scoped_site = segment.id.split_once('/').and_then(|(first, _)| {
                    first.parse::<std::net::IpAddr>().is_err().then_some(first)
                });
                let scope_matches = scoped_site
                    .map(|site| node.sites.contains(site))
                    .unwrap_or(true);
                scope_matches
                    && segment.subnet.is_some_and(|(network, prefix)| {
                        node.ips
                            .keys()
                            .any(|address| mycelium_core::ipv4_in_cidr(*address, network, prefix))
                    })
            })
            .map(|segment| segment.id.clone())
            .collect::<Vec<_>>();
    if lans.is_empty() {
        String::new()
    } else {
        format!(" lans=[{}]", lans.join(","))
    }
}

fn render_overlays(out: &mut Vec<String>, node: &mycelium_core::TopoNode) {
    for overlay in node.overlays.values() {
        let state = if overlay.online { "ONLINE" } else { "OFFLINE" };
        let path = if overlay.self_node {
            "path=self".into()
        } else {
            overlay
                .endpoint
                .as_deref()
                .map(|endpoint| format!("direct={endpoint}"))
                .or_else(|| {
                    overlay
                        .relay
                        .as_deref()
                        .map(|relay| format!("relay={relay}"))
                })
                .unwrap_or_else(|| "path=unknown".into())
        };
        let routes = if overlay.routed_lans.is_empty() {
            String::new()
        } else {
            format!(
                " routes={}",
                overlay
                    .routed_lans
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(",")
            )
        };
        let coordinator = match overlay.control_plane.coordinator {
            mycelium_core::MeshCoordinator::TailscaleCloud => "tailscale-cloud".to_owned(),
            mycelium_core::MeshCoordinator::Headscale => "headscale".to_owned(),
            mycelium_core::MeshCoordinator::Custom => overlay
                .control_plane
                .url
                .clone()
                .unwrap_or_else(|| "custom".into()),
            mycelium_core::MeshCoordinator::Unknown => "coordinator=unknown".to_owned(),
        };
        out.push(format!(
            "    └─ {} via {} ({})  {}{}  {}{}",
            overlay.network,
            overlay.observer,
            coordinator,
            state,
            if overlay.active { "/ACTIVE" } else { "" },
            path,
            routes
        ));
    }
}

fn render_boot_path(path: &mycelium_core::BootPath) -> Vec<String> {
    let mut out = vec![format!("boot paths for {}:", path.device)];
    for target in &path.targets {
        out.push(format!(
            "  {:<10} {:<32} {}",
            reachability_label(target.reachability),
            target.endpoint,
            target.reason
        ));
    }
    out
}

fn render_nbde_plan(plan: &NbdePlan) -> Vec<String> {
    let status = if plan.viable { "VIABLE" } else { "NOT VIABLE" };
    let mut out = vec![format!(
        "NBDE plan for {}: {status} — threshold {}, {} observed path(s)",
        plan.device, plan.threshold, plan.reachable
    )];
    for target in &plan.endpoints {
        out.push(format!(
            "  {:<10} {}",
            reachability_label(target.reachability),
            target.endpoint
        ));
    }
    for warning in &plan.warnings {
        out.push(format!("warning: {warning}"));
    }
    out
}

fn render_switch_plan(plan: &ActionPlan) -> Vec<String> {
    let status = if plan.ready_to_apply() {
        "READY"
    } else {
        "BLOCKED"
    };
    let mut lines = vec![format!(
        "switch plan {}: {status} — {} action(s), {} blocker(s)",
        plan.scope,
        plan.actions.len(),
        plan.blockers.len()
    )];
    for (index, action) in plan.actions.iter().enumerate() {
        let risk = match action.risk {
            ActionRisk::Low => "low",
            ActionRisk::Disruptive => "disruptive",
            ActionRisk::Destructive => "destructive",
        };
        lines.push(format!(
            "  {}. [{}] {} {}",
            index + 1,
            risk,
            action.capability,
            serde_json::to_string(&action.params).unwrap_or_else(|_| "{}".into())
        ));
        lines.push(format!(
            "     verify with {}",
            action.verification.capability
        ));
    }
    for blocker in &plan.blockers {
        let resource = blocker
            .resource
            .as_deref()
            .map(|resource| format!(" ({resource})"))
            .unwrap_or_default();
        lines.push(format!(
            "  BLOCKED {}{resource}: {}",
            blocker.code, blocker.message
        ));
    }
    lines
}

fn reachability_label(reachability: BootReachability) -> &'static str {
    match reachability {
        BootReachability::Direct => "direct",
        BootReachability::Routed => "routed",
        BootReachability::Unverified => "unverified",
    }
}

fn render_tunnel_plan(plan: &serde_json::Value) -> Vec<String> {
    let hop = &plan["hop"];
    vec![
        format!(
            "tunnel: http://127.0.0.1:{} -> {}:{} via {} ({}@{})",
            plan["local_port"].as_u64().unwrap_or(0),
            plan["target"].as_str().unwrap_or("?"),
            plan["remote_port"].as_u64().unwrap_or(0),
            hop["id"].as_str().unwrap_or("?"),
            hop["username"].as_str().unwrap_or("?"),
            hop["host"].as_str().unwrap_or("?"),
        ),
        "run with --write to open the foreground tunnel; Ctrl-C closes it".into(),
    ]
}
