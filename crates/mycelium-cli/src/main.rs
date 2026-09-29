//! mycelium CLI: a thin, scriptable client over myceliumd's Unix socket.
//!
//! Argument parsing is hand-rolled (tenet #11: no clap until its weight is
//! earned). `--json` on every read command for pipelines; mutations need
//! explicit `--write`, and `--dry-run` always shows the plan instead of
//! applying it.

use mycelium_core::Topology;
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
            std::process::exit(if matches!(e, ClientError::Rpc { .. }) { 2 } else { 1 });
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
  mycelium scan
  mycelium topology [--json]
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
                .chain(v.as_array().unwrap_or(&vec![]).iter().map(|d| format!("  {}", d.as_str().unwrap_or("?"))))
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
        "scan" => {
            let f = parse_flags(args);
            let mut c = connect().await?;
            let v = c.call(&Request::Scan).await?;
            if f.json {
                return Ok(vec![v.to_string()]);
            }
            Ok(render_scan(&v))
        }
        "topology" => {
            let f = parse_flags(args);
            let mut c = connect().await?;
            let v = c.call(&Request::Topology).await?;
            if f.json {
                return Ok(vec![v.to_string()]);
            }
            let topo: Topology =
                serde_json::from_value(v).map_err(|e| err_usage(&format!("bad topology json: {e}")))?;
            Ok(render_topology(&topo))
        }
        "remove" => {
            let f = parse_flags(args);
            let id = f.rest.first().ok_or(err_usage("remove needs an id"))?;
            let mut c = connect().await?;
            c.call(&Request::DeviceRemove { id: id.clone() }).await?;
            Ok(vec![format!("removed {id}")])
        }
        other => Err(err_usage(&format!("unknown command `{other}` (see `mycelium`)"))),
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
    let mut out = vec![format!("{:<28} {:<12} {:<22} {:<16} driver", "id", "kind", "model", "address")];
    if let Some(arr) = v.as_array() {
        for d in arr {
            out.push(format!(
                "{:<28} {:<12} {:<22} {:<16} {}",
                d["id"].as_str().unwrap_or("?"),
                d["kind"].as_str().unwrap_or("?"),
                d["model"].as_str().or(d["hostname"].as_str()).unwrap_or("-"),
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
                params.push_str(&format!(" <{}:{}>", p["name"].as_str().unwrap_or("?"), p["ty"].as_str().unwrap_or("string")));
            }
            let m = if c["spec"]["mutation"].as_bool().unwrap_or(false) { " [write]" } else { "" };
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
        out.push(format!("device error: {}", res["message"].as_str().unwrap_or("?")));
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
            out.push(format!("CONFLICT: {}", serde_json::to_string(conflict).unwrap_or_default()));
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
            seg.origins.iter().map(|o| o.split(':').next().unwrap_or("?")).collect::<Vec<_>>().join(","),
        ));
    }
    out.push("appliances:".into());
    for node in topo.nodes.values().filter(|n| n.device) {
        let ips = node.ips.keys().map(|i| i.to_string()).collect::<Vec<_>>().join(",");
        out.push(format!("  {:<28} ports={} ips={}", node.id, node.ports.len(), ips));
    }
    out.push(format!("hosts: {}", topo.nodes.values().filter(|n| !n.device).count()));
    for node in topo.nodes.values().filter(|n| !n.device) {
        let names = if node.hostnames.is_empty() {
            "-".to_owned()
        } else {
            node.hostnames.iter().cloned().collect::<Vec<_>>().join(",")
        };
        let ips = node.ips.keys().map(|i| i.to_string()).collect::<Vec<_>>().join(",");
        out.push(format!("  {:<20} {:<20} {names}  [{ips}]", node.mac.map(|m| m.to_string()).unwrap_or_else(|| "no-mac".into()), node.id));
    }
    if !topo.leases.is_empty() {
        out.push("leases:".into());
        for l in &topo.leases {
            out.push(format!("  {:<16} {:<20} {}", l.ip, l.mac, l.hostname.clone().unwrap_or_else(|| "-".into())));
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

