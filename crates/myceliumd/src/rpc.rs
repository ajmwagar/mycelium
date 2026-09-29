use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use mycelium_core::{
    CredentialSet, DeviceId, DeviceMeta, Driver, Inventory, MyceliumError, Result, Secret, Target,
    Topology, Transport, Value,
};
use mycelium_driver_edgeos::{EdgeOsDriver, SshSession};
use mycelium_driver_linux::LinuxDriver;
use mycelium_driver_redfish::RedfishDriver;
use mycelium_driver_snmp::SnmpDriver;
use mycelium_driver_unifi::{UnifiControllerDriver, UnifiDriver};
use mycelium_plugins_lua::{Connect, Plugin};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

use crate::protocol::{Request, Response};

/// One saved device: enough to reconnect it at boot. Contains env-var
/// *names* for secrets, never values.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SavedDevice {
    pub meta: DeviceMeta,
    pub target: String,
    pub username: Option<String>,
    pub password_env: Option<String>,
    pub key_path: Option<String>,
}

pub struct Daemon {
    pub inventory: Inventory,
    drivers: Vec<Arc<dyn Driver>>,
    pub topology: Mutex<Topology>,
    saved: Mutex<BTreeMap<DeviceId, SavedDevice>>,
}

/// SSH connector handed to Lua plugin drivers: vyos-family plugins reuse
/// the EdgeOS transport as their host-side Transport.
struct SshConnect;

#[async_trait]
impl Connect for SshConnect {
    async fn connect(&self, target: &Target, creds: &CredentialSet) -> Result<Arc<dyn Transport>> {
        let (host, port, jump) = match target {
            Target::Host { host, port, jump } => (host.clone(), port.unwrap_or(22), jump.clone()),
            Target::Subnet { .. } => {
                return Err(MyceliumError::Validation(
                    "plugins connect to single hosts".into(),
                ))
            }
        };
        let session = SshSession::connect(
            &host,
            port,
            creds,
            std::time::Duration::from_secs(8),
            jump.as_deref(),
        )
        .await?;
        Ok(Arc::new(session))
    }
}

impl Daemon {
    /// Builtin drivers + validated Lua plugins from $MYCELIUM_HOME/plugins.
    /// A plugin that fails to load aborts boot (fail loud at startup).
    pub async fn boot() -> Result<Self> {
        let mut drivers: Vec<Arc<dyn Driver>> = vec![
            Arc::new(EdgeOsDriver::default()),
            Arc::new(LinuxDriver::default()),
            Arc::new(RedfishDriver::default()),
            Arc::new(SnmpDriver::default()),
            Arc::new(UnifiDriver::default()),
            Arc::new(UnifiControllerDriver::default()),
        ];
        let pdir = crate::plugins_dir();
        if pdir.is_dir() {
            let mut entries: Vec<_> = std::fs::read_dir(&pdir)
                .map_err(mycelium_core::MyceliumError::Io)?
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().map(|x| x == "lua").unwrap_or(false))
                .collect();
            entries.sort_by_key(|e| e.path());
            for entry in entries {
                let source = std::fs::read_to_string(entry.path())
                    .map_err(mycelium_core::MyceliumError::Io)?;
                let plugin = Arc::new(Plugin::load(source).map_err(|e| MyceliumError::Plugin {
                    plugin: entry.file_name().to_string_lossy().into_owned(),
                    message: e.to_string(),
                })?);
                drivers.push(Arc::new(plugin.driver(Arc::new(SshConnect))) as Arc<dyn Driver>);
            }
        }

        let mut saved_map = BTreeMap::new();
        if let Ok(text) = std::fs::read_to_string(crate::devices_path()) {
            let saved: Vec<SavedDevice> = serde_json::from_str(&text).unwrap_or_default();
            for s in saved {
                saved_map.insert(s.meta.id.clone(), s);
            }
        }
        let topology = std::fs::read_to_string(crate::topology_path())
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_else(Topology::empty);

        let me = Self {
            inventory: Inventory::new(),
            drivers,
            topology: Mutex::new(topology),
            saved: Mutex::new(saved_map),
        };
        // Reconnect saved devices; failures are recorded but keep the entry
        // (the appliance may simply be asleep).
        let pending: Vec<SavedDevice> = me.saved.lock().await.values().cloned().collect();
        for s in pending {
            match me.attach_saved(&s).await {
                Ok(_) => {}
                Err(e) => eprintln!("myceliumd: reconnect {} failed: {e}", s.meta.id),
            }
        }
        Ok(me)
    }

    fn driver(&self, name: &str) -> Option<Arc<dyn Driver>> {
        self.drivers.iter().find(|d| d.name() == name).cloned()
    }

    async fn attach_saved(&self, s: &SavedDevice) -> Result<DeviceId> {
        let driver = self
            .driver(&s.meta.driver)
            .ok_or_else(|| MyceliumError::Validation(format!("no driver `{}`", s.meta.driver)))?;
        let target = Target::parse(&s.target)?;
        let creds = creds_from(s);
        driver.attach(&target, &creds, &self.inventory).await
    }

    async fn persist(&self) -> Result<()> {
        let saved: Vec<SavedDevice> = self.saved.lock().await.values().cloned().collect();
        std::fs::write(
            crate::devices_path(),
            serde_json::to_string_pretty(&saved).map_err(json_err)?,
        )?;
        Ok(())
    }

    async fn persist_topology(&self) -> Result<()> {
        let topo = self.topology.lock().await;
        std::fs::write(
            crate::topology_path(),
            serde_json::to_string_pretty(&*topo).map_err(json_err)?,
        )?;
        Ok(())
    }

    pub async fn dispatch(&self, req: Request) -> Response {
        let outcome = self.handle(req).await;
        match outcome {
            Ok(value) => Response::ok(value),
            Err(e) => Response::err(&e),
        }
    }

    async fn handle(&self, req: Request) -> Result<serde_json::Value> {
        use serde_json::to_value;
        match req {
            Request::Hello => to_value(serde_json::json!({
                "version": crate::VERSION,
                "pid": std::process::id(),
                "socket": crate::socket_path().display().to_string(),
            }))
            .map_err(json_err),
            Request::Drivers => to_value(self.drivers.iter().map(|d| d.name()).collect::<Vec<_>>())
                .map_err(json_err),
            Request::DeviceAdd {
                target,
                driver,
                username,
                password_env,
                key_path,
            } => {
                let target_parsed = Target::parse(&target)?;
                let creds = CredentialSet {
                    username,
                    password: password_env.clone().map(Secret::Env),
                    key_path,
                    sudo_password: None,
                };
                let chosen: Vec<Arc<dyn Driver>> = match &driver {
                    Some(name) => {
                        let d = self.driver(name).ok_or_else(|| {
                            MyceliumError::Validation(format!(
                                "unknown driver `{name}` (have: {})",
                                self.drivers
                                    .iter()
                                    .map(|d| d.name())
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            ))
                        })?;
                        vec![d]
                    }
                    None => self.drivers.clone(),
                };
                let mut opened = Vec::new();
                let mut recognized = false;
                for d in chosen {
                    if d.recognizes(&target_parsed, &creds).await? {
                        recognized = true;
                        let id = d.attach(&target_parsed, &creds, &self.inventory).await?;
                        let meta = self.inventory.get(&id.to_string())?.meta().clone();
                        self.saved.lock().await.insert(
                            id.clone(),
                            SavedDevice {
                                meta: meta.clone(),
                                target: target.clone(),
                                username: creds.username.clone(),
                                password_env: password_env.clone(),
                                key_path: creds.key_path.clone(),
                            },
                        );
                        opened.push(serde_json::json!({ "id": id.to_string(), "meta": to_value(&meta).map_err(json_err)? }));
                        break;
                    }
                }
                if !recognized {
                    return Err(MyceliumError::Validation(format!(
                        "no driver recognized {target_parsed} (drivers: {})",
                        self.drivers
                            .iter()
                            .map(|d| d.name())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )));
                }
                self.persist().await?;
                to_value(serde_json::json!({ "devices": opened })).map_err(json_err)
            }
            Request::DeviceRemove { id } => {
                let dev = self
                    .inventory
                    .remove(&id)
                    .ok_or_else(|| MyceliumError::UnknownDevice(id.clone()))?;
                self.saved.lock().await.remove(&dev.id());
                let mut topo = self.topology.lock().await;
                topo.nodes.remove(&id);
                drop(topo);
                self.persist().await?;
                to_value(serde_json::json!({ "removed": id })).map_err(json_err)
            }
            Request::DeviceList => to_value(
                self.inventory
                    .devices()
                    .iter()
                    .map(|d| d.meta())
                    .collect::<Vec<_>>(),
            )
            .map_err(json_err),
            Request::DeviceDescribe { id } => {
                let caps = self.inventory.capabilities(&id)?;
                to_value(&caps).map_err(json_err)
            }
            Request::DeviceCall {
                id,
                capability,
                params,
                write,
                dry_run,
            } => {
                let dev = self.inventory.get(&id)?;
                let mut p = mycelium_core::Params::new();
                for (k, v) in params {
                    p.insert(k, Value::from_json(&v));
                }
                let ctx = mycelium_core::ExecContext {
                    capability: capability.clone(),
                    allow_writes: write,
                    dry_run,
                };
                let res = dev.invoke(&ctx, &capability, p).await?;
                Ok(cap_result_json(&id, &capability, &res))
            }
            Request::Scan => {
                let mut warnings = Vec::new();
                let mut observations = Vec::new();
                for dev in self.inventory.devices() {
                    match dev.observe().await {
                        Ok((obs, warns)) => {
                            observations.extend(obs);
                            warnings
                                .extend(warns.into_iter().map(|w| format!("{}: {w}", dev.id())));
                        }
                        Err(e) => warnings.push(format!("{}: scan failed: {e}", dev.id())),
                    }
                }
                let report = {
                    let mut topo = self.topology.lock().await;
                    topo.observe_all(observations)
                };
                warnings.extend(self.fingerprint_services().await);
                self.persist_topology().await?;
                to_value(serde_json::json!({
                    "report": report,
                    "warnings": warnings,
                    "nodes": self.topology.lock().await.nodes.len(),
                    "segments": self.topology.lock().await.segments.len(),
                }))
                .map_err(json_err)
            }
            Request::Topology => {
                let topo = self.topology.lock().await;
                to_value(&*topo).map_err(json_err)
            }
            Request::TunnelPlan {
                target,
                remote_port,
                local_port,
                via,
            } => {
                let target_ip = target.parse::<std::net::IpAddr>().map_err(|_| {
                    MyceliumError::Validation(format!(
                        "tunnel target `{target}` must be an IP address"
                    ))
                })?;
                let saved = self.saved.lock().await;
                let hop = if let Some(selector) = via {
                    saved
                        .values()
                        .find(|device| {
                            device.meta.id.to_string() == selector
                                || device.meta.address == selector
                        })
                        .ok_or_else(|| MyceliumError::UnknownDevice(selector))?
                } else {
                    let topo = self.topology.lock().await;
                    let gateway = topo
                        .segments
                        .values()
                        .find(|segment| {
                            segment.subnet.is_some_and(|(network, prefix)| {
                                mycelium_core::ipv4_in_cidr(target_ip, network, prefix)
                            })
                        })
                        .and_then(|segment| segment.gw)
                        .ok_or_else(|| {
                            MyceliumError::Validation(format!(
                                "no observed gateway for tunnel target {target}"
                            ))
                        })?;
                    saved
                        .values()
                        .find(|device| device.meta.address == gateway.to_string())
                        .ok_or_else(|| {
                            MyceliumError::Validation(format!(
                                "gateway {gateway} is not an inventory device; add it first"
                            ))
                        })?
                };
                if hop.meta.driver != "edgeos" && hop.meta.driver != "linux" {
                    return Err(MyceliumError::Validation(format!(
                        "{} uses driver `{}`, which is not an SSH hop",
                        hop.meta.id, hop.meta.driver
                    )));
                }
                let username = hop.username.clone().ok_or_else(|| {
                    MyceliumError::Validation(format!("{} has no SSH username", hop.meta.id))
                })?;
                to_value(serde_json::json!({
                    "target": target,
                    "remote_port": remote_port,
                    "local_port": local_port,
                    "hop": {
                        "id": hop.meta.id,
                        "host": hop.meta.address,
                        "username": username,
                        "password_env": hop.password_env,
                        "key_path": hop.key_path,
                    },
                    "ssh_args": [
                        "-N",
                        "-o", "ExitOnForwardFailure=yes",
                        "-L", format!("{local_port}:{target}:{remote_port}"),
                        format!("{username}@{}", hop.meta.address),
                    ],
                }))
                .map_err(json_err)
            }
            Request::ConsolePlan { id } => {
                let saved = self.saved.lock().await;
                let device = saved
                    .values()
                    .find(|device| device.meta.id.to_string() == id)
                    .ok_or_else(|| MyceliumError::UnknownDevice(id.clone()))?;
                if device.meta.driver != "redfish" || device.meta.vendor.as_deref() != Some("HPE") {
                    return Err(MyceliumError::Unsupported {
                        device: id,
                        capability: "interactive text console".into(),
                    });
                }
                let username = device.username.clone().ok_or_else(|| {
                    MyceliumError::Validation(format!("{} has no console username", device.meta.id))
                })?;
                to_value(serde_json::json!({
                    "device": device.meta.id,
                    "kind": "ilo4_textcons",
                    "host": device.meta.address,
                    "username": username,
                    "password_env": device.password_env,
                }))
                .map_err(json_err)
            }
            Request::Shutdown => {
                self.persist().await?;
                self.persist_topology().await?;
                let home = crate::home_dir();
                let _ = std::fs::remove_file(crate::pid_path());
                let _ = std::fs::remove_file(home.join("myceliumd.sock"));
                to_value(serde_json::json!({ "bye": true })).map_err(json_err)
            }
        }
    }

    /// Fingerprint only endpoints already reported by an authoritative
    /// driver. This never adds hosts or ports and is deliberately bounded.
    async fn fingerprint_services(&self) -> Vec<String> {
        let saved = self.saved.lock().await;
        let topology = self.topology.lock().await;
        let candidates = topology
            .nodes
            .iter()
            .filter_map(|(node_id, node)| {
                let host = saved
                    .values()
                    .find(|saved| saved.meta.id.to_string() == *node_id)?
                    .meta
                    .address
                    .split(':')
                    .next()?
                    .to_owned();
                Some(node.services.iter().filter_map(move |(key, service)| {
                    (service.product.is_none() && matches!(service.name.as_str(), "http" | "https"))
                        .then(|| {
                            (
                                node_id.clone(),
                                key.clone(),
                                host.clone(),
                                service.name.clone(),
                                service.port,
                            )
                        })
                }))
            })
            .flatten()
            .collect::<Vec<_>>();
        drop(topology);
        drop(saved);

        let client = match reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(3))
            .redirect(reqwest::redirect::Policy::limited(2))
            .build()
        {
            Ok(client) => client,
            Err(error) => return vec![format!("service fingerprint client: {error}")],
        };
        let mut pending = tokio::task::JoinSet::new();
        for (node_id, key, host, scheme, port) in candidates {
            let url = format!("{scheme}://{host}:{port}/");
            let client = client.clone();
            pending.spawn(async move {
                let result = fingerprint_http(&client, &url).await;
                (node_id, key, scheme, port, result)
            });
        }
        let mut warnings = Vec::new();
        while let Some(joined) = pending.join_next().await {
            let Ok((node_id, key, scheme, port, result)) = joined else {
                warnings.push("service fingerprint task failed".into());
                continue;
            };
            match result {
                Ok(Some(product)) => {
                    if let Some(service) = self
                        .topology
                        .lock()
                        .await
                        .nodes
                        .get_mut(&node_id)
                        .and_then(|node| node.services.get_mut(&key))
                    {
                        service.product = Some(product);
                    }
                }
                Ok(None) => {}
                Err(error) => warnings.push(format!("{node_id} {scheme}:{port}: {error}")),
            }
        }
        warnings
    }
}

fn creds_from(s: &SavedDevice) -> CredentialSet {
    CredentialSet {
        username: s.username.clone(),
        password: s.password_env.as_ref().map(|v| Secret::Env(v.clone())),
        key_path: s.key_path.clone(),
        sudo_password: None,
    }
}

async fn fingerprint_http(
    client: &reqwest::Client,
    url: &str,
) -> std::result::Result<Option<String>, reqwest::Error> {
    let mut response = client.get(url).send().await?;
    let server = response
        .headers()
        .get(reqwest::header::SERVER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let mut body = Vec::new();
    while body.len() < 65_536 {
        let Some(chunk) = response.chunk().await? else {
            break;
        };
        let remaining = 65_536 - body.len();
        body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
    }
    Ok(classify_http(&server, &String::from_utf8_lossy(&body)))
}

fn classify_http(server: &str, body: &str) -> Option<String> {
    let evidence = format!("{server}\n{body}").to_ascii_lowercase();
    [
        ("gramps web", "Gramps Web"),
        ("frigate", "Frigate"),
        ("home assistant", "Home Assistant"),
        ("warpgate", "Warpgate"),
        ("unifi", "UniFi Network"),
        ("plex", "Plex Media Server"),
        ("airtunes", "Apple AirTunes"),
    ]
    .into_iter()
    .find(|(needle, _)| evidence.contains(needle))
    .map(|(_, product)| product.to_owned())
}

fn json_err(e: serde_json::Error) -> MyceliumError {
    MyceliumError::Parse(e.to_string())
}

/// CapResult on the wire: output uses the plain Value->JSON bridge, never
/// the Rust enum tag form (`{"str": ...}`).
pub fn cap_result_json(
    device: &str,
    capability: &str,
    r: &mycelium_core::CapResult,
) -> serde_json::Value {
    serde_json::json!({
        "device": device,
        "capability": capability,
        "result": {
            "ok": r.ok,
            "output": r.output.to_json(),
            "message": r.message,
            "dry_run": r.dry_run,
        },
    })
}

/// Serve forever on the daemon socket. Removes a stale socket file if no
/// live daemon owns it (pid check).
pub async fn serve() -> std::io::Result<()> {
    let home = crate::home_dir();
    std::fs::create_dir_all(&home)?;
    let socket = crate::socket_path();
    if socket.exists() {
        match UnixStream::connect(&socket).await {
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!("a myceliumd is already listening on {}", socket.display()),
                ))
            }
            Err(_) => {
                eprintln!("myceliumd: removing stale socket {}", socket.display());
                std::fs::remove_file(&socket)?;
            }
        }
    }
    let listener = UnixListener::bind(&socket)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // control plane = owner only
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::write(crate::pid_path(), format!("{}\n", std::process::id()))?;

    let daemon = Arc::new(
        Daemon::boot()
            .await
            .map_err(|e| std::io::Error::other(format!("boot failed: {e}")))?,
    );
    eprintln!(
        "myceliumd {} listening on {}",
        crate::VERSION,
        socket.display()
    );

    loop {
        let (stream, _) = listener.accept().await?;
        let daemon = daemon.clone();
        tokio::spawn(async move {
            handle_conn(stream, daemon).await;
        });
    }
}

async fn handle_conn(stream: UnixStream, daemon: Arc<Daemon>) {
    let (r, mut w) = stream.into_split();
    let mut reader = BufReader::new(r);
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<Request>(trimmed) {
            Ok(req) => {
                let shutdown = matches!(req, Request::Shutdown);
                let resp = daemon.dispatch(req).await;
                let out = serde_json::to_string(&resp).expect("Response serializes");
                if w.write_all(out.as_bytes()).await.is_err()
                    || w.write_all(b"\n").await.is_err()
                    || w.flush().await.is_err()
                {
                    break;
                }
                if shutdown {
                    std::process::exit(0);
                }
                continue;
            }
            Err(e) => serde_json::to_string(&Response::fail(format!("bad request: {e}")))
                .expect("serializable"),
        };
        if w.write_all(resp.as_bytes()).await.is_err() || w.write_all(b"\n").await.is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mycelium_core::{CapResult, CapSpec, DeviceKind, ExecContext, Params};
    use std::collections::BTreeMap as StdMap;

    /// A fake device+driver to exercise dispatch without hardware.
    struct FakeDev {
        meta: DeviceMeta,
    }

    #[async_trait]
    impl mycelium_core::Device for FakeDev {
        fn meta(&self) -> &DeviceMeta {
            &self.meta
        }
        fn capabilities(&self) -> StdMap<String, CapSpec> {
            StdMap::from_iter([(
                "fake.ping".to_string(),
                CapSpec::readonly("ping").returns("pong"),
            )])
        }
        async fn exec(&self, _ctx: &ExecContext, cap: &str, _params: Params) -> Result<CapResult> {
            Ok(CapResult::ok(Value::Str(format!("pong:{cap}"))))
        }
        async fn observe(&self) -> Result<(Vec<mycelium_core::Observation>, Vec<String>)> {
            Ok((
                vec![mycelium_core::Observation::Neighbor {
                    mac: mycelium_core::MacAddress::parse("02:00:00:00:00:99"),
                    ip: "10.0.9.9".parse().unwrap(),
                    hostname: Some("fakehost".into()),
                    port: None,
                    origin: mycelium_core::Origin::new(self.meta.id.to_string(), "fake"),
                }],
                vec![],
            ))
        }
    }

    struct FakeDriver;

    #[async_trait]
    impl Driver for FakeDriver {
        fn name(&self) -> &str {
            "fake"
        }
        async fn recognizes(&self, target: &Target, _creds: &CredentialSet) -> Result<bool> {
            Ok(matches!(target, Target::Host { host, .. } if host == "fakehost.local"))
        }
        async fn attach(
            &self,
            _target: &Target,
            _creds: &CredentialSet,
            inventory: &Inventory,
        ) -> Result<DeviceId> {
            let meta = DeviceMeta {
                id: DeviceId::new("fake-1"),
                kind: DeviceKind::Other,
                driver: "fake".into(),
                vendor: None,
                model: None,
                firmware: None,
                address: "fakehost.local".into(),
            };
            let id = meta.id.clone();
            inventory.add(Arc::new(FakeDev { meta }));
            Ok(id)
        }
    }

    fn daemon_with_fake() -> Daemon {
        Daemon {
            inventory: Inventory::new(),
            drivers: vec![Arc::new(FakeDriver)],
            topology: Mutex::new(Topology::empty()),
            saved: Mutex::new(BTreeMap::new()),
        }
    }

    #[test]
    fn fingerprints_known_web_products_from_bounded_evidence() {
        assert_eq!(
            classify_http("gunicorn", "<meta name=description content='Gramps Web'>").as_deref(),
            Some("Gramps Web")
        );
        assert_eq!(
            classify_http("nginx", "<title>Frigate</title>").as_deref(),
            Some("Frigate")
        );
        assert_eq!(classify_http("nginx", "generic page"), None);
    }

    #[tokio::test]
    async fn add_list_describe_call_scan_shutdown_flow() {
        let home = std::env::temp_dir().join(format!("myceliumd-test-{}", std::process::id()));
        std::fs::create_dir_all(&home).unwrap();
        std::env::set_var("MYCELIUM_HOME", &home);

        let d = daemon_with_fake();

        let resp = d.dispatch(Request::Hello).await;
        assert!(resp.ok);

        let resp = d
            .dispatch(Request::DeviceAdd {
                target: "fakehost.local".into(),
                driver: None,
                username: Some("u".into()),
                password_env: None,
                key_path: None,
            })
            .await;
        assert!(resp.ok, "{resp:?}");

        let resp = d.dispatch(Request::DeviceList).await;
        let list = resp.result.unwrap();
        assert_eq!(list.as_array().unwrap().len(), 1);
        assert_eq!(list[0]["id"], "fake-1");

        let resp = d
            .dispatch(Request::DeviceDescribe {
                id: "fake-1".into(),
            })
            .await;
        assert!(resp.ok);

        let resp = d
            .dispatch(Request::DeviceCall {
                id: "fake-1".into(),
                capability: "fake.ping".into(),
                params: serde_json::Map::new(),
                write: false,
                dry_run: false,
            })
            .await;
        assert_eq!(
            resp.result.unwrap()["result"]["output"],
            serde_json::json!("pong:fake.ping")
        );

        // unrecognized target: loud
        let resp = d
            .dispatch(Request::DeviceAdd {
                target: "nope".into(),
                driver: None,
                username: None,
                password_env: None,
                key_path: None,
            })
            .await;
        assert!(!resp.ok);
        assert_eq!(resp.kind.as_deref(), Some("validation"));

        // scan merges topology
        let resp = d.dispatch(Request::Scan).await;
        let v = resp.result.unwrap();
        assert_eq!(v["report"]["new_nodes"], 1);

        let resp = d.dispatch(Request::Topology).await;
        let topo: Topology = serde_json::from_value(resp.result.unwrap()).unwrap();
        assert!(topo.nodes.contains_key("02:00:00:00:00:99"));
        assert!(topo.nodes["02:00:00:00:00:99"]
            .hostnames
            .contains("fakehost"));

        // devices.json persisted with no secret literals
        let saved = std::fs::read_to_string(home.join("devices.json")).unwrap();
        assert!(saved.contains("fakehost.local"));

        d.dispatch(Request::DeviceRemove {
            id: "fake-1".into(),
        })
        .await;
        let saved = std::fs::read_to_string(home.join("devices.json")).unwrap();
        assert!(!saved.contains("fake-1"));
    }
}
