use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Arc;

use async_trait::async_trait;
use mycelium_core::{
    AllocationReceipt, AllocationValue, CredentialSet, DeviceId, DeviceMeta, DhcpScopeIntent,
    DiscoveryRequest, DiscoveryScope, Driver, Inventory, LogicalNetwork, MeshControlPlane,
    MeshCoordinator, MeshProtocol, MyceliumError, NetworkBinding, NetworkDriftReport,
    NetworkDriftState, Observation, Origin, OverlayPeerRecord, Result, Secret, Target, Topology,
    Transport, Value,
};
use mycelium_driver_darwin::DarwinDriver;
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

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn validate_cidr(value: &str) -> Result<()> {
    let (address, length) = value
        .split_once('/')
        .ok_or_else(|| MyceliumError::Validation(format!("`{value}` is not CIDR notation")))?;
    let address = address
        .parse::<std::net::IpAddr>()
        .map_err(|_| MyceliumError::Validation(format!("invalid address in `{value}`")))?;
    let length = length
        .parse::<u8>()
        .map_err(|_| MyceliumError::Validation(format!("invalid prefix length in `{value}`")))?;
    let maximum = if address.is_ipv4() { 32 } else { 128 };
    if length > maximum {
        return Err(MyceliumError::Validation(format!(
            "prefix length in `{value}` exceeds {maximum}"
        )));
    }
    Ok(())
}

fn load_or_create_wireguard_key() -> Result<String> {
    let path = crate::wireguard_private_key_path();
    let private = match std::fs::read_to_string(&path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let output = Command::new("wg").arg("genkey").output().map_err(|error| {
                MyceliumError::Validation(format!(
                    "WireGuard runtime is unavailable (`wg genkey`): {error}"
                ))
            })?;
            if !output.status.success() {
                return Err(MyceliumError::Validation(
                    "WireGuard key generation failed".into(),
                ));
            }
            let value = String::from_utf8(output.stdout)
                .map_err(|_| MyceliumError::Validation("wg returned a non-UTF-8 key".into()))?;
            std::fs::create_dir_all(crate::wireguard_dir())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(
                    crate::wireguard_dir(),
                    std::fs::Permissions::from_mode(0o700),
                )?;
            }
            let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
            std::fs::write(&temporary, value.as_bytes())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))?;
            }
            std::fs::rename(temporary, &path)?;
            value
        }
        Err(error) => return Err(error.into()),
    };
    let mut child = Command::new("wg")
        .arg("pubkey")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|error| {
            MyceliumError::Validation(format!(
                "WireGuard runtime is unavailable (`wg pubkey`): {error}"
            ))
        })?;
    child
        .stdin
        .take()
        .ok_or_else(|| MyceliumError::Validation("cannot open wg stdin".into()))?
        .write_all(private.as_bytes())?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(MyceliumError::Validation(
            "stored WireGuard private key is invalid".into(),
        ));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|_| MyceliumError::Validation("wg returned a non-UTF-8 public key".into()))
}

/// One saved device: enough to reconnect it at boot. Contains env-var
/// *names* for secrets, never values.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SavedDevice {
    pub meta: DeviceMeta,
    pub target: String,
    #[serde(default)]
    pub name: Option<String>,
    pub username: Option<String>,
    pub password_env: Option<String>,
    pub key_path: Option<String>,
}

pub struct Daemon {
    pub inventory: Inventory,
    drivers: Vec<Arc<dyn Driver>>,
    pub topology: Mutex<Topology>,
    saved: Mutex<BTreeMap<DeviceId, SavedDevice>>,
    discovery_scopes: Mutex<BTreeMap<String, DiscoveryScope>>,
    allocations: Mutex<BTreeMap<String, AllocationReceipt>>,
    networks: Mutex<BTreeMap<String, LogicalNetwork>>,
    network_bindings: Mutex<BTreeMap<String, NetworkBinding>>,
    dhcp_scopes: Mutex<BTreeMap<String, DhcpScopeIntent>>,
    pub mesh: Arc<crate::peer::Mesh>,
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
            Arc::new(DarwinDriver::default()),
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
        let discovery_scopes = match std::fs::read_to_string(crate::discovery_path()) {
            Ok(text) => serde_json::from_str::<Vec<DiscoveryScope>>(&text)
                .map_err(|error| MyceliumError::Parse(format!("discovery.json: {error}")))?
                .into_iter()
                .map(|scope| (scope.observer.clone(), scope))
                .collect(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(error) => return Err(MyceliumError::Io(error)),
        };
        let allocations = match std::fs::read_to_string(crate::allocations_path()) {
            Ok(text) => serde_json::from_str::<Vec<AllocationReceipt>>(&text)
                .map_err(|error| MyceliumError::Parse(format!("allocations.json: {error}")))?
                .into_iter()
                .map(|receipt| (receipt.identity.clone(), receipt))
                .collect(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(error) => return Err(MyceliumError::Io(error)),
        };
        let networks = match std::fs::read_to_string(crate::networks_path()) {
            Ok(text) => serde_json::from_str::<Vec<LogicalNetwork>>(&text)
                .map_err(|error| MyceliumError::Parse(format!("networks.json: {error}")))?
                .into_iter()
                .map(|network| (network.identity.clone(), network))
                .collect(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(error) => return Err(MyceliumError::Io(error)),
        };
        let network_bindings = match std::fs::read_to_string(crate::network_bindings_path()) {
            Ok(text) => serde_json::from_str::<Vec<NetworkBinding>>(&text)
                .map_err(|error| MyceliumError::Parse(format!("network-bindings.json: {error}")))?
                .into_iter()
                .map(|binding| (binding.identity.clone(), binding))
                .collect(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(error) => return Err(MyceliumError::Io(error)),
        };
        let dhcp_scopes = match std::fs::read_to_string(crate::dhcp_scopes_path()) {
            Ok(text) => serde_json::from_str::<Vec<DhcpScopeIntent>>(&text)
                .map_err(|error| MyceliumError::Parse(format!("dhcp-scopes.json: {error}")))?
                .into_iter()
                .map(|scope| (scope.identity.clone(), scope))
                .collect(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(error) => return Err(MyceliumError::Io(error)),
        };

        let mesh = crate::peer::Mesh::boot()
            .map_err(|error| MyceliumError::Validation(format!("peer mesh: {error}")))?;
        let me = Self {
            inventory: Inventory::new(),
            drivers,
            topology: Mutex::new(topology),
            saved: Mutex::new(saved_map),
            discovery_scopes: Mutex::new(discovery_scopes),
            allocations: Mutex::new(allocations),
            networks: Mutex::new(networks),
            network_bindings: Mutex::new(network_bindings),
            dhcp_scopes: Mutex::new(dhcp_scopes),
            mesh,
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

    async fn persist_discovery(&self) -> Result<()> {
        let scopes = self
            .discovery_scopes
            .lock()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        std::fs::write(
            crate::discovery_path(),
            serde_json::to_string_pretty(&scopes).map_err(json_err)?,
        )?;
        Ok(())
    }

    async fn persist_allocations(&self) -> Result<()> {
        let receipts = self
            .allocations
            .lock()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let path = crate::allocations_path();
        let temporary = path.with_extension(format!("json.tmp-{}", std::process::id()));
        std::fs::write(
            &temporary,
            serde_json::to_string_pretty(&receipts).map_err(json_err)?,
        )?;
        std::fs::rename(temporary, path)?;
        Ok(())
    }

    async fn persist_networks(&self) -> Result<()> {
        let networks = self
            .networks
            .lock()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let path = crate::networks_path();
        let temporary = path.with_extension(format!("json.tmp-{}", std::process::id()));
        std::fs::write(
            &temporary,
            serde_json::to_string_pretty(&networks).map_err(json_err)?,
        )?;
        std::fs::rename(temporary, path)?;
        Ok(())
    }

    async fn persist_network_bindings(&self) -> Result<()> {
        let bindings = self
            .network_bindings
            .lock()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let path = crate::network_bindings_path();
        let temporary = path.with_extension(format!("json.tmp-{}", std::process::id()));
        std::fs::write(
            &temporary,
            serde_json::to_string_pretty(&bindings).map_err(json_err)?,
        )?;
        std::fs::rename(temporary, path)?;
        Ok(())
    }

    async fn persist_dhcp_scopes(&self) -> Result<()> {
        let scopes = self
            .dhcp_scopes
            .lock()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let path = crate::dhcp_scopes_path();
        let temporary = path.with_extension(format!("json.tmp-{}", std::process::id()));
        std::fs::write(
            &temporary,
            serde_json::to_string_pretty(&scopes).map_err(json_err)?,
        )?;
        std::fs::rename(temporary, path)?;
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
                name,
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
                                name: name.clone(),
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
            Request::ActionPlanApply {
                plan,
                write,
                dry_run,
            } => {
                if !plan.ready_to_apply() {
                    return Err(MyceliumError::Validation(format!(
                        "action plan has {} blocker(s)",
                        plan.blockers.len()
                    )));
                }
                if !dry_run && !write {
                    return Err(MyceliumError::WritesNotPermitted(
                        "action-plan execution requires --write".into(),
                    ));
                }
                // Preflight the complete plan before the first mutation.
                for action in &plan.actions {
                    let capabilities = self.inventory.capabilities(&action.device)?;
                    let action_spec = capabilities
                        .iter()
                        .find(|capability| capability.id == action.capability)
                        .ok_or_else(|| {
                            MyceliumError::UnknownCapability(action.capability.clone())
                        })?;
                    action_spec
                        .spec
                        .validate(&action.params)
                        .map_err(MyceliumError::Validation)?;
                    let verification_spec = capabilities
                        .iter()
                        .find(|capability| capability.id == action.verification.capability)
                        .ok_or_else(|| {
                            MyceliumError::UnknownCapability(action.verification.capability.clone())
                        })?;
                    if verification_spec.spec.mutation {
                        return Err(MyceliumError::Validation(format!(
                            "verification capability `{}` must be read-only",
                            action.verification.capability
                        )));
                    }
                    verification_spec
                        .spec
                        .validate(&action.verification.params)
                        .map_err(MyceliumError::Validation)?;
                }
                let mut results = Vec::new();
                for action in &plan.actions {
                    let device = self.inventory.get(&action.device)?;
                    let context = mycelium_core::ExecContext {
                        capability: action.capability.clone(),
                        allow_writes: write,
                        dry_run,
                    };
                    let applied = device
                        .invoke(&context, &action.capability, action.params.clone())
                        .await?;
                    if !applied.ok {
                        return Err(MyceliumError::Device {
                            exit_code: 1,
                            stderr: format!(
                                "{}: {}",
                                action.device,
                                applied.message.unwrap_or_else(|| "action failed".into())
                            ),
                        });
                    }
                    let verification = if dry_run {
                        None
                    } else {
                        let verified = device
                            .invoke(
                                &mycelium_core::ExecContext::readonly(
                                    &action.verification.capability,
                                ),
                                &action.verification.capability,
                                action.verification.params.clone(),
                            )
                            .await?;
                        if !verified.ok
                            || !mycelium_core::verification_matches(
                                &verified.output,
                                &action.verification.predicate,
                            )
                        {
                            return Err(MyceliumError::Device {
                                exit_code: 1,
                                stderr: format!(
                                    "{}: postcondition failed after `{}`",
                                    action.device, action.capability
                                ),
                            });
                        }
                        Some(verified.output)
                    };
                    results.push(serde_json::json!({
                        "device": action.device,
                        "capability": action.capability,
                        "dry_run": dry_run,
                        "output": applied.output,
                        "verification": verification,
                    }));
                }
                to_value(serde_json::json!({
                    "scope": plan.scope,
                    "desired_revision": plan.desired_revision,
                    "dry_run": dry_run,
                    "actions": results,
                }))
                .map_err(json_err)
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
                let scopes = self
                    .discovery_scopes
                    .lock()
                    .await
                    .values()
                    .cloned()
                    .collect::<Vec<_>>();
                let requests = {
                    let topology = self.topology.lock().await;
                    let mut requests = Vec::new();
                    for scope in &scopes {
                        for segment_id in &scope.segments {
                            let source = topology
                                .segments
                                .get(segment_id)
                                .and_then(|segment| segment.gw);
                            for protocol in &scope.protocols {
                                requests.push((
                                    scope.observer.clone(),
                                    segment_id.clone(),
                                    *protocol,
                                    source,
                                ));
                            }
                        }
                    }
                    requests
                };
                for (observer, segment, protocol, source) in requests {
                    let Some(source) = source else {
                        warnings.push(format!(
                            "{observer}: discovery {protocol:?} skipped: segment {segment} has no observed gateway/source address"
                        ));
                        continue;
                    };
                    let device = match self.inventory.get(&observer) {
                        Ok(device) => device,
                        Err(error) => {
                            warnings.push(format!("{observer}: discovery skipped: {error}"));
                            continue;
                        }
                    };
                    match device
                        .discover(&DiscoveryRequest {
                            protocol,
                            segment: segment.clone(),
                            source,
                        })
                        .await
                    {
                        Ok(discovered) => observations.extend(discovered),
                        Err(error) => warnings.push(format!(
                            "{observer}: discovery {protocol:?} on {segment} failed: {error}"
                        )),
                    }
                }
                let report = {
                    let mut topo = self.topology.lock().await;
                    topo.observe_all(observations)
                };
                warnings.extend(self.fingerprint_services().await);
                self.persist_topology().await?;
                let topology_snapshot = self.topology.lock().await.clone();
                self.mesh
                    .publish_topology(&topology_snapshot)
                    .await
                    .map_err(|error| {
                        MyceliumError::Validation(format!("publish topology snapshot: {error}"))
                    })?;
                to_value(serde_json::json!({
                    "report": report,
                    "warnings": warnings,
                    "nodes": self.topology.lock().await.nodes.len(),
                    "segments": self.topology.lock().await.segments.len(),
                }))
                .map_err(json_err)
            }
            Request::Topology => {
                let mut topology = self.topology.lock().await.clone();
                for snapshot in self.mesh.topology_snapshots().await {
                    if snapshot.schema_version != 1 {
                        continue;
                    }
                    let remote =
                        serde_json::from_value::<Topology>(snapshot.topology).map_err(|error| {
                            MyceliumError::Parse(format!("peer topology snapshot: {error}"))
                        })?;
                    topology.merge_snapshot(remote);
                }
                let observations = self
                    .mesh
                    .wireguard_bindings()
                    .await
                    .into_iter()
                    .map(|binding| {
                        let hostname = binding.hostname.to_lowercase();
                        let device = topology
                            .nodes
                            .iter()
                            .find(|(_, node)| node.hostnames.contains(&hostname))
                            .map(|(id, _)| id.clone())
                            .unwrap_or_else(|| binding.hostname.clone());
                        Observation::OverlaySelf {
                            device,
                            ips: Vec::new(),
                            hostname: binding.hostname.clone(),
                            record: OverlayPeerRecord {
                                network: "mycelium0".into(),
                                protocol: MeshProtocol::WireGuard,
                                control_plane: MeshControlPlane {
                                    coordinator: MeshCoordinator::Custom,
                                    url: None,
                                },
                                self_node: true,
                                tailnet: None,
                                dns_name: Some(format!(
                                    "{}.{}.mycelium",
                                    binding.hostname, binding.site
                                )),
                                backend_state: Some("signed_planned".into()),
                                observer: binding.node_id,
                                online: false,
                                active: false,
                                relay: None,
                                endpoint: binding.endpoint,
                                routed_lans: binding.advertised_prefixes.into_iter().collect(),
                                observed_at: binding.generation,
                                origin: Origin::new(&binding.hostname, "wireguard-binding")
                                    .at_site(&binding.site),
                            },
                        }
                    })
                    .collect::<Vec<_>>();
                topology.observe_all(observations);
                to_value(topology).map_err(json_err)
            }
            Request::DiscoveryScopeList => {
                let scopes = self
                    .discovery_scopes
                    .lock()
                    .await
                    .values()
                    .cloned()
                    .collect::<Vec<_>>();
                to_value(scopes).map_err(json_err)
            }
            Request::DiscoveryScopeSet {
                observer,
                protocols,
                segments,
                write,
                dry_run,
            } => {
                if protocols.is_empty() || segments.is_empty() {
                    return Err(MyceliumError::Validation(
                        "discovery scope needs at least one protocol and segment".into(),
                    ));
                }
                self.inventory.get(&observer)?;
                let topology = self.topology.lock().await;
                for segment in &segments {
                    let observed = topology.segments.get(segment).ok_or_else(|| {
                        MyceliumError::Validation(format!("unknown topology segment `{segment}`"))
                    })?;
                    if observed.gw.is_none() {
                        return Err(MyceliumError::Validation(format!(
                            "segment `{segment}` has no observed gateway/source address"
                        )));
                    }
                }
                drop(topology);
                let scope = DiscoveryScope {
                    observer: observer.clone(),
                    protocols: protocols.into_iter().collect(),
                    segments: segments.into_iter().collect(),
                };
                if dry_run {
                    return to_value(serde_json::json!({"dry_run": true, "scope": scope}))
                        .map_err(json_err);
                }
                if !write {
                    return Err(MyceliumError::WritesNotPermitted(
                        "discovery scope changes require --write".into(),
                    ));
                }
                self.discovery_scopes
                    .lock()
                    .await
                    .insert(observer, scope.clone());
                self.persist_discovery().await?;
                to_value(scope).map_err(json_err)
            }
            Request::DiscoveryScopeRemove {
                observer,
                write,
                dry_run,
            } => {
                if dry_run {
                    return to_value(serde_json::json!({
                        "dry_run": true,
                        "observer": observer
                    }))
                    .map_err(json_err);
                }
                if !write {
                    return Err(MyceliumError::WritesNotPermitted(
                        "discovery scope changes require --write".into(),
                    ));
                }
                let removed = self.discovery_scopes.lock().await.remove(&observer);
                self.persist_discovery().await?;
                to_value(serde_json::json!({"removed": removed.is_some(), "observer": observer}))
                    .map_err(json_err)
            }
            Request::AllocationList => {
                let receipts = self
                    .allocations
                    .lock()
                    .await
                    .values()
                    .cloned()
                    .collect::<Vec<_>>();
                to_value(receipts).map_err(json_err)
            }
            Request::AllocationImport {
                site,
                write,
                dry_run,
            } => {
                validate_site_name(&site)?;
                let candidates = {
                    let topology = self.topology.lock().await;
                    import_allocation_receipts(&topology, &site)
                };
                let existing = self.allocations.lock().await;
                let additions = candidates
                    .into_iter()
                    .filter(|candidate| !existing.contains_key(&candidate.identity))
                    .collect::<Vec<_>>();
                drop(existing);
                if dry_run {
                    return to_value(serde_json::json!({
                        "dry_run": true,
                        "site": site,
                        "additions": additions,
                    }))
                    .map_err(json_err);
                }
                if !write {
                    return Err(MyceliumError::WritesNotPermitted(
                        "allocation imports require --write".into(),
                    ));
                }
                let mut allocations = self.allocations.lock().await;
                for receipt in &additions {
                    allocations.insert(receipt.identity.clone(), receipt.clone());
                }
                drop(allocations);
                self.persist_allocations().await?;
                to_value(serde_json::json!({
                    "site": site,
                    "imported": additions.len(),
                    "receipts": additions,
                }))
                .map_err(json_err)
            }
            Request::AllocationRecord {
                site,
                vlan,
                subnet,
                gateway,
                source,
                write,
                dry_run,
            } => {
                validate_site_name(&site)?;
                validate_evidence_source(&source)?;
                let allocation = match (vlan, subnet) {
                    (Some(id), None) => {
                        if gateway.is_some() {
                            return Err(MyceliumError::Validation(
                                "an allocation gateway requires --subnet".into(),
                            ));
                        }
                        AllocationValue::Vlan {
                            id: mycelium_core::VlanId(id),
                        }
                    }
                    (None, Some(subnet)) => {
                        let (network, prefix) = parse_cidr(&subnet)?;
                        let gateway = gateway
                            .map(|value| {
                                value.parse().map_err(|_| {
                                    MyceliumError::Validation(format!(
                                        "invalid gateway address `{value}`"
                                    ))
                                })
                            })
                            .transpose()?;
                        AllocationValue::Subnet {
                            network,
                            prefix,
                            gateway,
                        }
                    }
                    _ => {
                        return Err(MyceliumError::Validation(
                            "allocation record needs exactly one of --vlan or --subnet".into(),
                        ))
                    }
                };
                let mut candidate =
                    AllocationReceipt::imported(&site, allocation, BTreeSet::from([source]));
                if let Some(existing) = self
                    .allocations
                    .lock()
                    .await
                    .get(&candidate.identity)
                    .cloned()
                {
                    let mut merged = existing;
                    let previous_sources = merged.basis.sources.len();
                    merged.basis.sources.extend(candidate.basis.sources);
                    if merged.basis.sources.len() != previous_sources {
                        merged.generation = merged.generation.saturating_add(1);
                    }
                    candidate = merged;
                }
                if dry_run {
                    return to_value(serde_json::json!({
                        "dry_run": true,
                        "receipt": candidate,
                    }))
                    .map_err(json_err);
                }
                if !write {
                    return Err(MyceliumError::WritesNotPermitted(
                        "allocation recording requires --write".into(),
                    ));
                }
                self.allocations
                    .lock()
                    .await
                    .insert(candidate.identity.clone(), candidate.clone());
                self.persist_allocations().await?;
                to_value(candidate).map_err(json_err)
            }
            Request::NetworkList => {
                let networks = self
                    .networks
                    .lock()
                    .await
                    .values()
                    .cloned()
                    .collect::<Vec<_>>();
                to_value(networks).map_err(json_err)
            }
            Request::NetworkAdopt {
                name,
                site,
                vlan,
                subnet,
                write,
                dry_run,
            } => {
                validate_site_name(&site)?;
                validate_network_name(&name)?;
                let (network_address, prefix) = parse_cidr(&subnet)?;
                let allocations = self.allocations.lock().await;
                let vlan_receipt = vlan
                    .map(|vlan| {
                        allocations
                            .values()
                            .find(|receipt| {
                                receipt.site == site
                                    && receipt.allocation
                                        == AllocationValue::Vlan {
                                            id: mycelium_core::VlanId(vlan),
                                        }
                            })
                            .ok_or_else(|| {
                                MyceliumError::Validation(format!(
                                    "no allocation receipt for site `{site}` VLAN {vlan}"
                                ))
                            })
                    })
                    .transpose()?;
                let subnet_receipt = allocations
                    .values()
                    .find(|receipt| {
                        receipt.site == site
                            && matches!(
                                receipt.allocation,
                                AllocationValue::Subnet { network, prefix: observed, .. }
                                    if network == network_address && observed == prefix
                            )
                    })
                    .ok_or_else(|| {
                        MyceliumError::Validation(format!(
                            "no allocation receipt for site `{site}` subnet {network_address}/{prefix}"
                        ))
                    })?;
                let mut receipt_ids = BTreeSet::from([subnet_receipt.identity.clone()]);
                if let Some(vlan_receipt) = vlan_receipt {
                    receipt_ids.insert(vlan_receipt.identity.clone());
                }
                drop(allocations);
                let candidate = LogicalNetwork::adopted(&site, &name, receipt_ids.clone());
                let networks = self.networks.lock().await;
                if let Some(conflict) = networks.values().find(|network| {
                    network.identity != candidate.identity
                        && !network.receipt_ids.is_disjoint(&receipt_ids)
                }) {
                    return Err(MyceliumError::Validation(format!(
                        "allocation receipt already owned by network `{}`",
                        conflict.name
                    )));
                }
                if let Some(existing) = networks.get(&candidate.identity) {
                    if existing != &candidate {
                        return Err(MyceliumError::Validation(format!(
                            "network `{name}` already exists with different allocations"
                        )));
                    }
                }
                drop(networks);
                if dry_run {
                    return to_value(serde_json::json!({
                        "dry_run": true,
                        "network": candidate,
                    }))
                    .map_err(json_err);
                }
                if !write {
                    return Err(MyceliumError::WritesNotPermitted(
                        "network adoption requires --write".into(),
                    ));
                }
                self.networks
                    .lock()
                    .await
                    .insert(candidate.identity.clone(), candidate.clone());
                self.persist_networks().await?;
                to_value(candidate).map_err(json_err)
            }
            Request::NetworkDrift { name } => {
                let networks = self.networks.lock().await;
                let selected = networks
                    .values()
                    .filter(|network| name.as_ref().is_none_or(|name| &network.name == name))
                    .cloned()
                    .collect::<Vec<_>>();
                if name.is_some() && selected.is_empty() {
                    return Err(MyceliumError::Validation(format!(
                        "unknown logical network `{}`",
                        name.unwrap_or_default()
                    )));
                }
                drop(networks);
                let allocations = self.allocations.lock().await;
                let topology = self.topology.lock().await;
                let reports = selected
                    .into_iter()
                    .map(|network| network_drift_report(network, &allocations, &topology))
                    .collect::<Vec<_>>();
                to_value(reports).map_err(json_err)
            }
            Request::NetworkPlan { name } => {
                let networks = self.networks.lock().await;
                let selected = networks
                    .values()
                    .filter(|network| name.as_ref().is_none_or(|name| &network.name == name))
                    .cloned()
                    .collect::<Vec<_>>();
                if name.is_some() && selected.is_empty() {
                    return Err(MyceliumError::Validation(format!(
                        "unknown logical network `{}`",
                        name.unwrap_or_default()
                    )));
                }
                drop(networks);
                let allocations = self.allocations.lock().await;
                let topology = self.topology.lock().await;
                let bindings = self.network_bindings.lock().await;
                let dhcp_scopes = self.dhcp_scopes.lock().await;
                let plans = selected
                    .into_iter()
                    .map(|network| {
                        let report = network_drift_report(network, &allocations, &topology);
                        network_action_plan(report, &allocations, &bindings, &dhcp_scopes)
                    })
                    .collect::<Vec<_>>();
                to_value(plans).map_err(json_err)
            }
            Request::NetworkBindingList { network } => {
                let matching_ids = self
                    .networks
                    .lock()
                    .await
                    .values()
                    .filter(|logical| {
                        network.as_ref().is_none_or(|selector| {
                            logical.identity == *selector || logical.name == *selector
                        })
                    })
                    .map(|logical| logical.identity.clone())
                    .collect::<BTreeSet<_>>();
                let bindings = self.network_bindings.lock().await;
                let selected = bindings
                    .values()
                    .filter(|binding| network.is_none() || matching_ids.contains(&binding.network))
                    .cloned()
                    .collect::<Vec<_>>();
                to_value(selected).map_err(json_err)
            }
            Request::NetworkBindingSet {
                network,
                device,
                port,
                tagged,
                write,
                dry_run,
            } => {
                if port.is_empty() || port.len() > 64 {
                    return Err(MyceliumError::Validation(
                        "binding port must be 1-64 characters".into(),
                    ));
                }
                let networks = self.networks.lock().await;
                let logical = networks
                    .values()
                    .find(|candidate| candidate.identity == network || candidate.name == network)
                    .ok_or_else(|| {
                        MyceliumError::Validation(format!("unknown logical network `{network}`"))
                    })?;
                let network_id = logical.identity.clone();
                drop(networks);
                let capabilities = self.inventory.capabilities(&device)?;
                if !capabilities
                    .iter()
                    .any(|capability| capability.id == mycelium_core::ID_VLAN_ASSIGN)
                {
                    return Err(MyceliumError::Unsupported {
                        device,
                        capability: mycelium_core::ID_VLAN_ASSIGN.into(),
                    });
                }
                let candidate = NetworkBinding::new(network_id, device, port, tagged);
                if dry_run {
                    return to_value(serde_json::json!({"dry_run": true, "binding": candidate}))
                        .map_err(json_err);
                }
                if !write {
                    return Err(MyceliumError::WritesNotPermitted(
                        "network binding requires --write".into(),
                    ));
                }
                let mut bindings = self.network_bindings.lock().await;
                if let Some(existing) = bindings.get(&candidate.identity) {
                    if existing == &candidate {
                        return to_value(existing).map_err(json_err);
                    }
                }
                bindings.insert(candidate.identity.clone(), candidate.clone());
                drop(bindings);
                self.persist_network_bindings().await?;
                to_value(candidate).map_err(json_err)
            }
            Request::NetworkDhcpList { network } => {
                let matching_ids = self
                    .networks
                    .lock()
                    .await
                    .values()
                    .filter(|logical| {
                        network.as_ref().is_none_or(|selector| {
                            logical.identity == *selector || logical.name == *selector
                        })
                    })
                    .map(|logical| logical.identity.clone())
                    .collect::<BTreeSet<_>>();
                let scopes = self
                    .dhcp_scopes
                    .lock()
                    .await
                    .values()
                    .filter(|scope| network.is_none() || matching_ids.contains(&scope.network))
                    .cloned()
                    .collect::<Vec<_>>();
                to_value(scopes).map_err(json_err)
            }
            Request::NetworkDhcpSet {
                network,
                device,
                pool,
                range_start,
                range_end,
                dns_servers,
                write,
                dry_run,
            } => {
                validate_network_name(&pool.to_ascii_lowercase().replace('_', "-"))?;
                let networks = self.networks.lock().await;
                let logical = networks
                    .values()
                    .find(|candidate| candidate.identity == network || candidate.name == network)
                    .ok_or_else(|| {
                        MyceliumError::Validation(format!("unknown logical network `{network}`"))
                    })?;
                let network_id = logical.identity.clone();
                drop(networks);
                let capabilities = self.inventory.capabilities(&device)?;
                if !capabilities
                    .iter()
                    .any(|capability| capability.id == mycelium_core::ID_DHCP_ENSURE_POOL)
                {
                    return Err(MyceliumError::Unsupported {
                        device,
                        capability: mycelium_core::ID_DHCP_ENSURE_POOL.into(),
                    });
                }
                let range_start = range_start
                    .parse()
                    .map_err(|_| MyceliumError::Validation("invalid DHCP range start".into()))?;
                let range_end = range_end
                    .parse()
                    .map_err(|_| MyceliumError::Validation("invalid DHCP range end".into()))?;
                let dns_servers = dns_servers
                    .into_iter()
                    .map(|value| {
                        value.parse().map_err(|_| {
                            MyceliumError::Validation(format!("invalid DNS server `{value}`"))
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                let candidate = DhcpScopeIntent::new(
                    network_id,
                    device,
                    pool,
                    range_start,
                    range_end,
                    dns_servers,
                );
                if dry_run {
                    return to_value(serde_json::json!({"dry_run": true, "scope": candidate}))
                        .map_err(json_err);
                }
                if !write {
                    return Err(MyceliumError::WritesNotPermitted(
                        "DHCP scope intent requires --write".into(),
                    ));
                }
                self.dhcp_scopes
                    .lock()
                    .await
                    .insert(candidate.identity.clone(), candidate.clone());
                self.persist_dhcp_scopes().await?;
                to_value(candidate).map_err(json_err)
            }
            Request::PeerList => to_value(self.mesh.views().await).map_err(json_err),
            Request::WireGuardBindingList => {
                to_value(self.mesh.wireguard_bindings().await).map_err(json_err)
            }
            Request::WireGuardBindingInit {
                advertised_prefixes,
                endpoint,
                write,
                dry_run,
            } => {
                if advertised_prefixes.is_empty() {
                    return Err(MyceliumError::Validation(
                        "a WireGuard gateway must advertise at least one prefix".into(),
                    ));
                }
                for prefix in &advertised_prefixes {
                    validate_cidr(prefix)?;
                }
                if dry_run {
                    return to_value(serde_json::json!({
                        "dry_run": true,
                        "private_key": crate::wireguard_private_key_path(),
                        "advertised_prefixes": advertised_prefixes,
                        "endpoint": endpoint,
                        "requires": ["wg"],
                    }))
                    .map_err(json_err);
                }
                if !write {
                    return Err(MyceliumError::WritesNotPermitted(
                        "WireGuard key initialization requires --write".into(),
                    ));
                }
                let public_key = load_or_create_wireguard_key()?;
                let binding = self
                    .mesh
                    .publish_wireguard_binding(public_key, endpoint, advertised_prefixes)
                    .await
                    .map_err(|error| MyceliumError::Validation(error.to_string()))?;
                to_value(binding).map_err(json_err)
            }
            Request::SecurityPostureList => {
                to_value(self.mesh.security_postures().await).map_err(json_err)
            }
            Request::SecurityEventList => {
                to_value(self.mesh.security_events().await).map_err(json_err)
            }
            Request::SecuritySinkList => to_value(
                crate::siem::list()
                    .map_err(|error| MyceliumError::Validation(error.to_string()))?,
            )
            .map_err(json_err),
            Request::SecuritySinkAdd {
                config,
                write,
                dry_run,
            } => to_value(
                crate::siem::add(config, write, dry_run)
                    .map_err(|error| MyceliumError::Validation(error.to_string()))?,
            )
            .map_err(json_err),
            Request::SecurityExportStatus => to_value(
                crate::siem::status()
                    .map_err(|error| MyceliumError::Validation(error.to_string()))?,
            )
            .map_err(json_err),
            Request::SecurityExportRun {
                sink,
                write,
                dry_run,
            } => {
                let batches = self.mesh.security_events().await;
                to_value(
                    crate::siem::export(&batches, sink.as_deref(), dry_run, write)
                        .await
                        .map_err(|error| MyceliumError::Validation(error.to_string()))?,
                )
                .map_err(json_err)
            }
            Request::SecurityInspectionPlan { intent, candidates } => {
                to_value(mycelium_core::plan_inspection(intent, &candidates)).map_err(json_err)
            }
            Request::SecurityScan {
                stig_content,
                stig_profile,
                remediation_plan,
            } => {
                let posture = self
                    .mesh
                    .collect_and_publish_security(stig_content, stig_profile, remediation_plan)
                    .await
                    .map_err(|error| MyceliumError::Validation(error.to_string()))?;
                to_value(posture).map_err(json_err)
            }
            Request::SecurityRemediationList => to_value(
                crate::security::remediation_plans()
                    .map_err(|error| MyceliumError::Validation(error.to_string()))?,
            )
            .map_err(json_err),
            Request::SecurityRemediationApply { digest, write } => {
                if !write {
                    return Err(MyceliumError::WritesNotPermitted(
                        "security remediation requires --write".into(),
                    ));
                }
                to_value(
                    crate::security::apply_remediation(&digest)
                        .map_err(|error| MyceliumError::Validation(error.to_string()))?,
                )
                .map_err(json_err)
            }
            Request::SecurityRemediationVerify { digest } => to_value(
                crate::security::verify_remediation(&digest)
                    .map_err(|error| MyceliumError::Validation(error.to_string()))?,
            )
            .map_err(json_err),
            Request::ReleaseList => to_value(self.mesh.releases().await).map_err(json_err),
            Request::ReleaseKeygen { path, write } => {
                if !write {
                    return Err(MyceliumError::WritesNotPermitted(
                        "release key generation requires --write".into(),
                    ));
                }
                let signer = crate::peer::Mesh::generate_release_key(std::path::Path::new(&path))
                    .map_err(|error| MyceliumError::Validation(error.to_string()))?;
                to_value(serde_json::json!({ "path": path, "signer": signer })).map_err(json_err)
            }
            Request::ReleasePublish {
                binary,
                signing_key,
                version,
                channel,
                target,
                write,
                dry_run,
            } => {
                if dry_run {
                    return to_value(serde_json::json!({
                        "dry_run": true,
                        "binary": binary,
                        "signing_key": signing_key,
                        "version": version,
                        "channel": channel,
                        "target": target,
                    }))
                    .map_err(json_err);
                }
                if !write {
                    return Err(MyceliumError::WritesNotPermitted(
                        "release publication requires --write".into(),
                    ));
                }
                let release = self
                    .mesh
                    .publish_artifact(
                        std::path::Path::new(&binary),
                        std::path::Path::new(&signing_key),
                        version,
                        channel,
                        target,
                    )
                    .await
                    .map_err(|error| MyceliumError::Validation(error.to_string()))?;
                to_value(release).map_err(json_err)
            }
            Request::ReleasePublishSet {
                manifest,
                signing_key,
                write,
                dry_run,
            } => {
                if dry_run {
                    return to_value(serde_json::json!({
                        "dry_run": true,
                        "manifest": manifest,
                        "signing_key": signing_key,
                    }))
                    .map_err(json_err);
                }
                if !write {
                    return Err(MyceliumError::WritesNotPermitted(
                        "release-set publication requires --write".into(),
                    ));
                }
                let releases = self
                    .mesh
                    .publish_artifact_set(
                        std::path::Path::new(&manifest),
                        std::path::Path::new(&signing_key),
                    )
                    .await
                    .map_err(|error| MyceliumError::Validation(error.to_string()))?;
                to_value(releases).map_err(json_err)
            }
            Request::ReleaseSeed {
                binary,
                digest,
                write,
                dry_run,
            } => {
                if dry_run {
                    return to_value(serde_json::json!({
                        "dry_run": true,
                        "binary": binary,
                        "digest": digest,
                    }))
                    .map_err(json_err);
                }
                if !write {
                    return Err(MyceliumError::WritesNotPermitted(
                        "release seeding requires --write".into(),
                    ));
                }
                let seeded = self
                    .mesh
                    .seed_artifact(std::path::Path::new(&binary), &digest)
                    .await
                    .map_err(|error| MyceliumError::Validation(error.to_string()))?;
                to_value(seeded).map_err(json_err)
            }
            Request::AccessList => {
                to_value(self.mesh.access_view(unix_now()).await).map_err(json_err)
            }
            Request::AccessKeygen { path, write } => {
                if !write {
                    return Err(MyceliumError::WritesNotPermitted(
                        "access key generation requires --write".into(),
                    ));
                }
                let signer = crate::peer::Mesh::generate_release_key(std::path::Path::new(&path))
                    .map_err(|error| MyceliumError::Validation(error.to_string()))?;
                to_value(serde_json::json!({ "path": path, "signer": signer })).map_err(json_err)
            }
            Request::AccessPublish {
                statement,
                signing_key,
                write,
                dry_run,
            } => {
                if dry_run {
                    return to_value(serde_json::json!({
                        "dry_run": true,
                        "statement": statement,
                        "signing_key": signing_key,
                    }))
                    .map_err(json_err);
                }
                if !write {
                    return Err(MyceliumError::WritesNotPermitted(
                        "access publication requires --write".into(),
                    ));
                }
                let record = self
                    .mesh
                    .publish_access(
                        std::path::Path::new(&statement),
                        std::path::Path::new(&signing_key),
                    )
                    .await
                    .map_err(|error| MyceliumError::Validation(error.to_string()))?;
                to_value(record).map_err(json_err)
            }
            Request::TopologyAnnotate {
                selector,
                name,
                kind,
                write,
                dry_run,
            } => {
                validate_annotation(name.as_deref(), kind.as_deref())?;
                if !write && !dry_run {
                    return Err(MyceliumError::WritesNotPermitted(
                        "topology annotation requires --write".into(),
                    ));
                }
                let mut topology = self.topology.lock().await;
                let matches = topology
                    .nodes
                    .iter()
                    .filter(|(id, node)| node_matches(id, node, &selector))
                    .map(|(id, _)| id.clone())
                    .collect::<Vec<_>>();
                let node_id = match matches.as_slice() {
                    [node_id] => node_id.clone(),
                    [] => return Err(MyceliumError::UnknownDevice(selector)),
                    _ => {
                        return Err(MyceliumError::Validation(format!(
                            "annotation selector `{selector}` is ambiguous: {}",
                            matches.join(", ")
                        )))
                    }
                };
                let plan = serde_json::json!({
                    "node": node_id,
                    "name": name,
                    "kind": kind,
                    "dry_run": dry_run,
                });
                if !dry_run {
                    let node = topology
                        .nodes
                        .get_mut(&node_id)
                        .expect("resolved node exists");
                    if name.is_some() {
                        node.annotation.name = name;
                    }
                    if kind.is_some() {
                        node.annotation.kind = kind;
                    }
                    drop(topology);
                    self.persist_topology().await?;
                }
                Ok(plan)
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
            Request::SshPlan { selector, username } => {
                let saved = self.saved.lock().await;
                let device = saved
                    .values()
                    .find(|device| {
                        let id = device.meta.id.to_string();
                        let inferred_name = id
                            .strip_prefix(&format!("{}-", device.meta.driver))
                            .unwrap_or(&id);
                        id.eq_ignore_ascii_case(&selector)
                            || inferred_name.eq_ignore_ascii_case(&selector)
                            || device
                                .name
                                .as_deref()
                                .is_some_and(|name| name.eq_ignore_ascii_case(&selector))
                            || device.meta.address.eq_ignore_ascii_case(&selector)
                    })
                    .cloned();
                drop(saved);
                if let Some(device) = device {
                    if device.meta.driver != "linux"
                        && device.meta.driver != "darwin"
                        && device.meta.driver != "edgeos"
                    {
                        return Err(MyceliumError::Validation(format!(
                            "{} uses driver `{}`, which is not an interactive SSH target",
                            device.meta.id, device.meta.driver
                        )));
                    }
                    let username =
                        username
                            .or_else(|| device.username.clone())
                            .ok_or_else(|| {
                                MyceliumError::Validation(format!(
                                    "{} has no SSH username; pass --user or re-add it with --user",
                                    device.meta.id
                                ))
                            })?;
                    let target = Target::parse(&device.target)?;
                    let Target::Host { host, port, jump } = target else {
                        return Err(MyceliumError::Validation(format!(
                            "{} is a subnet target, not an interactive SSH host",
                            device.meta.id
                        )));
                    };
                    return to_value(serde_json::json!({
                        "device": device.meta.id,
                        "host": host,
                        "username": username,
                        "port": port.unwrap_or(22),
                        "jump": jump,
                        "identity": device.key_path,
                        "source": "inventory",
                    }))
                    .map_err(json_err);
                }

                let peer = self
                    .mesh
                    .views()
                    .await
                    .into_iter()
                    .find(|peer| {
                        peer.origin.eq_ignore_ascii_case(&selector)
                            || peer.hello.as_ref().is_some_and(|hello| {
                                hello.node_id.eq_ignore_ascii_case(&selector)
                                    || hello.hostname.eq_ignore_ascii_case(&selector)
                            })
                    })
                    .ok_or_else(|| MyceliumError::UnknownDevice(selector.clone()))?;
                let hello = peer.hello.ok_or_else(|| {
                    MyceliumError::Validation(format!(
                        "peer `{selector}` has not published its identity"
                    ))
                })?;
                if peer
                    .health
                    .as_ref()
                    .is_none_or(|health| !health.ssh_listening)
                {
                    return Err(MyceliumError::Validation(format!(
                        "peer `{}` is not reporting an SSH listener",
                        hello.hostname
                    )));
                }
                let username = username
                    .or_else(|| std::env::var("MYCELIUM_SSH_USER").ok())
                    .ok_or_else(|| {
                        MyceliumError::Validation(format!(
                            "peer `{}` has no local SSH username mapping; pass --user",
                            hello.hostname
                        ))
                    })?;
                to_value(serde_json::json!({
                    "device": hello.node_id,
                    "host": hello.hostname,
                    "username": username,
                    "port": 22,
                    "jump": null,
                    "identity": null,
                    "source": "peer",
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

fn validate_site_name(site: &str) -> Result<()> {
    if site.is_empty()
        || site.len() > 64
        || !site
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(MyceliumError::Validation(
            "site must be 1-64 lowercase letters, digits, or hyphens".into(),
        ));
    }
    Ok(())
}

fn validate_evidence_source(source: &str) -> Result<()> {
    if source.is_empty()
        || source.len() > 256
        || source
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(MyceliumError::Validation(
            "allocation source must be a non-empty, whitespace-free identifier".into(),
        ));
    }
    Ok(())
}

fn validate_network_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(MyceliumError::Validation(
            "network name must be 1-64 lowercase letters, digits, or hyphens".into(),
        ));
    }
    Ok(())
}

fn parse_cidr(value: &str) -> Result<(std::net::IpAddr, u8)> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| MyceliumError::Validation("subnet must be CIDR notation".into()))?;
    let address = address
        .parse::<std::net::IpAddr>()
        .map_err(|_| MyceliumError::Validation(format!("invalid subnet `{value}`")))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| MyceliumError::Validation(format!("invalid subnet `{value}`")))?;
    let valid = match address {
        std::net::IpAddr::V4(_) => prefix <= 32,
        std::net::IpAddr::V6(_) => prefix <= 128,
    };
    if !valid {
        return Err(MyceliumError::Validation(format!(
            "invalid subnet `{value}`"
        )));
    }
    Ok((address, prefix))
}

fn network_drift_report(
    network: LogicalNetwork,
    allocations: &BTreeMap<String, AllocationReceipt>,
    topology: &Topology,
) -> NetworkDriftReport {
    let mut missing_receipts = std::collections::BTreeSet::new();
    let mut missing_allocations = std::collections::BTreeSet::new();
    let mut gateway_mismatches = std::collections::BTreeSet::new();
    let mut known_members = std::collections::BTreeSet::new();
    let mut evidence_sources = std::collections::BTreeSet::new();
    for receipt_id in &network.receipt_ids {
        let Some(receipt) = allocations.get(receipt_id) else {
            missing_receipts.insert(receipt_id.clone());
            continue;
        };
        evidence_sources.extend(receipt.basis.sources.iter().cloned());
        match receipt.allocation {
            AllocationValue::Vlan { id } => {
                if !topology
                    .segments
                    .values()
                    .any(|segment| segment.vlan == Some(id))
                {
                    missing_allocations.insert(receipt.allocation.canonical());
                }
            }
            AllocationValue::Subnet {
                network: subnet,
                prefix,
                gateway,
            } => {
                let observed = topology
                    .segments
                    .values()
                    .find(|segment| segment.subnet == Some((subnet, prefix)));
                match observed {
                    None => {
                        missing_allocations.insert(receipt.allocation.canonical());
                    }
                    Some(segment) => {
                        evidence_sources.extend(segment.origins.iter().cloned());
                        if gateway.is_some() && gateway != segment.gw {
                            gateway_mismatches.insert(format!(
                                "{} expected={} observed={}",
                                receipt.allocation.canonical(),
                                gateway.map(|value| value.to_string()).unwrap_or_default(),
                                segment
                                    .gw
                                    .map(|value| value.to_string())
                                    .unwrap_or_else(|| "none".into())
                            ));
                        }
                    }
                }
                for node in topology.nodes.values().filter(|node| {
                    node.ips
                        .keys()
                        .any(|address| mycelium_core::ipv4_in_cidr(*address, subnet, prefix))
                }) {
                    let label = node
                        .annotation
                        .name
                        .clone()
                        .or_else(|| node.hostnames.iter().next().cloned())
                        .unwrap_or_else(|| node.id.clone());
                    known_members.insert(label);
                }
            }
        }
    }
    let state = if missing_receipts.is_empty()
        && missing_allocations.is_empty()
        && gateway_mismatches.is_empty()
    {
        NetworkDriftState::InSync
    } else {
        NetworkDriftState::Drifted
    };
    NetworkDriftReport {
        network,
        state,
        missing_receipts,
        missing_allocations,
        gateway_mismatches,
        known_members,
        evidence_sources,
    }
}

fn network_action_plan(
    report: NetworkDriftReport,
    allocations: &BTreeMap<String, AllocationReceipt>,
    bindings: &BTreeMap<String, NetworkBinding>,
    dhcp_scopes: &BTreeMap<String, DhcpScopeIntent>,
) -> mycelium_core::ActionPlan {
    let mut plan = report.action_plan();
    let placements = bindings
        .values()
        .filter(|binding| binding.network == report.network.identity)
        .collect::<Vec<_>>();
    if placements.is_empty() {
        return plan;
    }
    plan.blockers
        .retain(|blocker| blocker.code != "no_managed_bindings");
    if !plan.blockers.is_empty() {
        return plan;
    }
    let receipts = report
        .network
        .receipt_ids
        .iter()
        .filter_map(|identity| allocations.get(identity))
        .collect::<Vec<_>>();
    let vlan = receipts
        .iter()
        .find_map(|receipt| match receipt.allocation {
            AllocationValue::Vlan { id } => Some(id.0),
            _ => None,
        });
    let subnet = receipts
        .iter()
        .find_map(|receipt| match receipt.allocation {
            AllocationValue::Subnet {
                network,
                prefix,
                gateway: Some(gateway),
                ..
            } => Some((format!("{network}/{prefix}"), gateway, prefix)),
            _ => None,
        });
    let Some(vlan) = vlan else {
        plan.blockers.push(mycelium_core::PlanBlocker {
            code: "vlan_allocation_required".into(),
            message: "a physical VLAN binding requires a stable VLAN allocation".into(),
            resource: Some(report.network.identity),
        });
        return plan;
    };
    let Some((subnet_cidr, gateway, prefix)) = subnet else {
        plan.blockers.push(mycelium_core::PlanBlocker {
            code: "gateway_address_required".into(),
            message: "vlan.assign requires a gateway CIDR from the subnet allocation".into(),
            resource: Some(report.network.identity),
        });
        return plan;
    };
    let address = format!("{gateway}/{prefix}");
    for binding in placements {
        let expected = Value::Map(mycelium_core::Params::from_iter([
            ("id".into(), Value::Int(i64::from(vlan))),
            ("name".into(), Value::Str(report.network.name.clone())),
        ]));
        plan.actions.push(mycelium_core::PlannedAction {
            device: binding.device.clone(),
            capability: mycelium_core::ID_VLAN_ASSIGN.into(),
            params: mycelium_core::Params::from_iter([
                ("port".into(), Value::Str(binding.port.clone())),
                ("id".into(), Value::Int(i64::from(vlan))),
                ("name".into(), Value::Str(report.network.name.clone())),
                ("tagged".into(), Value::Bool(binding.tagged)),
                ("address".into(), Value::Str(address.clone())),
            ]),
            risk: mycelium_core::ActionRisk::Disruptive,
            before: None,
            expected_after: Some(expected.clone()),
            verification: mycelium_core::VerificationSpec {
                capability: mycelium_core::ID_VLAN_LIST.into(),
                params: mycelium_core::Params::new(),
                predicate: mycelium_core::VerificationPredicate::Contains { expected },
            },
        });
    }
    for scope in dhcp_scopes
        .values()
        .filter(|scope| scope.network == report.network.identity)
    {
        let expected_range = Value::Map(mycelium_core::Params::from_iter([
            ("start".into(), Value::Str(scope.range_start.to_string())),
            ("stop".into(), Value::Str(scope.range_end.to_string())),
        ]));
        let expected_subnet = Value::Map(mycelium_core::Params::from_iter([
            ("cidr".into(), Value::Str(subnet_cidr.clone())),
            ("default_router".into(), Value::Str(gateway.to_string())),
            ("ranges".into(), Value::List(vec![expected_range])),
        ]));
        let expected = Value::Map(mycelium_core::Params::from_iter([
            ("name".into(), Value::Str(scope.pool.clone())),
            ("subnets".into(), Value::List(vec![expected_subnet])),
        ]));
        plan.actions.push(mycelium_core::PlannedAction {
            device: scope.device.clone(),
            capability: mycelium_core::ID_DHCP_ENSURE_POOL.into(),
            params: mycelium_core::Params::from_iter([
                ("pool".into(), Value::Str(scope.pool.clone())),
                ("subnet".into(), Value::Str(subnet_cidr.clone())),
                ("gateway".into(), Value::Str(gateway.to_string())),
                (
                    "range_start".into(),
                    Value::Str(scope.range_start.to_string()),
                ),
                ("range_end".into(), Value::Str(scope.range_end.to_string())),
                (
                    "dns_servers".into(),
                    Value::List(
                        scope
                            .dns_servers
                            .iter()
                            .map(ToString::to_string)
                            .map(Value::Str)
                            .collect(),
                    ),
                ),
            ]),
            risk: mycelium_core::ActionRisk::Disruptive,
            before: None,
            expected_after: Some(expected.clone()),
            verification: mycelium_core::VerificationSpec {
                capability: mycelium_core::ID_DHCP_LIST_POOLS.into(),
                params: mycelium_core::Params::new(),
                predicate: mycelium_core::VerificationPredicate::Contains { expected },
            },
        });
    }
    plan
}

fn import_allocation_receipts(topology: &Topology, site: &str) -> Vec<AllocationReceipt> {
    let mut receipts = BTreeMap::<String, AllocationReceipt>::new();
    for segment in topology.segments.values().filter(|segment| {
        segment.id.starts_with("vlan:")
            || segment
                .id
                .split('/')
                .next()
                .is_some_and(|value| value.parse::<std::net::IpAddr>().is_ok())
    }) {
        if let Some(id) = segment.vlan {
            let receipt = AllocationReceipt::imported(
                site,
                AllocationValue::Vlan { id },
                segment.origins.clone(),
            );
            receipts.insert(receipt.identity.clone(), receipt);
        }
        if let Some((network, prefix)) = segment.subnet {
            let receipt = AllocationReceipt::imported(
                site,
                AllocationValue::Subnet {
                    network,
                    prefix,
                    gateway: segment.gw,
                },
                segment.origins.clone(),
            );
            receipts.insert(receipt.identity.clone(), receipt);
        }
    }
    receipts.into_values().collect()
}

fn creds_from(s: &SavedDevice) -> CredentialSet {
    CredentialSet {
        username: s.username.clone(),
        password: s.password_env.as_ref().map(|v| Secret::Env(v.clone())),
        key_path: s.key_path.clone(),
        sudo_password: None,
    }
}

fn node_matches(id: &str, node: &mycelium_core::TopoNode, selector: &str) -> bool {
    id.eq_ignore_ascii_case(selector)
        || node
            .ips
            .keys()
            .any(|address| address.to_string() == selector)
        || node
            .hostnames
            .iter()
            .any(|hostname| hostname.eq_ignore_ascii_case(selector))
        || node
            .annotation
            .name
            .as_deref()
            .is_some_and(|name| name.eq_ignore_ascii_case(selector))
}

fn validate_annotation(name: Option<&str>, kind: Option<&str>) -> Result<()> {
    if name.is_none() && kind.is_none() {
        return Err(MyceliumError::Validation(
            "annotation needs --name and/or --kind".into(),
        ));
    }
    if name.is_some_and(|name| name.trim().is_empty() || name.len() > 127) {
        return Err(MyceliumError::Validation(
            "annotation name must be 1..127 characters".into(),
        ));
    }
    if kind.is_some_and(|kind| {
        kind.is_empty()
            || kind.len() > 63
            || !kind.chars().all(|character| {
                character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
            })
    }) {
        return Err(MyceliumError::Validation(
            "annotation kind must use lowercase letters, digits, or hyphens".into(),
        ));
    }
    Ok(())
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
    daemon
        .mesh
        .start()
        .await
        .map_err(|error| std::io::Error::other(format!("peer mesh failed: {error}")))?;
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
    use mycelium_core::{
        CapResult, CapSpec, DeviceKind, DiscoveryProtocol, ExecContext, Params, Segment,
    };
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
            StdMap::from_iter([
                (
                    "fake.ping".to_string(),
                    CapSpec::readonly("ping").returns("pong"),
                ),
                (
                    "fake.apply".to_string(),
                    CapSpec::mutation("apply fake state"),
                ),
            ])
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
            discovery_scopes: Mutex::new(BTreeMap::new()),
            allocations: Mutex::new(BTreeMap::new()),
            networks: Mutex::new(BTreeMap::new()),
            network_bindings: Mutex::new(BTreeMap::new()),
            dhcp_scopes: Mutex::new(BTreeMap::new()),
            mesh: crate::peer::Mesh::ephemeral_for_test(),
        }
    }

    #[tokio::test]
    async fn action_plan_preflights_and_honors_dry_run_gate() {
        let daemon = daemon_with_fake();
        daemon.inventory.add(Arc::new(FakeDev {
            meta: DeviceMeta {
                id: DeviceId::new("fake-1"),
                kind: DeviceKind::Other,
                driver: "fake".into(),
                vendor: None,
                model: None,
                firmware: None,
                address: "fakehost.local".into(),
            },
        }));
        let mut plan = mycelium_core::ActionPlan::new("test:fake");
        plan.actions.push(mycelium_core::PlannedAction {
            device: "fake-1".into(),
            capability: "fake.apply".into(),
            params: Params::new(),
            risk: mycelium_core::ActionRisk::Low,
            before: None,
            expected_after: None,
            verification: mycelium_core::VerificationSpec {
                capability: "fake.ping".into(),
                params: Params::new(),
                predicate: mycelium_core::VerificationPredicate::Succeeds,
            },
        });
        let refused = daemon
            .dispatch(Request::ActionPlanApply {
                plan: plan.clone(),
                write: false,
                dry_run: false,
            })
            .await;
        assert!(!refused.ok);
        assert_eq!(refused.kind.as_deref(), Some("writes_not_permitted"));

        let dry_run = daemon
            .dispatch(Request::ActionPlanApply {
                plan,
                write: false,
                dry_run: true,
            })
            .await;
        assert!(dry_run.ok, "{dry_run:?}");
        assert_eq!(dry_run.result.unwrap()["dry_run"], true);
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

    #[test]
    fn validates_annotation_fields() {
        assert!(validate_annotation(Some("Front camera"), Some("camera")).is_ok());
        assert!(validate_annotation(None, None).is_err());
        assert!(validate_annotation(Some(""), None).is_err());
        assert!(validate_annotation(None, Some("IP Camera")).is_err());
    }

    #[test]
    fn imports_only_unscoped_observed_allocations() {
        let mut topology = Topology::empty();
        topology.segments.insert(
            "192.168.30.0/24".into(),
            Segment {
                id: "192.168.30.0/24".into(),
                subnet: Some(("192.168.30.0".parse().unwrap(), 24)),
                gw: Some("192.168.30.1".parse().unwrap()),
                ..Segment::default()
            },
        );
        topology.segments.insert(
            "vlan:30".into(),
            Segment {
                id: "vlan:30".into(),
                vlan: Some(mycelium_core::VlanId(30)),
                ..Segment::default()
            },
        );
        topology.segments.insert(
            "pris/172.17.0.0/16".into(),
            Segment {
                id: "pris/172.17.0.0/16".into(),
                subnet: Some(("172.17.0.0".parse().unwrap(), 16)),
                ..Segment::default()
            },
        );
        let receipts = import_allocation_receipts(&topology, "home");
        assert_eq!(receipts.len(), 2);
        assert!(receipts.iter().all(|receipt| receipt.site == "home"));
    }

    #[test]
    fn network_binding_derives_a_verified_vlan_action() {
        let vlan = AllocationReceipt::imported(
            "home",
            AllocationValue::Vlan {
                id: mycelium_core::VlanId(30),
            },
            BTreeSet::new(),
        );
        let subnet = AllocationReceipt::imported(
            "home",
            AllocationValue::Subnet {
                network: "192.168.30.0".parse().unwrap(),
                prefix: 24,
                gateway: Some("192.168.30.1".parse().unwrap()),
            },
            BTreeSet::new(),
        );
        let network = LogicalNetwork::adopted(
            "home",
            "cctv",
            BTreeSet::from([vlan.identity.clone(), subnet.identity.clone()]),
        );
        let binding = NetworkBinding::new(&network.identity, "edge-router", "eth1", true);
        let allocations = BTreeMap::from([
            (vlan.identity.clone(), vlan),
            (subnet.identity.clone(), subnet),
        ]);
        let bindings = BTreeMap::from([(binding.identity.clone(), binding)]);
        let dhcp = DhcpScopeIntent::new(
            &network.identity,
            "edge-router",
            "CCTV",
            "192.168.30.100".parse().unwrap(),
            "192.168.30.220".parse().unwrap(),
            vec!["192.168.30.1".parse().unwrap()],
        );
        let dhcp_scopes = BTreeMap::from([(dhcp.identity.clone(), dhcp)]);
        let plan = network_action_plan(
            NetworkDriftReport {
                network,
                state: NetworkDriftState::InSync,
                missing_receipts: BTreeSet::new(),
                missing_allocations: BTreeSet::new(),
                gateway_mismatches: BTreeSet::new(),
                known_members: BTreeSet::new(),
                evidence_sources: BTreeSet::new(),
            },
            &allocations,
            &bindings,
            &dhcp_scopes,
        );
        assert!(plan.ready_to_apply());
        assert_eq!(plan.actions.len(), 2);
        assert_eq!(plan.actions[0].capability, mycelium_core::ID_VLAN_ASSIGN);
        assert_eq!(plan.actions[0].params["id"], Value::Int(30));
        assert_eq!(
            plan.actions[0].params["address"],
            Value::Str("192.168.30.1/24".into())
        );
        assert_eq!(
            plan.actions[1].capability,
            mycelium_core::ID_DHCP_ENSURE_POOL
        );
        assert_eq!(
            plan.actions[1].params["subnet"],
            Value::Str("192.168.30.0/24".into())
        );
    }

    #[tokio::test]
    async fn ssh_plan_resolves_inventory_identity_without_secrets() {
        let daemon = daemon_with_fake();
        daemon.saved.lock().await.insert(
            DeviceId::new("linux-lab-node"),
            SavedDevice {
                meta: DeviceMeta {
                    id: DeviceId::new("linux-lab-node"),
                    kind: mycelium_core::DeviceKind::Other,
                    driver: "linux".into(),
                    vendor: None,
                    model: None,
                    firmware: None,
                    address: "100.83.7.116".into(),
                },
                target: "100.83.7.116@gateway".into(),
                name: Some("compute".into()),
                username: Some("operator".into()),
                password_env: Some("SECRET_PASSWORD".into()),
                key_path: Some("~/.ssh/id_ed25519".into()),
            },
        );
        let response = daemon
            .dispatch(Request::SshPlan {
                selector: "COMPUTE".into(),
                username: None,
            })
            .await;
        assert!(response.ok, "{response:?}");
        let plan = response.result.unwrap();
        assert_eq!(plan["host"], "100.83.7.116");
        assert_eq!(plan["username"], "operator");
        assert_eq!(plan["jump"], "gateway");
        assert_eq!(plan["identity"], "~/.ssh/id_ed25519");
        assert!(plan.get("password_env").is_none());
    }

    #[tokio::test]
    async fn ssh_plan_falls_back_to_a_healthy_mesh_peer() {
        let daemon = daemon_with_fake();
        daemon.mesh.publish_ssh_peer_for_test("home-pi", true).await;
        let response = daemon
            .dispatch(Request::SshPlan {
                selector: "HOME-PI".into(),
                username: Some("mames".into()),
            })
            .await;
        assert!(response.ok, "{response:?}");
        let plan = response.result.unwrap();
        assert_eq!(plan["host"], "home-pi");
        assert_eq!(plan["username"], "mames");
        assert_eq!(plan["source"], "peer");
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
                name: None,
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
                name: None,
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

        d.topology.lock().await.segments.insert(
            "10.0.9.0/24".into(),
            Segment {
                id: "10.0.9.0/24".into(),
                gw: Some("10.0.9.1".parse().unwrap()),
                ..Segment::default()
            },
        );
        let request = || Request::DiscoveryScopeSet {
            observer: "fake-1".into(),
            protocols: vec![DiscoveryProtocol::Ssdp],
            segments: vec!["10.0.9.0/24".into()],
            write: false,
            dry_run: false,
        };
        let denied = d.dispatch(request()).await;
        assert_eq!(denied.kind.as_deref(), Some("writes_not_permitted"));
        let mut allowed = request();
        if let Request::DiscoveryScopeSet { write, .. } = &mut allowed {
            *write = true;
        }
        assert!(d.dispatch(allowed).await.ok);
        let scopes = d.dispatch(Request::DiscoveryScopeList).await;
        assert_eq!(scopes.result.unwrap().as_array().unwrap().len(), 1);
        let saved_scope = std::fs::read_to_string(home.join("discovery.json")).unwrap();
        assert!(saved_scope.contains("10.0.9.0/24"));

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
