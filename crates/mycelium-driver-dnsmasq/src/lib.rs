//! DNS is optional and replaceable. This adapter manages dnsmasq, not a new DNS server.
//! macOS activation is scoped to a suffix; DHCP/default DNS remain router policy.
use mycelium_core::{
    ActionRisk, CapResult, CapSpec, Device, DeviceId, DeviceKind, DeviceMeta, ExecContext,
    MyceliumError, Params,
};
use mycelium_dns_policy::resolver::{usable_address, ResolverConfig, ResolverMode};
use mycelium_dns_policy::{canonical_domain, DnsRecord};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    net::IpAddr,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const LABEL: &str = "dev.fpl.mycelium-dns";
const MARKER: &str = "# Managed by Mycelium DNS resolver\n";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub resolver: ResolverConfig,
    pub dnsmasq: PathBuf,
    pub mycelium: PathBuf,
    /// Explicit reachable address scopes; do not publish every remote private IP.
    pub reachable_prefixes: Vec<String>,
    pub refresh_seconds: u64,
    pub expiry_seconds: u64,
}

impl Settings {
    fn validate(&self) -> Result<(), String> {
        self.resolver.render(vec![])?;
        if !self.dnsmasq.is_absolute() || !self.mycelium.is_absolute() {
            return Err("binary paths must be absolute".into());
        }
        if !(10..=3600).contains(&self.refresh_seconds)
            || !(30..=3600).contains(&self.expiry_seconds)
            || self.refresh_seconds > self.expiry_seconds
        {
            return Err("invalid refresh/expiry interval".into());
        }
        if self.reachable_prefixes.is_empty()
            || self.reachable_prefixes.len() > 32
            || self
                .reachable_prefixes
                .iter()
                .any(|s| mycelium_core::parse_cidr(s).is_none())
        {
            return Err("provide 1..32 valid reachable prefixes".into());
        }
        Ok(())
    }
}

fn failure(message: impl ToString) -> MyceliumError {
    MyceliumError::Validation(message.to_string())
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let mut bytes = vec![];
    fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 65536 {
        return Err("configuration exceeds 64 KiB".into());
    }
    serde_json::from_slice(&bytes).map_err(|e| format!("invalid configuration: {e}"))
}
fn home() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or("HOME is not set".into())
}
fn state_dir() -> Result<PathBuf, String> {
    Ok(home()?.join(".mycelium/dns"))
}
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(format!("refusing symlink {}", path.display()));
    }
    let parent = path.parent().ok_or("file needs parent")?;
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let temporary = path.with_extension(format!("pending-{}", std::process::id()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        use std::io::Write;
        let mut file = options.open(&temporary).map_err(|e| e.to_string())?;
        file.write_all(bytes).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        fs::rename(&temporary, path).map_err(|e| e.to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn in_prefix(address: IpAddr, prefix: &str) -> bool {
    let Some((network, length)) = mycelium_core::parse_cidr(prefix) else {
        return false;
    };
    match (network, address) {
        (IpAddr::V4(n), IpAddr::V4(a)) => {
            let mask = if length == 0 {
                0
            } else {
                u32::MAX << (32 - length)
            };
            u32::from(n) & mask == u32::from(a) & mask
        }
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            let mask = if length == 0 {
                0
            } else {
                u128::MAX << (128 - length)
            };
            u128::from(n) & mask == u128::from(a) & mask
        }
        _ => false,
    }
}

/// Adapt the daemon's JSON peer view, already subject to fleet authentication.
/// Expired identities cannot squat a name after re-enrollment. Competing live
/// owners fail closed instead of arbitrarily choosing an identity.
pub fn peer_records(
    settings: &Settings,
    peers: &Value,
    timestamp: u64,
) -> Result<Vec<DnsRecord>, String> {
    let peers = peers.as_array().ok_or("peers must be an array")?;
    let site = canonical_domain(&settings.resolver.site)?;
    let suffix = canonical_domain(&settings.resolver.suffix)?;
    let mut records = BTreeSet::new();
    let mut owners = BTreeMap::new();
    for peer in peers {
        let Some(hello) = peer.get("hello") else {
            continue;
        };
        if hello["site"].as_str() != Some(settings.resolver.site.as_str()) {
            continue;
        }
        let Some(seen) = peer["last_seen"].as_u64() else {
            continue;
        };
        if seen > timestamp + 30 || timestamp.saturating_sub(seen) > settings.expiry_seconds {
            continue;
        }
        let Some(node) = hello["node_id"].as_str() else {
            continue;
        };
        let Some(host) = hello["hostname"].as_str() else {
            continue;
        };
        let host = canonical_domain(host)?;
        if host.contains('.') {
            return Err("peer hostname must be one DNS label".into());
        }
        let name = format!("{host}.{site}.{suffix}");
        let Some(interfaces) = hello["interfaces"].as_array() else {
            continue;
        };
        for address in interfaces
            .iter()
            .filter_map(|i| i["addresses"].as_array())
            .flatten()
        {
            let Some(address) = address.as_str().and_then(|a| a.parse::<IpAddr>().ok()) else {
                continue;
            };
            if !usable_address(address)
                || !settings
                    .reachable_prefixes
                    .iter()
                    .any(|p| in_prefix(address, p))
            {
                continue;
            }
            if owners
                .insert(name.clone(), node.to_owned())
                .is_some_and(|owner| owner != node)
            {
                return Err(format!("competing live owners for {name}"));
            }
            records.insert(DnsRecord {
                name: name.clone(),
                address,
                site: settings.resolver.site.clone(),
                node: node.into(),
            });
        }
    }
    Ok(records.into_iter().collect())
}

async fn observation(settings: &Settings) -> Result<(Vec<DnsRecord>, u64), String> {
    let mut command = tokio::process::Command::new(&settings.mycelium);
    command.args(["peers", "--json"]).kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(10), command.output())
        .await
        .map_err(|_| "peer observation timed out")?
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err("Mycelium peer observation failed".into());
    }
    if output.stdout.len() > 16 * 1024 * 1024 {
        return Err("peer response too large".into());
    }
    let peers: Value = serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())?;
    let timestamp = now();
    let records = peer_records(settings, &peers, timestamp)?;
    let owners = records
        .iter()
        .map(|r| r.node.as_str())
        .collect::<BTreeSet<_>>();
    let deadline = peers
        .as_array()
        .ok_or("peers must be an array")?
        .iter()
        .filter(|p| {
            p["hello"]["node_id"]
                .as_str()
                .is_some_and(|id| owners.contains(id))
        })
        .filter_map(|p| p["last_seen"].as_u64())
        .map(|seen| seen.saturating_add(settings.expiry_seconds))
        .min()
        .unwrap_or(timestamp + settings.expiry_seconds);
    Ok((records, deadline))
}
async fn observe(settings: &Settings) -> Result<Vec<DnsRecord>, String> {
    Ok(observation(settings).await?.0)
}

fn syntax(settings: &Settings, file: &Path) -> Result<(), String> {
    let output = Command::new(&settings.dnsmasq)
        .arg("--test")
        .arg(format!("--conf-file={}", file.display()))
        .output()
        .map_err(|e| e.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "dnsmasq validation: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

/// Read-only postcondition: query a generated record and verify its actual RDATA.
pub fn verify(settings: &Settings, record: &DnsRecord) -> Result<(), String> {
    use std::net::UdpSocket;
    let server = settings
        .resolver
        .listen
        .iter()
        .find(|s| s.ip().is_loopback())
        .unwrap_or(&settings.resolver.listen[0]);
    let socket = UdpSocket::bind(if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .map_err(|e| e.to_string())?;
    socket.connect(server).map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| e.to_string())?;
    let id = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u16)
        .to_be_bytes();
    let mut query = vec![id[0], id[1], 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in record.name.split('.') {
        query.push(label.len() as u8);
        query.extend(label.as_bytes());
    }
    query.push(0);
    let kind = if record.address.is_ipv4() {
        1u16
    } else {
        28u16
    };
    query.extend(kind.to_be_bytes());
    query.extend([0, 1]);
    socket.send(&query).map_err(|e| e.to_string())?;
    let mut packet = [0u8; 4096];
    let size = socket.recv(&mut packet).map_err(|e| e.to_string())?;
    let packet = &packet[..size];
    if size < 12
        || packet[..2] != id
        || packet[2] & 0x80 == 0
        || packet[3] & 15 != 0
        || packet[2] & 2 != 0
    {
        return Err("invalid DNS verification response".into());
    }
    let mut offset = 12;
    for _ in 0..u16::from_be_bytes([packet[4], packet[5]]) {
        skip_name(packet, &mut offset)?;
        offset += 4;
    }
    let expected = match record.address {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    };
    for _ in 0..u16::from_be_bytes([packet[6], packet[7]]) {
        skip_name(packet, &mut offset)?;
        let header = packet
            .get(offset..offset + 10)
            .ok_or("truncated DNS answer")?;
        let answer_kind = u16::from_be_bytes([header[0], header[1]]);
        let class = u16::from_be_bytes([header[2], header[3]]);
        let length = u16::from_be_bytes([header[8], header[9]]) as usize;
        offset += 10;
        let data = packet
            .get(offset..offset + length)
            .ok_or("truncated DNS data")?;
        if answer_kind == kind && class == 1 && data == expected {
            return Ok(());
        }
        offset += length;
    }
    Err("DNS response lacks the expected address".into())
}
fn skip_name(packet: &[u8], offset: &mut usize) -> Result<(), String> {
    loop {
        let length = *packet.get(*offset).ok_or("truncated DNS name")?;
        *offset += 1;
        if length == 0 {
            return Ok(());
        }
        if length & 0xc0 == 0xc0 {
            if packet.get(*offset).is_none() {
                return Err("truncated DNS pointer".into());
            }
            *offset += 1;
            return Ok(());
        }
        if length > 63 {
            return Err("invalid DNS label".into());
        }
        *offset += length as usize;
        if *offset > packet.len() {
            return Err("truncated DNS label".into());
        }
    }
}

fn xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
fn launch_plist(executable: &Path, config: &Path, directory: &Path) -> String {
    let mut args = vec![executable.display().to_string()];
    if executable.file_name().and_then(|n| n.to_str()) == Some("mycelium") {
        args.extend(["dns".into(), "resolver".into()]);
    }
    args.extend([
        "run".into(),
        "--config".into(),
        config.display().to_string(),
        "--write".into(),
    ]);
    let args = args
        .iter()
        .map(|a| format!("<string>{}</string>", xml(a)))
        .collect::<String>();
    format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>Label</key><string>{LABEL}</string><key>ProgramArguments</key><array>{args}</array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>15</integer><key>StandardOutPath</key><string>{}</string><key>StandardErrorPath</key><string>{}</string></dict></plist>",xml(&directory.join("resolver.log").display().to_string()),xml(&directory.join("resolver.log").display().to_string()))
}
fn gui_domain() -> Result<String, String> {
    let output = Command::new("id")
        .arg("-u")
        .output()
        .map_err(|e| e.to_string())?;
    let id = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u32>()
        .map_err(|e| e.to_string())?;
    if id == 0 {
        return Err("apply must run as the logged-in user, not root".into());
    }
    Ok(format!("gui/{id}"))
}

fn owned_namespace(config: &ResolverConfig, remove: bool) -> Result<Value, String> {
    if !cfg!(target_os = "macos") {
        return Err("OS namespace activation currently supports macOS only".into());
    }
    let mut active = config.clone();
    if remove && active.mode == ResolverMode::Off {
        active.mode = ResolverMode::LocalhostOnly;
    }
    let (zone, text) = active.macos_namespace()?;
    let directory = Path::new("/etc/resolver");
    if fs::symlink_metadata(directory).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err("refusing symlink resolver directory".into());
    }
    let path = directory.join(zone);
    if fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err("refusing symlink namespace file".into());
    }
    if path.exists()
        && !fs::read_to_string(&path)
            .map_err(|e| e.to_string())?
            .starts_with(MARKER)
    {
        return Err("namespace already owned by another resolver; unchanged".into());
    }
    if remove {
        if path.exists() {
            fs::remove_file(&path).map_err(|e| e.to_string())?;
        }
    } else {
        atomic_write(&path, text.as_bytes())?;
    }
    Ok(json!({"namespace":path,"installed":!remove,"default_dns_changed":false}))
}

pub struct ResolverDevice {
    settings: Settings,
    config: PathBuf,
    meta: DeviceMeta,
}
impl ResolverDevice {
    fn load(path: &Path) -> Result<Self, String> {
        let settings: Settings = read_json(path)?;
        settings.validate()?;
        Ok(Self {
            settings,
            config: fs::canonicalize(path).map_err(|e| e.to_string())?,
            meta: DeviceMeta {
                id: DeviceId::new("local-dns"),
                kind: DeviceKind::Other,
                driver: "dnsmasq".into(),
                vendor: None,
                model: None,
                firmware: None,
                address: "localhost".into(),
            },
        })
    }
}
#[async_trait::async_trait]
impl Device for ResolverDevice {
    fn meta(&self) -> &DeviceMeta {
        &self.meta
    }
    fn capabilities(&self) -> BTreeMap<String, CapSpec> {
        let mut caps = BTreeMap::new();
        caps.insert(
            "dns.resolver.status".into(),
            CapSpec::readonly("Query the generated record and report namespace activation"),
        );
        for cap in [
            "dns.resolver.apply",
            "dns.resolver.system-install",
            "dns.resolver.system-remove",
            "dns.resolver.run",
        ] {
            caps.insert(
                cap.into(),
                CapSpec::mutation("Manage optional local resolver")
                    .verified_by(ActionRisk::Disruptive, "dns.resolver.status"),
            );
        }
        caps
    }
    async fn exec(
        &self,
        ctx: &ExecContext,
        cap: &str,
        _params: Params,
    ) -> mycelium_core::Result<CapResult> {
        ctx.gate(cap != "dns.resolver.status")?;
        if ctx.dry_run {
            return Ok(CapResult::dry_run(mycelium_core::Value::from_json(
                &serde_json::to_value(&self.settings).map_err(failure)?,
            )));
        }
        let value = match cap {
            "dns.resolver.status" => {
                let records = observe(&self.settings).await.map_err(failure)?;
                let first = records
                    .first()
                    .ok_or_else(|| failure("no fresh reachable peer records"))?;
                verify(&self.settings, first).map_err(failure)?;
                let (zone, expected) = self.settings.resolver.macos_namespace().map_err(failure)?;
                json!({"mode":self.settings.resolver.mode,"verified_record":first,
                    "namespace_installed":fs::read_to_string(Path::new("/etc/resolver").join(zone)).is_ok_and(|s|s==expected),"default_dns_changed":false})
            }
            "dns.resolver.system-install" => {
                owned_namespace(&self.settings.resolver, false).map_err(failure)?
            }
            "dns.resolver.system-remove" => {
                owned_namespace(&self.settings.resolver, true).map_err(failure)?
            }
            "dns.resolver.apply" => apply(&self.settings, &self.config).await.map_err(failure)?,
            "dns.resolver.run" => {
                supervise(&self.settings).await.map_err(failure)?;
                json!({"stopped":true})
            }
            _ => return Err(MyceliumError::UnknownCapability(cap.into())),
        };
        Ok(CapResult::ok(mycelium_core::Value::from_json(&value)))
    }
}

async fn apply(settings: &Settings, _config: &Path) -> Result<Value, String> {
    if !cfg!(target_os = "macos") {
        return Err("persistent activation currently supports macOS only".into());
    }
    if settings.resolver.mode == ResolverMode::LanServing {
        return Err("LAN activation requires a verified client-network firewall policy; plan only in this slice".into());
    }
    let directory = state_dir()?;
    let plist = home()?.join(format!("Library/LaunchAgents/{LABEL}.plist"));
    let domain = gui_domain()?;
    if settings.resolver.mode == ResolverMode::Off {
        if Command::new("launchctl")
            .args(["print", &format!("{domain}/{LABEL}")])
            .output()
            .map_err(|e| e.to_string())?
            .status
            .success()
            && !Command::new("launchctl")
                .args(["bootout", &format!("{domain}/{LABEL}")])
                .status()
                .map_err(|e| e.to_string())?
                .success()
        {
            return Err("resolver stop failed; files retained".into());
        }
        if plist.exists() {
            fs::remove_file(&plist).map_err(|e| e.to_string())?;
        }
        return Ok(json!({"mode":"off","namespace_removal_required":true}));
    }
    let records = observe(settings).await?;
    if records.is_empty() {
        return Err("no fresh reachable records; refusing empty initial activation".into());
    }
    let candidate = directory.join("candidate.conf");
    atomic_write(
        &candidate,
        settings.resolver.render(records.clone())?.as_bytes(),
    )?;
    syntax(settings, &candidate)?;
    // Do not disrupt an unrelated process already listening on our socket.
    let print = Command::new("launchctl")
        .args(["print", &format!("{domain}/{LABEL}")])
        .output()
        .map_err(|e| e.to_string())?;
    if !print.status.success() {
        for listener in &settings.resolver.listen {
            std::net::UdpSocket::bind(listener)
                .map_err(|e| format!("listener unavailable: {e}"))?;
            std::net::TcpListener::bind(listener)
                .map_err(|e| format!("TCP listener unavailable: {e}"))?;
        }
    }
    if plist.exists()
        && !fs::read_to_string(&plist)
            .map_err(|e| e.to_string())?
            .contains(&format!("<string>{LABEL}</string>"))
    {
        return Err("existing launch agent has another owner".into());
    }
    let old = fs::read(&plist).ok();
    let stored = directory.join("active-settings.json");
    let old_settings = fs::read(&stored).ok();
    if print.status.success()
        && !Command::new("launchctl")
            .args(["bootout", &format!("{domain}/{LABEL}")])
            .status()
            .map_err(|e| e.to_string())?
            .success()
    {
        return Err("previous resolver stop failed; configuration unchanged".into());
    }
    atomic_write(
        &stored,
        &serde_json::to_vec(settings).map_err(|e| e.to_string())?,
    )?;
    atomic_write(
        &plist,
        launch_plist(
            &std::env::current_exe().map_err(|e| e.to_string())?,
            &stored,
            &directory,
        )
        .as_bytes(),
    )?;
    let status = Command::new("launchctl")
        .arg("bootstrap")
        .arg(&domain)
        .arg(&plist)
        .status()
        .map_err(|e| e.to_string())?;
    let mut verified = false;
    if status.success() {
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if verify(settings, &records[0]).is_ok() {
                verified = true;
                break;
            }
        }
    }
    if !verified {
        let _ = Command::new("launchctl")
            .args(["bootout", &format!("{domain}/{LABEL}")])
            .status();
        if let Some(old) = old {
            if let Some(old_settings) = old_settings {
                atomic_write(&stored, &old_settings)?;
            }
            atomic_write(&plist, &old)?;
            Command::new("launchctl")
                .arg("bootstrap")
                .arg(&domain)
                .arg(&plist)
                .status()
                .map_err(|e| e.to_string())?;
        } else {
            fs::remove_file(&plist).map_err(|e| e.to_string())?;
        }
        return Err("resolver postcondition failed; restored previous launch agent".into());
    }
    Ok(
        json!({"mode":settings.resolver.mode,"listening":settings.resolver.listen,
        "records":records.len(),"verified_record":records[0],"namespace_install_required":true,"default_dns_changed":false}),
    )
}

struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn start(settings: &Settings, config: &Path) -> Result<Running, String> {
    Command::new(&settings.dnsmasq)
        .args(["--keep-in-foreground", "--pid-file="])
        .arg(format!("--conf-file={}", config.display()))
        .stdin(Stdio::null())
        .spawn()
        .map(Running)
        .map_err(|e| e.to_string())
}
async fn supervise(settings: &Settings) -> Result<(), String> {
    if settings.resolver.mode != ResolverMode::LocalhostOnly {
        return Err("supervisor currently activates localhost-only".into());
    }
    let directory = state_dir()?;
    let path = directory.join("dnsmasq.conf");
    let (records, mut expires_at) = observation(settings).await?;
    let mut active = settings.resolver.render(records)?;
    atomic_write(&path, active.as_bytes())?;
    syntax(settings, &path)?;
    let mut running = start(settings, &path)?;
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| e.to_string())?;
    loop {
        #[cfg(unix)]
        tokio::select! {
            _=tokio::time::sleep(Duration::from_secs(settings.refresh_seconds))=>{},
            _=terminate.recv()=>return Ok(()),
            _=tokio::signal::ctrl_c()=>return Ok(()),
        }
        #[cfg(not(unix))]
        tokio::time::sleep(Duration::from_secs(settings.refresh_seconds)).await;
        if let Some(status) = running.0.try_wait().map_err(|e| e.to_string())? {
            return Err(format!("dnsmasq exited: {status}"));
        }
        let (records, next_expiry) = match observation(settings).await {
            Ok(result) => result,
            Err(error) => {
                eprintln!("DNS observation failed: {error}");
                if now() < expires_at {
                    continue;
                }
                eprintln!("Retained records expired; withdrawing mesh addresses");
                (vec![], now())
            }
        };
        let next = settings.resolver.render(records.clone())?;
        if next == active {
            expires_at = next_expiry;
            continue;
        }
        let candidate = directory.join("candidate.conf");
        atomic_write(&candidate, next.as_bytes())?;
        syntax(settings, &candidate)?;
        drop(running);
        atomic_write(&path, next.as_bytes())?;
        running = start(settings, &path)?;
        tokio::time::sleep(Duration::from_millis(250)).await;
        let healthy = running.0.try_wait().map_err(|e| e.to_string())?.is_none()
            && records
                .first()
                .is_none_or(|record| verify(settings, record).is_ok());
        if healthy {
            active = next;
            expires_at = next_expiry;
        } else {
            drop(running);
            atomic_write(&path, active.as_bytes())?;
            running = start(settings, &path)?;
            eprintln!("DNS refresh postcondition failed; previous configuration restored");
        }
    }
}

pub async fn command(args: &[String]) -> Result<String, String> {
    let action = args
        .first()
        .map(String::as_str)
        .ok_or("expected plan|apply|status|run|system-install|system-remove --config FILE")?;
    if !matches!(
        action,
        "plan" | "apply" | "status" | "run" | "system-install" | "system-remove"
    ) {
        return Err("unknown resolver action".into());
    }
    let mut config = None;
    let mut write = false;
    let mut dry_run = false;
    let mut rest = args[1..].iter();
    let mut seen = BTreeSet::new();
    while let Some(flag) = rest.next() {
        if !seen.insert(flag) {
            return Err("duplicate resolver option".into());
        }
        match flag.as_str() {
            "--config" => {
                config = Some(PathBuf::from(
                    rest.next().ok_or("--config requires a file")?,
                ))
            }
            "--write" => write = true,
            "--dry-run" => dry_run = true,
            _ => return Err("unknown resolver option".into()),
        }
    }
    let device = ResolverDevice::load(&config.ok_or("--config is required")?)?;
    if action == "plan" {
        let records = observe(&device.settings).await?;
        return Ok(
            json!({"mode":device.settings.resolver.mode,"records":records,
            "dnsmasq":device.settings.resolver.render(records.clone())?,
            "lan_activation_supported":false,"dhcp_changed":false})
            .to_string(),
        );
    }
    let cap = format!("dns.resolver.{action}");
    let result = device
        .invoke(
            &ExecContext {
                capability: cap.clone(),
                allow_writes: write,
                dry_run,
            },
            &cap,
            Params::new(),
        )
        .await
        .map_err(|e| e.to_string())?;
    Ok(result.output.to_json().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn settings() -> Settings {
        Settings {
            resolver: ResolverConfig {
                mode: ResolverMode::LocalhostOnly,
                site: "lab".into(),
                suffix: "myc".into(),
                listen: vec!["127.0.0.1:1053".parse().unwrap()],
                upstreams: vec![],
                delegations: vec![],
            },
            dnsmasq: "/bin/dnsmasq".into(),
            mycelium: "/bin/mycelium".into(),
            reachable_prefixes: vec!["192.0.2.0/24".into()],
            refresh_seconds: 30,
            expiry_seconds: 300,
        }
    }
    fn peer(node: &str, seen: u64) -> Value {
        json!({"hello":{"node_id":node,"hostname":"gpu","site":"lab","interfaces":[{"addresses":["192.0.2.12","198.51.100.1","fe80::1"]}]},"last_seen":seen})
    }
    #[test]
    fn fresh_scoped_addresses_and_expired_identity() {
        let records = peer_records(
            &settings(),
            &json!([peer("old", 1), peer("new", 999)]),
            1000,
        )
        .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].node, "new");
        assert_eq!(records[0].name, "gpu.lab.myc");
    }
    #[test]
    fn competing_live_identity_fails_closed() {
        assert!(peer_records(&settings(), &json!([peer("a", 999), peer("b", 999)]), 1000).is_err());
    }
    #[test]
    fn settings_roundtrip_and_invalid_refresh() {
        let s = settings();
        let text = serde_json::to_string(&s).unwrap();
        let mut s: Settings = serde_json::from_str(&text).unwrap();
        s.validate().unwrap();
        s.refresh_seconds = 1;
        assert!(s.validate().is_err());
    }
    #[test]
    fn plist_escapes_paths_and_contains_no_shell() {
        let p = launch_plist(
            Path::new("/Users/A & B/mycelium"),
            Path::new("/tmp/config"),
            Path::new("/tmp/state"),
        );
        assert!(p.contains("A &amp; B"));
        assert!(p.contains("<string>resolver</string>"));
        assert!(!p.contains("/bin/sh"));
    }
    #[test]
    fn truncated_dns_names_fail_without_panicking() {
        for packet in [vec![0xc0], vec![4, 1], vec![64, 0], vec![]] {
            assert!(skip_name(&packet, &mut 0).is_err());
        }
    }
    #[tokio::test]
    async fn device_write_gate_runs_before_mutation() {
        let d = ResolverDevice {
            settings: settings(),
            config: "/missing".into(),
            meta: DeviceMeta {
                id: DeviceId::new("test"),
                kind: DeviceKind::Other,
                driver: "dnsmasq".into(),
                vendor: None,
                model: None,
                firmware: None,
                address: "localhost".into(),
            },
        };
        assert!(matches!(
            d.invoke(
                &ExecContext::readonly("dns.resolver.apply"),
                "dns.resolver.apply",
                Params::new()
            )
            .await,
            Err(MyceliumError::WritesNotPermitted(_))
        ));
        assert!(
            d.invoke(
                &ExecContext {
                    capability: "dns.resolver.apply".into(),
                    allow_writes: false,
                    dry_run: true
                },
                "dns.resolver.apply",
                Params::new()
            )
            .await
            .unwrap()
            .dry_run
        );
    }
}
