use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use mycelium_core::{
    CapResult, CapSpec, CredentialSet, Device, DeviceId, DeviceKind, DeviceMeta, Driver,
    ExecContext, Inventory, LinkState, MyceliumError, Observation, Origin, OverlayPeerRecord,
    Params, PortRef, Result, Segment, SegmentKind, ServiceRecord, ServiceState, Target, Value,
    ID_IDENTIFY,
};
use mycelium_driver_edgeos::SshSession;

use crate::parsers::{
    parse_interfaces, parse_listeners, parse_neighbors, parse_routes, parse_tailscale_status,
};

pub const DRIVER_NAME: &str = "linux";
const OBSERVE_COMMAND: &str = "printf '__MYCELIUM_LINKS__\\n'; ip -o link show; printf '__MYCELIUM_ADDRS__\\n'; ip -o -4 addr show scope global; printf '__MYCELIUM_NEIGH__\\n'; ip neigh show; printf '__MYCELIUM_ROUTES__\\n'; ip -4 route show proto kernel scope link; printf '__MYCELIUM_SERVICES__\\n'; ss -H -lntup; printf '__MYCELIUM_TAILSCALE__\\n'; tailscale status --json 2>/dev/null || true";

pub struct LinuxDriver {
    timeout: Duration,
}

impl Default for LinuxDriver {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(8),
        }
    }
}

pub struct LinuxDevice {
    session: SshSession,
    meta: DeviceMeta,
    site: String,
}

fn host(target: &Target) -> Result<(&str, u16, Option<&str>)> {
    match target {
        Target::Host { host, port, jump } => Ok((host, port.unwrap_or(22), jump.as_deref())),
        Target::Subnet { .. } => Err(MyceliumError::Validation(
            "linux observer needs one SSH host".into(),
        )),
    }
}

async fn identity(session: &SshSession) -> Result<(String, String)> {
    let out = session
        .exec("printf '%s\\n' \"$(hostname)\" \"$(uname -srm)\"")
        .await?;
    if !out.success() {
        return Err(MyceliumError::Device {
            exit_code: out.exit_code,
            stderr: out.stderr,
        });
    }
    let mut lines = out.stdout.lines();
    let hostname = lines.next().unwrap_or_default().trim().to_owned();
    let uname = lines.next().unwrap_or_default().trim().to_owned();
    if hostname.is_empty() || !uname.starts_with("Linux ") {
        return Err(MyceliumError::Validation(
            "SSH target is not a recognizable Linux host".into(),
        ));
    }
    Ok((hostname, uname))
}

#[async_trait]
impl Driver for LinuxDriver {
    fn name(&self) -> &str {
        DRIVER_NAME
    }

    async fn recognizes(&self, target: &Target, creds: &CredentialSet) -> Result<bool> {
        let (host, port, jump) = host(target)?;
        let session = SshSession::connect(host, port, creds, self.timeout, jump).await?;
        Ok(identity(&session).await.is_ok())
    }

    async fn attach(
        &self,
        target: &Target,
        creds: &CredentialSet,
        inventory: &Inventory,
    ) -> Result<DeviceId> {
        let (host, port, jump) = host(target)?;
        let session = SshSession::connect(host, port, creds, self.timeout, jump).await?;
        let (hostname, uname) = identity(&session).await?;
        let slug = hostname
            .to_lowercase()
            .replace(|c: char| !c.is_ascii_alphanumeric(), "-");
        let meta = DeviceMeta {
            id: DeviceId::new(format!("linux-{slug}")),
            kind: DeviceKind::Other,
            driver: DRIVER_NAME.into(),
            vendor: Some("Linux".into()),
            model: Some(uname),
            firmware: None,
            address: host.to_owned(),
        };
        let id = meta.id.clone();
        inventory.add(Arc::new(LinuxDevice {
            session,
            meta,
            site: hostname.to_lowercase(),
        }));
        Ok(id)
    }
}

#[async_trait]
impl Device for LinuxDevice {
    fn meta(&self) -> &DeviceMeta {
        &self.meta
    }

    fn capabilities(&self) -> BTreeMap<String, CapSpec> {
        BTreeMap::from_iter([(
            ID_IDENTIFY.into(),
            CapSpec::readonly("Linux SSH vantage-point identity"),
        )])
    }

    async fn exec(&self, _ctx: &ExecContext, cap: &str, _params: Params) -> Result<CapResult> {
        match cap {
            ID_IDENTIFY => Ok(CapResult::ok(Value::Map(Params::from_iter([
                ("vendor".into(), Value::Str("Linux".into())),
                ("hostname".into(), Value::Str(self.site.clone())),
                (
                    "model".into(),
                    self.meta
                        .model
                        .clone()
                        .map(Value::Str)
                        .unwrap_or(Value::Null),
                ),
            ])))),
            other => Err(MyceliumError::Unsupported {
                device: self.meta.id.to_string(),
                capability: other.into(),
            }),
        }
    }

    async fn observe(&self) -> Result<(Vec<Observation>, Vec<String>)> {
        let raw = self.session.exec(OBSERVE_COMMAND).await?;
        if !raw.success() {
            return Err(MyceliumError::Device {
                exit_code: raw.exit_code,
                stderr: raw.stderr,
            });
        }
        let sections = split_sections(&raw.stdout)?;
        let interfaces = parse_interfaces(sections[0], sections[1]);
        let primary_mac = interfaces
            .iter()
            .find(|interface| {
                !interface.name.starts_with("br-")
                    && !interface.name.starts_with("docker")
                    && !interface.name.starts_with("tailscale")
                    && !interface.name.starts_with("veth")
                    && !interface.name.starts_with("sh-")
                    && !interface.name.starts_with("sv")
                    && interface.addresses.iter().any(|(address, _)| {
                        matches!(address, std::net::IpAddr::V4(address) if address.is_private())
                    })
            })
            .and_then(|interface| interface.mac);
        let mut out = Vec::new();
        let origin = |source: &str| {
            Origin::new(self.meta.id.to_string(), source.to_owned()).at_site(self.site.clone())
        };
        for iface in interfaces {
            out.push(Observation::DevicePort {
                device: self.meta.id.to_string(),
                port: iface.name,
                mac: iface.mac.filter(|mac| Some(*mac) == primary_mac),
                ips: iface.addresses.into_iter().map(|(ip, _)| ip).collect(),
                state: if iface.up {
                    LinkState::Up
                } else {
                    LinkState::Down
                },
                origin: origin("ip-link"),
            });
        }
        for neighbor in parse_neighbors(sections[2]) {
            out.push(Observation::Neighbor {
                mac: Some(neighbor.mac),
                ip: neighbor.ip,
                hostname: None,
                port: Some(PortRef {
                    device: self.meta.id.to_string(),
                    port: neighbor.iface,
                    vif: None,
                }),
                origin: origin("ip-neigh"),
            });
        }
        for route in parse_routes(sections[3]) {
            out.push(Observation::Segment {
                segment: Segment {
                    id: format!("{}/{}", route.network, route.prefix),
                    kind: SegmentKind::Lan,
                    vlan: None,
                    subnet: Some((route.network, route.prefix)),
                    gw: None,
                    domain_name: None,
                    origins: Default::default(),
                },
                origin: origin(&format!("ip-route:{}", route.iface)),
            });
        }
        let observed_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        for listener in parse_listeners(sections[4]) {
            out.push(Observation::Service {
                device: self.meta.id.to_string(),
                mac: None,
                ip: None,
                service: ServiceRecord {
                    name: service_name(listener.port, listener.process.as_deref()),
                    transport: listener.transport,
                    port: listener.port,
                    product: listener.process,
                    state: ServiceState::Up,
                    observed_at,
                    origin: origin("ss-listen"),
                },
            });
        }
        let mut warnings = Vec::new();
        match parse_tailscale_status(sections[5]) {
            Ok(peers) => {
                for peer in peers {
                    for ip in peer.ips {
                        out.push(Observation::OverlayPeer {
                            ip,
                            hostname: peer.hostname.clone(),
                            record: OverlayPeerRecord {
                                network: "tailscale".into(),
                                observer: self.meta.id.to_string(),
                                online: peer.online,
                                active: peer.active,
                                relay: peer.relay.clone(),
                                endpoint: peer.endpoint.clone(),
                                routed_lans: peer
                                    .routed_lans
                                    .iter()
                                    .cloned()
                                    .collect::<BTreeSet<_>>(),
                                observed_at,
                                origin: origin("tailscale-status"),
                            },
                        });
                    }
                }
            }
            Err(error) => warnings.push(format!("tailscale status: {error}")),
        }
        Ok((out, warnings))
    }
}

fn service_name(port: u16, process: Option<&str>) -> String {
    match port {
        22 => "ssh".into(),
        25 => "smtp".into(),
        53 => "dns".into(),
        111 => "rpcbind".into(),
        631 => "ipp".into(),
        2049 => "nfs".into(),
        2222 => "ssh".into(),
        3000 | 3001 | 3002 => "http".into(),
        5432 | 5433 | 5435 => "postgres".into(),
        5900 => "vnc".into(),
        7878 => "radarr".into(),
        8123 => "home-assistant".into(),
        80 | 5000 | 8080 => "http".into(),
        443 | 8443 | 8888 | 8971 => "https".into(),
        8554 => "rtsp".into(),
        8555 => "webrtc".into(),
        8989 => "sonarr".into(),
        11434 => "ollama".into(),
        32400 => "plex".into(),
        _ => process.unwrap_or("unknown").to_owned(),
    }
}

fn split_sections(text: &str) -> Result<[&str; 6]> {
    let (_, after_links) = text
        .split_once("__MYCELIUM_LINKS__\n")
        .ok_or_else(|| MyceliumError::Parse("missing links marker".into()))?;
    let (links, after_addrs) = after_links
        .split_once("__MYCELIUM_ADDRS__\n")
        .ok_or_else(|| MyceliumError::Parse("missing addresses marker".into()))?;
    let (addrs, after_neigh) = after_addrs
        .split_once("__MYCELIUM_NEIGH__\n")
        .ok_or_else(|| MyceliumError::Parse("missing neighbors marker".into()))?;
    let (neigh, after_routes) = after_neigh
        .split_once("__MYCELIUM_ROUTES__\n")
        .ok_or_else(|| MyceliumError::Parse("missing routes marker".into()))?;
    let (routes, after_services) = after_routes
        .split_once("__MYCELIUM_SERVICES__\n")
        .ok_or_else(|| MyceliumError::Parse("missing services marker".into()))?;
    let (services, tailscale) = after_services
        .split_once("__MYCELIUM_TAILSCALE__\n")
        .ok_or_else(|| MyceliumError::Parse("missing tailscale marker".into()))?;
    Ok([links, addrs, neigh, routes, services, tailscale])
}
