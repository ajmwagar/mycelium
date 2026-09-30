use std::collections::BTreeMap;
use std::net::IpAddr;

use mycelium_core::{LinkDuplex, LinkMedium, MacAddress, MeshControlPlane, MeshCoordinator};
use serde::Deserialize;

#[derive(Clone, Debug, PartialEq)]
pub struct Interface {
    pub name: String,
    pub mac: Option<MacAddress>,
    pub addresses: Vec<(IpAddr, u8)>,
    pub up: bool,
    pub medium: LinkMedium,
    pub speed_mbps: Option<u32>,
    pub duplex: Option<LinkDuplex>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Neighbor {
    pub ip: IpAddr,
    pub iface: String,
    pub mac: MacAddress,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ConnectedRoute {
    pub network: IpAddr,
    pub prefix: u8,
    pub iface: String,
    pub source: Option<IpAddr>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Listener {
    pub transport: String,
    pub port: u16,
    pub process: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TailscalePeer {
    pub hostname: String,
    pub ips: Vec<IpAddr>,
    pub online: bool,
    pub active: bool,
    pub relay: Option<String>,
    pub endpoint: Option<String>,
    pub routed_lans: Vec<String>,
}

#[derive(Deserialize)]
struct TailscaleStatus {
    #[serde(rename = "Peer", default)]
    peer: BTreeMap<String, TailscalePeerWire>,
}

#[derive(Deserialize)]
struct TailscalePeerWire {
    #[serde(rename = "HostName", default)]
    host_name: String,
    #[serde(rename = "TailscaleIPs", default)]
    tailscale_ips: Vec<IpAddr>,
    #[serde(rename = "Online", default)]
    online: bool,
    #[serde(rename = "Active", default)]
    active: bool,
    #[serde(rename = "Relay")]
    relay: Option<String>,
    #[serde(rename = "CurAddr")]
    cur_addr: Option<String>,
    #[serde(rename = "AllowedIPs", default)]
    allowed_ips: Vec<String>,
    #[serde(rename = "PrimaryRoutes", default)]
    primary_routes: Vec<String>,
}

#[derive(Deserialize)]
struct TailscalePrefsWire {
    #[serde(rename = "ControlURL")]
    control_url: Option<String>,
}

pub fn parse_interfaces(links: &str, addresses: &str) -> Vec<Interface> {
    let mut out: BTreeMap<String, Interface> = BTreeMap::new();
    for line in links.lines() {
        let mut fields = line.split_whitespace();
        let _index = fields.next();
        let Some(raw_name) = fields.next() else {
            continue;
        };
        let name = raw_name
            .trim_end_matches(':')
            .split('@')
            .next()
            .unwrap_or(raw_name);
        let words: Vec<&str> = line.split_whitespace().collect();
        let mac = words
            .windows(2)
            .find(|w| w[0].starts_with("link/"))
            .and_then(|w| MacAddress::parse(w[1]));
        out.insert(
            name.to_owned(),
            Interface {
                name: name.to_owned(),
                mac,
                addresses: Vec::new(),
                up: line.contains("state UP") || line.contains(",UP,"),
                medium: LinkMedium::Unknown,
                speed_mbps: None,
                duplex: None,
            },
        );
    }
    for line in addresses.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(name) = fields.get(1).map(|s| s.split('@').next().unwrap_or(s)) else {
            continue;
        };
        let Some(cidr) = fields.iter().find(|s| s.contains('/')) else {
            continue;
        };
        let Some((ip, prefix)) = parse_cidr(cidr) else {
            continue;
        };
        out.entry(name.to_owned())
            .or_insert_with(|| Interface {
                name: name.to_owned(),
                mac: None,
                addresses: Vec::new(),
                up: true,
                medium: LinkMedium::Unknown,
                speed_mbps: None,
                duplex: None,
            })
            .addresses
            .push((ip, prefix));
    }
    out.into_values().collect()
}

pub fn parse_link_properties(text: &str, interfaces: &mut [Interface]) {
    for line in text.lines() {
        let mut fields = line.split('\t');
        let Some(name) = fields.next() else { continue };
        let medium = match fields.next().unwrap_or_default() {
            "ethernet" => LinkMedium::Ethernet,
            "wifi" => LinkMedium::Wifi,
            "virtual" => LinkMedium::Virtual,
            "loopback" => LinkMedium::Loopback,
            "cellular" => LinkMedium::Cellular,
            _ => LinkMedium::Unknown,
        };
        let speed_mbps = fields
            .next()
            .and_then(|value| value.parse::<i64>().ok())
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| *value > 0);
        let duplex = match fields
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str()
        {
            "full" => Some(LinkDuplex::Full),
            "half" => Some(LinkDuplex::Half),
            _ => None,
        };
        if let Some(interface) = interfaces
            .iter_mut()
            .find(|interface| interface.name == name)
        {
            interface.medium = medium;
            interface.speed_mbps = speed_mbps;
            interface.duplex = duplex;
        }
    }
}

pub fn parse_neighbors(text: &str) -> Vec<Neighbor> {
    text.lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let ip = fields.first()?.parse().ok()?;
            let iface = fields.windows(2).find(|w| w[0] == "dev")?[1].to_owned();
            let mac = fields
                .windows(2)
                .find(|w| w[0] == "lladdr")
                .and_then(|w| MacAddress::parse(w[1]))?;
            Some(Neighbor { ip, iface, mac })
        })
        .collect()
}

pub fn parse_routes(text: &str) -> Vec<ConnectedRoute> {
    text.lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let (network, prefix) = parse_cidr(fields.first()?)?;
            let iface = fields.windows(2).find(|w| w[0] == "dev")?[1].to_owned();
            let source = fields
                .windows(2)
                .find(|w| w[0] == "src")
                .and_then(|w| w[1].parse().ok());
            Some(ConnectedRoute {
                network,
                prefix,
                iface,
                source,
            })
        })
        .collect()
}

pub fn parse_listeners(text: &str) -> Vec<Listener> {
    let mut listeners = text
        .lines()
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            let transport = fields.first()?.trim_end_matches('6').to_owned();
            let port = fields.get(4)?.rsplit(':').next()?.parse().ok()?;
            let process = line
                .split("users:((\"")
                .nth(1)
                .and_then(|rest| rest.split('"').next())
                .map(str::to_owned);
            Some(Listener {
                transport,
                port,
                process,
            })
        })
        .collect::<Vec<_>>();
    listeners.sort();
    listeners.dedup();
    listeners
}

pub fn parse_tailscale_status(text: &str) -> Result<Vec<TailscalePeer>, serde_json::Error> {
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    let status: TailscaleStatus = serde_json::from_str(text)?;
    Ok(status
        .peer
        .into_values()
        .map(|peer| {
            let mut routed_lans = peer.primary_routes;
            routed_lans.extend(
                peer.allowed_ips
                    .into_iter()
                    .filter(|prefix| !prefix.ends_with("/32") && !prefix.ends_with("/128")),
            );
            routed_lans.sort();
            routed_lans.dedup();
            TailscalePeer {
                hostname: peer.host_name,
                ips: peer.tailscale_ips,
                online: peer.online,
                active: peer.active,
                relay: peer.relay.filter(|relay| !relay.is_empty()),
                endpoint: peer.cur_addr.filter(|endpoint| !endpoint.is_empty()),
                routed_lans,
            }
        })
        .collect())
}

pub fn parse_tailscale_control_plane(text: &str) -> Result<MeshControlPlane, serde_json::Error> {
    if text.trim().is_empty() {
        return Ok(MeshControlPlane::default());
    }
    let prefs: TailscalePrefsWire = serde_json::from_str(text)?;
    let url = prefs.control_url.filter(|url| !url.trim().is_empty());
    let coordinator = match url.as_deref() {
        Some(url) if is_tailscale_cloud_url(url) => MeshCoordinator::TailscaleCloud,
        Some(url) if url.to_ascii_lowercase().contains("headscale") => MeshCoordinator::Headscale,
        Some(_) => MeshCoordinator::Custom,
        None => MeshCoordinator::Unknown,
    };
    Ok(MeshControlPlane { coordinator, url })
}

fn is_tailscale_cloud_url(url: &str) -> bool {
    let host = url
        .split_once("://")
        .map(|(_, authority)| authority)
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or_default()
        .split(':')
        .next()
        .unwrap_or_default()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    host == "tailscale.com" || host.ends_with(".tailscale.com")
}

fn parse_cidr(text: &str) -> Option<(IpAddr, u8)> {
    let (ip, prefix) = text.split_once('/')?;
    Some((ip.parse().ok()?, prefix.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_iproute2_observations() {
        let links = "2: enp4s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP mode DEFAULT group default qlen 1000 link/ether 06:7c:16:77:ea:c0 brd ff:ff:ff:ff:ff:ff";
        let addrs =
            "2: enp4s0    inet 192.168.1.9/24 brd 192.168.1.255 scope global dynamic enp4s0";
        let mut interfaces = parse_interfaces(links, addrs);
        parse_link_properties("enp4s0\tethernet\t100\tfull\n", &mut interfaces);
        assert_eq!(interfaces[0].name, "enp4s0");
        assert_eq!(interfaces[0].addresses[0].0.to_string(), "192.168.1.9");
        assert_eq!(interfaces[0].medium, LinkMedium::Ethernet);
        assert_eq!(interfaces[0].speed_mbps, Some(100));
        assert_eq!(interfaces[0].duplex, Some(LinkDuplex::Full));

        let neighbors = parse_neighbors("192.168.1.1 dev enp4s0 lladdr 94:18:65:19:e9:bb REACHABLE\n192.168.1.2 dev enp4s0 FAILED");
        assert_eq!(neighbors.len(), 1);
        assert_eq!(neighbors[0].mac.to_string(), "94:18:65:19:e9:bb");

        let routes = parse_routes(
            "192.168.1.0/24 dev enp4s0 proto kernel scope link src 192.168.1.9 metric 100",
        );
        assert_eq!(routes[0].prefix, 24);
        assert_eq!(routes[0].source.unwrap().to_string(), "192.168.1.9");
    }

    #[test]
    fn parses_listening_sockets_and_processes() {
        let rows = parse_listeners(
            "tcp LISTEN 0 4096 0.0.0.0:8971 0.0.0.0:* users:((\"frigate\",pid=12,fd=4))\nudp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:*",
        );
        assert_eq!(rows[0].process.as_deref(), Some("frigate"));
        assert_eq!(rows[0].port, 8971);
        assert_eq!(rows[1].transport, "udp");
    }

    #[test]
    fn parses_tailscale_peers_and_subnet_routes() {
        let peers = parse_tailscale_status(
            r#"{
              "Peer": {
                "node-key": {
                  "HostName": "agora-one",
                  "TailscaleIPs": ["100.80.85.86"],
                  "Online": true,
                  "Active": false,
                  "Relay": "sea",
                  "CurAddr": "192.0.2.4:41641",
                  "AllowedIPs": ["100.80.85.86/32", "192.168.40.0/24"]
                }
              }
            }"#,
        )
        .unwrap();
        assert_eq!(peers[0].hostname, "agora-one");
        assert_eq!(peers[0].ips[0].to_string(), "100.80.85.86");
        assert_eq!(peers[0].routed_lans, vec!["192.168.40.0/24"]);
        assert!(peers[0].online);
    }

    #[test]
    fn classifies_tailscale_coordination_servers_without_guessing_custom_hosts() {
        let cloud =
            parse_tailscale_control_plane(r#"{"ControlURL":"https://controlplane.tailscale.com"}"#)
                .unwrap();
        assert_eq!(cloud.coordinator, MeshCoordinator::TailscaleCloud);

        let headscale =
            parse_tailscale_control_plane(r#"{"ControlURL":"https://headscale.fpl.dev"}"#).unwrap();
        assert_eq!(headscale.coordinator, MeshCoordinator::Headscale);

        let custom =
            parse_tailscale_control_plane(r#"{"ControlURL":"https://mesh.fpl.dev"}"#).unwrap();
        assert_eq!(custom.coordinator, MeshCoordinator::Custom);

        let lookalike =
            parse_tailscale_control_plane(r#"{"ControlURL":"https://notreallytailscale.com"}"#)
                .unwrap();
        assert_eq!(lookalike.coordinator, MeshCoordinator::Custom);
    }
}
