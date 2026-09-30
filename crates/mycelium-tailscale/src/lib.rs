//! Platform-neutral parsing of the Tailscale CLI's JSON observations.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::net::IpAddr;

use mycelium_core::{
    MeshControlPlane, MeshCoordinator, MeshProtocol, Observation, Origin, OverlayPeerRecord,
};
use serde::Deserialize;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub hostname: String,
    pub dns_name: Option<String>,
    pub ips: Vec<IpAddr>,
    pub online: bool,
    pub active: bool,
    pub relay: Option<String>,
    pub endpoint: Option<String>,
    pub routed_lans: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    pub backend_state: Option<String>,
    pub tailnet: Option<String>,
    pub self_node: Option<Peer>,
    pub peers: Vec<Peer>,
}

#[derive(Deserialize)]
struct StatusWire {
    #[serde(rename = "BackendState")]
    backend_state: Option<String>,
    #[serde(rename = "CurrentTailnet")]
    current_tailnet: Option<TailnetWire>,
    #[serde(rename = "Self")]
    self_node: Option<PeerWire>,
    #[serde(rename = "Peer", default)]
    peer: BTreeMap<String, PeerWire>,
}

#[derive(Deserialize)]
struct TailnetWire {
    #[serde(rename = "Name")]
    name: Option<String>,
}

#[derive(Deserialize)]
struct PeerWire {
    #[serde(rename = "HostName", default)]
    host_name: String,
    #[serde(rename = "DNSName")]
    dns_name: Option<String>,
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
    allowed_ips: Option<Vec<String>>,
    #[serde(rename = "PrimaryRoutes", default)]
    primary_routes: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct PrefsWire {
    #[serde(rename = "ControlURL")]
    control_url: Option<String>,
}

pub fn parse_status(text: &str) -> Result<Status, serde_json::Error> {
    if text.trim().is_empty() {
        return Ok(Status {
            backend_state: None,
            tailnet: None,
            self_node: None,
            peers: Vec::new(),
        });
    }
    let status: StatusWire = serde_json::from_str(text)?;
    Ok(Status {
        backend_state: status.backend_state.filter(|state| !state.is_empty()),
        tailnet: status.current_tailnet.and_then(|tailnet| tailnet.name),
        self_node: status.self_node.map(peer),
        peers: status.peer.into_values().map(peer).collect(),
    })
}

fn peer(peer: PeerWire) -> Peer {
    let mut routed_lans = peer.primary_routes.unwrap_or_default();
    routed_lans.extend(
        peer.allowed_ips
            .unwrap_or_default()
            .into_iter()
            .filter(|prefix| !prefix.ends_with("/32") && !prefix.ends_with("/128")),
    );
    routed_lans.sort();
    routed_lans.dedup();
    Peer {
        hostname: peer.host_name,
        dns_name: peer.dns_name.filter(|name| !name.is_empty()),
        ips: peer.tailscale_ips,
        online: peer.online,
        active: peer.active,
        relay: peer.relay.filter(|relay| !relay.is_empty()),
        endpoint: peer.cur_addr.filter(|endpoint| !endpoint.is_empty()),
        routed_lans,
    }
}

pub fn parse_control_plane(text: &str) -> Result<MeshControlPlane, serde_json::Error> {
    if text.trim().is_empty() {
        return Ok(MeshControlPlane::default());
    }
    let prefs: PrefsWire = serde_json::from_str(text)?;
    let url = prefs.control_url.filter(|url| !url.trim().is_empty());
    let coordinator = match url.as_deref() {
        Some(url) if is_tailscale_cloud_url(url) => MeshCoordinator::TailscaleCloud,
        Some(url) if url.to_ascii_lowercase().contains("headscale") => MeshCoordinator::Headscale,
        Some(_) => MeshCoordinator::Custom,
        None => MeshCoordinator::Unknown,
    };
    Ok(MeshControlPlane { coordinator, url })
}

/// Convert one platform's CLI snapshots into the shared topology contract.
pub fn topology_observations(
    status: Status,
    control_plane: MeshControlPlane,
    device: &str,
    site: &str,
    observed_at: u64,
) -> Vec<Observation> {
    let origin = || Origin::new(device, "tailscale-status").at_site(site);
    let mut out = Vec::new();
    if let Some(peer) = &status.self_node {
        out.push(Observation::OverlaySelf {
            device: device.to_owned(),
            ips: peer.ips.clone(),
            hostname: peer.hostname.clone(),
            record: record(
                &peer,
                true,
                &status,
                control_plane.clone(),
                device,
                observed_at,
                origin(),
            ),
        });
    }
    for peer in &status.peers {
        for ip in &peer.ips {
            out.push(Observation::OverlayPeer {
                ip: *ip,
                hostname: peer.hostname.clone(),
                record: record(
                    &peer,
                    false,
                    &status,
                    control_plane.clone(),
                    device,
                    observed_at,
                    origin(),
                ),
            });
        }
    }
    out
}

fn record(
    peer: &Peer,
    self_node: bool,
    status: &Status,
    control_plane: MeshControlPlane,
    device: &str,
    observed_at: u64,
    origin: Origin,
) -> OverlayPeerRecord {
    OverlayPeerRecord {
        network: "tailscale".into(),
        protocol: MeshProtocol::Tailscale,
        control_plane,
        self_node,
        tailnet: status.tailnet.clone(),
        dns_name: peer.dns_name.clone(),
        backend_state: status.backend_state.clone(),
        observer: device.to_owned(),
        online: peer.online,
        active: peer.active,
        relay: (!self_node).then(|| peer.relay.clone()).flatten(),
        endpoint: (!self_node).then(|| peer.endpoint.clone()).flatten(),
        routed_lans: peer.routed_lans.iter().cloned().collect::<BTreeSet<_>>(),
        observed_at,
        origin,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_self_peers_routes_and_nullable_fields() {
        let status = parse_status(
            r#"{
          "BackendState":"Running","CurrentTailnet":{"Name":"fpl"},
          "Self":{"HostName":"pris","TailscaleIPs":["100.64.0.1"],"PrimaryRoutes":null},
          "Peer":{"key":{"HostName":"lab","TailscaleIPs":["100.64.0.2"],
            "AllowedIPs":["100.64.0.2/32","192.168.40.0/24"]}}
        }"#,
        )
        .unwrap();
        assert_eq!(status.tailnet.as_deref(), Some("fpl"));
        assert_eq!(status.self_node.unwrap().hostname, "pris");
        assert_eq!(status.peers[0].routed_lans, ["192.168.40.0/24"]);
    }

    #[test]
    fn classifies_coordinators() {
        assert_eq!(
            parse_control_plane(r#"{"ControlURL":"https://controlplane.tailscale.com"}"#)
                .unwrap()
                .coordinator,
            MeshCoordinator::TailscaleCloud
        );
        assert_eq!(
            parse_control_plane(r#"{"ControlURL":"https://headscale.fpl.dev"}"#)
                .unwrap()
                .coordinator,
            MeshCoordinator::Headscale
        );
        assert_eq!(
            parse_control_plane(r#"{"ControlURL":"https://mesh.fpl.dev"}"#)
                .unwrap()
                .coordinator,
            MeshCoordinator::Custom
        );
    }
}
