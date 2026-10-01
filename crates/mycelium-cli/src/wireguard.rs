use std::net::IpAddr;

use mycelium_core::topology::{
    MeshControlPlane, MeshCoordinator, MeshProtocol, Observation, Origin, OverlayPeerRecord,
};
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct GatewayIdentity {
    pub node_id: String,
    pub hostname: String,
    pub site: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Prefix {
    pub address: IpAddr,
    pub length: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct GatewayBinding {
    pub identity: GatewayIdentity,
    pub public_key: Option<String>,
    pub endpoint: Option<String>,
    pub advertised_prefixes: Vec<Prefix>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct PeerConfig {
    pub identity: GatewayIdentity,
    pub public_key: Option<String>,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<Prefix>,
    pub persistent_keepalive_seconds: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct GatewayPlan {
    pub local: GatewayIdentity,
    pub peer: PeerConfig,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct LinkPlan {
    pub interface: String,
    pub left: GatewayPlan,
    pub right: GatewayPlan,
    pub ready: bool,
    pub blockers: Vec<String>,
    /// The exact overlay observations reconciliation will insert into the
    /// shared topology once both endpoints are active.
    pub topology_bindings: Vec<Observation>,
}

pub(crate) fn plan_link(
    interface: String,
    left: GatewayBinding,
    right: GatewayBinding,
) -> Result<LinkPlan, String> {
    if left.identity.node_id == right.identity.node_id {
        return Err("WireGuard link endpoints resolve to the same Mycelium identity".into());
    }
    if left.identity.site == right.identity.site {
        return Err(format!(
            "both endpoints belong to site `{}`; a site link needs distinct routing domains",
            left.identity.site
        ));
    }
    if left.advertised_prefixes.is_empty() || right.advertised_prefixes.is_empty() {
        return Err("each endpoint must advertise at least one routed prefix".into());
    }
    for a in &left.advertised_prefixes {
        for b in &right.advertised_prefixes {
            if prefixes_overlap(a, b) {
                return Err(format!(
                    "routed prefixes {}/{} and {}/{} overlap",
                    a.address, a.length, b.address, b.length
                ));
            }
        }
    }

    let mut blockers = Vec::new();
    for binding in [&left, &right] {
        if binding.public_key.is_none() {
            blockers.push(format!(
                "{} has no identity-authorized WireGuard public key",
                binding.identity.hostname
            ));
        }
        if binding.endpoint.is_none() {
            blockers.push(format!(
                "{} has no observed public endpoint",
                binding.identity.hostname
            ));
        }
    }
    let topology_bindings = vec![
        topology_binding(&interface, &left),
        topology_binding(&interface, &right),
    ];
    let left_plan = GatewayPlan {
        local: left.identity.clone(),
        peer: PeerConfig {
            identity: right.identity.clone(),
            public_key: right.public_key.clone(),
            endpoint: right.endpoint.clone(),
            allowed_ips: right.advertised_prefixes.clone(),
            persistent_keepalive_seconds: Some(25),
        },
    };
    let right_plan = GatewayPlan {
        local: right.identity,
        peer: PeerConfig {
            identity: left.identity,
            public_key: left.public_key,
            endpoint: left.endpoint,
            allowed_ips: left.advertised_prefixes,
            persistent_keepalive_seconds: Some(25),
        },
    };
    Ok(LinkPlan {
        interface,
        left: left_plan,
        right: right_plan,
        ready: blockers.is_empty(),
        blockers,
        topology_bindings,
    })
}

fn topology_binding(interface: &str, binding: &GatewayBinding) -> Observation {
    Observation::OverlaySelf {
        device: binding.identity.hostname.clone(),
        ips: Vec::new(),
        hostname: binding.identity.hostname.clone(),
        record: OverlayPeerRecord {
            network: interface.into(),
            protocol: MeshProtocol::WireGuard,
            control_plane: MeshControlPlane {
                coordinator: MeshCoordinator::Custom,
                url: None,
            },
            self_node: true,
            tailnet: None,
            dns_name: Some(format!(
                "{}.{}.mycelium",
                binding.identity.hostname, binding.identity.site
            )),
            backend_state: Some(
                if binding.public_key.is_some() {
                    "planned"
                } else {
                    "missing_key"
                }
                .into(),
            ),
            observer: binding.identity.node_id.clone(),
            online: false,
            active: false,
            relay: None,
            endpoint: binding.endpoint.clone(),
            routed_lans: binding
                .advertised_prefixes
                .iter()
                .map(|prefix| format!("{}/{}", prefix.address, prefix.length))
                .collect::<BTreeSet<_>>(),
            observed_at: 0,
            origin: Origin::new(&binding.identity.hostname, "wireguard-plan")
                .at_site(&binding.identity.site),
        },
    }
}

pub(crate) fn parse_prefix(value: &str) -> Result<Prefix, String> {
    let (address, length) = value
        .split_once('/')
        .ok_or_else(|| format!("prefix `{value}` must be CIDR notation"))?;
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| format!("invalid IP address in prefix `{value}`"))?;
    let length = length
        .parse::<u8>()
        .map_err(|_| format!("invalid prefix length in `{value}`"))?;
    let bits = if address.is_ipv4() { 32 } else { 128 };
    if length > bits {
        return Err(format!("prefix length in `{value}` exceeds {bits}"));
    }
    Ok(Prefix {
        address: mask(address, length),
        length,
    })
}

fn prefixes_overlap(a: &Prefix, b: &Prefix) -> bool {
    if a.address.is_ipv4() != b.address.is_ipv4() {
        return false;
    }
    let common = a.length.min(b.length);
    mask(a.address, common) == mask(b.address, common)
}

fn mask(address: IpAddr, length: u8) -> IpAddr {
    match address {
        IpAddr::V4(address) => {
            let value = u32::from(address);
            let mask = if length == 0 {
                0
            } else {
                u32::MAX << (32 - length)
            };
            IpAddr::V4((value & mask).into())
        }
        IpAddr::V6(address) => {
            let value = u128::from(address);
            let mask = if length == 0 {
                0
            } else {
                u128::MAX << (128 - length)
            };
            IpAddr::V6((value & mask).into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(name: &str, site: &str, prefix: &str) -> GatewayBinding {
        GatewayBinding {
            identity: GatewayIdentity {
                node_id: format!("identity-{name}"),
                hostname: name.into(),
                site: site.into(),
            },
            public_key: None,
            endpoint: None,
            advertised_prefixes: vec![parse_prefix(prefix).unwrap()],
        }
    }

    #[test]
    fn normalizes_prefixes_and_rejects_overlap() {
        assert_eq!(
            parse_prefix("192.168.10.99/24").unwrap().address,
            "192.168.10.0".parse::<IpAddr>().unwrap()
        );
        let error = plan_link(
            "mycelium0".into(),
            binding("left", "home", "192.168.10.0/24"),
            binding("right", "lab", "192.168.10.128/25"),
        )
        .unwrap_err();
        assert!(error.contains("overlap"));
    }

    #[test]
    fn missing_keys_and_endpoints_are_loud_blockers() {
        let plan = plan_link(
            "mycelium0".into(),
            binding("left", "home", "192.168.10.0/24"),
            binding("right", "lab", "192.168.20.0/24"),
        )
        .unwrap();
        assert!(!plan.ready);
        assert_eq!(plan.blockers.len(), 4);
        assert_eq!(
            plan.left.peer.allowed_ips[0].address.to_string(),
            "192.168.20.0"
        );
    }

    #[test]
    fn complete_distinct_site_plan_is_ready() {
        let mut left = binding("left", "home", "192.168.10.0/24");
        left.public_key = Some("left-key".into());
        left.endpoint = Some("198.51.100.10:51820".into());
        let mut right = binding("right", "lab", "192.168.20.0/24");
        right.public_key = Some("right-key".into());
        right.endpoint = Some("203.0.113.20:51820".into());
        assert!(plan_link("mycelium0".into(), left, right).unwrap().ready);
    }
}
