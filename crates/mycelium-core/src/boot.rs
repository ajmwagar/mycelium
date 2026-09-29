//! Deterministic early-boot network and NBDE planning.
//!
//! The planner only reasons over observed topology. It does not probe, mutate
//! routing, or execute Clevis: those belong to drivers and an explicitly
//! write-gated enrollment workflow.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::{ipv4_in_cidr, Segment, TopoNode, Topology};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootReachability {
    Direct,
    Routed,
    Unverified,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootTarget {
    pub endpoint: String,
    pub address: IpAddr,
    pub reachability: BootReachability,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_segment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_segment: Option<String>,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootPath {
    pub device: String,
    pub source_addresses: Vec<IpAddr>,
    pub targets: Vec<BootTarget>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NbdePlan {
    pub device: String,
    pub threshold: usize,
    pub endpoints: Vec<BootTarget>,
    pub reachable: usize,
    pub viable: bool,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BootPlanError {
    DeviceNotFound(String),
    AmbiguousDevice(String),
    InvalidEndpoint(String),
    InvalidThreshold { threshold: usize, endpoints: usize },
}

impl std::fmt::Display for BootPlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DeviceNotFound(device) => write!(f, "device `{device}` is absent from topology"),
            Self::AmbiguousDevice(device) => write!(f, "device selector `{device}` is ambiguous"),
            Self::InvalidEndpoint(endpoint) => {
                write!(f, "endpoint `{endpoint}` must contain an IP address")
            }
            Self::InvalidThreshold {
                threshold,
                endpoints,
            } => write!(
                f,
                "threshold {threshold} is invalid for {endpoints} endpoint(s)"
            ),
        }
    }
}

impl std::error::Error for BootPlanError {}

impl Topology {
    pub fn boot_path(&self, device: &str, endpoints: &[String]) -> Result<BootPath, BootPlanError> {
        let node = self.resolve_node(device)?;
        let source_addresses = node.ips.keys().copied().collect::<Vec<_>>();
        let source_segments = matching_segments(self, node);
        let mut targets = Vec::with_capacity(endpoints.len());

        for endpoint in endpoints {
            let address = endpoint_ip(endpoint)
                .ok_or_else(|| BootPlanError::InvalidEndpoint(endpoint.clone()))?;
            let target_segments = self
                .segments
                .values()
                .filter(|segment| segment_contains(segment, address))
                .collect::<Vec<_>>();

            let direct = source_segments
                .iter()
                .find(|source| target_segments.iter().any(|target| source.id == target.id));
            let (reachability, source_segment, target_segment, reason) = if let Some(segment) =
                direct
            {
                (
                    BootReachability::Direct,
                    Some(segment.id.clone()),
                    Some(segment.id.clone()),
                    "endpoint shares an observed boot segment".to_owned(),
                )
            } else if let (Some(source), Some(target)) = (
                source_segments.iter().find(|segment| segment.gw.is_some()),
                target_segments.first(),
            ) {
                (
                    BootReachability::Routed,
                    Some(source.id.clone()),
                    Some(target.id.clone()),
                    "source has a gateway and target is on an observed segment; initramfs route/firewall still requires verification".to_owned(),
                )
            } else {
                (
                    BootReachability::Unverified,
                    source_segments.first().map(|segment| segment.id.clone()),
                    target_segments.first().map(|segment| segment.id.clone()),
                    "topology does not prove an early-boot path".to_owned(),
                )
            };
            targets.push(BootTarget {
                endpoint: endpoint.clone(),
                address,
                reachability,
                source_segment,
                target_segment,
                reason,
            });
        }

        Ok(BootPath {
            device: node.id.clone(),
            source_addresses,
            targets,
        })
    }

    pub fn nbde_plan(
        &self,
        device: &str,
        endpoints: &[String],
        threshold: usize,
    ) -> Result<NbdePlan, BootPlanError> {
        if threshold == 0 || threshold > endpoints.len() {
            return Err(BootPlanError::InvalidThreshold {
                threshold,
                endpoints: endpoints.len(),
            });
        }
        let path = self.boot_path(device, endpoints)?;
        let reachable = path
            .targets
            .iter()
            .filter(|target| target.reachability != BootReachability::Unverified)
            .count();
        let mut warnings = path
            .targets
            .iter()
            .filter(|target| target.reachability == BootReachability::Routed)
            .map(|target| {
                format!(
                    "{} is routed; verify initramfs addressing, gateway, and firewall policy",
                    target.endpoint
                )
            })
            .collect::<Vec<_>>();
        if reachable < threshold {
            warnings.push(format!(
                "only {reachable} of {} endpoints have an observed path; threshold is {threshold}",
                endpoints.len()
            ));
        }
        Ok(NbdePlan {
            device: path.device,
            threshold,
            endpoints: path.targets,
            reachable,
            viable: reachable >= threshold,
            warnings,
        })
    }

    fn resolve_node(&self, selector: &str) -> Result<&TopoNode, BootPlanError> {
        if let Some(node) = self.nodes.get(selector) {
            return Ok(node);
        }
        let selector_ip = selector.parse::<IpAddr>().ok();
        let matches = self
            .nodes
            .values()
            .filter(|node| {
                node.hostnames.contains(&selector.to_lowercase())
                    || selector_ip.is_some_and(|ip| node.ips.contains_key(&ip))
            })
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [] => Err(BootPlanError::DeviceNotFound(selector.to_owned())),
            [node] => Ok(node),
            _ => Err(BootPlanError::AmbiguousDevice(selector.to_owned())),
        }
    }
}

fn matching_segments<'a>(topology: &'a Topology, node: &TopoNode) -> Vec<&'a Segment> {
    topology
        .segments
        .values()
        .filter(|segment| {
            node.ips
                .keys()
                .any(|address| segment_contains(segment, *address))
        })
        .collect()
}

fn segment_contains(segment: &Segment, address: IpAddr) -> bool {
    segment
        .subnet
        .is_some_and(|(network, prefix)| ipv4_in_cidr(address, network, prefix))
}

fn endpoint_ip(endpoint: &str) -> Option<IpAddr> {
    let authority = endpoint
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(endpoint)
        .split('/')
        .next()?;
    if let Ok(address) = authority.parse() {
        return Some(address);
    }
    authority
        .rsplit_once(':')
        .and_then(|(host, _)| host.parse().ok())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::{IpRecord, SegmentKind};

    fn topology() -> Topology {
        let host_ip = "192.168.20.50".parse().unwrap();
        Topology {
            nodes: BTreeMap::from([(
                "server".into(),
                TopoNode {
                    id: "server".into(),
                    ips: BTreeMap::from([(
                        host_ip,
                        IpRecord {
                            addr: host_ip,
                            prefix: Some(24),
                            vlan: None,
                            origins: BTreeSet::new(),
                        },
                    )]),
                    hostnames: BTreeSet::from(["compute-1".into()]),
                    ..TopoNode::default()
                },
            )]),
            segments: BTreeMap::from([
                (
                    "boot".into(),
                    Segment {
                        id: "boot".into(),
                        kind: SegmentKind::Vlan,
                        subnet: Some(("192.168.20.0".parse().unwrap(), 24)),
                        gw: Some("192.168.20.1".parse().unwrap()),
                        ..Segment::default()
                    },
                ),
                (
                    "services".into(),
                    Segment {
                        id: "services".into(),
                        kind: SegmentKind::Vlan,
                        subnet: Some(("192.168.99.0".parse().unwrap(), 24)),
                        gw: Some("192.168.99.1".parse().unwrap()),
                        ..Segment::default()
                    },
                ),
            ]),
            ..Topology::default()
        }
    }

    #[test]
    fn classifies_direct_routed_and_unknown_paths() {
        let endpoints = vec![
            "http://192.168.20.8:7500".into(),
            "http://192.168.99.8:7500".into(),
            "http://10.4.0.8:7500".into(),
        ];
        let path = topology().boot_path("compute-1", &endpoints).unwrap();
        assert_eq!(path.targets[0].reachability, BootReachability::Direct);
        assert_eq!(path.targets[1].reachability, BootReachability::Routed);
        assert_eq!(path.targets[2].reachability, BootReachability::Unverified);
    }

    #[test]
    fn nbde_threshold_fails_loud_when_topology_cannot_support_it() {
        let endpoints = vec![
            "http://192.168.20.8:7500".into(),
            "http://10.4.0.8:7500".into(),
        ];
        let plan = topology().nbde_plan("server", &endpoints, 2).unwrap();
        assert!(!plan.viable);
        assert_eq!(plan.reachable, 1);
        assert!(!plan.warnings.is_empty());
    }

    #[test]
    fn rejects_dns_until_early_boot_dns_is_modeled() {
        let error = topology()
            .boot_path("server", &["http://tang.local:7500".into()])
            .unwrap_err();
        assert!(matches!(error, BootPlanError::InvalidEndpoint(_)));
    }
}
