//! Network topology: derived, typed, and mergeable across LANs/WANs.
//!
//! Nothing here is configured by hand (tenet #3). A topology is assembled
//! from `Observation`s reported by drivers — ARP/mroute tables, interface
//! inventories, DHCP pools and leases, VLAN membership config — keyed by
//! the physical LAN segment so devices on different subnets/LANs describe
//! the same hosts into the same node.
//!
//! Identity rules (v0):
//! - a node is keyed by MAC when known (the stable L2 id), else by IP
//!   prefixed `ip:` (anycast/gateway addresses without MAC report).
//! - conflicting metadata never resolves silently; it is recorded as a
//!   `Conflict` and surfaced in the report (fail loud, tenet #12).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MacAddress(pub [u8; 6]);

impl Serialize for MacAddress {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for MacAddress {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        MacAddress::parse(&s).ok_or_else(|| serde::de::Error::custom(format!("bad mac `{s}`")))
    }
}

impl MacAddress {
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split([':', '-']).collect();
        if parts.len() != 6 {
            return None;
        }
        let mut octets = [0u8; 6];
        for (i, p) in parts.iter().enumerate() {
            octets[i] = u8::from_str_radix(p, 16).ok()?;
        }
        Some(MacAddress(octets))
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VlanId(pub u16);

/// How an address was observed, for trust ranking and provenance.
#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Origin {
    pub device: String,
    pub source: String,
    /// Routing/identity domain. Identical RFC1918 addresses in different
    /// sites are distinct facts, not conflicts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
}

impl Origin {
    pub fn new(device: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            device: device.into(),
            source: source.into(),
            site: None,
        }
    }

    pub fn at_site(mut self, site: impl Into<String>) -> Self {
        self.site = Some(site.into());
        self
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IpRecord {
    pub addr: IpAddr,
    pub prefix: Option<u8>,
    /// VLAN the address was seen on, if known.
    pub vlan: Option<VlanId>,
    pub origins: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkState {
    Up,
    Down,
    Unknown,
}

/// One port on one device — a link endpoint.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PortRef {
    pub device: String,
    pub port: String,
    /// e.g. "eth0" carrying VLAN 35 as `eth0.35`
    pub vif: Option<VlanId>,
}

impl fmt::Display for PortRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.vif {
            Some(v) => write!(f, "{}/{}.{}", self.device, self.port, v.0),
            None => write!(f, "{}/{}", self.device, self.port),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Link {
    pub a: PortRef,
    pub b: Option<PortRef>,
    pub state: LinkState,
    pub origins: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SegmentKind {
    #[default]
    Lan,
    Vlan,
    Wan,
    PointToPoint,
}

/// An L2/L3 domain as seen by one or more devices. Segment ids are stable
/// across reports: `<net>` for IPv4 LANs, `vlan:<id>` when reported.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct Segment {
    pub id: String,
    pub kind: SegmentKind,
    pub vlan: Option<VlanId>,
    pub subnet: Option<(IpAddr, u8)>,
    pub gw: Option<IpAddr>,
    pub domain_name: Option<String>,
    pub origins: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LeaseRecord {
    pub ip: IpAddr,
    pub mac: MacAddress,
    pub hostname: Option<String>,
    pub pool: Option<String>,
    pub origin: Origin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceState {
    Up,
    Down,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceRecord {
    pub name: String,
    pub transport: String,
    pub port: u16,
    pub product: Option<String>,
    pub state: ServiceState,
    pub observed_at: u64,
    pub origin: Origin,
}

/// One atomic piece of topology truth from one device.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Observation {
    /// Reachable host seen in a forwarding table (arp/neighbors).
    Neighbor {
        mac: Option<MacAddress>,
        ip: IpAddr,
        hostname: Option<String>,
        port: Option<PortRef>,
        origin: Origin,
    },
    /// A layer-2 attachment learned without an IP address (for example from
    /// a switch forwarding table or a wireless controller association).
    Attachment {
        mac: MacAddress,
        hostname: Option<String>,
        port: PortRef,
        origin: Origin,
    },
    /// A listening or remotely identified service. MAC is preferred for
    /// identity, then an existing node with `ip`, then `device`.
    Service {
        device: String,
        mac: Option<MacAddress>,
        ip: Option<IpAddr>,
        service: ServiceRecord,
    },
    /// A port of a device, with link state.
    DevicePort {
        device: String,
        port: String,
        mac: Option<MacAddress>,
        ips: Vec<IpAddr>,
        state: LinkState,
        origin: Origin,
    },
    /// VLAN membership: device trunk/access port carrying a VLAN.
    VlanMember {
        device: String,
        vlan: VlanId,
        members: Vec<String>,
        origin: Origin,
    },
    /// A DHCP pool / network segment as configured on a device.
    Segment { segment: Segment, origin: Origin },
    /// A configured or active DHCP lease.
    Lease { lease: LeaseRecord, origin: Origin },
}

/// A node in the merged graph: one host, or one appliance device.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct TopoNode {
    pub id: String,
    pub mac: Option<MacAddress>,
    pub ips: BTreeMap<IpAddr, IpRecord>,
    pub hostnames: BTreeSet<String>,
    pub device: bool,
    pub ports: BTreeMap<String, Link>,
    pub origins: BTreeSet<String>,
    #[serde(default)]
    pub sites: BTreeSet<String>,
    #[serde(default)]
    pub services: BTreeMap<String, ServiceRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Conflict {
    SameIpDiffMac {
        ip: IpAddr,
        macs: Vec<MacAddress>,
        sources: Vec<String>,
    },
    SameMacDiffSubnet {
        mac: MacAddress,
        subnets: Vec<String>,
        sources: Vec<String>,
    },
    SegmentParamsDiff {
        segment: String,
        field: String,
        values: Vec<String>,
        sources: Vec<String>,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct TopologyReport {
    pub conflicts: Vec<Conflict>,
    pub new_nodes: usize,
    pub updated_nodes: usize,
    pub merged_segments: usize,
}

/// The merged topology. Build once with `empty()`, then `observe()` over
/// time; serialization is the on-disk cache format.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Topology {
    pub nodes: BTreeMap<String, TopoNode>,
    pub segments: BTreeMap<String, Segment>,
    pub leases: Vec<LeaseRecord>,
    pub conflicts: Vec<Conflict>,
    pub updated_from: Vec<Origin>,
}

fn origin_key(o: &Origin) -> String {
    match &o.site {
        Some(site) => format!("{site}/{}:{}", o.device, o.source),
        None => format!("{}:{}", o.device, o.source),
    }
}

fn node_key(mac: Option<MacAddress>, ip: IpAddr, site: Option<&str>) -> String {
    match mac {
        Some(m) => m.to_string(),
        None => match site {
            Some(site) => format!("site:{site}:ip:{ip}"),
            None => format!("ip:{ip}"),
        },
    }
}

impl Topology {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn observe_all(&mut self, obs: impl IntoIterator<Item = Observation>) -> TopologyReport {
        let mut report = TopologyReport::default();
        for o in obs {
            self.observe_one(o, &mut report);
        }
        for c in std::mem::take(&mut report.conflicts) {
            if !self.conflicts.contains(&c) {
                self.conflicts.push(c.clone());
                report.conflicts.push(c);
            }
        }
        report
    }

    fn observe_one(&mut self, obs: Observation, report: &mut TopologyReport) {
        let obs_origin = observation_origin(&obs);
        match obs {
            Observation::Neighbor {
                mac,
                ip,
                hostname,
                port,
                origin,
            } => {
                let key = node_key(mac, ip, origin.site.as_deref());
                let node = self.nodes.entry(key.clone()).or_insert_with(|| {
                    report.new_nodes += 1;
                    TopoNode {
                        id: key,
                        mac,
                        ips: BTreeMap::new(),
                        hostnames: BTreeSet::new(),
                        device: false,
                        ports: BTreeMap::new(),
                        origins: BTreeSet::new(),
                        sites: BTreeSet::new(),
                        services: BTreeMap::new(),
                    }
                });
                if let Some(site) = &origin.site {
                    node.sites.insert(site.clone());
                }
                let k = origin_key(&origin);
                node.origins.insert(k);
                if let Some(h) = hostname.filter(|h| !h.is_empty() && h != "Unknown") {
                    node.hostnames.insert(h.to_lowercase());
                }
                match node.ips.get_mut(&ip) {
                    None => {
                        node.ips.insert(
                            ip,
                            IpRecord {
                                addr: ip,
                                prefix: None,
                                vlan: None,
                                origins: BTreeSet::from_iter([origin_key(&origin)]),
                            },
                        );
                    }
                    Some(rec) => {
                        rec.origins.insert(origin_key(&origin));
                    }
                }
                if let Some(port) = port {
                    let entry = node.ports.entry(port.port.clone()).or_insert_with(|| Link {
                        a: PortRef {
                            device: node.id.clone(),
                            port: port.port.clone(),
                            vif: None,
                        },
                        b: None,
                        state: LinkState::Unknown,
                        origins: BTreeSet::new(),
                    });
                    entry.origins.insert(origin_key(&origin));
                    if let Some(v) = port.vif {
                        entry.a.vif = Some(v);
                    }
                }
                report.updated_nodes += 1;
                let snapshot = node.clone();
                self.check_ip_mac(&snapshot, ip, mac, &origin, report);
            }
            Observation::Attachment {
                mac,
                hostname,
                port,
                origin,
            } => {
                let key = mac.to_string();
                let node = self.nodes.entry(key.clone()).or_insert_with(|| {
                    report.new_nodes += 1;
                    TopoNode {
                        id: key,
                        mac: Some(mac),
                        ..TopoNode::default()
                    }
                });
                if let Some(site) = &origin.site {
                    node.sites.insert(site.clone());
                }
                if let Some(hostname) = hostname.filter(|name| !name.is_empty()) {
                    node.hostnames.insert(hostname.to_lowercase());
                }
                let origin = origin_key(&origin);
                node.origins.insert(origin.clone());
                node.ports.insert(
                    format!("{}/{}", port.device, port.port),
                    Link {
                        a: PortRef {
                            device: node.id.clone(),
                            port: "attachment".into(),
                            vif: None,
                        },
                        b: Some(port),
                        state: LinkState::Up,
                        origins: BTreeSet::from_iter([origin]),
                    },
                );
                report.updated_nodes += 1;
            }
            Observation::Service {
                device,
                mac,
                ip,
                service,
            } => {
                let key = mac.map(|value| value.to_string()).or_else(|| {
                    ip.and_then(|address| {
                        self.nodes
                            .iter()
                            .find(|(_, node)| node.ips.contains_key(&address))
                            .map(|(id, _)| id.clone())
                    })
                });
                let key = key.unwrap_or_else(|| device.clone());
                let node = self.nodes.entry(key.clone()).or_insert_with(|| TopoNode {
                    id: key,
                    mac,
                    device: mac.is_none() && ip.is_none(),
                    ..TopoNode::default()
                });
                if let Some(address) = ip {
                    node.ips.entry(address).or_insert_with(|| IpRecord {
                        addr: address,
                        prefix: None,
                        vlan: None,
                        origins: BTreeSet::from_iter([origin_key(&service.origin)]),
                    });
                }
                let service_key =
                    format!("{}:{}/{}", service.transport, service.port, service.name);
                node.origins.insert(origin_key(&service.origin));
                node.services.insert(service_key, service);
                report.updated_nodes += 1;
            }
            Observation::DevicePort {
                device,
                port,
                mac,
                ips,
                state,
                origin,
            } => {
                let node = self.device_node(&device, mac, &origin);
                let k = origin_key(&origin);
                node.origins.insert(k.clone());
                for ip in ips {
                    node.ips
                        .entry(ip)
                        .or_insert_with(|| IpRecord {
                            addr: ip,
                            prefix: None,
                            vlan: None,
                            origins: BTreeSet::new(),
                        })
                        .origins
                        .insert(k.clone());
                }
                let entry = node.ports.entry(port.clone()).or_insert_with(|| Link {
                    a: PortRef {
                        device: device.clone(),
                        port: port.clone(),
                        vif: None,
                    },
                    b: None,
                    state: LinkState::Unknown,
                    origins: BTreeSet::new(),
                });
                entry.state = merge_state(entry.state, state);
                entry.origins.insert(k);
                report.updated_nodes += 1;
            }
            Observation::VlanMember {
                device,
                vlan,
                members,
                origin,
            } => {
                let k = origin_key(&origin);
                let id = scoped_id(origin.site.as_deref(), &format!("vlan:{}", vlan.0));
                let seg = self.segments.entry(id.clone()).or_insert_with(|| {
                    report.merged_segments += 1;
                    Segment {
                        id,
                        kind: SegmentKind::Vlan,
                        vlan: Some(vlan),
                        subnet: None,
                        gw: None,
                        domain_name: None,
                        origins: BTreeSet::new(),
                    }
                });
                seg.origins.insert(k.clone());
                // attach membership onto each member device's ports
                for m in members {
                    let dev = self.device_node(&device, None, &origin);
                    dev.origins.insert(k.clone());
                    let _ = m; // v0: membership recorded on the segment only;
                               // port-level member edges are a v1 refinement.
                }
            }
            Observation::Segment { segment, origin } => {
                let k = origin_key(&origin);
                let mut segment = segment;
                segment.id = scoped_id(origin.site.as_deref(), &segment.id);
                if let Some(existing) = self.segments.get(&segment.id) {
                    let existing = existing.clone();
                    if let (Some(old), Some(new)) = (existing.gw, segment.gw) {
                        if old != new {
                            report.conflicts_push(Conflict::SegmentParamsDiff {
                                segment: segment.id.clone(),
                                field: "gateway".into(),
                                values: vec![old.to_string(), new.to_string()],
                                sources: existing
                                    .origins
                                    .iter()
                                    .chain(std::iter::once(&k))
                                    .cloned()
                                    .collect(),
                            });
                        }
                    }
                    if let (Some((a_ip, a_pfx)), Some((b_ip, b_pfx))) =
                        (existing.subnet, segment.subnet)
                    {
                        if a_ip != b_ip || a_pfx != b_pfx {
                            report.conflicts_push(Conflict::SegmentParamsDiff {
                                segment: segment.id.clone(),
                                field: "subnet".into(),
                                values: vec![format!("{a_ip}/{a_pfx}"), format!("{b_ip}/{b_pfx}")],
                                sources: existing
                                    .origins
                                    .iter()
                                    .chain(std::iter::once(&k))
                                    .cloned()
                                    .collect(),
                            });
                        }
                    }
                    if let (Some(a), Some(b)) = (&existing.domain_name, &segment.domain_name) {
                        if a != b {
                            report.conflicts_push(Conflict::SegmentParamsDiff {
                                segment: segment.id.clone(),
                                field: "domain".into(),
                                values: vec![a.clone(), b.clone()],
                                sources: existing
                                    .origins
                                    .iter()
                                    .chain(std::iter::once(&k))
                                    .cloned()
                                    .collect(),
                            });
                        }
                    }
                    let seg = self.segments.get_mut(&segment.id).expect("present");
                    seg.origins.insert(k);
                } else {
                    report.merged_segments += 1;
                    let mut segment = segment;
                    segment.origins.insert(k);
                    self.segments.insert(segment.id.clone(), segment);
                }
            }
            Observation::Lease { lease, origin } => {
                if !self.leases.iter().any(|l| {
                    l.ip == lease.ip
                        && l.mac == lease.mac
                        && l.pool == lease.pool
                        && l.origin.device == lease.origin.device
                }) {
                    let mut lease = lease;
                    lease.origin = origin;
                    self.leases.push(lease);
                }
            }
        }
        self.updated_from.push(obs_origin);
    }

    fn device_node(
        &mut self,
        device: &str,
        mac: Option<MacAddress>,
        _origin: &Origin,
    ) -> &mut TopoNode {
        let node = self
            .nodes
            .entry(device.to_owned())
            .or_insert_with(|| TopoNode {
                id: device.to_owned(),
                mac,
                ips: BTreeMap::new(),
                hostnames: BTreeSet::new(),
                device: true,
                ports: BTreeMap::new(),
                origins: BTreeSet::new(),
                sites: BTreeSet::new(),
                services: BTreeMap::new(),
            });
        node.device = true;
        if node.mac.is_none() {
            node.mac = mac;
        }
        if let Some(site) = &_origin.site {
            node.sites.insert(site.clone());
        }
        node
    }

    fn check_ip_mac(
        &self,
        node: &TopoNode,
        ip: IpAddr,
        mac: Option<MacAddress>,
        origin: &Origin,
        report: &mut TopologyReport,
    ) {
        if let Some(new_mac) = mac {
            // same ip claimed by a different mac elsewhere?
            for (other_id, other) in &self.nodes {
                if other_id == &node.id {
                    continue;
                }
                if let Some(site) = &origin.site {
                    if !other.sites.contains(site) {
                        continue;
                    }
                }
                if other.mac.is_some_and(|m| m != new_mac) && other.ips.contains_key(&ip) {
                    report.conflicts_push(Conflict::SameIpDiffMac {
                        ip,
                        macs: vec![other.mac.unwrap(), new_mac],
                        sources: other
                            .origins
                            .iter()
                            .cloned()
                            .chain(std::iter::once(origin_key(origin)))
                            .collect(),
                    });
                }
            }
        }
    }
}

fn observation_origin(o: &Observation) -> Origin {
    match o {
        Observation::Neighbor { origin, .. }
        | Observation::Attachment { origin, .. }
        | Observation::DevicePort { origin, .. }
        | Observation::VlanMember { origin, .. }
        | Observation::Segment { origin, .. }
        | Observation::Lease { origin, .. } => origin.clone(),
        Observation::Service { service, .. } => service.origin.clone(),
    }
}

fn merge_state(cur: LinkState, new: LinkState) -> LinkState {
    match (cur, new) {
        (LinkState::Unknown, s) | (s, LinkState::Unknown) => s,
        (LinkState::Down, LinkState::Up) | (LinkState::Up, LinkState::Down) => {
            // both are trusted reports; keep Up (freshest evidence wins once
            // timestamps are wired; v0 conservative = up)
            LinkState::Up
        }
        (s, _) => s,
    }
}

fn scoped_id(site: Option<&str>, id: &str) -> String {
    match site {
        Some(site) => format!("{site}/{id}"),
        None => id.to_owned(),
    }
}

impl TopologyReport {
    fn conflicts_push(&mut self, c: Conflict) {
        if !self.conflicts.contains(&c) {
            self.conflicts.push(c);
        }
    }
}

/// IPv4 CIDR utilities (v0 keeps IPv6 /n semantics to the segment record).
pub fn ipv4_in_cidr(ip: IpAddr, network: IpAddr, prefix: u8) -> bool {
    let (IpAddr::V4(ip), IpAddr::V4(net)) = (ip, network) else {
        return false;
    };
    if prefix > 32 {
        return false;
    }
    let mask: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    u32::from(ip) & mask == u32::from(net) & mask
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn mac_parse_and_display() {
        let m = MacAddress::parse("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(m.to_string(), "aa:bb:cc:dd:ee:ff");
        assert!(MacAddress::parse("aa:bb:cc").is_none());
    }

    #[test]
    fn cidr_membership() {
        assert!(ipv4_in_cidr(ip("10.0.5.7"), ip("10.0.5.0"), 24));
        assert!(!ipv4_in_cidr(ip("10.0.6.7"), ip("10.0.5.0"), 24));
        assert!(ipv4_in_cidr(ip("10.0.5.7"), ip("10.0.0.0"), 8));
    }

    #[test]
    fn same_mac_from_two_devices_merges_into_one_node() {
        let mut topo = Topology::empty();
        topo.observe_all([
            Observation::Neighbor {
                mac: MacAddress::parse("aa:bb:cc:dd:ee:01"),
                ip: ip("10.0.7.20"),
                hostname: Some("nas".into()),
                port: None,
                origin: Origin::new("er-1", "arp"),
            },
            Observation::Neighbor {
                mac: MacAddress::parse("aa:bb:cc:dd:ee:01"),
                ip: ip("10.0.7.20"),
                hostname: None,
                port: Some(PortRef {
                    device: "sw-1".into(),
                    port: "eth2".into(),
                    vif: None,
                }),
                origin: Origin::new("sw-1", "arp"),
            },
        ]);
        assert_eq!(topo.nodes.len(), 1);
        let nas = &topo.nodes["aa:bb:cc:dd:ee:01"];
        assert_eq!(nas.origins.len(), 2);
        assert!(nas.hostnames.contains("nas"));
    }

    #[test]
    fn ip_without_mac_keys_by_ip() {
        let mut topo = Topology::empty();
        topo.observe_all([Observation::Neighbor {
            mac: None,
            ip: ip("8.8.8.8"),
            hostname: None,
            port: None,
            origin: Origin::new("er-1", "arp"),
        }]);
        assert!(topo.nodes.contains_key("ip:8.8.8.8"));
    }

    #[test]
    fn segment_conflict_is_recorded_not_swallowed() {
        let mut topo = Topology::empty();
        let seg = |id: &str, gw: &str, dev: &str| Observation::Segment {
            segment: Segment {
                id: id.into(),
                kind: SegmentKind::Lan,
                vlan: None,
                subnet: Some((ip("10.0.7.0"), 24)),
                gw: Some(ip(gw)),
                domain_name: None,
                origins: BTreeSet::new(),
            },
            origin: Origin::new(dev, "dhcp-config"),
        };
        topo.observe_all([
            seg("10.0.7.0/24", "10.0.7.1", "er-1"),
            seg("10.0.7.0/24", "10.0.7.9", "er-2"),
        ]);
        assert!(matches!(
            topo.conflicts.as_slice(),
            [Conflict::SegmentParamsDiff { field, .. }] if field == "gateway"
        ));
    }

    #[test]
    fn overlapping_sites_do_not_collide() {
        let mut topo = Topology::empty();
        let neighbor = |site: &str, mac: &str| Observation::Neighbor {
            mac: MacAddress::parse(mac),
            ip: ip("192.168.1.1"),
            hostname: None,
            port: None,
            origin: Origin::new(site, "ip-neigh").at_site(site),
        };
        topo.observe_all([
            neighbor("pris", "02:00:00:00:00:01"),
            neighbor("titan", "02:00:00:00:00:02"),
        ]);
        assert!(topo.conflicts.is_empty());

        topo.observe_all([Observation::Neighbor {
            mac: MacAddress::parse("02:00:00:00:00:03"),
            ip: ip("192.168.1.1"),
            hostname: None,
            port: None,
            origin: Origin::new("pris-second", "ip-neigh").at_site("pris"),
        }]);
        assert!(matches!(
            topo.conflicts.as_slice(),
            [Conflict::SameIpDiffMac { .. }]
        ));
    }

    #[test]
    fn duplicate_leases_deduped() {
        let mut topo = Topology::empty();
        let lease = Observation::Lease {
            lease: LeaseRecord {
                ip: ip("10.0.7.50"),
                mac: MacAddress::parse("02:00:00:00:00:05").unwrap(),
                hostname: Some("lamp".into()),
                pool: Some("LAN".into()),
                origin: Origin::new("er-1", "dhcp-config"),
            },
            origin: Origin::new("er-1", "dhcp-config"),
        };
        topo.observe_all([lease.clone(), lease]);
        assert_eq!(topo.leases.len(), 1);
    }

    #[test]
    fn mac_only_attachment_preserves_parent_port() {
        let mut topo = Topology::empty();
        topo.observe_all([Observation::Attachment {
            mac: MacAddress::parse("02:00:00:00:00:05").unwrap(),
            hostname: Some("camera".into()),
            port: PortRef {
                device: "switch-1".into(),
                port: "g25".into(),
                vif: None,
            },
            origin: Origin::new("switch-1", "bridge-fdb"),
        }]);
        let node = &topo.nodes["02:00:00:00:00:05"];
        assert!(node.hostnames.contains("camera"));
        assert_eq!(node.ports["switch-1/g25"].b.as_ref().unwrap().port, "g25");
    }

    #[test]
    fn service_merges_into_node_by_ip() {
        let mut topo = Topology::empty();
        topo.observe_all([Observation::Neighbor {
            mac: MacAddress::parse("02:00:00:00:00:05"),
            ip: ip("10.0.7.20"),
            hostname: Some("nvr".into()),
            port: None,
            origin: Origin::new("router", "arp"),
        }]);
        topo.observe_all([Observation::Service {
            device: "observer".into(),
            mac: None,
            ip: Some(ip("10.0.7.20")),
            service: ServiceRecord {
                name: "frigate".into(),
                transport: "tcp".into(),
                port: 8971,
                product: Some("Frigate".into()),
                state: ServiceState::Up,
                observed_at: 1,
                origin: Origin::new("observer", "probe"),
            },
        }]);
        assert_eq!(topo.nodes.len(), 1);
        assert_eq!(topo.nodes["02:00:00:00:00:05"].services.len(), 1);
    }

    #[test]
    fn serde_round_trips() {
        let mut topo = Topology::empty();
        topo.observe_all([Observation::DevicePort {
            device: "er-1".into(),
            port: "eth0".into(),
            mac: MacAddress::parse("00:11:22:33:44:55"),
            ips: vec![Ipv4Addr::new(10, 0, 7, 1).into()],
            state: LinkState::Up,
            origin: Origin::new("er-1", "interfaces"),
        }]);
        let json = serde_json::to_string(&topo).unwrap();
        let back: Topology = serde_json::from_str(&json).unwrap();
        assert_eq!(topo, back);
    }
}
