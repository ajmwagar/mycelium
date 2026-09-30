use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::OnceLock;

use async_trait::async_trait;
use mycelium_core::{
    CapResult, CapSpec, Device, DeviceKind, DeviceMeta, ExecContext, Identity, IntoValue,
    MacAddress, MyceliumError, Observation, Origin, ParamType, Params, PortRef, Result, Value,
    ID_IDENTIFY, ID_SWITCH_OBSERVE,
};
use mycelium_network_types::{
    ObservationCoverage, PortId, VlanId as SemanticVlanId, VlanMembership, VlanTagging,
};

use crate::client::SnmpHandle;

pub const DEFAULT_SNMP_PORT: u16 = 161;

// system
const SYS_DESCR: &str = "1.3.6.1.2.1.1.1.0";
const SYS_OBJECTID: &str = "1.3.6.1.2.1.1.2.0";
const SYS_UPTIME: &str = "1.3.6.1.2.1.1.3.0";
const SYS_NAME: &str = "1.3.6.1.2.1.1.5.0";
// interfaces
const IF_DESCR: &str = "1.3.6.1.2.1.2.2.1.2";
const IF_PHYS: &str = "1.3.6.1.2.1.2.2.1.6";
const IF_OPER: &str = "1.3.6.1.2.1.2.2.1.8";
// arp
const ARP_IFIDX: &str = "1.3.6.1.2.1.4.22.2.1.1";
const ARP_IP: &str = "1.3.6.1.2.1.4.22.2.1.2";
const ARP_MAC: &str = "1.3.6.1.2.1.4.22.2.1.4";
// BRIDGE-MIB: learned MAC -> bridge port, then bridge port -> ifIndex.
const BRIDGE_PORT_IFINDEX: &str = "1.3.6.1.2.1.17.1.4.1.2";
const FDB_PORT: &str = "1.3.6.1.2.1.17.4.3.1.2";
const Q_FDB_PORT: &str = "1.3.6.1.2.1.17.7.1.2.2.1.2";
// Q-BRIDGE-MIB: VLAN names and per-bridge-port default VLAN IDs.
const Q_VLAN_STATIC_NAME: &str = "1.3.6.1.2.1.17.7.1.4.3.1.1";
const Q_VLAN_STATIC_EGRESS: &str = "1.3.6.1.2.1.17.7.1.4.3.1.2";
const Q_VLAN_STATIC_UNTAGGED: &str = "1.3.6.1.2.1.17.7.1.4.3.1.4";
const Q_PVID: &str = "1.3.6.1.2.1.17.7.1.4.5.1.1";

pub const ID_SNMP_GET: &str = "snmp.get";
pub const ID_SNMP_WALK: &str = "snmp.walk";
pub const ID_SNMP_SET: &str = "snmp.set";
pub const ID_NET_IFACES: &str = "net.ifaces";
pub const ID_NET_ARP: &str = "net.arp";

pub fn caps() -> &'static BTreeMap<String, CapSpec> {
    static CAPS: OnceLock<BTreeMap<String, CapSpec>> = OnceLock::new();
    CAPS.get_or_init(|| {
        BTreeMap::from_iter([
            (
                ID_IDENTIFY.to_owned(),
                CapSpec::readonly("sysDescr/sysName/sysObjectID/sysUpTime")
                    .returns("map {vendor, model, firmware, hostname, uptime}"),
            ),
            (
                ID_NET_IFACES.to_owned(),
                CapSpec::readonly("interfaces from ifTable: descr, mac, oper status")
                    .returns("list of {index, descr, mac, up}"),
            ),
            (
                ID_NET_ARP.to_owned(),
                CapSpec::readonly("arp/ipNetToMedia table").returns("list of {ip, mac, iface}"),
            ),
            (
                ID_SWITCH_OBSERVE.to_owned(),
                CapSpec::readonly("partial switch state from standard Q-BRIDGE-MIB")
                    .returns("versioned map with explicit coverage, VLANs, and interface PVIDs"),
            ),
            (
                ID_SNMP_GET.to_owned(),
                CapSpec::readonly("raw SNMP GET of one dotted oid").param(
                    "oid",
                    ParamType::Str,
                    "dotted oid, e.g. 1.3.6.1.2.1.1.1.0",
                ),
            ),
            (
                ID_SNMP_WALK.to_owned(),
                CapSpec::readonly("raw SNMP WALK of a subtree")
                    .param(
                        "oid",
                        ParamType::Str,
                        "subtree root, e.g. 1.3.6.1.2.1.2.2.1.2",
                    )
                    .optional("limit", ParamType::Int, "max rows (default 4096)"),
            ),
            (
                ID_SNMP_SET.to_owned(),
                CapSpec::mutation("raw SNMP SET (requires write community)")
                    .param("oid", ParamType::Str, "dotted oid")
                    .param("value", ParamType::Str, "string, int, or hex:<bytes>"),
            ),
        ])
    })
}

pub struct SnmpDevice {
    handle: SnmpHandle,
    meta: DeviceMeta,
}

impl SnmpDevice {
    pub fn new(handle: SnmpHandle, meta: DeviceMeta) -> Self {
        Self { handle, meta }
    }

    pub async fn probe(handle: &SnmpHandle) -> Result<SnmpInfo> {
        let rows = handle
            .get(&[
                SYS_DESCR.into(),
                SYS_OBJECTID.into(),
                SYS_UPTIME.into(),
                SYS_NAME.into(),
            ])
            .await?;
        let mut info = SnmpInfo::default();
        for (oid, v) in rows {
            match oid.as_str() {
                SYS_DESCR => info.sys_descr = v.as_str().unwrap_or_default().to_owned(),
                SYS_OBJECTID => info.sys_objectid = v.as_str().unwrap_or_default().to_owned(),
                SYS_UPTIME => info.uptime = v.as_i64().unwrap_or(0),
                SYS_NAME => info.sys_name = v.as_str().unwrap_or_default().to_owned(),
                _ => {}
            }
        }
        Ok(info)
    }

    fn ifaces_map(
        &self,
        rows: Vec<(String, Value)>,
    ) -> BTreeMap<u32, (String, Option<String>, Option<u32>)> {
        // index -> (descr, mac, oper)
        let mut out: BTreeMap<u32, (String, Option<String>, Option<u32>)> = BTreeMap::new();
        for (oid, v) in rows {
            let idx = row_index(&oid);
            let slot = out
                .entry(idx)
                .or_insert_with(|| (String::new(), None, None));
            if oid.starts_with(IF_DESCR) {
                slot.0 = v.as_str().unwrap_or_default().to_owned();
            } else if oid.starts_with(IF_PHYS) {
                slot.1 = v.as_str().map(str::to_owned).filter(|s| !s.is_empty());
            } else if oid.starts_with(IF_OPER) {
                slot.2 = v.as_i64().map(|i| i as u32);
            }
        }
        out
    }

    async fn iface_rows(&self) -> Result<BTreeMap<u32, (String, Option<String>, Option<u32>)>> {
        let mut rows = Vec::new();
        for root in [IF_DESCR, IF_PHYS, IF_OPER] {
            rows.extend(self.handle.walk(root, 4096).await?);
        }
        let map = self.ifaces_map(rows);
        Ok(map)
    }

    async fn ifaces(&self) -> Result<Value> {
        let map = self.iface_rows().await?;
        let list: Vec<Value> = map
            .into_values()
            .filter(|(d, _, _)| !d.is_empty())
            .map(|(descr, mac, oper)| {
                Value::Map(Params::from_iter([
                    ("descr".into(), Value::Str(descr)),
                    ("mac".into(), mac.map(Value::Str).unwrap_or(Value::Null)),
                    ("up".into(), Value::Bool(oper == Some(1))),
                ]))
            })
            .collect();
        Ok(Value::List(list))
    }

    async fn arp(&self) -> Result<Vec<ArpRow>> {
        let mut rows = Vec::new();
        for root in [ARP_IFIDX, ARP_IP, ARP_MAC] {
            rows.extend(self.handle.walk(root, 4096).await?);
        }
        let mut out: BTreeMap<u32, ArpRow> = BTreeMap::new();
        for (oid, v) in rows {
            // ipNetToMedia rows embed the IPv4 address as 4 arcs: the row key
            // is their fold; `<col>` is the arc right before them.
            let (col, rowkey) = split_column(&oid);
            let e = out.entry(rowkey).or_default();
            match col {
                1 => e.ifindex = v.as_i64().map(|i| i as u32),
                2 => e.ip = v.as_str().and_then(|s| s.parse().ok()),
                4 => {
                    if let Some(s) = v.as_str() {
                        e.mac = MacAddress::parse(s);
                    }
                }
                _ => {}
            }
        }
        Ok(out
            .into_values()
            .filter(|r| r.ip.is_some() && r.mac.is_some() && r.ifindex.is_some())
            .collect())
    }

    async fn forwarding_table(&self) -> Result<Vec<(MacAddress, u32, Option<u16>)>> {
        let bridge_ports = self.handle.walk(BRIDGE_PORT_IFINDEX, 4096).await?;
        let port_to_ifindex = bridge_ports
            .into_iter()
            .filter_map(|(oid, value)| Some((row_index(&oid), value.as_i64()? as u32)))
            .collect::<HashMap<_, _>>();
        let mut rows = self
            .handle
            .walk(FDB_PORT, 16384)
            .await?
            .into_iter()
            .filter_map(|(oid, value)| {
                let bridge_port = value.as_i64()? as u32;
                let ifindex = *port_to_ifindex.get(&bridge_port)?;
                Some((mac_from_oid_index(&oid)?, ifindex, None))
            })
            .collect::<Vec<_>>();
        rows.extend(
            self.handle
                .walk(Q_FDB_PORT, 16384)
                .await?
                .into_iter()
                .filter_map(|(oid, value)| {
                    let bridge_port = value.as_i64()? as u32;
                    let ifindex = *port_to_ifindex.get(&bridge_port)?;
                    Some((
                        mac_from_oid_index(&oid)?,
                        ifindex,
                        vlan_from_q_fdb_oid(&oid),
                    ))
                }),
        );
        rows.sort_unstable_by_key(|(mac, ifindex, vlan)| (*mac, *ifindex, *vlan));
        rows.dedup();
        Ok(rows)
    }

    async fn switch_state(&self) -> Result<Value> {
        let (info, vlan_rows, pvid_rows, bridge_rows, egress_rows, untagged_rows, ifaces) = tokio::try_join!(
            Self::probe(&self.handle),
            self.handle.walk(Q_VLAN_STATIC_NAME, 4096),
            self.handle.walk(Q_PVID, 4096),
            self.handle.walk(BRIDGE_PORT_IFINDEX, 4096),
            self.handle.walk(Q_VLAN_STATIC_EGRESS, 4096),
            self.handle.walk(Q_VLAN_STATIC_UNTAGGED, 4096),
            self.iface_rows(),
        )?;
        Ok(switch_state_value(
            self.meta.model.clone(),
            &info,
            vlan_rows,
            pvid_rows,
            bridge_rows,
            egress_rows,
            untagged_rows,
            &ifaces,
        ))
    }

    fn ifindex_names(
        &self,
        map: &BTreeMap<u32, (String, Option<String>, Option<u32>)>,
    ) -> HashMap<u32, String> {
        map.iter()
            .filter(|(_, (d, ..))| !d.is_empty())
            .map(|(idx, (d, ..))| (*idx, d.clone()))
            .collect()
    }
}

#[derive(Default, Clone, Copy)]
pub struct ArpRow {
    pub ip: Option<IpAddr>,
    pub mac: Option<MacAddress>,
    pub ifindex: Option<u32>,
}

#[derive(Default, Clone, Debug)]
pub struct SnmpInfo {
    pub sys_descr: String,
    pub sys_objectid: String,
    pub sys_name: String,
    pub uptime: i64,
}

fn row_index(oid: &str) -> u32 {
    oid.rsplit('.')
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn mac_from_oid_index(oid: &str) -> Option<MacAddress> {
    let arcs = oid
        .split('.')
        .rev()
        .take(6)
        .map(|arc| arc.parse::<u8>().ok())
        .collect::<Option<Vec<_>>>()?;
    Some(MacAddress([
        arcs[5], arcs[4], arcs[3], arcs[2], arcs[1], arcs[0],
    ]))
}

fn vlan_from_q_fdb_oid(oid: &str) -> Option<u16> {
    oid.split('.').rev().nth(6)?.parse().ok()
}

/// `<prefix>.<col>.<rowkey>` — rowkey is the last arc for ifTable, the
/// ip part for ipNetToMedia (where the index is ifaddr + entry).
fn split_column(oid: &str) -> (u32, u32) {
    let arcs: Vec<&str> = oid.split('.').collect();
    if arcs.len() < 2 {
        return (0, 0);
    }
    let col: u32 = arcs[arcs.len() - 2].parse().unwrap_or(0);
    // ipNetToMedia row key embeds the IPv4 address as 4 arcs before entry id
    if arcs.len() >= 13 {
        let ip_arc_start = arcs.len() - 5;
        let key = arcs[ip_arc_start..ip_arc_start + 4]
            .iter()
            .map(|a| a.parse::<u32>().unwrap_or(0))
            .fold(0u32, |acc, a| (acc << 8) | (a & 0xff));
        (col, key)
    } else {
        (col, arcs[arcs.len() - 1].parse().unwrap_or(0))
    }
}

fn switch_state_value(
    model: Option<String>,
    info: &SnmpInfo,
    vlan_rows: Vec<(String, Value)>,
    pvid_rows: Vec<(String, Value)>,
    bridge_rows: Vec<(String, Value)>,
    egress_rows: Vec<(String, Value)>,
    untagged_rows: Vec<(String, Value)>,
    ifaces: &BTreeMap<u32, (String, Option<String>, Option<u32>)>,
) -> Value {
    let vlan_inventory_covered = !vlan_rows.is_empty();
    let pvid_row_count = pvid_rows.len();
    let vlans = vlan_rows
        .into_iter()
        .filter_map(|(oid, value)| {
            let id = SemanticVlanId::new(u16::try_from(row_index(&oid)).ok()?)?;
            Some((
                id.get().to_string(),
                Value::Map(Params::from_iter([
                    ("id".into(), Value::Int(id.get() as i64)),
                    (
                        "name".into(),
                        value
                            .as_str()
                            .filter(|name| !name.is_empty())
                            .map(|name| Value::Str(name.to_owned()))
                            .unwrap_or(Value::Null),
                    ),
                ])),
            ))
        })
        .collect::<Params>();
    let bridge_to_ifindex = bridge_rows
        .into_iter()
        .filter_map(|(oid, value)| Some((row_index(&oid), value.as_i64()? as u32)))
        .collect::<HashMap<_, _>>();
    let mut interfaces = pvid_rows
        .into_iter()
        .filter_map(|(oid, value)| {
            let bridge_port = row_index(&oid);
            let ifindex = bridge_to_ifindex.get(&bridge_port)?;
            let name = fastpath_interface_name(&ifaces.get(ifindex)?.0);
            let pvid = value.as_i64()?;
            Some((
                name.clone(),
                Value::Map(Params::from_iter([
                    ("port_id".into(), Value::Int(*ifindex as i64)),
                    ("name".into(), Value::Str(name)),
                    ("pvid".into(), Value::Int(pvid)),
                ])),
            ))
        })
        .collect::<Params>();
    let interface_pvids_covered = pvid_row_count > 0 && interfaces.len() == pvid_row_count;
    let egress = vlan_port_sets(egress_rows);
    let untagged = vlan_port_sets(untagged_rows);
    let membership_covered = matches!((&egress, &untagged), (Some(egress), Some(untagged))
        if !egress.is_empty()
            && egress.keys().eq(untagged.keys())
            && egress.keys().all(|id| vlans.contains_key(&id.to_string())));
    if membership_covered {
        let egress = egress
            .as_ref()
            .expect("coverage proves decoded egress rows");
        let untagged = untagged
            .as_ref()
            .expect("coverage proves decoded untagged rows");
        for (vlan, ports) in egress {
            let untagged_ports = &untagged[vlan];
            for bridge_port in ports {
                let Some(ifindex) = bridge_to_ifindex.get(bridge_port) else {
                    continue;
                };
                let Some(name) = ifaces
                    .get(ifindex)
                    .map(|row| fastpath_interface_name(&row.0))
                else {
                    continue;
                };
                let Some(Value::Map(interface)) = interfaces.get_mut(&name) else {
                    continue;
                };
                let membership = VlanMembership {
                    port: PortId(*ifindex),
                    vlan: SemanticVlanId::new(*vlan).expect("Q-BRIDGE VLAN keys were validated"),
                    tagging: if untagged_ports.contains(bridge_port) {
                        VlanTagging::Untagged
                    } else {
                        VlanTagging::Tagged
                    },
                };
                push_int(interface, "included_vlans", membership.vlan.get() as i64);
                if membership.tagging == VlanTagging::Tagged {
                    push_int(interface, "tagged_vlans", membership.vlan.get() as i64);
                }
            }
        }
    }

    let mut coverage = ObservationCoverage::empty();
    for (present, capability) in [
        (vlan_inventory_covered, ObservationCoverage::VLAN_INVENTORY),
        (vlan_inventory_covered, ObservationCoverage::VLAN_NAMES),
        (interface_pvids_covered, ObservationCoverage::PORT_PVIDS),
        (membership_covered, ObservationCoverage::VLAN_MEMBERSHIP),
    ] {
        if present {
            coverage = coverage.with(capability);
        }
    }

    Value::Map(Params::from_iter([
        ("schema_version".into(), Value::Int(1)),
        ("coverage_bits".into(), Value::Int(coverage.bits() as i64)),
        (
            "model_family".into(),
            model
                .or_else(|| first_model_token(&info.sys_descr))
                .map(Value::Str)
                .unwrap_or(Value::Null),
        ),
        ("firmware_version".into(), Value::Null),
        (
            "coverage".into(),
            Value::Map(Params::from_iter([
                ("vlan_inventory".into(), Value::Bool(vlan_inventory_covered)),
                ("vlan_names".into(), Value::Bool(vlan_inventory_covered)),
                (
                    "interface_pvids".into(),
                    Value::Bool(interface_pvids_covered),
                ),
                (
                    "interface_membership".into(),
                    Value::Bool(membership_covered),
                ),
                ("management_vlan".into(), Value::Bool(false)),
                ("lag_membership".into(), Value::Bool(false)),
            ])),
        ),
        ("vlans".into(), Value::Map(vlans)),
        ("interfaces".into(), Value::Map(interfaces)),
    ]))
}

fn vlan_port_sets(rows: Vec<(String, Value)>) -> Option<BTreeMap<u16, Vec<u32>>> {
    let count = rows.len();
    let decoded = rows
        .into_iter()
        .filter_map(|(oid, value)| {
            let vlan = u16::try_from(row_index(&oid)).ok()?;
            Some((vlan, port_bitmap(value.as_str()?)?))
        })
        .collect::<BTreeMap<_, _>>();
    (count > 0 && decoded.len() == count).then_some(decoded)
}

fn port_bitmap(value: &str) -> Option<Vec<u32>> {
    let bytes = if let Some(hex) = value.strip_prefix("0x") {
        if hex.len() % 2 != 0 {
            return None;
        }
        (0..hex.len())
            .step_by(2)
            .map(|offset| u8::from_str_radix(&hex[offset..offset + 2], 16).ok())
            .collect::<Option<Vec<_>>>()?
    } else if value.len() == 17 && value.as_bytes().get(2) == Some(&b':') {
        value
            .split(':')
            .map(|octet| u8::from_str_radix(octet, 16).ok())
            .collect::<Option<Vec<_>>>()?
    } else {
        value.as_bytes().to_vec()
    };
    Some(
        bytes
            .into_iter()
            .enumerate()
            .flat_map(|(byte_index, byte)| {
                (0..8).filter_map(move |bit| {
                    (byte & (0x80 >> bit) != 0).then_some((byte_index * 8 + bit + 1) as u32)
                })
            })
            .collect(),
    )
}

fn push_int(map: &mut Params, key: &str, value: i64) {
    match map
        .entry(key.into())
        .or_insert_with(|| Value::List(Vec::new()))
    {
        Value::List(values) => values.push(Value::Int(value)),
        _ => unreachable!("switch observation owns this field"),
    }
}

fn fastpath_interface_name(description: &str) -> String {
    let trimmed = description.trim();
    if let Some(id) = trimmed.strip_prefix("Link Aggregate ") {
        return format!("lag {}", id.trim());
    }
    if let Some(rest) = trimmed.strip_prefix("unit ") {
        if let Some((unit, port_description)) = rest.split_once(" port ") {
            if let Some(port) = port_description
                .split_whitespace()
                .next()
                .and_then(|value| value.parse::<u16>().ok())
            {
                return if port <= 48 {
                    format!("{unit}/g{port}")
                } else {
                    format!("{unit}/xg{}", port - 48)
                };
            }
        }
    }
    trimmed.to_owned()
}

pub fn classify(info: &SnmpInfo, host: &str) -> (DeviceKind, String, Option<String>) {
    let d = info.sys_descr.to_lowercase();
    let ent = enterprise_number(&info.sys_objectid).unwrap_or("");
    let kind = match (d.as_str(), ent) {
        (s, _) if s.contains("edgerouter") || s.contains("edgeos") || s.contains("vyos") => {
            DeviceKind::Router
        }
        (s, _) if s.contains("uap") || s.contains("unifi") || s.contains("aircube") => {
            DeviceKind::AccessPoint
        }
        (s, "4526") | (s, "14823") | (s, "11")
            if s.contains("switch")
                || s.contains("gs")
                || s.contains("jgs")
                || s.contains("aruba")
                || s.contains("procurve") =>
        {
            DeviceKind::Switch
        }
        (_, "4526") => DeviceKind::Switch,
        (s, "41112") if !s.contains("edgerouter") => DeviceKind::AccessPoint,
        (s, _) if s.contains("procurve") || s.contains("aruba") || s.contains("hpe") => {
            DeviceKind::Switch
        }
        _ => DeviceKind::Other,
    };
    let model = first_model_token(&info.sys_descr).unwrap_or_else(|| "snmp-device".into());
    let host_part = host
        .replace(|c: char| !(c.is_ascii_alphanumeric()), "-")
        .trim_matches('-')
        .to_owned();
    (kind, format!("{model}-{host_part}"), Some(model))
}

fn first_model_token(descr: &str) -> Option<String> {
    descr
        .split_whitespace()
        .find(|t| {
            t.len() >= 3
                && t.chars()
                    .next()
                    .map(|c| c.is_ascii_alphabetic())
                    .unwrap_or(false)
                && t.chars().any(|c| c.is_ascii_digit())
        })
        .map(|t| {
            t.trim_end_matches(|c: char| !c.is_ascii_alphanumeric())
                .to_lowercase()
        })
}

#[async_trait]
impl Device for SnmpDevice {
    fn meta(&self) -> &DeviceMeta {
        &self.meta
    }

    fn capabilities(&self) -> BTreeMap<String, CapSpec> {
        caps().clone()
    }

    async fn exec(&self, ctx: &ExecContext, cap: &str, params: Params) -> Result<CapResult> {
        match cap {
            ID_IDENTIFY => {
                let info = SnmpDevice::probe(&self.handle).await?;
                Ok(CapResult::ok(Value::Map(Params::from_iter([
                    (
                        "vendor".into(),
                        enterprise_vendor(&info.sys_objectid).into_value(),
                    ),
                    (
                        "model".into(),
                        first_model_token(&info.sys_descr)
                            .unwrap_or_default()
                            .into_value(),
                    ),
                    ("firmware".into(), Value::Null),
                    (
                        "hostname".into(),
                        (!info.sys_name.is_empty())
                            .then_some(info.sys_name.clone())
                            .into_value(),
                    ),
                    ("sysDescr".into(), info.sys_descr.into_value()),
                    ("uptime_centisec".into(), Value::Int(info.uptime)),
                ]))))
            }
            ID_NET_IFACES => Ok(CapResult::ok(self.ifaces().await?)),
            ID_SWITCH_OBSERVE => Ok(CapResult::ok(self.switch_state().await?)),
            ID_NET_ARP => {
                let rows = self.arp().await?;
                let names = self.ifindex_names(&self.iface_rows().await?);
                Ok(CapResult::ok(Value::List(
                    rows.iter()
                        .map(|r| {
                            Value::Map(Params::from_iter([
                                ("ip".into(), r.ip.unwrap().to_string().into_value()),
                                ("mac".into(), r.mac.unwrap().to_string().into_value()),
                                ("ifindex".into(), Value::Int(r.ifindex.unwrap() as i64)),
                                (
                                    "iface".into(),
                                    names
                                        .get(&r.ifindex.unwrap())
                                        .cloned()
                                        .map(Value::Str)
                                        .unwrap_or(Value::Null),
                                ),
                            ]))
                        })
                        .collect(),
                )))
            }
            ID_SNMP_GET => {
                let oid = oid_param(&params)?;
                let rows = self.handle.get(&[oid.clone()]).await?;
                Ok(CapResult::ok(Value::List(
                    rows.into_iter()
                        .map(|(oid, value)| {
                            Value::Map(Params::from_iter([
                                ("oid".into(), Value::Str(oid)),
                                ("value".into(), value),
                            ]))
                        })
                        .collect(),
                )))
            }
            ID_SNMP_WALK => {
                let oid = oid_param(&params)?;
                let limit = params
                    .get("limit")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(4096)
                    .clamp(1, 65535) as usize;
                let rows = self.handle.walk(&oid, limit).await?;
                Ok(CapResult::ok(Value::List(
                    rows.into_iter()
                        .map(|(o, v)| {
                            Value::Map(Params::from_iter([
                                ("oid".into(), Value::Str(o)),
                                ("value".into(), v),
                            ]))
                        })
                        .collect(),
                )))
            }
            ID_SNMP_SET => {
                let oid = oid_param(&params)?;
                let raw = params
                    .get("value")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| MyceliumError::Validation("param `value` missing".into()))?;
                let value = match raw {
                    "true" => Value::Int(1),
                    "false" => Value::Int(2),
                    _ => raw
                        .parse::<i64>()
                        .map(Value::Int)
                        .unwrap_or_else(|_| Value::Str(raw.to_owned())),
                };
                if ctx.dry_run {
                    return Ok(CapResult::dry_run(Value::Map(Params::from_iter([
                        ("oid".into(), Value::Str(oid)),
                        ("value".into(), value),
                    ]))));
                }
                let (o, v) = self.handle.set(&oid, value).await?;
                Ok(CapResult::ok(Value::Map(Params::from_iter([
                    ("oid".into(), Value::Str(o)),
                    ("echo".into(), v),
                ]))))
            }
            other => Err(MyceliumError::Unsupported {
                device: self.meta.id.to_string(),
                capability: other.to_owned(),
            }),
        }
    }

    /// ARP + interfaces from the appliance itself: this is how a managed
    /// switch makes the topology map even when nobody has SSH on it.
    async fn observe(&self) -> Result<(Vec<Observation>, Vec<String>)> {
        let mut obs = Vec::new();
        let mut warnings = Vec::new();
        let me = self.meta.id.to_string();

        match self.ifaces().await {
            Ok(Value::List(rows)) => {
                for r in rows {
                    let descr = r
                        .get("descr")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned();
                    let mac = r
                        .get("mac")
                        .and_then(|v| v.as_str())
                        .and_then(MacAddress::parse);
                    let up = r.get("up").and_then(|v| v.as_bool()).unwrap_or(false);
                    obs.push(Observation::DevicePort {
                        device: me.clone(),
                        port: descr,
                        mac,
                        ips: Vec::new(),
                        state: if up {
                            mycelium_core::LinkState::Up
                        } else {
                            mycelium_core::LinkState::Down
                        },
                        medium: None,
                        speed_mbps: None,
                        duplex: None,
                        origin: Origin::new(me.clone(), "snmp-ifTable"),
                    });
                }
            }
            Ok(_) => {}
            Err(e) => warnings.push(format!("ifTable: {e}")),
        }

        match self.arp().await {
            Ok(rows) => {
                for r in rows {
                    obs.push(Observation::Neighbor {
                        mac: r.mac,
                        ip: r.ip.unwrap(),
                        hostname: None,
                        port: Some(PortRef {
                            device: me.clone(),
                            port: format!("if{}", r.ifindex.unwrap()),
                            vif: None,
                        }),
                        origin: Origin::new(me.clone(), "snmp-arp"),
                    });
                }
            }
            Err(e) => warnings.push(format!("ipNetToMedia: {e}")),
        }

        match (self.forwarding_table().await, self.iface_rows().await) {
            (Ok(rows), Ok(ifaces)) => {
                let names = self.ifindex_names(&ifaces);
                for (mac, ifindex, vlan) in rows {
                    obs.push(Observation::Attachment {
                        mac,
                        hostname: None,
                        port: PortRef {
                            device: me.clone(),
                            port: names
                                .get(&ifindex)
                                .cloned()
                                .unwrap_or_else(|| format!("if{ifindex}")),
                            vif: vlan.map(mycelium_core::VlanId),
                        },
                        origin: Origin::new(me.clone(), "snmp-bridge-fdb"),
                    });
                }
            }
            (Err(e), _) => warnings.push(format!("bridge FDB: {e}")),
            (_, Err(e)) => warnings.push(format!("ifTable for bridge FDB: {e}")),
        }

        Ok((obs, warnings))
    }
}

#[cfg(test)]
mod fdb_tests {
    use super::*;

    #[test]
    fn parses_bridge_mib_mac_index() {
        let oid = "1.3.6.1.2.1.17.7.1.2.2.1.2.30.160.96.50.5.0.202";
        let mac = mac_from_oid_index(oid).unwrap();
        assert_eq!(mac.to_string(), "a0:60:32:05:00:ca");
        assert_eq!(vlan_from_q_fdb_oid(oid), Some(30));
    }
}

#[async_trait]
impl Identity for SnmpDevice {}

fn oid_param(params: &Params) -> Result<String> {
    let oid = params
        .get("oid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MyceliumError::Validation("param `oid` required".into()))?
        .to_owned();
    if oid.split('.').all(|a| a.parse::<u32>().is_ok()) && oid.starts_with("1.") {
        Ok(oid)
    } else {
        Err(MyceliumError::Validation(format!(
            "not a dotted numeric oid: {oid}"
        )))
    }
}

fn enterprise_vendor(objectid: &str) -> String {
    match enterprise_number(objectid) {
        Some("4526") => "NETGEAR".into(),
        Some("41112") | Some("8072") | Some("28577") => "Ubiquiti".into(),
        Some("11") => "HPE".into(),
        Some("14823") => "Aruba".into(),
        Some("2271") => "Ubiquiti".into(),
        Some(e) => format!("enterprise:{e}"),
        None => "generic".into(),
    }
}

fn enterprise_number(objectid: &str) -> Option<&str> {
    objectid.strip_prefix("1.3.6.1.4.1.")?.split('.').next()
}

/// Public form used when constructing metadata before a device is attached.
pub(crate) fn enterprise_vendor_public(objectid: &str) -> String {
    enterprise_vendor(objectid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_device() -> SnmpDevice {
        SnmpDevice::new(
            SnmpHandle::new("192.0.2.1", DEFAULT_SNMP_PORT, "public"),
            DeviceMeta {
                id: mycelium_core::DeviceId::new("test-switch"),
                kind: DeviceKind::Switch,
                driver: "snmp".into(),
                vendor: Some("NETGEAR".into()),
                model: None,
                firmware: None,
                address: "192.0.2.1:161".into(),
            },
        )
    }

    fn info(descr: &str, objectid: &str) -> SnmpInfo {
        SnmpInfo {
            sys_descr: descr.into(),
            sys_objectid: objectid.into(),
            ..SnmpInfo::default()
        }
    }

    #[test]
    fn classifies_netgear_switch_from_enterprise_oid() {
        let (kind, id, model) = classify(
            &info(
                "NETGEAR GS724Tv4 ProSafe 24-port switch",
                "1.3.6.1.4.1.4526.100.4.6",
            ),
            "192.0.2.10",
        );
        assert_eq!(kind, DeviceKind::Switch);
        assert_eq!(id, "gs724tv4-192-0-2-10");
        assert_eq!(model.as_deref(), Some("gs724tv4"));
        assert_eq!(enterprise_vendor("1.3.6.1.4.1.4526.100.4.6"), "NETGEAR");
    }

    #[test]
    fn classifies_edge_router_before_ubiquiti_enterprise_fallback() {
        let (kind, _, _) = classify(&info("EdgeRouter 6P", "1.3.6.1.4.1.41112.1.5"), "192.0.2.1");
        assert_eq!(kind, DeviceKind::Router);
    }

    #[tokio::test]
    async fn snmp_set_dry_run_never_needs_a_write_community_or_network() {
        let device = test_device();
        let context = ExecContext {
            capability: ID_SNMP_SET.into(),
            allow_writes: false,
            dry_run: true,
        };
        let result = device
            .invoke(
                &context,
                ID_SNMP_SET,
                Params::from_iter([
                    ("oid".into(), Value::Str("1.3.6.1.2.1.1.5.0".into())),
                    ("value".into(), Value::Str("42".into())),
                ]),
            )
            .await
            .unwrap();

        assert!(result.dry_run);
        assert_eq!(
            result.output,
            Value::Map(Params::from_iter([
                ("oid".into(), Value::Str("1.3.6.1.2.1.1.5.0".into())),
                ("value".into(), Value::Int(42)),
            ]))
        );
    }

    #[test]
    fn standard_mibs_form_a_versioned_partial_switch_snapshot() {
        let info = SnmpInfo {
            sys_descr: "NETGEAR GS728TS 6.0.1.29".into(),
            ..SnmpInfo::default()
        };
        let ifaces = BTreeMap::from_iter([(
            7,
            (
                "unit 1 port 7 Gigabit - Level".into(),
                Some("00:11:22:33:44:55".into()),
                Some(1),
            ),
        )]);
        let value = switch_state_value(
            Some("GS728TS".into()),
            &info,
            vec![(
                format!("{Q_VLAN_STATIC_NAME}.20"),
                Value::Str("CAMERAS".into()),
            )],
            vec![(format!("{Q_PVID}.3"), Value::Int(20))],
            vec![(format!("{BRIDGE_PORT_IFINDEX}.3"), Value::Int(7))],
            vec![(
                format!("{Q_VLAN_STATIC_EGRESS}.20"),
                Value::Str("0x20".into()),
            )],
            vec![(
                format!("{Q_VLAN_STATIC_UNTAGGED}.20"),
                Value::Str("0x20".into()),
            )],
            &ifaces,
        );

        assert_eq!(value.get("schema_version"), Some(&Value::Int(1)));
        assert_eq!(
            value
                .get("coverage")
                .and_then(|coverage| coverage.get("interface_pvids")),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            value
                .get("interfaces")
                .and_then(|interfaces| interfaces.get("1/g7"))
                .and_then(|interface| interface.get("pvid")),
            Some(&Value::Int(20))
        );
        assert_eq!(
            value
                .get("interfaces")
                .and_then(|interfaces| interfaces.get("1/g7"))
                .and_then(|interface| interface.get("included_vlans")),
            Some(&Value::List(vec![Value::Int(20)]))
        );
    }

    #[test]
    fn q_bridge_port_bitmaps_are_most_significant_bit_first() {
        assert_eq!(port_bitmap("0x8101"), Some(vec![1, 8, 16]));
        assert_eq!(port_bitmap("80:00:00:00:00:01"), Some(vec![1, 48]));
    }

    #[test]
    fn netgear_if_mib_descriptions_match_fastpath_interface_names() {
        assert_eq!(
            fastpath_interface_name("unit 1 port 7 Gigabit - Level"),
            "1/g7"
        );
        assert_eq!(
            fastpath_interface_name("unit 1 port 49 Gigabit - Level"),
            "1/xg1"
        );
        assert_eq!(fastpath_interface_name(" Link Aggregate 3"), "lag 3");
    }
}
