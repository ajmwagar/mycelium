#![no_std]
#![forbid(unsafe_code)]

//! Allocation-free network semantics shared across host drivers and firmware.
//!
//! These types describe facts and intent, never a transport. Human labels,
//! maps, JSON, vendor commands, and reconciliation policy belong above this
//! crate. All wire-visible enums have explicit representations.

use core::fmt;

/// Canonical link-layer identity shared by host, boot, and firmware contracts.
///
/// Its serde representation is the conventional lowercase colon-delimited
/// string rather than an implementation-specific byte array.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    pub fn parse(value: &str) -> Option<Self> {
        let mut octets = [0_u8; 6];
        let mut parts = value.split([':', '-']);
        for octet in &mut octets {
            *octet = u8::from_str_radix(parts.next()?, 16).ok()?;
        }
        if parts.next().is_some() {
            return None;
        }
        Some(Self(octets))
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, f] = self.0;
        write!(formatter, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}")
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for MacAddress {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for MacAddress {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MacVisitor;

        impl serde::de::Visitor<'_> for MacVisitor {
            type Value = MacAddress;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a six-octet colon- or hyphen-delimited MAC address")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                MacAddress::parse(value).ok_or_else(|| E::custom(format_args!("bad mac `{value}`")))
            }
        }

        deserializer.deserialize_str(MacVisitor)
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VlanId(u16);

impl VlanId {
    pub const MIN: u16 = 1;
    pub const MAX: u16 = 4094;
    pub const DEFAULT: Self = Self(1);

    pub const fn new(value: u16) -> Option<Self> {
        if value >= Self::MIN && value <= Self::MAX {
            Some(Self(value))
        } else {
            None
        }
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PortId(pub u32);

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum PortKind {
    Physical = 1,
    Aggregate = 2,
    Virtual = 3,
    Management = 4,
    Unknown = 255,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum LinkState {
    Unknown = 0,
    Down = 1,
    Up = 2,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum LinkMedium {
    Ethernet = 1,
    Wifi = 2,
    Fiber = 3,
    Virtual = 4,
    Loopback = 5,
    Cellular = 6,
    Unknown = 255,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum LinkDuplex {
    Half = 1,
    Full = 2,
    Unknown = 255,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum VlanTagging {
    Untagged = 1,
    Tagged = 2,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PortState {
    pub id: PortId,
    pub kind: PortKind,
    pub link: LinkState,
    /// Zero means the source did not observe a PVID.
    pub pvid: u16,
}

impl PortState {
    pub const fn observed_pvid(self) -> Option<VlanId> {
        VlanId::new(self.pvid)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VlanMembership {
    pub port: PortId,
    pub vlan: VlanId,
    pub tagging: VlanTagging,
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ObservationCoverage(u32);

impl ObservationCoverage {
    pub const VLAN_INVENTORY: u32 = 1 << 0;
    pub const VLAN_NAMES: u32 = 1 << 1;
    pub const PORT_PVIDS: u32 = 1 << 2;
    pub const VLAN_MEMBERSHIP: u32 = 1 << 3;
    pub const MANAGEMENT_VLAN: u32 = 1 << 4;
    pub const LAG_MEMBERSHIP: u32 = 1 << 5;
    pub const IP_ASSIGNMENTS: u32 = 1 << 6;
    pub const FORWARDING_RULES: u32 = 1 << 7;

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn contains(self, capability: u32) -> bool {
        self.0 & capability == capability
    }

    pub const fn with(self, capability: u32) -> Self {
        Self(self.0 | capability)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Ipv4Prefix {
    pub address: [u8; 4],
    pub prefix_length: u8,
}

impl Ipv4Prefix {
    pub const fn new(address: [u8; 4], prefix_length: u8) -> Option<Self> {
        if prefix_length <= 32 {
            Some(Self {
                address,
                prefix_length,
            })
        } else {
            None
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum TransportProtocol {
    Tcp = 6,
    Udp = 17,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PortForward {
    pub protocol: TransportProtocol,
    pub listen_address: [u8; 4],
    pub listen_port: u16,
    pub target_address: [u8; 4],
    pub target_port: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vlan_ids_reject_reserved_values() {
        assert_eq!(VlanId::new(0), None);
        assert_eq!(VlanId::new(1).map(VlanId::get), Some(1));
        assert_eq!(VlanId::new(4094).map(VlanId::get), Some(4094));
        assert_eq!(VlanId::new(4095), None);
    }

    #[test]
    fn coverage_is_composable_without_dynamic_collections() {
        let coverage = ObservationCoverage::empty()
            .with(ObservationCoverage::VLAN_INVENTORY)
            .with(ObservationCoverage::PORT_PVIDS);
        assert!(coverage.contains(ObservationCoverage::VLAN_INVENTORY));
        assert!(!coverage.contains(ObservationCoverage::FORWARDING_RULES));
    }

    #[test]
    fn host_network_primitives_are_bounded() {
        assert!(Ipv4Prefix::new([192, 0, 2, 10], 24).is_some());
        assert!(Ipv4Prefix::new([192, 0, 2, 10], 33).is_none());
    }
}
