//! Core abstractions for mycelium: a management layer over heterogeneous
//! network appliances (routers, switches, APs, IPMI/BMC, DNS filters...).
//!
//! The seam is deliberately narrow:
//! - [`driver::Driver`] discovers and opens a class of appliances.
//! - [`device::Device`] is a live, self-describing handle on one appliance.
//!   Everything structured (capabilities, params, results) is *declared data*;
//!   only [`device::Device::exec`] is code, and it is gated: mutations require
//!   `allow_writes`, dry-run is honored end-to-end (tenet: secure by default).
//! - Capability subtraits ([`capabilities`]) are typed facades over declared
//!   capabilities; drivers may override them for native implementations.

pub mod capabilities;
pub mod credentials;
pub mod device;
pub mod driver;
pub mod error;
pub mod exec;
pub mod inventory;
pub mod spec;
pub mod topology;
pub mod value;

pub use capabilities::{
    DhcpManagement, DnsFiltering, Identity, Sensors, VlanManagement, Wireless,
};
pub use capabilities::{
    ID_CAPABILITIES, ID_DHCP_ADD_STATIC_LEASE, ID_DHCP_LIST_POOLS, ID_DNS_BLOCK,
    ID_DNS_LIST_ENTRIES, ID_IDENTIFY, ID_SENSOR_HISTORY, ID_SENSOR_READ, ID_VLAN_ASSIGN,
    ID_VLAN_CREATE, ID_VLAN_LIST, ID_WLAN_GUEST_ENABLE, ID_WLAN_LIST_SSID,
};
pub use credentials::{CredentialSet, Secret};
pub use device::{DeviceId, DeviceKind, DeviceMeta};
pub use driver::{Driver, Target};
pub use error::{MyceliumError, Result};
pub use exec::{ExecContext, ExecOutcome};
pub use inventory::{
    result_from_outcome, CapabilityInfo, Device, Inventory, InvokeResult,
};
pub use spec::{CapResult, CapSpec, ParamSpec, ParamType};
pub use topology::{
    ipv4_in_cidr, Conflict, IpRecord, LeaseRecord, Link, LinkState, MacAddress, Observation,
    Origin, PortRef, Segment, SegmentKind, TopoNode, Topology, TopologyReport, VlanId,
};
pub use value::{IntoValue, Params, Value};
