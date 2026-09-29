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
pub mod value;

pub use capabilities::{
    DhcpManagement, DnsFiltering, Identity, Sensors, VlanManagement, Wireless,
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
pub use value::{IntoValue, Params, Value};
