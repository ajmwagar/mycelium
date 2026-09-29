//! mycelium driver for Ubiquiti EdgeOS appliances (EdgeRouter, EdgeRunner,
//! EPX switches with vyos-style CLI) over SSH.
//!
//! The vyos CLI is command-string driven; every capability is a parse of
//! `show …` output or a `configure; set …; commit; save` sequence. Writes
//! are gated by core's invoke path and dry-run returns the exact planned
//! command list without touching the device.

pub mod device;
pub mod driver;
pub mod parsers;
pub mod transport;

pub use device::{EdgeIdentity, EdgeOsDevice, DRIVER_NAME, PRIMARY_COMMAND};
pub use driver::EdgeOsDriver;
pub use parsers::{
    ArpEntry, DhcpPool, DhcpRange, DhcpSubnet, EdgeConfig, StaticLease, VlanInfo, VlanMember,
};
pub use transport::SshSession;

/// Default SSH port.
pub const DEFAULT_PORT: u16 = 22;
