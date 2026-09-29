//! Read-only Linux SSH vantage-point driver.
//!
//! Linux hosts contribute their kernel's interfaces, connected routes, and
//! neighbor table. Commands are fixed and parsing is deterministic; this is
//! an observer, not a general remote-shell capability.

mod driver;
mod parsers;

pub use driver::{LinuxDevice, LinuxDriver, DRIVER_NAME};
