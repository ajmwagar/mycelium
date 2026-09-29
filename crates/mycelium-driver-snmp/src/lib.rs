//! mycelium driver for SNMP-speaking appliances: switches, APs, cameras,
//! printers, UPSes.
//!
//! v2c (community strings) with optional per-device write community;
//! pure Rust (async-snmp), no net-snmp subprocesses — the community never
//! appears in process arguments. v3 (auth+privacy) is a tracked seam for
//! later (tenet #12: no silent downgrade — v3 targets must be pinned
//! explicitly when support lands).
//!
//! The credential mapping for `mycelium add`:
//! - `--user <community>`        read community (stored; "public" is not a secret)
//! - `--password-env VAR`        read community resolved from env at use time
//!   (use this for private read communities and for write access)
//! - `--key <name>`              write community *env var name* (SNMP reuses the
//!   key_path slot only for nothing here; v0: write uses the password community)

pub mod client;
pub mod device;
pub mod driver;

pub use client::SnmpHandle;
pub use device::{SnmpDevice, DEFAULT_SNMP_PORT};
pub use driver::SnmpDriver;
