//! mycelium control-plane daemon.
//!
//! Process model: one `myceliumd` per machine owns the inventory (open
//! device handles), driver/plugin registry, and the merged multi-LAN
//! topology. The CLI is a thin client speaking newline-delimited JSON-RPC
//! over a Unix socket — deliberately `curl`/`nc`-able, so every workflow
//! keeps runbook parity (tenet #8) and automation can skip the CLI.
//!
//! State lives in `$MYCELIUM_HOME` (default `~/.mycelium`):
//! - `myceliumd.sock`  JSON-RPC socket
//! - `daemon.pid`      running daemon pid
//! - `devices.json`    saved device configs, reconnected at boot
//! - `topology.json`   last merged topology (facts, re-derivable via scan)
//! - `plugins/*.lua`   Lua plugin drivers, validated at boot
//!
//! Secrets never persist: `CredentialSet` round-trips `Secret::Env`, so
//! `devices.json` stores variable names, not values.

pub mod client;
pub mod protocol;
pub mod rpc;

use std::path::PathBuf;

/// Resolve the state dir. Inferred, not configured, unless overridden.
pub fn home_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("MYCELIUM_HOME") {
        return PathBuf::from(dir);
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".mycelium")
}

pub fn socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("MYCELIUM_SOCKET") {
        return PathBuf::from(p);
    }
    home_dir().join("myceliumd.sock")
}

pub fn pid_path() -> PathBuf {
    home_dir().join("daemon.pid")
}

pub fn devices_path() -> PathBuf {
    home_dir().join("devices.json")
}

pub fn topology_path() -> PathBuf {
    home_dir().join("topology.json")
}

pub fn plugins_dir() -> PathBuf {
    home_dir().join("plugins")
}

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
