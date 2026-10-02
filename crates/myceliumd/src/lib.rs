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
mod execution;
pub mod peer;
pub mod protocol;
pub mod rpc;
mod security;
pub mod siem;
mod state_change;

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UpdateState {
    pub release_version: Option<String>,
    pub release_digest: Option<String>,
    pub release_target: Option<String>,
    pub activation_state: String,
    pub activated_at: Option<u64>,
    pub last_error: Option<String>,
}

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

pub fn discovery_path() -> PathBuf {
    home_dir().join("discovery.json")
}

pub fn allocations_path() -> PathBuf {
    home_dir().join("allocations.json")
}

pub fn networks_path() -> PathBuf {
    home_dir().join("networks.json")
}

pub fn network_bindings_path() -> PathBuf {
    home_dir().join("network-bindings.json")
}

pub fn dhcp_scopes_path() -> PathBuf {
    home_dir().join("dhcp-scopes.json")
}

pub fn siem_dir() -> PathBuf {
    home_dir().join("security").join("siem")
}

pub fn execution_receipts_dir() -> PathBuf {
    home_dir().join("executions")
}

pub fn peer_key_path() -> PathBuf {
    home_dir().join("peer.key")
}

pub fn peer_observations_path() -> PathBuf {
    home_dir().join("peer-observations.json")
}

pub fn artifacts_dir() -> PathBuf {
    home_dir().join("artifacts")
}

pub fn update_state_path() -> PathBuf {
    home_dir().join("update-state.json")
}

pub fn wireguard_dir() -> PathBuf {
    home_dir().join("wireguard")
}

pub fn wireguard_private_key_path() -> PathBuf {
    wireguard_dir().join("private.key")
}

pub fn read_update_state() -> UpdateState {
    std::fs::read(update_state_path())
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

pub fn write_update_state(state: &UpdateState) -> std::io::Result<()> {
    let path = update_state_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(state).map_err(std::io::Error::other)?;
    std::fs::write(&temporary, bytes)?;
    std::fs::rename(temporary, path)
}

pub fn plugins_dir() -> PathBuf {
    home_dir().join("plugins")
}

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
