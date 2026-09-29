use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::credentials::CredentialSet;
use crate::error::{MyceliumError, Result};
use crate::inventory::Inventory;

/// Where a driver should look for appliances.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    Host { host: String, port: Option<u16> },
    Subnet { network: String },
}

impl Target {
    pub fn host(host: impl Into<String>) -> Self {
        Target::Host { host: host.into(), port: None }
    }

    pub fn parse(s: &str) -> Result<Self> {
        if let Some(rest) = s.strip_prefix("subnet:") {
            return Ok(Target::Subnet { network: rest.to_owned() });
        }
        // host or host:port; bare IPv6 in brackets
        if let Some(bracketed) = s.strip_prefix('[') {
            let (host, tail) = bracketed
                .split_once(']')
                .ok_or_else(|| MyceliumError::Parse(format!("bad address `{s}`")))?;
            let port = tail
                .strip_prefix(':')
                .map(|p| p.parse::<u16>())
                .transpose()
                .map_err(|_| MyceliumError::Parse(format!("bad port in `{s}`")))?;
            return Ok(Target::Host { host: host.to_owned(), port });
        }
        if s.contains(':') && s.parse::<IpAddr>().is_err() {
            let (host, port) = s
                .split_once(':')
                .ok_or_else(|| MyceliumError::Parse(format!("bad address `{s}`")))?;
            let port = port
                .parse::<u16>()
                .map_err(|_| MyceliumError::Parse(format!("bad port in `{s}`")))?;
            return Ok(Target::Host { host: host.to_owned(), port: Some(port) });
        }
        Ok(Target::Host { host: s.to_owned(), port: None })
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Host { host, port: Some(p) } => write!(f, "{host}:{p}"),
            Target::Host { host, port: None } => write!(f, "{host}"),
            Target::Subnet { network } => write!(f, "subnet:{network}"),
        }
    }
}

/// A driver discovers and opens a *class* of appliances.
///
/// Discovery is inferential: a driver recognizes its devices by probing,
/// not by the user naming the vendor. Subnet scans start with cheap
/// identification probes (banner/port checks) — never destructive actions.
#[async_trait::async_trait]
pub trait Driver: Send + Sync {
    fn name(&self) -> &str;

    /// Quick recognition probe. `Ok(true)` if `target` looks like this
    /// driver's device class.
    async fn recognizes(&self, target: &Target, creds: &CredentialSet) -> Result<bool>;

    /// Identify + open, registering the device (and its capabilities) into
    /// the inventory.
    async fn attach(
        &self,
        target: &Target,
        creds: &CredentialSet,
        inventory: &Inventory,
    ) -> Result<crate::device::DeviceId>;
}
