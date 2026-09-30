use std::collections::BTreeSet;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// A network discovery mechanism that can be authorized per observer and
/// segment. Routed discovery is opt-in; an empty policy authorizes nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryProtocol {
    Ssdp,
    Mdns,
}

/// Durable desired policy. Segment IDs refer to observed topology rather than
/// platform interface names, which remain driver-owned implementation details.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryScope {
    pub observer: String,
    pub protocols: BTreeSet<DiscoveryProtocol>,
    pub segments: BTreeSet<String>,
}

impl DiscoveryScope {
    pub fn key(&self) -> &str {
        &self.observer
    }
}

/// One fully resolved probe passed across the generic device/driver seam.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryRequest {
    pub protocol: DiscoveryProtocol,
    pub segment: String,
    pub source: IpAddr,
}
