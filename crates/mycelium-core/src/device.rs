use serde::{Deserialize, Serialize};

/// Identity of an appliance, inferred at probe time (tenet: infer, don't
/// configure). Nothing here is hand-maintained config.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeviceKind {
    Router,
    Switch,
    AccessPoint,
    Bmc,
    DnsFilter,
    Other,
}

impl std::fmt::Display for DeviceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            DeviceKind::Router => "router",
            DeviceKind::Switch => "switch",
            DeviceKind::AccessPoint => "access-point",
            DeviceKind::Bmc => "bmc",
            DeviceKind::DnsFilter => "dns-filter",
            DeviceKind::Other => "other",
        };
        f.write_str(s)
    }
}

/// Stable identifier for a device within an inventory.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeviceId(pub String);

impl DeviceId {
    pub fn new(slug: impl AsRef<str>) -> Self {
        Self(slug.as_ref().to_owned())
    }
}

impl std::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// What a device reports about itself.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeviceMeta {
    pub id: DeviceId,
    pub kind: DeviceKind,
    /// Driver that opened this device (e.g. "edgeos", "lua:dnsmasq").
    pub driver: String,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub firmware: Option<String>,
    pub address: String,
}
