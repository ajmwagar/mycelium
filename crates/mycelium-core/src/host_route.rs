//! Add-only private host routes: never change default gateways or export a LAN.
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

pub const ID_HOST_ROUTE_ENSURE: &str = "net.route.ensure";
pub const ID_HOST_ROUTE_VERIFY: &str = "net.route.verify";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRoute {
    pub destination: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub interface: String,
    /// Stable connection identity, not a user-visible profile name.
    pub connection_uuid: String,
}

impl HostRoute {
    pub fn validate(&self) -> Result<(), String> {
        if !self.destination.is_private()
            || !self.gateway.is_private()
            || self.destination == self.gateway
        {
            return Err("host routes require distinct RFC1918 destination and gateway".into());
        }
        if self.interface.is_empty()
            || self.interface.len() > 15
            || !self
                .interface
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err("unsafe host route interface".into());
        }
        if self.connection_uuid.len() != 36
            || !self.connection_uuid.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }
            })
        {
            return Err("connection must be a canonical UUID".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_private_route() {
        let mut r = HostRoute {
            destination: "10.253.0.1".parse().unwrap(),
            gateway: "192.168.1.39".parse().unwrap(),
            interface: "enP7s7".into(),
            connection_uuid: "c6cf14db-1c49-34e5-adb2-33badd79a9b0".into(),
        };
        assert!(r.validate().is_ok());
        r.destination = "0.0.0.0".parse().unwrap();
        assert!(r.validate().is_err());
        r.destination = "10.253.0.1".parse().unwrap();
        r.interface = "eth0; reboot".into();
        assert!(r.validate().is_err());
    }
}
