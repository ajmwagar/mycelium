//! Persistent, narrowly scoped WireGuard intent. Private keys remain references
//! to locally generated identity-bound files; plans never carry key material.
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};

pub const ID_WIREGUARD_ENSURE: &str = "net.wireguard.ensure";
pub const ID_WIREGUARD_VERIFY: &str = "net.wireguard.verify";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireGuardTunnel {
    pub interface: String,
    pub address: String,
    pub listen_port: u16,
    pub private_key_path: String,
    pub local_public_key: String,
    pub peer_public_key: String,
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<SocketAddr>,
    pub keepalive_seconds: u16,
}

impl WireGuardTunnel {
    pub fn validate(&self) -> Result<(), String> {
        if !self.interface.starts_with("mc-")
            || self.interface.len() > 15
            || !self
                .interface
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(
                "WireGuard interface must be an owned mc- name, at most 15 characters".into(),
            );
        }
        parse_private_prefix(&self.address, false)?;
        if self.listen_port == 0
            || self.keepalive_seconds > 120
            || self.endpoint.is_some_and(|endpoint| {
                endpoint.port() == 0
                    || endpoint.ip().is_unspecified()
                    || endpoint.ip().is_multicast()
            })
        {
            return Err("invalid WireGuard port, endpoint or keepalive".into());
        }
        for key in [&self.local_public_key, &self.peer_public_key] {
            if key.len() != 44
                || !key.ends_with('=')
                || !key.as_bytes()[..43]
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || b"+/".contains(b))
                || !b"AEIMQUYcgkosw048".contains(&key.as_bytes()[42])
                || key.as_bytes()[..43].iter().all(|b| *b == b'A')
            {
                return Err("invalid canonical WireGuard public key".into());
            }
        }
        if self.local_public_key == self.peer_public_key {
            return Err("WireGuard endpoints share a key".into());
        }
        if !self.private_key_path.starts_with('/')
            || self.private_key_path.len() > 256
            || !self.private_key_path.ends_with("/wireguard/private.key")
            || self
                .private_key_path
                .split('/')
                .any(|part| part == "." || part == "..")
            || !self
                .private_key_path
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
        {
            return Err(
                "private key must reference a local Mycelium wireguard/private.key file".into(),
            );
        }
        if self.allowed_ips.is_empty() || self.allowed_ips.len() > 16 {
            return Err("expected 1..16 routed private prefixes".into());
        }
        let mut prefixes = std::collections::BTreeSet::new();
        for prefix in &self.allowed_ips {
            parse_private_prefix(prefix, true)?;
            if !prefixes.insert(prefix) {
                return Err("duplicate routed prefix".into());
            }
        }
        Ok(())
    }
}

fn parse_private_prefix(text: &str, canonical: bool) -> Result<(), String> {
    let (address, length) = text.split_once('/').ok_or("expected IPv4 CIDR")?;
    let address: Ipv4Addr = address.parse().map_err(|_| "invalid IPv4 address")?;
    let length: u32 = length.parse().map_err(|_| "invalid prefix length")?;
    if length == 0 || length > 32 || !address.is_private() {
        return Err("only scoped RFC1918 routes are supported; no default routes".into());
    }
    let octets = address.octets();
    let minimum = if octets[0] == 10 {
        8
    } else if octets[0] == 172 {
        12
    } else {
        16
    };
    if length < minimum {
        return Err("route extends outside RFC1918 address space".into());
    }
    let mask = u32::MAX << (32 - length);
    if canonical && u32::from(address) & !mask != 0 {
        return Err("routed prefix must be canonical".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn tunnel() -> WireGuardTunnel {
        WireGuardTunnel {
            interface: "mc-lab".into(),
            address: "10.253.180.1/30".into(),
            listen_port: 51820,
            private_key_path: "/var/lib/mycelium/wireguard/private.key".into(),
            local_public_key: format!("{}A=", "B".repeat(42)),
            peer_public_key: format!("{}A=", "C".repeat(42)),
            allowed_ips: vec!["192.168.1.48/32".into()],
            endpoint: Some("165.227.93.206:51820".parse().unwrap()),
            keepalive_seconds: 25,
        }
    }
    #[test]
    fn accepts_scoped_local_key_reference() {
        tunnel().validate().unwrap();
    }
    #[test]
    fn rejects_default_noncanonical_and_public_routes() {
        for prefix in [
            "0.0.0.0/0",
            "192.168.1.48/24",
            "165.227.93.206/32",
            "192.168.1.0/33",
            "10.0.0.0/1",
        ] {
            let mut value = tunnel();
            value.allowed_ips = vec![prefix.into()];
            assert!(value.validate().is_err());
        }
    }
    #[test]
    fn rejects_command_injection_and_key_material_as_reference() {
        let mut value = tunnel();
        value.interface = "mc-a;reboot".into();
        assert!(value.validate().is_err());
        let mut value = tunnel();
        value.private_key_path = "/tmp/../wireguard/private.key".into();
        assert!(value.validate().is_err());
        let mut value = tunnel();
        value.peer_public_key.push('\n');
        assert!(value.validate().is_err());
    }
}
