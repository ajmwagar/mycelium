//! Optional resolver policy. Naming is separate from reachability and grants.
use crate::{canonical_domain, plan, Delegation, DnsRecord};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResolverMode {
    #[default]
    Off,
    LocalhostOnly,
    LanServing,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolverConfig {
    #[serde(default)]
    pub mode: ResolverMode,
    pub site: String,
    pub suffix: String,
    pub listen: Vec<SocketAddr>,
    /// Explicit upstreams, never inferred from a resolver pointing at ourselves.
    pub upstreams: Vec<SocketAddr>,
    #[serde(default)]
    pub delegations: Vec<Delegation>,
}

impl ResolverConfig {
    /// Produces only DNS configuration: never DHCP or an OS default DNS change.
    pub fn render(&self, records: Vec<DnsRecord>) -> Result<String, String> {
        let zone = plan(&self.site, &self.suffix, records, self.delegations.clone())?;
        if self.mode == ResolverMode::Off {
            return Ok(String::new());
        }
        if self.listen.is_empty() || self.listen.len() > 8 || self.upstreams.len() > 8 {
            return Err("resolver needs 1..8 explicit listeners and at most 8 upstreams".into());
        }
        let port = self.listen[0].port();
        if port == 0 || self.listen.iter().any(|s| s.port() != port) {
            return Err("listeners must use the same nonzero port".into());
        }
        for listener in &self.listen {
            let address = listener.ip();
            if address.is_unspecified() || address.is_multicast() {
                return Err("wildcard and multicast DNS listeners are forbidden".into());
            }
            if self.mode == ResolverMode::LocalhostOnly && !address.is_loopback() {
                return Err("localhost-only requires loopback listeners".into());
            }
        }
        for server in self.upstreams.iter().copied().chain(
            self.delegations
                .iter()
                .map(|d| SocketAddr::new(d.server, d.port)),
        ) {
            if server.port() == 0
                || server.ip().is_unspecified()
                || server.ip().is_multicast()
                || server.ip().is_loopback()
                || self.listen.contains(&server)
            {
                return Err("invalid upstream or forwarding loop".into());
            }
        }
        let mut config = format!(
            "# Managed by Mycelium; DNS only.\nport={port}\nbind-interfaces\nno-resolv\nno-hosts\ncache-size=256\nlocal-ttl=30\n"
        );
        for address in &self.listen {
            config.push_str(&format!("listen-address={}\n", address.ip()));
        }
        for server in &self.upstreams {
            config.push_str(&format!("server={}#{}\n", server.ip(), server.port()));
        }
        config.push_str(&zone.dnsmasq);
        Ok(config)
    }

    /// macOS supplemental resolver: this zone only, never replaces uplink DNS.
    pub fn macos_namespace(&self) -> Result<(String, String), String> {
        self.render(Vec::new())?;
        if self.mode == ResolverMode::Off {
            return Err("off mode has no supplemental resolver".into());
        }
        let listener = self
            .listen
            .iter()
            .find(|s| s.ip().is_loopback())
            .ok_or("macOS namespace routing needs a loopback listener")?;
        let suffix = canonical_domain(&self.suffix)?;
        Ok((suffix.clone(), format!(
            "# Managed by Mycelium DNS resolver\ndomain {suffix}\nnameserver {}\nport {}\ntimeout 2\n",
            listener.ip(), listener.port()
        )))
    }
}

/// Only usable unicast records may be published by a local observation adapter.
pub fn usable_address(address: IpAddr) -> bool {
    !address.is_loopback()
        && !address.is_unspecified()
        && !address.is_multicast()
        && match address {
            IpAddr::V4(a) => !a.is_link_local() && !a.is_broadcast(),
            IpAddr::V6(a) => a.segments()[0] & 0xffc0 != 0xfe80,
        }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> ResolverConfig {
        ResolverConfig {
            mode: ResolverMode::LocalhostOnly,
            site: "lab".into(),
            suffix: "myc".into(),
            listen: vec!["127.0.0.1:1053".parse().unwrap()],
            upstreams: vec!["1.1.1.1:53".parse().unwrap()],
            delegations: vec![],
        }
    }
    #[test]
    fn off_is_default_and_has_no_listener_config() {
        assert_eq!(ResolverMode::default(), ResolverMode::Off);
        let mut c = config();
        c.mode = ResolverMode::Off;
        assert_eq!(c.render(vec![]).unwrap(), "");
    }
    #[test]
    fn localhost_guard_and_split_namespace() {
        let c = config();
        let text = c.render(vec![]).unwrap();
        assert!(text.contains("local=/myc/"));
        assert!(text.contains("no-resolv\n"));
        assert!(!text.contains("dhcp"));
        assert_eq!(c.macos_namespace().unwrap().0, "myc");
        let mut c = c;
        c.listen = vec!["192.0.2.1:53".parse().unwrap()];
        assert!(c.render(vec![]).is_err());
    }
    #[test]
    fn rejects_wildcards_zero_ports_and_recursive_upstreams() {
        for listener in ["0.0.0.0:1053", "[::]:1053", "127.0.0.1:0"] {
            let mut c = config();
            c.listen = vec![listener.parse().unwrap()];
            assert!(c.render(vec![]).is_err());
        }
        let mut c = config();
        c.upstreams = c.listen.clone();
        assert!(c.render(vec![]).is_err());
    }
    #[test]
    fn lan_is_explicit_and_keeps_namespace_ownership() {
        let mut c = config();
        c.mode = ResolverMode::LanServing;
        c.listen.push("192.0.2.1:1053".parse().unwrap());
        assert!(c
            .render(vec![])
            .unwrap()
            .contains("listen-address=192.0.2.1"));
        c.delegations.push(Delegation {
            zone: "myc".into(),
            site: "lab".into(),
            owner: "shroud".into(),
            server: "192.0.2.2".parse().unwrap(),
            port: 53,
        });
        assert!(c.render(vec![]).is_err());
    }
}
