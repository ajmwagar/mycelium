use std::collections::BTreeMap;
use std::net::IpAddr;

use mycelium_core::MacAddress;

#[derive(Clone, Debug, PartialEq)]
pub struct Interface {
    pub name: String,
    pub mac: Option<MacAddress>,
    pub addresses: Vec<(IpAddr, u8)>,
    pub up: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Neighbor {
    pub ip: IpAddr,
    pub iface: String,
    pub mac: MacAddress,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ConnectedRoute {
    pub network: IpAddr,
    pub prefix: u8,
    pub iface: String,
    pub source: Option<IpAddr>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Listener {
    pub transport: String,
    pub port: u16,
    pub process: Option<String>,
}

pub fn parse_interfaces(links: &str, addresses: &str) -> Vec<Interface> {
    let mut out: BTreeMap<String, Interface> = BTreeMap::new();
    for line in links.lines() {
        let mut fields = line.split_whitespace();
        let _index = fields.next();
        let Some(raw_name) = fields.next() else {
            continue;
        };
        let name = raw_name
            .trim_end_matches(':')
            .split('@')
            .next()
            .unwrap_or(raw_name);
        let words: Vec<&str> = line.split_whitespace().collect();
        let mac = words
            .windows(2)
            .find(|w| w[0].starts_with("link/"))
            .and_then(|w| MacAddress::parse(w[1]));
        out.insert(
            name.to_owned(),
            Interface {
                name: name.to_owned(),
                mac,
                addresses: Vec::new(),
                up: line.contains("state UP") || line.contains(",UP,"),
            },
        );
    }
    for line in addresses.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(name) = fields.get(1).map(|s| s.split('@').next().unwrap_or(s)) else {
            continue;
        };
        let Some(cidr) = fields.iter().find(|s| s.contains('/')) else {
            continue;
        };
        let Some((ip, prefix)) = parse_cidr(cidr) else {
            continue;
        };
        out.entry(name.to_owned())
            .or_insert_with(|| Interface {
                name: name.to_owned(),
                mac: None,
                addresses: Vec::new(),
                up: true,
            })
            .addresses
            .push((ip, prefix));
    }
    out.into_values().collect()
}

pub fn parse_neighbors(text: &str) -> Vec<Neighbor> {
    text.lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let ip = fields.first()?.parse().ok()?;
            let iface = fields.windows(2).find(|w| w[0] == "dev")?[1].to_owned();
            let mac = fields
                .windows(2)
                .find(|w| w[0] == "lladdr")
                .and_then(|w| MacAddress::parse(w[1]))?;
            Some(Neighbor { ip, iface, mac })
        })
        .collect()
}

pub fn parse_routes(text: &str) -> Vec<ConnectedRoute> {
    text.lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let (network, prefix) = parse_cidr(fields.first()?)?;
            let iface = fields.windows(2).find(|w| w[0] == "dev")?[1].to_owned();
            let source = fields
                .windows(2)
                .find(|w| w[0] == "src")
                .and_then(|w| w[1].parse().ok());
            Some(ConnectedRoute {
                network,
                prefix,
                iface,
                source,
            })
        })
        .collect()
}

pub fn parse_listeners(text: &str) -> Vec<Listener> {
    let mut listeners = text
        .lines()
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            let transport = fields.first()?.trim_end_matches('6').to_owned();
            let port = fields.get(4)?.rsplit(':').next()?.parse().ok()?;
            let process = line
                .split("users:((\"")
                .nth(1)
                .and_then(|rest| rest.split('"').next())
                .map(str::to_owned);
            Some(Listener {
                transport,
                port,
                process,
            })
        })
        .collect::<Vec<_>>();
    listeners.sort();
    listeners.dedup();
    listeners
}

fn parse_cidr(text: &str) -> Option<(IpAddr, u8)> {
    let (ip, prefix) = text.split_once('/')?;
    Some((ip.parse().ok()?, prefix.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_iproute2_observations() {
        let links = "2: enp4s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP mode DEFAULT group default qlen 1000 link/ether 06:7c:16:77:ea:c0 brd ff:ff:ff:ff:ff:ff";
        let addrs =
            "2: enp4s0    inet 192.168.1.9/24 brd 192.168.1.255 scope global dynamic enp4s0";
        let interfaces = parse_interfaces(links, addrs);
        assert_eq!(interfaces[0].name, "enp4s0");
        assert_eq!(interfaces[0].addresses[0].0.to_string(), "192.168.1.9");

        let neighbors = parse_neighbors("192.168.1.1 dev enp4s0 lladdr 94:18:65:19:e9:bb REACHABLE\n192.168.1.2 dev enp4s0 FAILED");
        assert_eq!(neighbors.len(), 1);
        assert_eq!(neighbors[0].mac.to_string(), "94:18:65:19:e9:bb");

        let routes = parse_routes(
            "192.168.1.0/24 dev enp4s0 proto kernel scope link src 192.168.1.9 metric 100",
        );
        assert_eq!(routes[0].prefix, 24);
        assert_eq!(routes[0].source.unwrap().to_string(), "192.168.1.9");
    }

    #[test]
    fn parses_listening_sockets_and_processes() {
        let rows = parse_listeners(
            "tcp LISTEN 0 4096 0.0.0.0:8971 0.0.0.0:* users:((\"frigate\",pid=12,fd=4))\nudp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:*",
        );
        assert_eq!(rows[0].process.as_deref(), Some("frigate"));
        assert_eq!(rows[0].port, 8971);
        assert_eq!(rows[1].transport, "udp");
    }
}
