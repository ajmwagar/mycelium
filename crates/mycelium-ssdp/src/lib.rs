//! Parser for SSDP discovery responses.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use mycelium_core::ServiceAdvertisement;

/// Parse one or more concatenated HTTP-like SSDP M-SEARCH responses.
pub fn parse_responses(input: &str, observed_at: u64) -> Vec<ServiceAdvertisement> {
    split_responses(input)
        .filter_map(|response| parse_response(response, observed_at))
        .collect()
}

/// Parse responses grouped by an observer-emitted interface marker. This
/// preserves the LAN vantage point without coupling the protocol parser to a
/// particular operating system's interface inventory format.
pub fn parse_probes(input: &str, observed_at: u64) -> Vec<ServiceAdvertisement> {
    const MARKER: &str = "__MYCELIUM_SSDP_PROBE__\t";
    if !input.contains(MARKER) {
        return parse_responses(input, observed_at);
    }
    input
        .split(MARKER)
        .skip(1)
        .flat_map(|probe| {
            let (header, responses) = probe.split_once('\n').unwrap_or((probe, ""));
            let mut fields = header.split('\t');
            let interface = fields
                .next()
                .filter(|value| !value.is_empty())
                .map(str::to_owned);
            parse_responses(responses, observed_at)
                .into_iter()
                .map(move |mut advertisement| {
                    advertisement.interface = interface.clone();
                    advertisement
                })
        })
        .collect()
}

fn split_responses(input: &str) -> impl Iterator<Item = &str> {
    input
        .split("HTTP/1.1")
        .skip(1)
        .map(|response| response.trim_matches(['\r', '\n']))
}

fn parse_response(response: &str, observed_at: u64) -> Option<ServiceAdvertisement> {
    let headers = response
        .lines()
        .filter_map(|line| line.trim_end_matches('\r').split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect::<BTreeMap<_, _>>();
    let service_type = headers.get("st").or_else(|| headers.get("nt"))?.clone();
    let usn = headers
        .get("usn")
        .cloned()
        .unwrap_or_else(|| service_type.clone());
    let location = headers.get("location").cloned();
    let (address, port) = location
        .as_deref()
        .and_then(parse_http_endpoint)
        .map(|(address, port)| (Some(address), port))
        .unwrap_or_default();
    let ttl = headers.get("cache-control").and_then(|value| {
        value.split(',').find_map(|part| {
            let (name, value) = part.trim().split_once('=')?;
            name.eq_ignore_ascii_case("max-age")
                .then(|| value.trim().parse().ok())
                .flatten()
        })
    });
    let txt = headers
        .iter()
        .filter(|(name, _)| !matches!(name.as_str(), "st" | "nt" | "usn"))
        .map(|(name, value)| format!("{name}={value}"))
        .collect();
    Some(ServiceAdvertisement {
        instance: usn,
        service_type,
        domain: "ssdp".into(),
        target: address.map(|value| value.to_string()),
        addresses: address.into_iter().collect(),
        port,
        txt,
        interface: None,
        ttl,
        first_seen: observed_at,
        last_seen: observed_at,
        origins: BTreeSet::new(),
    })
}

fn parse_http_endpoint(location: &str) -> Option<(IpAddr, Option<u16>)> {
    if let Ok(address) = location.parse() {
        return Some((address, None));
    }
    let authority = location
        .strip_prefix("http://")
        .or_else(|| location.strip_prefix("https://"))?
        .split('/')
        .next()?;
    if let Some(bracketed) = authority.strip_prefix('[') {
        let (address, rest) = bracketed.split_once(']')?;
        let port = rest.strip_prefix(':').and_then(|value| value.parse().ok());
        return Some((address.parse().ok()?, port));
    }
    let (host, port) = authority
        .rsplit_once(':')
        .map(|(host, port)| (host, port.parse().ok()))
        .unwrap_or((authority, None));
    Some((host.parse().ok()?, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_multiple_responses_and_upnp_metadata() {
        let input = concat!(
            "HTTP/1.1 200 OK\r\n",
            "CACHE-CONTROL: max-age=1800\r\n",
            "LOCATION: http://192.168.10.15:80/description.xml\r\n",
            "SERVER: Linux/3.14 UPnP/1.0 IpBridge/1.0\r\n",
            "ST: upnp:rootdevice\r\n",
            "USN: uuid:2f402f80-da50-11e1-9b23-ecb5fa134f06::upnp:rootdevice\r\n\r\n",
            "HTTP/1.1 200 OK\r\n",
            "LOCATION: http://192.168.10.97:8008/ssdp/device-desc.xml\r\n",
            "ST: urn:dial-multiscreen-org:service:dial:1\r\n",
            "USN: uuid:fire-tv::urn:dial-multiscreen-org:service:dial:1\r\n\r\n",
        );
        let records = parse_responses(input, 42);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].port, Some(80));
        assert_eq!(records[0].target.as_deref(), Some("192.168.10.15"));
        assert_eq!(records[0].ttl, Some(1800));
        assert!(records[0]
            .addresses
            .contains(&"192.168.10.15".parse().unwrap()));
        assert_eq!(records[1].port, Some(8008));
    }

    #[test]
    fn parses_ipv6_location() {
        let input = "HTTP/1.1 200 OK\r\nLOCATION: http://[fe80::1]:8080/root.xml\r\nST: upnp:rootdevice\r\nUSN: uuid:test\r\n\r\n";
        let record = parse_responses(input, 42).pop().unwrap();
        assert!(record.addresses.contains(&"fe80::1".parse().unwrap()));
        assert_eq!(record.port, Some(8080));
    }

    #[test]
    fn probe_markers_preserve_interface_provenance() {
        let input = "__MYCELIUM_SSDP_PROBE__\ten1\t192.168.10.84\nHTTP/1.1 200 OK\r\nLOCATION: http://192.168.10.97:8008/root.xml\r\nST: upnp:rootdevice\r\nUSN: uuid:fire-tv\r\n\r\n";
        let record = parse_probes(input, 42).pop().unwrap();
        assert_eq!(record.interface.as_deref(), Some("en1"));
    }

    #[test]
    fn parses_bambu_notify_with_bare_ip_location() {
        let input = concat!(
            "NOTIFY * HTTP/1.1\r\n",
            "Host: 239.255.255.250:1990\r\n",
            "Location: 10.0.0.3\r\n",
            "NT: urn:bambulab-com:device:3dprinter:1\r\n",
            "NTS: ssdp:alive\r\n",
            "USN: 22E8AJ5A0400044\r\n",
            "Cache-Control: max-age=1800\r\n",
            "DevModel.bambu.com: N7\r\n",
            "DevName.bambu.com: P2S - Thing 2\r\n\r\n",
        );
        let record = parse_responses(input, 42).pop().unwrap();
        assert_eq!(record.instance, "22E8AJ5A0400044");
        assert_eq!(record.target.as_deref(), Some("10.0.0.3"));
        assert!(record.addresses.contains(&"10.0.0.3".parse().unwrap()));
        assert!(record.txt.contains("devmodel.bambu.com=N7"));
    }
}
