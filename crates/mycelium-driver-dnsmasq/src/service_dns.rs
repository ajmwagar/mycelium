//! DNS aliases from application-owned leases, never scanned listeners or ACLs.
use super::Settings;
use fpl_resource_observation::{SCHEMA_VERSION, ServiceCatalog};
use mycelium_dns_policy::{DnsRecord, canonical_domain};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
};

pub(super) fn validate_aliases(aliases: &BTreeMap<String, String>) -> Result<(), String> {
    if aliases.len() > 32 {
        return Err("too many service aliases".into());
    }
    let mut labels = BTreeSet::new();
    for (kind, label) in aliases {
        if kind.is_empty()
            || kind.len() > 128
            || kind.chars().any(char::is_control)
            || canonical_domain(label)? != *label
            || label.contains('.')
            || !labels.insert(label)
        {
            return Err("service aliases need unique canonical single-label names".into());
        }
    }
    Ok(())
}

/// Restricted literal HTTPS entrance. Names, paths, credentials and queries are
/// not rewritten or resolved; service catalogs retain ports and transport hints.
fn address(endpoint: &str) -> Option<IpAddr> {
    let authority = endpoint.strip_prefix("https://")?.trim_end_matches('/');
    let socket: SocketAddr = authority.parse().ok()?;
    (socket.port() != 0 && socket.port() != 80).then_some(socket.ip())
}

pub(super) fn project(
    settings: &Settings,
    mut records: Vec<DnsRecord>,
    catalog: &ServiceCatalog,
    now: u64,
    mut deadline: u64,
) -> Result<(Vec<DnsRecord>, u64), String> {
    validate_aliases(&settings.service_aliases)?;
    if catalog.schema_version != SCHEMA_VERSION || catalog.observations.len() > 4096 {
        return Err("unsupported or oversized service DNS catalog".into());
    }
    let hosts = records.clone();
    let mut identities = BTreeSet::new();
    let mut entrances = BTreeMap::new();
    for service in &catalog.observations {
        let Some(label) = settings.service_aliases.get(&service.value.kind) else {
            continue;
        };
        if service.schema_version != SCHEMA_VERSION
            || !service.is_fresh_at(now)
            || service.expires_at.saturating_sub(service.observed_at) > 300
            || service.provenance.provider != "mycelium-application-owner-lease"
            || service.value.attributes.get("node_id") != Some(&service.provenance.observer)
        {
            continue;
        }
        if !identities.insert(&service.service_id) {
            return Err("duplicate service DNS identity".into());
        }
        for endpoint in &service.value.endpoints {
            let Some(ip) = address(endpoint) else {
                continue;
            };
            for host in hosts
                .iter()
                .filter(|r| r.node == service.provenance.observer && r.address == ip)
            {
                let name = canonical_domain(&format!("{label}.{}", host.name))?;
                // One entrance per name/address: DNS cannot choose a port or URL.
                if entrances
                    .insert((name.clone(), ip), endpoint.clone())
                    .is_some_and(|old| old != *endpoint)
                {
                    return Err("ambiguous service entrance; DNS cannot select ports".into());
                }
                records.push(DnsRecord {
                    name,
                    ..host.clone()
                });
                if settings.service_index_peers.get(&service.value.kind) == Some(&service.provenance.observer) {
                    records.push(DnsRecord {
                        name: canonical_domain(&format!("{label}.{}", settings.resolver.suffix))?,
                        ..host.clone()
                    });
                }
                deadline = deadline.min(service.expires_at);
            }
        }
    }
    records.sort();
    records.dedup();
    settings.resolver.render(records.clone())?;
    Ok((records, deadline))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn catalog() -> ServiceCatalog {
        serde_json::from_value(json!({"schema_version":1,"observations":[{
            "schema_version":1,"service_id":"service/neo/unibus/viewer","observed_at":990,"expires_at":1050,
            "provenance":{"provider":"mycelium-application-owner-lease","observer":"neo"},"confidence":"strong",
            "value":{"kind":"unibus-viewer","endpoints":["https://192.0.2.12:8444"],"attributes":{"node_id":"neo"}}
        }]})).unwrap()
    }
    fn run(c: &ServiceCatalog) -> Result<(Vec<DnsRecord>, u64), String> {
        let mut s = crate::tests::settings();
        s.service_aliases
            .insert("unibus-viewer".into(), "unibus".into());
        let hosts = vec![DnsRecord {
            name: "neo.lab.myc".into(),
            address: "192.0.2.12".parse().unwrap(),
            site: "lab".into(),
            node: "neo".into(),
        }];
        project(&s, hosts, c, 1000, 1200)
    }
    #[test]
    fn exact_owner_endpoint_and_expiry() {
        let (records, expiry) = run(&catalog()).unwrap();
        assert_eq!(expiry, 1050);
        assert!(records.iter().any(|r| r.name == "unibus.neo.lab.myc"));
    }
    #[test]
    fn root_index_requires_explicit_owner_and_fresh_matching_lease() {
        let mut settings = crate::tests::settings();
        settings.service_aliases.insert("unibus-viewer".into(), "unibus".into());
        settings.service_index_peers.insert("unibus-viewer".into(), "neo".into());
        let hosts = vec![DnsRecord { name: "neo.lab.myc".into(), address: "192.0.2.12".parse().unwrap(), site:"lab".into(), node:"neo".into() }];
        let mut services = catalog();
        let (records, _) = project(&settings, hosts.clone(), &services, 1000, 1200).unwrap();
        assert!(records.iter().any(|r| r.name == "unibus.myc"));
        settings.service_index_peers.insert("unibus-viewer".into(), "other".into());
        assert!(!project(&settings, hosts.clone(), &services, 1000, 1200).unwrap().0.iter().any(|r| r.name == "unibus.myc"));
        settings.service_index_peers.insert("unibus-viewer".into(), "neo".into());
        services.observations[0].expires_at = 999;
        assert_eq!(project(&settings, hosts, &services, 1000, 1200).unwrap().0.len(), 1);
    }
    #[test]
    fn no_promotion_of_scans_expired_or_other_hosts() {
        for scenario in 0..5 {
            let mut c = catalog();
            let s = &mut c.observations[0];
            match scenario {
                0 => s.provenance.provider = "mycelium-topology".into(),
                1 => s.expires_at = 999,
                2 => s.value.endpoints = BTreeSet::from(["https://127.0.0.1:8444".into()]),
                3 => s.provenance.observer = "other".into(),
                _ => s.value.endpoints = BTreeSet::from(["https://198.51.100.2:8444".into()]),
            }
            assert_eq!(run(&c).unwrap().0.len(), 1);
        }
    }
    #[test]
    fn aliases_and_entrances_fail_closed() {
        assert!(validate_aliases(&BTreeMap::from([("a".into(), "bad.name".into())])).is_err());
        let mut c = catalog();
        c.observations[0]
            .value
            .endpoints
            .insert("https://192.0.2.12:9444".into());
        assert!(run(&c).is_err());
        for url in [
            "http://192.0.2.12:8444",
            "https://user@192.0.2.12:8444",
            "https://neo.lab.myc:8444",
            "https://192.0.2.12:8444/admin",
            "https://192.0.2.12:8444?token=x",
        ] {
            assert!(address(url).is_none());
        }
    }
}
