use std::collections::{BTreeMap, BTreeSet};

use fpl_resource_observation::{
    Confidence, Provenance, Service, ServiceCatalog, ServiceId, ServiceObservation, SCHEMA_VERSION,
};
use mycelium_core::{ServiceRecord, Topology};

const SERVICE_TTL_SECONDS: u64 = 15 * 60;

pub fn project(topology: &Topology) -> ServiceCatalog {
    let mut catalog = ServiceCatalog {
        schema_version: SCHEMA_VERSION,
        ..ServiceCatalog::default()
    };
    for (node_id, node) in &topology.nodes {
        for service in node.services.values() {
            let Some((kind, confidence)) = recognize(service) else {
                continue;
            };
            let endpoints = node
                .ips
                .keys()
                .map(|ip| endpoint(&service.transport, ip.to_string(), service.port))
                .collect();
            let mut protocols = BTreeSet::from([service.transport.to_lowercase()]);
            if kind == "mcp" {
                protocols.insert("json-rpc".into());
            }
            let mut formats = BTreeSet::new();
            let evidence = evidence(service);
            if evidence.contains("h264") || evidence.contains("h.264") {
                formats.insert("h264".into());
            }
            let mut attributes = BTreeMap::new();
            attributes.insert("node_id".into(), node_id.clone());
            if let Some(label) = node
                .annotation
                .name
                .as_ref()
                .or_else(|| node.hostnames.iter().next())
            {
                attributes.insert("node_label".into(), label.clone());
            }
            attributes.insert("service_name".into(), service.name.clone());
            if let Some(product) = &service.product {
                attributes.insert("product".into(), product.clone());
            }
            if let Some(site) = &service.origin.site {
                attributes.insert("site".into(), site.clone());
            }
            catalog.observations.push(ServiceObservation {
                schema_version: SCHEMA_VERSION,
                service_id: ServiceId(format!(
                    "service/{node_id}/{kind}/{}/{}",
                    service.transport.to_lowercase(),
                    service.port
                )),
                observed_at: service.observed_at,
                expires_at: service.observed_at.saturating_add(SERVICE_TTL_SECONDS),
                provenance: Provenance {
                    provider: "mycelium-topology".into(),
                    observer: service.origin.device.clone(),
                    source_id: Some(format!(
                        "{}:{}/{}",
                        service.transport, service.port, service.name
                    )),
                },
                confidence,
                value: Service {
                    kind,
                    endpoints,
                    protocols,
                    formats,
                    attributes,
                },
            });
        }
    }
    catalog.normalize();
    catalog
}

fn endpoint(transport: &str, host: String, port: u16) -> String {
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    };
    format!("{}://{host}:{port}", transport.to_lowercase())
}

fn evidence(service: &ServiceRecord) -> String {
    format!(
        "{} {}",
        service.name.to_lowercase(),
        service
            .product
            .as_deref()
            .unwrap_or_default()
            .to_lowercase()
    )
}

fn recognize(service: &ServiceRecord) -> Option<(String, Confidence)> {
    let evidence = evidence(service);
    for kind in ["isochrone", "unibus", "mcp", "dcp", "adb"] {
        if evidence
            .split(|character: char| !character.is_ascii_alphanumeric())
            .any(|token| token == kind)
        {
            return Some((kind.into(), Confidence::Strong));
        }
    }
    // TCP/5555 is Android Debug Bridge's standard network endpoint. This is
    // deliberately only derived confidence: another service can use the port.
    (service.transport.eq_ignore_ascii_case("tcp") && service.port == 5555)
        .then(|| ("adb".into(), Confidence::Derived))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mycelium_core::{IpRecord, Origin, ServiceState, TopoNode};
    use std::net::IpAddr;

    fn service(name: &str, product: Option<&str>, port: u16) -> ServiceRecord {
        ServiceRecord {
            name: name.into(),
            transport: "tcp".into(),
            port,
            product: product.map(str::to_owned),
            state: ServiceState::Up,
            observed_at: 100,
            origin: Origin::new("neo", "fixture").at_site("home"),
        }
    }

    #[test]
    fn recognizes_named_protocols_without_network_io() {
        for (name, product, port, expected) in [
            ("https", Some("MCP server"), 8443, "mcp"),
            ("unibus", None, 4222, "unibus"),
            ("isochrone", Some("H.264"), 9443, "isochrone"),
            ("dcp", None, 9000, "dcp"),
            ("adb", None, 5555, "adb"),
        ] {
            assert_eq!(
                recognize(&service(name, product, port)).unwrap().0,
                expected
            );
        }
    }

    #[test]
    fn adb_port_is_derived_and_unrelated_ports_are_ignored() {
        let (_, confidence) = recognize(&service("unknown", None, 5555)).unwrap();
        assert_eq!(confidence, Confidence::Derived);
        assert!(recognize(&service("ssh", Some("OpenSSH"), 22)).is_none());
    }

    #[test]
    fn topology_services_project_to_stable_ipv4_and_ipv6_endpoints() {
        let mut topology = Topology::default();
        let mut node = TopoNode {
            id: "peer-a".into(),
            hostnames: BTreeSet::from(["agora-one".into()]),
            ..TopoNode::default()
        };
        for address in ["192.0.2.10", "2001:db8::10"] {
            let addr = address.parse::<IpAddr>().unwrap();
            node.ips.insert(
                addr,
                IpRecord {
                    addr,
                    prefix: None,
                    vlan: None,
                    origins: BTreeSet::new(),
                },
            );
        }
        node.services.insert(
            "tcp:9443/isochrone".into(),
            service("isochrone", Some("H.264"), 9443),
        );
        topology.nodes.insert(node.id.clone(), node);

        let catalog = project(&topology);
        assert_eq!(catalog.observations.len(), 1);
        let observation = &catalog.observations[0];
        assert_eq!(observation.value.kind, "isochrone");
        assert_eq!(observation.value.attributes["node_label"], "agora-one");
        assert!(observation.value.formats.contains("h264"));
        assert!(observation
            .value
            .endpoints
            .contains("tcp://192.0.2.10:9443"));
        assert!(observation
            .value
            .endpoints
            .contains("tcp://[2001:db8::10]:9443"));
    }
}
