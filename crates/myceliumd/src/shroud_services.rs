//! Read-only Shroud discovery projection. Shroud retains DNS and runtime ownership.
use fpl_resource_observation::{
    Confidence, Provenance, SCHEMA_VERSION, Service, ServiceCatalog, ServiceId, ServiceObservation,
};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Deserialize)]
struct Response {
    ok: bool,
    protocol: String,
    #[serde(default)]
    services: Vec<Record>,
}
#[derive(Deserialize)]
struct Record {
    name: String,
    port_name: String,
    protocol: String,
    scheme: String,
    power: String,
    health: String,
    guest: Port,
}
#[derive(Deserialize)]
struct Port {
    port: u16,
}

fn label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
}

/// Project only ready HTTP services onto stable owner-controlled DNS names.
/// Replica addresses, VM IDs, metadata and proposed ingress routes are omitted.
pub fn project(bytes: &[u8], node: &str, now: u64) -> Result<ServiceCatalog, String> {
    if bytes.len() > 262144 || node.len() != 64 || !node.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid Shroud response bound or owner identity".into());
    }
    let response: Response =
        serde_json::from_slice(bytes).map_err(|_| "invalid Shroud discovery response")?;
    if !response.ok || response.protocol != "shroud.control.v1" || response.services.len() > 128 {
        return Err("unsupported or failed Shroud discovery response".into());
    }
    let expires_at = now.checked_add(120).ok_or("invalid observation time")?;
    let mut observations = BTreeMap::new();
    let mut aliases = BTreeMap::new();
    for record in response.services {
        if record.power != "running" || record.health != "ready" {
            continue;
        }
        if record.protocol != "tcp" || !matches!(record.scheme.as_str(), "http" | "https") {
            continue;
        }
        if !label(&record.name) || !label(&record.port_name) || record.guest.port == 0 {
            return Err("unsafe Shroud service name or port".into());
        }
        let endpoint = format!(
            "{}://{}.shroud.svc:{}/",
            record.scheme, record.name, record.guest.port
        );
        if aliases
            .insert(record.name.clone(), endpoint.clone())
            .is_some_and(|previous| previous != endpoint)
        {
            return Err("conflicting Shroud service alias endpoints".into());
        }
        let id = format!("service/{node}/shroud/{}/{}", record.name, record.port_name);
        let observation = ServiceObservation {
            schema_version: SCHEMA_VERSION,
            service_id: ServiceId(id.clone()),
            observed_at: now,
            expires_at,
            provenance: Provenance {
                provider: "shroud-discover".into(),
                observer: node.into(),
                source_id: Some("shroud.control.v1/discover".into()),
            },
            confidence: Confidence::Strong,
            value: Service {
                kind: "shroud".into(),
                endpoints: BTreeSet::from([endpoint]),
                protocols: BTreeSet::from([record.scheme]),
                formats: BTreeSet::new(),
                attributes: BTreeMap::from([
                    ("node_id".into(), node.into()),
                    ("service_name".into(), record.name),
                    ("port_name".into(), record.port_name),
                    ("owner_health".into(), "ready".into()),
                ]),
            },
        };
        observations.insert(id, observation);
    }
    let catalog = ServiceCatalog {
        schema_version: SCHEMA_VERSION,
        observations: observations.into_values().collect(),
    };
    if serde_json::to_vec(&catalog)
        .map_err(|e| e.to_string())?
        .len()
        > crate::local_services::MAX_DOCUMENT_BYTES
    {
        return Err("Shroud catalog exceeds owner lease bound".into());
    }
    Ok(catalog)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record() -> serde_json::Value {
        serde_json::json!({"name":"invoker","port_name":"http","protocol":"tcp","scheme":"http","power":"running","health":"ready","guest":{"address":"172.16.0.9","port":8080},"metadata":{"secret":"not-exported"},"vm":"revision-123"})
    }
    fn run(records: Vec<serde_json::Value>) -> Result<ServiceCatalog, String> {
        project(
            &serde_json::to_vec(
                &serde_json::json!({"ok":true,"protocol":"shroud.control.v1","services":records}),
            )
            .unwrap(),
            &"a".repeat(64),
            100,
        )
    }
    #[test]
    fn stable_replica_identity_and_private_metadata_omission() {
        let result = run(vec![record(), record()]).unwrap();
        assert_eq!(result.observations.len(), 1);
        let encoded = serde_json::to_string(&result).unwrap();
        assert!(encoded.contains("http://invoker.shroud.svc:8080/"));
        for private in ["172.16", "revision-123", "not-exported"] {
            assert!(!encoded.contains(private));
        }
        assert!(result.observations[0].is_fresh_at(219));
        assert!(!result.observations[0].is_fresh_at(220));
    }
    #[test]
    fn filters_unready_and_rejects_unsafe_or_conflicting_names() {
        let mut r = record();
        r["health"] = "starting".into();
        assert!(run(vec![r]).unwrap().observations.is_empty());
        let mut r = record();
        r["name"] = "bad/path".into();
        assert!(run(vec![r]).is_err());
        let mut r = record();
        r["guest"]["port"] = 9000.into();
        assert!(run(vec![record(), r]).is_err());
    }
    #[test]
    fn empty_success_withdraws_and_errors_fail_closed() {
        assert!(
            project(
                br#"{"ok":true,"protocol":"shroud.control.v1"}"#,
                &"a".repeat(64),
                1
            )
            .unwrap()
            .observations
            .is_empty()
        );
        assert!(
            project(
                br#"{"ok":false,"protocol":"shroud.control.v1"}"#,
                &"a".repeat(64),
                1
            )
            .is_err()
        );
        assert!(project(&vec![b' '; 262145], &"a".repeat(64), 1).is_err());
    }
}
