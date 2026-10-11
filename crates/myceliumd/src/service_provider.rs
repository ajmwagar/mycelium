//! Generic validation boundary for sandboxed service discovery dialects.
use fpl_resource_observation::{ServiceCatalog, SCHEMA_VERSION};
use mycelium_plugins_lua::ServiceProvider;

pub fn project(
    provider: &ServiceProvider,
    bytes: &[u8],
    node: &str,
    now: u64,
) -> Result<ServiceCatalog, String> {
    if node.len() != 64
        || !node
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || now > u64::MAX - 300
    {
        return Err("invalid owner identity or observation time".into());
    }
    let response = std::str::from_utf8(bytes).map_err(|_| "service response is not UTF-8")?;
    let value = provider
        .project(
            response,
            serde_json::json!({
                "schema_version": SCHEMA_VERSION, "node_id": node,
                "observed_at": now, "empty_array": [],
            }),
        )
        .map_err(|e| e.to_string())?;
    let catalog: ServiceCatalog =
        serde_json::from_value(value).map_err(|_| "provider returned invalid service catalog")?;
    // Reuse the owner-lease validator; plugins cannot mint alternate authority,
    // credentials, unbounded metadata, duplicate IDs or unsupported validity.
    let encoded = serde_json::to_vec(&catalog).map_err(|e| e.to_string())?;
    crate::local_services::observe(&encoded, node, now)?;
    if catalog
        .observations
        .iter()
        .any(|o| o.observed_at != now || !o.is_fresh_at(now))
    {
        return Err("provider returned a stale or fabricated observation time".into());
    }
    Ok(catalog)
}

#[cfg(test)]
mod tests {
    use super::*;
    const SHROUD: &str = include_str!("../../mycelium-plugins-lua/plugins/shroud.lua");
    fn record() -> serde_json::Value {
        serde_json::json!({"name":"invoker","port_name":"http","protocol":"tcp","scheme":"http","power":"running","health":"ready","guest":{"address":"172.16.0.9","port":8080},"metadata":{"secret":"not-exported"},"vm":"revision-123"})
    }
    fn run(records: Vec<serde_json::Value>) -> Result<ServiceCatalog, String> {
        let provider = ServiceProvider::load(SHROUD).unwrap();
        project(
            &provider,
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
    fn empty_success_and_failed_response() {
        let p = ServiceProvider::load(SHROUD).unwrap();
        assert_eq!(
            p.request().unwrap(),
            serde_json::json!({"action":"discover","includeUnready":false})
        );
        assert!(project(
            &p,
            br#"{"ok":true,"protocol":"shroud.control.v1"}"#,
            &"a".repeat(64),
            100
        )
        .unwrap()
        .observations
        .is_empty());
        assert!(project(
            &p,
            br#"{"ok":false,"protocol":"shroud.control.v1"}"#,
            &"a".repeat(64),
            100
        )
        .is_err());
    }
    #[test]
    fn provider_cannot_bypass_host_validation() {
        let source = r#"service_provider = {name='fake', request={}, project=function(_,c)
          return {schema_version=c.schema_version, observations={{schema_version=c.schema_version,
          service_id='service/fake', observed_at=c.observed_at, expires_at=c.observed_at+120,
          provenance={provider='fake',observer='somebody-else'}, confidence='strong',
          value={kind='fake',endpoints={'https://user:secret@example.com/'}}}}}
        end}"#;
        assert!(project(
            &ServiceProvider::load(source).unwrap(),
            b"{}",
            &"a".repeat(64),
            100
        )
        .is_err());
    }
    #[test]
    fn sandbox_is_bounded_and_vendor_neutral() {
        assert!(ServiceProvider::load("while true do end").is_err());
        let p = ServiceProvider::load("service_provider={name='other',request={action='list'},project=function(_,c) assert(os==nil and io==nil and require==nil); return {schema_version=c.schema_version,observations=c.empty_array} end}").unwrap();
        assert!(project(&p, b"{}", &"a".repeat(64), 100)
            .unwrap()
            .observations
            .is_empty());
        let p = ServiceProvider::load(
            "service_provider={name='loop',request={},project=function() while true do end end}",
        )
        .unwrap();
        assert!(project(&p, b"{}", &"a".repeat(64), 100).is_err());
        assert!(project(&p, &vec![b' '; 262145], &"a".repeat(64), 100).is_err());
    }
}
