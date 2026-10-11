//! Host page owns its availability lease; discovery, naming and grants remain
//! separate. Uses the same application-owner contract as external applications.
use fpl_resource_observation::{
    Confidence, Provenance, Service, ServiceCatalog, ServiceId, ServiceObservation, SCHEMA_VERSION,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    net::SocketAddr,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn catalog(node: &str, address: SocketAddr, now: u64) -> ServiceCatalog {
    ServiceCatalog {
        schema_version: SCHEMA_VERSION,
        observations: vec![ServiceObservation {
            schema_version: SCHEMA_VERSION,
            service_id: ServiceId(format!("service/{node}/mycelium/host-web")),
            observed_at: now,
            expires_at: now.saturating_add(120),
            provenance: Provenance {
                provider: "mycelium-host-web".into(),
                observer: node.into(),
                source_id: None,
            },
            confidence: Confidence::Strong,
            value: Service {
                kind: "mycelium-host-web".into(),
                endpoints: BTreeSet::from([format!("https://{address}")]),
                protocols: BTreeSet::from(["https".into(), "mtls".into()]),
                formats: BTreeSet::from(["html".into(), "json".into()]),
                attributes: BTreeMap::from([
                    ("node_id".into(), node.into()),
                    ("authentication".into(), "signed-grant".into()),
                ]),
            },
        }],
    }
}
pub(crate) fn publish(home: &Path, node: &str, address: SocketAddr) -> Result<()> {
    if address.ip().is_loopback() || address.ip().is_unspecified() || address.ip().is_multicast() {
        return Err("refusing unservable host page advertisement".into());
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let document = catalog(node, address, now);
    // Validate through the owning contract before making the document visible.
    let bytes = serde_json::to_vec(&document)?;
    crate::local_services::observe(&bytes, node, now)?;
    let directory = home.join("application-services.d");
    std::fs::create_dir_all(&directory)?;
    let path = directory.join("mycelium-host-web.json");
    if let Ok(metadata) = std::fs::symlink_metadata(&path) {
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err("refusing nonregular host page owner document".into());
        }
        let mut previous = Vec::new();
        std::fs::File::open(&path)?
            .take(65537)
            .read_to_end(&mut previous)?;
        if previous.len() > 65536 {
            return Err("host page owner document exceeds bounds".into());
        }
        let previous: ServiceCatalog = serde_json::from_slice(&previous)?;
        if previous.observations.len() != 1
            || previous.observations[0].service_id != document.observations[0].service_id
            || previous.observations[0].provenance.provider != "mycelium-host-web"
            || previous.observations[0].provenance.observer != node
        {
            return Err("refusing another application's owner document".into());
        }
    }
    let pending = directory.join(format!(
        ".host-web-{}-{}.pending",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| -> Result<()> {
        let mut file = options.open(&pending)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&pending, &path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&pending);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn page_lease_uses_the_existing_owner_contract() {
        let c = catalog("neo", "192.0.2.12:8443".parse().unwrap(), 1000);
        assert_eq!(c.observations[0].expires_at, 1120);
        assert_eq!(
            crate::local_services::observe(&serde_json::to_vec(&c).unwrap(), "neo", 1000)
                .unwrap()
                .len(),
            1
        );
        assert!(publish(
            Path::new("/not-written"),
            "neo",
            "127.0.0.1:8443".parse().unwrap()
        )
        .is_err());
    }
    #[test]
    fn page_owner_file_can_renew_without_overwriting_another_owner() {
        let home = std::env::temp_dir().join(format!(
            "mycelium-page-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&home).unwrap();
        let address = "192.0.2.12:8443".parse().unwrap();
        publish(&home, "neo", address).unwrap();
        publish(&home, "neo", address).unwrap();
        assert!(publish(&home, "other", address).is_err());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(
            crate::local_services::observe_sources(&home, "neo", now)
                .unwrap()
                .len(),
            1
        );
        std::fs::remove_dir_all(home).unwrap();
    }
}
