use std::time::Duration;

use async_trait::async_trait;
use mycelium_core::{
    CredentialSet, DeviceId, DeviceKind, DeviceMeta, Driver, Inventory, MyceliumError, Result,
    Target,
};

use crate::device::{EdgeOsDevice, DRIVER_NAME};
use crate::transport::SshSession;

/// Discovery of EdgeOS/vyos appliances over SSH: recognize by probing
/// `show version` (the vyos banner), never by a configured vendor label.
pub struct EdgeOsDriver {
    connect_timeout: Duration,
}

impl Default for EdgeOsDriver {
    fn default() -> Self {
        Self { connect_timeout: Duration::from_secs(8) }
    }
}

impl EdgeOsDriver {
    pub fn with_timeout(connect_timeout: Duration) -> Self {
        Self { connect_timeout }
    }

    fn port_of(target: &Target) -> u16 {
        match target {
            Target::Host { port: Some(p), .. } => *p,
            _ => crate::DEFAULT_PORT,
        }
    }

    fn jump_of(target: &Target) -> Option<String> {
        match target {
            Target::Host { jump, .. } => jump.clone(),
            Target::Subnet { .. } => None,
        }
    }

    fn host_of(target: &Target) -> Result<&str> {
        match target {
            Target::Host { host, .. } => Ok(host),
            Target::Subnet { .. } => Err(MyceliumError::Validation(
                "edgeos v0 probes single hosts; subnet scan is a daemon-side fan-out".into(),
            )),
        }
    }

    /// Device id slug: model-tail + address, sanitized, e.g. `edgerouter-10x-10-0-7-1`.
    fn slug(model: Option<&str>, host: &str) -> DeviceId {
        let tail = model
            .map(|m| {
                m.split_whitespace()
                    .last()
                    .unwrap_or(m)
                    .to_lowercase()
                    .replace(|c: char| !(c.is_ascii_alphanumeric()), "-")
            })
            .unwrap_or_else(|| "vyos".into());
        let host_part = host
            .replace(|c: char| !(c.is_ascii_alphanumeric()), "-")
            .trim_matches('-')
            .to_owned();
        DeviceId::new(format!("{tail}-{host_part}"))
    }
}

#[async_trait]
impl Driver for EdgeOsDriver {
    fn name(&self) -> &str {
        DRIVER_NAME
    }

    async fn recognizes(&self, target: &Target, creds: &CredentialSet) -> Result<bool> {
        let host = Self::host_of(target)?;
        let jump = Self::jump_of(target);
        let session = match SshSession::connect(host, Self::port_of(target), creds, self.connect_timeout, jump.as_deref()).await {
            Ok(s) => s,
            // Unreachable/refused => not this class. But bad credentials is
            // the user's error, not a negative observation: fail loud.
            Err(MyceliumError::Auth(_)) => return Err(MyceliumError::Auth(format!("{host}: {}", creds.username().unwrap_or("?")))),
            Err(e) => {
                eprintln!("edgeos: recognize {host} failed: {e}");
                return Ok(false);
            }
        };
        match session.cli("show version").await {
            Ok(out) if out.success() => {
                let text = out.stdout;
                let hit = text.contains("vyos")
                    || text.contains("EdgeOS")
                    || text.contains("EdgeRouter")
                    || text.contains("EdgeRunner")
                    || text.contains("Ubiquiti");
                if !hit {
                    eprintln!("edgeos: {host} banner matched no known marker:\n{}", &text[..text.len().min(400)]);
                }
                Ok(hit)
            }
            Ok(out) => {
                eprintln!(
                    "edgeos: {host} probe exit {}: {}",
                    out.exit_code,
                    out.stderr.trim().lines().next().unwrap_or("")
                );
                Ok(false)
            }
            Err(e) => {
                eprintln!("edgeos: recognize {host} probe failed: {e}");
                Ok(false)
            }
        }
    }

    async fn attach(&self, target: &Target, creds: &CredentialSet, inventory: &Inventory) -> Result<DeviceId> {
        let host = Self::host_of(target)?.to_owned();
        let jump = Self::jump_of(target);
        let session =
            SshSession::connect(&host, Self::port_of(target), creds, self.connect_timeout, jump.as_deref()).await?;
        let (identity, config) = EdgeOsDevice::identify(&session).await?;
        let model = identity.model.clone().or_else(|| config.hostname.clone());
        let kind = model.as_deref().map(classify).unwrap_or(DeviceKind::Router);
        let meta = DeviceMeta {
            id: Self::slug(identity.model.as_deref(), &host),
            kind,
            driver: DRIVER_NAME.to_owned(),
            vendor: identity.vendor,
            model: identity.model,
            firmware: identity.firmware,
            address: host,
        };
        let id = meta.id.clone();
        inventory.add(std::sync::Arc::new(EdgeOsDevice::new(session, meta)));
        Ok(id)
    }
}

fn classify(model: &str) -> DeviceKind {
    let m = model.to_lowercase();
    if m.contains("switch") || m.starts_with("es-") || m.contains("epx") {
        DeviceKind::Switch
    } else {
        DeviceKind::Router
    }
}
