use std::time::Duration;

use async_trait::async_trait;
use mycelium_core::{
    CredentialSet, DeviceId, DeviceMeta, Driver, Inventory, MyceliumError, Result, Secret, Target,
};

use crate::client::SnmpHandle;
use crate::device::{classify, SnmpDevice, DEFAULT_SNMP_PORT};

pub const DRIVER_NAME: &str = "snmp";

/// Discovery by GET sysDescr.0: if a device answers SNMP, it is *this*
/// class — vendor inferred from the response, never from config.
pub struct SnmpDriver {
    timeout: Duration,
}

impl Default for SnmpDriver {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(3),
        }
    }
}

impl SnmpDriver {
    fn host_of(target: &Target) -> Result<String> {
        match target {
            Target::Host { host, .. } => Ok(host.clone()),
            Target::Subnet { .. } => Err(MyceliumError::Validation(
                "snmp v0 probes single hosts".into(),
            )),
        }
    }

    fn port_of(target: &Target) -> u16 {
        match target {
            Target::Host { port: Some(p), .. } => *p,
            _ => DEFAULT_SNMP_PORT,
        }
    }

    /// Community resolution (fail loud if an env-named secret is unset):
    /// - username = read community (literal; public ones aren't secrets)
    /// - password env = read community if no username, and doubles as the
    ///   write community (snmp.set needs it; switches rarely split them)
    fn handle(&self, target: &Target, creds: &CredentialSet) -> Result<SnmpHandle> {
        let host = Self::host_of(target)?;
        let port = Self::port_of(target);
        let resolved_password = creds
            .password
            .as_ref()
            .map(|secret| {
                secret.resolve().ok_or_else(|| {
                    let name = match secret {
                        Secret::Env(name) => name.as_str(),
                        Secret::Literal(_) => "literal secret",
                    };
                    MyceliumError::Auth(format!("SNMP community `{name}` is unavailable"))
                })
            })
            .transpose()?;
        let (read, write) = match (&creds.username, resolved_password) {
            (Some(u), pw) => (u.clone(), pw),
            (None, Some(pw)) => (pw.clone(), Some(pw)),
            (None, None) => ("public".to_owned(), None),
        };
        let handle = SnmpHandle::new(host, port, read).with_timeout(self.timeout);
        Ok(match write {
            Some(community) => handle.with_write_community(community),
            None => handle,
        })
    }
}

#[async_trait]
impl Driver for SnmpDriver {
    fn name(&self) -> &str {
        DRIVER_NAME
    }

    async fn recognizes(&self, target: &Target, creds: &CredentialSet) -> Result<bool> {
        let handle = self.handle(target, creds)?;
        match SnmpDevice::probe(&handle).await {
            Ok(info) => Ok(!info.sys_descr.is_empty() || !info.sys_name.is_empty()),
            Err(MyceliumError::Transport(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    async fn attach(
        &self,
        target: &Target,
        creds: &CredentialSet,
        inventory: &Inventory,
    ) -> Result<DeviceId> {
        let handle = self.handle(target, creds)?;
        let host = handle.host.clone();
        let info = SnmpDevice::probe(&handle).await?;
        let (kind, id, model) = classify(&info, &host);
        let meta = DeviceMeta {
            id: DeviceId::new(id),
            kind,
            driver: DRIVER_NAME.to_owned(),
            vendor: Some(crate::device::enterprise_vendor_public(&info.sys_objectid)),
            model: model.filter(|_| !info.sys_descr.is_empty()),
            firmware: None,
            address: format!("{host}:{}", handle.port),
        };
        let id = meta.id.clone();
        inventory.add(std::sync::Arc::new(SnmpDevice::new(handle, meta)));
        Ok(id)
    }
}
