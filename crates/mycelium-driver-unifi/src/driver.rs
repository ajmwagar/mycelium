use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use mycelium_core::{
    CapResult, CapSpec, CredentialSet, Device, DeviceId, DeviceKind, DeviceMeta, Driver,
    ExecContext, Inventory, MyceliumError, ParamType, Params, Result, Target, Value, ID_IDENTIFY,
    ID_WLAN_LIST_SSID,
};
use mycelium_driver_edgeos::SshSession;

use crate::parsers::{fields, slug};

pub const DRIVER_NAME: &str = "unifi";
const ID_STATUS: &str = "unifi.status";
const ID_STATIONS: &str = "wlan.list-stations";
const ID_SET_INFORM: &str = "unifi.set-inform";
const ID_REBOOT: &str = "system.reboot";
const INFO_COMMAND: &str = "mca-cli-op info 2>/dev/null || info 2>/dev/null";

pub struct UnifiDriver {
    timeout: Duration,
}

impl Default for UnifiDriver {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(8),
        }
    }
}

pub struct UnifiDevice {
    session: SshSession,
    meta: DeviceMeta,
    identity: BTreeMap<String, String>,
}

fn host(target: &Target) -> Result<(&str, u16, Option<&str>)> {
    match target {
        Target::Host { host, port, jump } => Ok((host, port.unwrap_or(22), jump.as_deref())),
        Target::Subnet { .. } => Err(MyceliumError::Validation(
            "UniFi attachment needs one AP address".into(),
        )),
    }
}

async fn identify(session: &SshSession) -> Result<BTreeMap<String, String>> {
    let output = session.exec(INFO_COMMAND).await?;
    if !output.success() {
        return Err(MyceliumError::Device {
            exit_code: output.exit_code,
            stderr: output.stderr,
        });
    }
    let identity = fields(&output.stdout);
    let model = identity
        .get("model")
        .map(String::as_str)
        .unwrap_or_default();
    if !model.to_ascii_uppercase().contains("UAP") {
        return Err(MyceliumError::Validation(
            "SSH target did not report a UniFi AP model".into(),
        ));
    }
    Ok(identity)
}

#[async_trait]
impl Driver for UnifiDriver {
    fn name(&self) -> &str {
        DRIVER_NAME
    }

    async fn recognizes(&self, target: &Target, creds: &CredentialSet) -> Result<bool> {
        let (host, port, jump) = host(target)?;
        let session = SshSession::connect(host, port, creds, self.timeout, jump).await?;
        Ok(identify(&session).await.is_ok())
    }

    async fn attach(
        &self,
        target: &Target,
        creds: &CredentialSet,
        inventory: &Inventory,
    ) -> Result<DeviceId> {
        let (host, port, jump) = host(target)?;
        let session = SshSession::connect(host, port, creds, self.timeout, jump).await?;
        let identity = identify(&session).await?;
        let model = identity.get("model").cloned();
        let firmware = identity.get("version").cloned();
        let stable = identity
            .get("mac_address")
            .or_else(|| identity.get("hostname"))
            .map(|value| slug(value))
            .unwrap_or_else(|| slug(host));
        let meta = DeviceMeta {
            id: DeviceId::new(format!("unifi-{stable}")),
            kind: DeviceKind::AccessPoint,
            driver: DRIVER_NAME.into(),
            vendor: Some("Ubiquiti".into()),
            model,
            firmware,
            address: host.to_owned(),
        };
        let id = meta.id.clone();
        inventory.add(Arc::new(UnifiDevice {
            session,
            meta,
            identity,
        }));
        Ok(id)
    }
}

#[async_trait]
impl Device for UnifiDevice {
    fn meta(&self) -> &DeviceMeta {
        &self.meta
    }

    fn capabilities(&self) -> BTreeMap<String, CapSpec> {
        BTreeMap::from_iter([
            (
                ID_IDENTIFY.into(),
                CapSpec::readonly("UniFi AP identity and firmware"),
            ),
            (
                ID_STATUS.into(),
                CapSpec::readonly("adoption state and controller inform URL"),
            ),
            (
                ID_WLAN_LIST_SSID.into(),
                CapSpec::readonly("configured radio interfaces and SSIDs"),
            ),
            (
                ID_STATIONS.into(),
                CapSpec::readonly("currently associated wireless stations"),
            ),
            (
                ID_SET_INFORM.into(),
                CapSpec::mutation("change the UniFi controller inform URL").param(
                    "url",
                    ParamType::Str,
                    "HTTP(S) controller inform URL",
                ),
            ),
            (
                ID_REBOOT.into(),
                CapSpec::mutation("reboot the access point"),
            ),
        ])
    }

    async fn exec(&self, ctx: &ExecContext, cap: &str, params: Params) -> Result<CapResult> {
        match cap {
            ID_IDENTIFY => Ok(CapResult::ok(string_map(&self.identity))),
            ID_STATUS => self.run_read(INFO_COMMAND).await,
            ID_WLAN_LIST_SSID => self.run_read("iwconfig 2>/dev/null").await,
            ID_STATIONS => self.run_json("wstalist 2>/dev/null").await,
            ID_SET_INFORM => {
                let url = string_param(&params, "url")?;
                validate_inform_url(url)?;
                let command = format!("set-inform {}", shell_quote(url));
                if ctx.dry_run {
                    return Ok(CapResult::dry_run(Value::List(vec![Value::Str(command)])));
                }
                self.run_read(&command).await
            }
            ID_REBOOT => {
                if ctx.dry_run {
                    return Ok(CapResult::dry_run(Value::List(vec![Value::Str(
                        "reboot".into(),
                    )])));
                }
                self.run_read("reboot").await
            }
            other => Err(MyceliumError::Unsupported {
                device: self.meta.id.to_string(),
                capability: other.into(),
            }),
        }
    }
}

impl UnifiDevice {
    async fn run_read(&self, command: &str) -> Result<CapResult> {
        let output = self.session.exec(command).await?;
        if output.success() {
            Ok(CapResult::ok(Value::Str(output.stdout.trim().to_owned())))
        } else {
            Err(MyceliumError::Device {
                exit_code: output.exit_code,
                stderr: output.stderr,
            })
        }
    }

    async fn run_json(&self, command: &str) -> Result<CapResult> {
        let output = self.session.exec(command).await?;
        if !output.success() {
            return Err(MyceliumError::Device {
                exit_code: output.exit_code,
                stderr: output.stderr,
            });
        }
        let json: serde_json::Value = serde_json::from_str(output.stdout.trim())
            .map_err(|error| MyceliumError::Parse(format!("AP returned invalid JSON: {error}")))?;
        Ok(CapResult::ok(Value::from_json(&json)))
    }
}

fn string_map(values: &BTreeMap<String, String>) -> Value {
    Value::Map(
        values
            .iter()
            .map(|(key, value)| (key.clone(), Value::Str(value.clone())))
            .collect(),
    )
}

fn string_param<'a>(params: &'a Params, name: &str) -> Result<&'a str> {
    params
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| MyceliumError::Validation(format!("`{name}` must be a string")))
}

fn validate_inform_url(url: &str) -> Result<()> {
    let valid_scheme = url.starts_with("http://") || url.starts_with("https://");
    let unsafe_character = url
        .chars()
        .any(|character| character.is_whitespace() || matches!(character, '\'' | '"' | '`'));
    if !valid_scheme || unsafe_character {
        return Err(MyceliumError::Validation(
            "inform URL must be an HTTP(S) URL without whitespace or quotes".into(),
        ));
    }
    Ok(())
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_inform_urls_before_shell_use() {
        assert!(validate_inform_url("http://192.168.99.20:8080/inform").is_ok());
        assert!(validate_inform_url("https://controller.example/inform").is_ok());
        assert!(validate_inform_url("file:///tmp/nope").is_err());
        assert!(validate_inform_url("http://ok/; reboot").is_err());
        assert!(validate_inform_url("http://ok/'bad'").is_err());
    }
}
