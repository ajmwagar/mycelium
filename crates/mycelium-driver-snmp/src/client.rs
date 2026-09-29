use std::net::IpAddr;
use std::time::Duration;

use async_snmp::{Auth, Oid, Retry, UdpClient, Value as Snm};
use mycelium_core::{MyceliumError, Result, Value};

/// Thin reusable wrapper around an async-snmp UDP client.
#[derive(Clone)]
pub struct SnmpHandle {
    pub host: String,
    pub port: u16,
    /// read community
    pub community: String,
    /// write community (None => v2c SET refused explicitly, no silent reuse)
    pub write_community: Option<String>,
    timeout: Duration,
}

pub type VarBind = (String, Value);

impl SnmpHandle {
    pub fn new(host: impl Into<String>, port: u16, community: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port,
            community: community.into(),
            write_community: None,
            timeout: Duration::from_secs(3),
        }
    }

    pub fn with_write_community(mut self, c: impl Into<String>) -> Self {
        self.write_community = Some(c.into());
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn target(&self) -> (String, u16) {
        (self.host.clone(), self.port)
    }

    async fn client(&self, community: &str) -> Result<UdpClient> {
        UdpClient::builder(self.target(), Auth::v2c(community.to_owned()))
            .request_timeout(self.timeout)
            .retry(Retry::none())
            .connect()
            .await
            .map_err(|e| MyceliumError::Transport(e.to_string()))
    }

    pub async fn get(&self, oids: &[String]) -> Result<Vec<VarBind>> {
        let parsed: Vec<Oid> = oids
            .iter()
            .map(|o| Oid::parse(o).map_err(|e| MyceliumError::Parse(format!("oid `{o}`: {e}"))))
            .collect::<std::result::Result<_, _>>()?;
        let client = self.client(&self.community).await?;
        let resp = client
            .get_many(&parsed)
            .await
            .map_err(|e| MyceliumError::Transport(e.to_string()))?;
        Ok(resp.varbinds.iter().map(convert_vb).collect())
    }

    /// Single-OID GET; None for exceptions (noSuchObject/Instance/EndOfMib).
    pub async fn get_one(&self, oid: &str) -> Result<Option<Value>> {
        let vb = self.get(&[oid.to_owned()]).await?;
        Ok(vb.into_iter().next().map(|(_, v)| v))
    }

    pub async fn walk(&self, root: &str, limit: usize) -> Result<Vec<VarBind>> {
        let oid =
            Oid::parse(root).map_err(|e| MyceliumError::Parse(format!("oid `{root}`: {e}")))?;
        let client = self.client(&self.community).await?;
        let mut stream = client
            .walk(oid)
            .map_err(|e| MyceliumError::Transport(e.to_string()))?;
        let mut out = Vec::new();
        while let Some(item) = stream.next().await {
            match item {
                Ok(vb) => {
                    let (_, v) = convert_vb(&vb);
                    if matches!(v, Value::Null) {
                        // walk end markers arrive as exception values
                        break;
                    }
                    out.push((vb.oid.to_string(), v));
                    if out.len() >= limit {
                        break;
                    }
                }
                Err(e) => return Err(MyceliumError::Transport(e.to_string())),
            }
        }
        Ok(out)
    }

    pub async fn set(&self, oid: &str, value: Value) -> Result<VarBind> {
        let community = self.write_community.as_ref().ok_or_else(|| {
            MyceliumError::Auth("no write community configured for this device".into())
        })?;
        let parsed =
            Oid::parse(oid).map_err(|e| MyceliumError::Parse(format!("oid `{oid}`: {e}")))?;
        let wire = to_snmp_value(&parsed, value)?;
        let client = self.client(community).await?;
        let resp = client
            .set(&parsed, wire)
            .await
            .map_err(|e| MyceliumError::Transport(e.to_string()))?;
        let vb = resp
            .varbinds
            .first()
            .ok_or_else(|| MyceliumError::Transport("empty SET response".into()))?;
        Ok(convert_vb(vb))
    }
}

fn convert_vb(vb: &async_snmp::VarBind) -> VarBind {
    (vb.oid.to_string(), convert(vb))
}

fn convert(vb: &async_snmp::VarBind) -> Value {
    value_of(&vb.value)
}

pub fn value_of(v: &Snm) -> Value {
    match v {
        Snm::Integer(i) => Value::Int(*i as i64),
        Snm::Counter32(c) | Snm::Gauge32(c) | Snm::UInteger32(c) | Snm::TimeTicks(c) => {
            Value::Int(*c as i64)
        }
        Snm::Counter64(c) => Value::Int(*c as i64),
        Snm::IpAddress(octets) => Value::Str(IpAddr::from(*octets).to_string()),
        Snm::ObjectIdentifier(o) => Value::Str(o.to_string()),
        Snm::OctetString(b) | Snm::Opaque(b) | Snm::Nsap(b) => {
            // SMIv2 says MAC addresses are octet strings: render 6-byte
            // values as MACs, 4-byte as nothing special, else UTF-8/hex.
            if b.len() == 6 {
                Value::Str(hex_mac(b))
            } else if let Some(s) = std::str::from_utf8(b).ok() {
                Value::Str(s.to_owned())
            } else {
                Value::Str(hex_bytes(b))
            }
        }
        Snm::Null => Value::Null,
        Snm::NoSuchObject | Snm::NoSuchInstance | Snm::EndOfMibView => Value::Null,
        _ => Value::Str(format!("{v:?}")),
    }
}

fn hex_mac(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn hex_bytes(b: &[u8]) -> String {
    format!(
        "0x{}",
        b.iter().map(|x| format!("{x:02x}")).collect::<String>()
    )
}

fn to_snmp_value(_oid: &Oid, v: Value) -> Result<Snm> {
    let v = match v {
        Value::Int(i) => Snm::Integer(i as i32),
        Value::Str(s) => {
            if let Some(rest) = s.strip_prefix("hex:") {
                let bytes = (0..rest.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&rest[i..i + 2], 16))
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(|e| MyceliumError::Validation(format!("bad hex value: {e}")))?;
                Snm::OctetString(bytes::Bytes::from(bytes))
            } else {
                Snm::OctetString(s.clone().into())
            }
        }
        other => {
            return Err(MyceliumError::Validation(format!(
                "snmp SET accepts int or string values, got {other:?}"
            )))
        }
    };
    Ok(v)
}
