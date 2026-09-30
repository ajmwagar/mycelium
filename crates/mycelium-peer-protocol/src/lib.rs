//! Symmetric, transport-neutral messages exchanged by Mycelium peers.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Linux,
    Darwin,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerHello {
    /// Hex-encoded Ed25519 public key; also the stable node identity.
    pub node_id: String,
    pub protocol_version: u16,
    pub site: String,
    pub hostname: String,
    pub platform: Platform,
    pub architecture: String,
    pub daemon_version: String,
    pub capabilities: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FilesystemHealth {
    pub mount: String,
    pub total_bytes: u64,
    pub available_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProcessHealth {
    pub pid: u32,
    pub name: String,
    pub cpu_percent: f32,
    pub memory_percent: f32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HostHealth {
    pub observed_at: u64,
    pub uptime_seconds: u64,
    pub load_average: [f64; 3],
    pub logical_cpus: u32,
    pub memory_total_bytes: u64,
    pub memory_available_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_free_bytes: u64,
    pub filesystems: Vec<FilesystemHealth>,
    pub process_leaders: Vec<ProcessHealth>,
    pub ssh_listening: bool,
    pub established_ssh_sessions: u32,
    #[serde(default)]
    pub platform_metrics: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum PeerEvent {
    Hello(PeerHello),
    Health(HostHealth),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignedEnvelope {
    pub origin: String,
    pub sequence: u64,
    pub emitted_at: u64,
    pub event: PeerEvent,
    pub signature: String,
}

#[derive(Serialize)]
struct Signable<'a> {
    origin: &'a str,
    sequence: u64,
    emitted_at: u64,
    event: &'a PeerEvent,
}

impl SignedEnvelope {
    pub fn sign(
        key: &SigningKey,
        sequence: u64,
        emitted_at: u64,
        event: PeerEvent,
    ) -> Result<Self, serde_json::Error> {
        let origin = encode_hex(key.verifying_key().as_bytes());
        let bytes = serde_json::to_vec(&Signable {
            origin: &origin,
            sequence,
            emitted_at,
            event: &event,
        })?;
        let signature = encode_hex(&key.sign(&bytes).to_bytes());
        Ok(Self {
            origin,
            sequence,
            emitted_at,
            event,
            signature,
        })
    }

    pub fn verify(&self) -> Result<(), String> {
        let public = decode_array::<32>(&self.origin)?;
        let signature = Signature::from_bytes(&decode_array::<64>(&self.signature)?);
        let key = VerifyingKey::from_bytes(&public).map_err(|error| error.to_string())?;
        let bytes = serde_json::to_vec(&Signable {
            origin: &self.origin,
            sequence: self.sequence,
            emitted_at: self.emitted_at,
            event: &self.event,
        })
        .map_err(|error| error.to_string())?;
        key.verify(&bytes, &signature)
            .map_err(|error| error.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum PeerMessage {
    Hello(PeerHello),
    Digest(BTreeMap<String, u64>),
    Observations(Vec<SignedEnvelope>),
    Ping { sent_at: u64 },
}

pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn decode_array<const N: usize>(text: &str) -> Result<[u8; N], String> {
    if text.len() != N * 2 {
        return Err(format!("expected {} hex characters", N * 2));
    }
    let mut output = [0_u8; N];
    for (index, slot) in output.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invalid hex".to_owned())?;
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwarded_envelopes_remain_origin_authenticated() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let event = PeerEvent::Hello(PeerHello {
            node_id: encode_hex(key.verifying_key().as_bytes()),
            protocol_version: PROTOCOL_VERSION,
            site: "home".into(),
            hostname: "node".into(),
            platform: Platform::Linux,
            architecture: "x86_64".into(),
            daemon_version: "0.1.0".into(),
            capabilities: vec!["system.health".into()],
        });
        let mut envelope = SignedEnvelope::sign(&key, 1, 2, event).unwrap();
        envelope.verify().unwrap();
        envelope.sequence = 3;
        assert!(envelope.verify().is_err());
    }
}
