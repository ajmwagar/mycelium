//! Symmetric, transport-neutral messages exchanged by Mycelium peers.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
    Release(ReleaseManifest),
    Access(AccessRecord),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AccessStatement {
    Grant {
        grant_id: String,
        principal: String,
        serial: u64,
        #[serde(default)]
        roles: Vec<String>,
        #[serde(default)]
        scopes: Vec<String>,
        #[serde(default)]
        unix_users: Vec<String>,
        #[serde(default)]
        ssh_public_keys: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        oidc_audiences: Vec<String>,
        #[serde(default, skip_serializing_if = "is_false")]
        oidc_ssh_key_exchange: bool,
        not_before: u64,
        not_after: u64,
    },
    Revoke {
        revocation_id: String,
        #[serde(default)]
        grant_id: Option<String>,
        #[serde(default)]
        principal: Option<String>,
        #[serde(default)]
        serial: Option<u64>,
        revoked_at: u64,
        reason: String,
    },
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl AccessStatement {
    pub fn revokes(&self, grant: &AccessStatement) -> bool {
        let Self::Revoke {
            grant_id,
            principal,
            serial,
            ..
        } = self
        else {
            return false;
        };
        let Self::Grant {
            grant_id: candidate_id,
            principal: candidate_principal,
            serial: candidate_serial,
            ..
        } = grant
        else {
            return false;
        };
        grant_id.as_ref().is_none_or(|value| value == candidate_id)
            && principal
                .as_ref()
                .is_none_or(|value| value == candidate_principal)
            && serial.is_none_or(|value| value == *candidate_serial)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessRecord {
    pub protocol_version: u16,
    pub statement: AccessStatement,
    pub signer: String,
    pub signature: String,
}

#[derive(Serialize)]
struct UnsignedAccess<'a> {
    protocol_version: u16,
    statement: &'a AccessStatement,
    signer: &'a str,
}

impl AccessRecord {
    pub fn sign(key: &SigningKey, statement: AccessStatement) -> Result<Self, serde_json::Error> {
        let signer = encode_hex(key.verifying_key().as_bytes());
        let bytes = serde_json::to_vec(&UnsignedAccess {
            protocol_version: PROTOCOL_VERSION,
            statement: &statement,
            signer: &signer,
        })?;
        Ok(Self {
            protocol_version: PROTOCOL_VERSION,
            statement,
            signer,
            signature: encode_hex(&key.sign(&bytes).to_bytes()),
        })
    }

    pub fn verify(&self) -> Result<(), String> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(format!("unsupported protocol {}", self.protocol_version));
        }
        let key = VerifyingKey::from_bytes(&decode_array::<32>(&self.signer)?)
            .map_err(|error| error.to_string())?;
        let signature = Signature::from_bytes(&decode_array::<64>(&self.signature)?);
        let bytes = serde_json::to_vec(&UnsignedAccess {
            protocol_version: self.protocol_version,
            statement: &self.statement,
            signer: &self.signer,
        })
        .map_err(|error| error.to_string())?;
        key.verify(&bytes, &signature)
            .map_err(|error| error.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseManifest {
    pub version: String,
    pub channel: String,
    pub target: String,
    pub protocol_version: u16,
    pub artifact_digest: String,
    pub artifact_size: u64,
    pub signer: String,
    pub signature: String,
}

#[derive(Serialize)]
struct UnsignedRelease<'a> {
    version: &'a str,
    channel: &'a str,
    target: &'a str,
    protocol_version: u16,
    artifact_digest: &'a str,
    artifact_size: u64,
    signer: &'a str,
}

impl ReleaseManifest {
    pub fn sign(
        key: &SigningKey,
        version: String,
        channel: String,
        target: String,
        artifact: &[u8],
    ) -> Result<Self, serde_json::Error> {
        let signer = encode_hex(key.verifying_key().as_bytes());
        let artifact_digest = sha256_hex(artifact);
        let artifact_size = artifact.len() as u64;
        let bytes = serde_json::to_vec(&UnsignedRelease {
            version: &version,
            channel: &channel,
            target: &target,
            protocol_version: PROTOCOL_VERSION,
            artifact_digest: &artifact_digest,
            artifact_size,
            signer: &signer,
        })?;
        Ok(Self {
            version,
            channel,
            target,
            protocol_version: PROTOCOL_VERSION,
            artifact_digest,
            artifact_size,
            signer,
            signature: encode_hex(&key.sign(&bytes).to_bytes()),
        })
    }

    pub fn verify(&self) -> Result<(), String> {
        let key = VerifyingKey::from_bytes(&decode_array::<32>(&self.signer)?)
            .map_err(|error| error.to_string())?;
        let signature = Signature::from_bytes(&decode_array::<64>(&self.signature)?);
        let bytes = serde_json::to_vec(&UnsignedRelease {
            version: &self.version,
            channel: &self.channel,
            target: &self.target,
            protocol_version: self.protocol_version,
            artifact_digest: &self.artifact_digest,
            artifact_size: self.artifact_size,
            signer: &self.signer,
        })
        .map_err(|error| error.to_string())?;
        key.verify(&bytes, &signature)
            .map_err(|error| error.to_string())
    }
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
    Ping {
        sent_at: u64,
    },
    ArtifactRequest {
        digest: String,
        offset: u64,
        length: u32,
    },
    ArtifactChunk {
        digest: String,
        offset: u64,
        data: String,
        complete: bool,
    },
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    encode_hex(&Sha256::digest(bytes))
}

pub fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    if text.len() % 2 != 0 {
        return Err("hex value must contain pairs of characters".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&text[index..index + 2], 16).map_err(|_| "invalid hex".to_owned())
        })
        .collect()
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

    #[test]
    fn release_signature_authorizes_exact_artifact() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let mut release = ReleaseManifest::sign(
            &key,
            "1.2.3".into(),
            "canary".into(),
            "aarch64-apple-darwin".into(),
            b"binary",
        )
        .unwrap();
        release.verify().unwrap();
        release.artifact_size += 1;
        assert!(release.verify().is_err());
    }

    #[test]
    fn access_signature_covers_authorization_and_revocation_fields() {
        let key = SigningKey::from_bytes(&[11; 32]);
        let mut record = AccessRecord::sign(
            &key,
            AccessStatement::Grant {
                grant_id: "avery-laptop".into(),
                principal: "avery".into(),
                serial: 42,
                roles: vec!["operator".into()],
                scopes: vec!["home".into()],
                unix_users: vec!["avery".into()],
                ssh_public_keys: vec!["ssh-ed25519 AAAA".into()],
                oidc_audiences: vec![],
                oidc_ssh_key_exchange: false,
                not_before: 10,
                not_after: 20,
            },
        )
        .unwrap();
        let encoded = serde_json::to_value(&record.statement).unwrap();
        assert!(encoded.get("oidc_audiences").is_none());
        assert!(encoded.get("oidc_ssh_key_exchange").is_none());
        record.verify().unwrap();
        if let AccessStatement::Grant { scopes, .. } = &mut record.statement {
            scopes.push("prod".into());
        }
        assert!(record.verify().is_err());
    }

    #[test]
    fn access_revocation_matches_all_supplied_selectors() {
        let grant = AccessStatement::Grant {
            grant_id: "avery-laptop".into(),
            principal: "avery".into(),
            serial: 42,
            roles: vec![],
            scopes: vec![],
            unix_users: vec![],
            ssh_public_keys: vec![],
            oidc_audiences: vec![],
            oidc_ssh_key_exchange: false,
            not_before: 10,
            not_after: 20,
        };
        let matching = AccessStatement::Revoke {
            revocation_id: "lost-laptop".into(),
            grant_id: None,
            principal: Some("avery".into()),
            serial: Some(42),
            revoked_at: 15,
            reason: "lost".into(),
        };
        let wrong_serial = AccessStatement::Revoke {
            revocation_id: "wrong-serial".into(),
            grant_id: None,
            principal: Some("avery".into()),
            serial: Some(43),
            revoked_at: 15,
            reason: "lost".into(),
        };
        assert!(matching.revokes(&grant));
        assert!(!wrong_serial.revokes(&grant));
    }

    #[test]
    fn documented_access_statements_match_the_protocol() {
        let grant: AccessStatement =
            serde_json::from_str(include_str!("../../../docs/examples/access-grant.json")).unwrap();
        let revocation: AccessStatement = serde_json::from_str(include_str!(
            "../../../docs/examples/access-revocation.json"
        ))
        .unwrap();
        assert!(matches!(grant, AccessStatement::Grant { .. }));
        assert!(revocation.revokes(&grant));
    }
}
