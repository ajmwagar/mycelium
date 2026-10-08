//! Portable fleet membership and transport identity verification.
//!
//! No daemon, OIDC, discovery, ALPN or ACL dependency. Membership identifies
//! the actual gossip signing key; transport records reuse the existing
//! credential binding. Successful verification authenticates a machine,
//! never a human or permission to perform an operation.
use crate::{
    decode_array, encode_hex, TransportCredentialBinding, TransportKind, PROTOCOL_VERSION,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const DOMAIN: &str = "mycelium/fleet-identity";

/// Distinct records allow policy changes without reissuing endpoint identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum IdentityStatement {
    Membership {
        credential_id: String,
        peer_id: String,
        generation: u64,
        not_before: u64,
        not_after: u64,
    },
    Endpoint {
        credential_id: String,
        credential: TransportCredentialBinding,
        not_before: u64,
    },
    /// Permanent tombstone. Retain it even after the target credential expires.
    Revoke {
        peer_id: String,
        credential_id: String,
        revoked_at: u64,
    },
}

/// A standalone proof, suitable for carriage over any authenticated transport.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityRecord {
    pub protocol_version: u16,
    pub fleet_id: String,
    pub signer: String,
    pub statement: IdentityStatement,
    pub signature: String,
}

#[derive(Serialize)]
struct Signable<'a> {
    domain: &'static str,
    protocol_version: u16,
    fleet_id: &'a str,
    signer: &'a str,
    statement: &'a IdentityStatement,
}

fn label(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:/".contains(&b))
    {
        return Err("identity labels must be bounded ASCII identifiers".into());
    }
    Ok(())
}

fn hex(value: &str, bytes: usize) -> Result<(), String> {
    if value.len() != bytes * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("identity keys/signatures must be canonical lowercase hex".into());
    }
    Ok(())
}

fn key(value: &str) -> Result<VerifyingKey, String> {
    hex(value, 32)?;
    let key = VerifyingKey::from_bytes(&decode_array(value)?).map_err(|e| e.to_string())?;
    if key.is_weak() {
        return Err("weak identity public key".into());
    }
    Ok(key)
}

fn interval(start: u64, end: u64) -> Result<(), String> {
    if start >= end {
        return Err("identity validity interval is empty".into());
    }
    Ok(())
}

impl IdentityRecord {
    fn bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(&Signable {
            domain: DOMAIN,
            protocol_version: self.protocol_version,
            fleet_id: &self.fleet_id,
            signer: &self.signer,
            statement: &self.statement,
        })
        .map_err(|e| e.to_string())
    }

    fn validate(&self) -> Result<(), String> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("unsupported identity protocol".into());
        }
        label(&self.fleet_id)?;
        key(&self.signer)?;
        match &self.statement {
            IdentityStatement::Membership {
                credential_id,
                peer_id,
                generation,
                not_before,
                not_after,
            } => {
                label(credential_id)?;
                key(peer_id)?;
                if *generation == 0 {
                    return Err("membership generation must be positive".into());
                }
                interval(*not_before, *not_after)?;
            }
            IdentityStatement::Endpoint {
                credential_id,
                credential,
                not_before,
            } => {
                label(credential_id)?;
                credential.validate_for(&self.signer)?;
                key(&credential.node_id)?;
                if credential.kind != TransportKind::Iroh {
                    return Err("unsupported endpoint identity kind".into());
                }
                key(&credential.public_key)?;
                if credential.generation == 0 {
                    return Err("endpoint generation must be positive".into());
                }
                interval(
                    *not_before,
                    credential
                        .valid_until
                        .ok_or("endpoint identity requires expiry")?,
                )?;
            }
            IdentityStatement::Revoke {
                peer_id,
                credential_id,
                ..
            } => {
                key(peer_id)?;
                label(credential_id)?;
            }
        }
        Ok(())
    }

    pub fn sign(
        key: &SigningKey,
        fleet_id: String,
        statement: IdentityStatement,
    ) -> Result<Self, String> {
        let mut record = Self {
            protocol_version: PROTOCOL_VERSION,
            fleet_id,
            signer: encode_hex(key.verifying_key().as_bytes()),
            statement,
            signature: String::new(),
        };
        record.validate()?;
        record.signature = encode_hex(&key.sign(&record.bytes()?).to_bytes());
        Ok(record)
    }

    /// Signature validity alone is not fleet membership or authorization.
    pub fn verify_signature(&self) -> Result<(), String> {
        self.validate()?;
        hex(&self.signature, 64)?;
        let signature = Signature::from_bytes(&decode_array(&self.signature)?);
        key(&self.signer)?
            .verify_strict(&self.bytes()?, &signature)
            .map_err(|e| e.to_string())
    }
}

/// Trusted local state, not claims accepted from the connecting peer.
///
/// The consumer must validate its policy snapshot's freshness separately,
/// retain revocations and persist generation floors across reboot. Authority
/// delegation can resolve into this issuer set without coupling to a daemon.
pub struct IdentityTrust<'a> {
    pub fleet_id: &'a str,
    pub membership_issuers: &'a BTreeSet<String>,
    pub revocations: &'a [IdentityRecord],
    pub minimum_membership_generation: u64,
    pub minimum_endpoint_generation: u64,
    pub now: u64,
}

/// Authenticate the key obtained from the actual Iroh handshake, not from
/// discovery or an unverified payload. ACL evaluation follows this function.
pub fn verify_iroh_peer(
    membership: &IdentityRecord,
    endpoint: &IdentityRecord,
    remote_endpoint_key: &str,
    trust: &IdentityTrust<'_>,
) -> Result<String, String> {
    membership.verify_signature()?;
    endpoint.verify_signature()?;
    if membership.fleet_id != trust.fleet_id
        || endpoint.fleet_id != trust.fleet_id
        || !trust.membership_issuers.contains(&membership.signer)
    {
        return Err("untrusted fleet membership issuer or fleet".into());
    }
    let IdentityStatement::Membership {
        credential_id: membership_id,
        peer_id,
        generation,
        not_before,
        not_after,
    } = &membership.statement
    else {
        return Err("expected fleet membership".into());
    };
    let IdentityStatement::Endpoint {
        credential_id: endpoint_id,
        credential,
        not_before: endpoint_start,
    } = &endpoint.statement
    else {
        return Err("expected endpoint binding".into());
    };
    if membership_id == endpoint_id {
        return Err("membership and endpoint credential IDs must be distinct".into());
    }
    if endpoint.signer != *peer_id
        || credential.node_id != *peer_id
        || credential.public_key != remote_endpoint_key
    {
        return Err("handshake endpoint does not represent enrolled peer".into());
    }
    if *generation < trust.minimum_membership_generation
        || credential.generation < trust.minimum_endpoint_generation
    {
        return Err("retired identity generation".into());
    }
    if trust.now < *not_before
        || trust.now >= *not_after
        || trust.now < *endpoint_start
        || trust.now >= credential.valid_until.ok_or("missing endpoint expiry")?
    {
        return Err("identity is not currently valid".into());
    }
    for revocation in trust.revocations {
        revocation.verify_signature()?;
        if revocation.fleet_id != trust.fleet_id {
            return Err("revocation belongs to another fleet".into());
        }
        let IdentityStatement::Revoke {
            peer_id: revoked_peer,
            credential_id,
            revoked_at,
        } = &revocation.statement
        else {
            return Err("expected revocation tombstone".into());
        };
        let authority = trust.membership_issuers.contains(&revocation.signer);
        let peer = revocation.signer == *revoked_peer;
        if !authority && !peer {
            return Err("untrusted revocation signer".into());
        }
        if revoked_peer != peer_id {
            continue;
        }
        if *revoked_at <= trust.now
            && ((authority && credential_id == membership_id)
                || ((authority || peer) && credential_id == endpoint_id))
        {
            return Err("identity credential revoked".into());
        }
    }
    Ok(peer_id.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public(key: &SigningKey) -> String {
        encode_hex(key.verifying_key().as_bytes())
    }

    fn fixture() -> (
        SigningKey,
        SigningKey,
        IdentityRecord,
        IdentityRecord,
        BTreeSet<String>,
    ) {
        let authority = SigningKey::from_bytes(&[1; 32]);
        let peer = SigningKey::from_bytes(&[2; 32]);
        let endpoint_key = SigningKey::from_bytes(&[3; 32]);
        let membership = IdentityRecord::sign(
            &authority,
            "fleet".into(),
            IdentityStatement::Membership {
                credential_id: "membership".into(),
                peer_id: public(&peer),
                generation: 2,
                not_before: 10,
                not_after: 100,
            },
        )
        .unwrap();
        let endpoint = IdentityRecord::sign(
            &peer,
            "fleet".into(),
            IdentityStatement::Endpoint {
                credential_id: "endpoint".into(),
                credential: TransportCredentialBinding {
                    node_id: public(&peer),
                    kind: TransportKind::Iroh,
                    public_key: public(&endpoint_key),
                    generation: 2,
                    valid_until: Some(90),
                },
                not_before: 20,
            },
        )
        .unwrap();
        let issuers = BTreeSet::from([public(&authority)]);
        (authority, peer, membership, endpoint, issuers)
    }

    fn verify(
        m: &IdentityRecord,
        e: &IdentityRecord,
        issuers: &BTreeSet<String>,
        revocations: &[IdentityRecord],
        now: u64,
        floor: u64,
    ) -> Result<String, String> {
        let IdentityStatement::Endpoint { credential, .. } = &e.statement else {
            panic!()
        };
        verify_iroh_peer(
            m,
            e,
            &credential.public_key,
            &IdentityTrust {
                fleet_id: "fleet",
                membership_issuers: issuers,
                revocations,
                minimum_membership_generation: floor,
                minimum_endpoint_generation: floor,
                now,
            },
        )
    }

    #[test]
    fn authenticates_machine_without_permissions() {
        let (_, peer, m, e, issuers) = fixture();
        assert_eq!(verify(&m, &e, &issuers, &[], 30, 2).unwrap(), public(&peer));
        let json = serde_json::to_string(&e).unwrap();
        for field in ["alpn", "role", "oidc", "permission"] {
            assert!(!json.contains(field));
        }
    }

    #[test]
    fn rejects_unknown_issuer_tampering_and_key_substitution() {
        let (_, _, mut m, e, issuers) = fixture();
        assert!(verify(&m, &e, &BTreeSet::new(), &[], 30, 1).is_err());
        let trust = IdentityTrust {
            fleet_id: "fleet",
            membership_issuers: &issuers,
            revocations: &[],
            minimum_membership_generation: 1,
            minimum_endpoint_generation: 1,
            now: 30,
        };
        assert!(
            verify_iroh_peer(&m, &e, &public(&SigningKey::from_bytes(&[4; 32])), &trust).is_err()
        );
        m.fleet_id = "other".into();
        assert!(verify(&m, &e, &issuers, &[], 30, 1).is_err());
    }

    #[test]
    fn enforces_validity_boundaries_and_generation_floors() {
        let (_, _, m, e, issuers) = fixture();
        for now in [0, 19, 90, 100] {
            assert!(verify(&m, &e, &issuers, &[], now, 1).is_err());
        }
        for now in [20, 89] {
            assert!(verify(&m, &e, &issuers, &[], now, 2).is_ok());
        }
        assert!(verify(&m, &e, &issuers, &[], 30, 3).is_err());
    }

    #[test]
    fn authority_revokes_membership_peer_only_revokes_own_endpoint() {
        let (authority, peer, m, e, issuers) = fixture();
        for (signer, id, rejected) in [
            (&authority, "membership", true),
            (&peer, "membership", false),
            (&peer, "endpoint", true),
        ] {
            let revocation = IdentityRecord::sign(
                signer,
                "fleet".into(),
                IdentityStatement::Revoke {
                    peer_id: public(&peer),
                    credential_id: id.into(),
                    revoked_at: 25,
                },
            )
            .unwrap();
            assert_eq!(
                verify(&m, &e, &issuers, &[revocation], 30, 1).is_err(),
                rejected
            );
        }
        let other = SigningKey::from_bytes(&[4; 32]);
        let revocation = IdentityRecord::sign(
            &authority,
            "fleet".into(),
            IdentityStatement::Revoke {
                peer_id: public(&other),
                credential_id: "endpoint".into(),
                revoked_at: 25,
            },
        )
        .unwrap();
        assert!(verify(&m, &e, &issuers, &[revocation], 30, 1).is_ok());
    }

    #[test]
    fn supports_independent_endpoint_slots() {
        let (_, peer, m, mut e, issuers) = fixture();
        if let IdentityStatement::Endpoint {
            credential_id,
            credential,
            ..
        } = &mut e.statement
        {
            *credential_id = "unibus-endpoint".into();
            credential.public_key = public(&SigningKey::from_bytes(&[5; 32]));
        }
        let e = IdentityRecord::sign(&peer, "fleet".into(), e.statement).unwrap();
        assert!(verify(&m, &e, &issuers, &[], 30, 2).is_ok());
    }

    #[test]
    fn malformed_keys_and_unknown_policy_fields_fail_closed() {
        let (_, _, mut m, e, _) = fixture();
        m.signer = "é".repeat(32);
        assert!(m.verify_signature().is_err());
        m.signer = "00".repeat(32);
        assert!(m.verify_signature().is_err());
        let mut json = serde_json::to_value(&e).unwrap();
        json["statement"]["alpn"] = "unibus".into();
        assert!(serde_json::from_value::<IdentityRecord>(json).is_err());
    }

    #[test]
    fn rejects_validly_signed_wrong_fleet_and_unrelated_peer() {
        let (authority, _, m, e, issuers) = fixture();
        let other_fleet =
            IdentityRecord::sign(&authority, "other".into(), m.statement.clone()).unwrap();
        assert!(verify(&other_fleet, &e, &issuers, &[], 30, 1).is_err());
        let mut statement = m.statement;
        if let IdentityStatement::Membership { peer_id, .. } = &mut statement {
            *peer_id = public(&SigningKey::from_bytes(&[6; 32]));
        }
        let unrelated = IdentityRecord::sign(&authority, "fleet".into(), statement).unwrap();
        assert!(verify(&unrelated, &e, &issuers, &[], 30, 1).is_err());
    }

    #[test]
    fn revocations_require_authority_and_take_effect_at_signed_time() {
        let (_, peer, m, e, issuers) = fixture();
        let statement = IdentityStatement::Revoke {
            peer_id: public(&peer),
            credential_id: "endpoint".into(),
            revoked_at: 40,
        };
        let own = IdentityRecord::sign(&peer, "fleet".into(), statement.clone()).unwrap();
        assert!(verify(&m, &e, &issuers, &[own.clone()], 39, 1).is_ok());
        assert!(verify(&m, &e, &issuers, &[own], 40, 1).is_err());
        let stranger =
            IdentityRecord::sign(&SigningKey::from_bytes(&[7; 32]), "fleet".into(), statement)
                .unwrap();
        assert!(verify(&m, &e, &issuers, &[stranger], 30, 1).is_err());
    }

    #[test]
    fn rejects_missing_expiry_empty_intervals_and_colliding_ids() {
        let (_, peer, m, mut e, issuers) = fixture();
        if let IdentityStatement::Endpoint { credential_id, .. } = &mut e.statement {
            *credential_id = "membership".into();
        }
        e = IdentityRecord::sign(&peer, "fleet".into(), e.statement).unwrap();
        assert!(verify(&m, &e, &issuers, &[], 30, 1).is_err());
        if let IdentityStatement::Endpoint { credential, .. } = &mut e.statement {
            credential.valid_until = None;
        }
        assert!(IdentityRecord::sign(&peer, "fleet".into(), e.statement.clone()).is_err());
        if let IdentityStatement::Endpoint { credential, .. } = &mut e.statement {
            credential.valid_until = Some(20);
        }
        assert!(IdentityRecord::sign(&peer, "fleet".into(), e.statement).is_err());
    }
}
