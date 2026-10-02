//! Deterministic authorization over Mycelium's gossiped authority graph.
//!
//! The resolver is deliberately pure and offline: configured public root keys,
//! signed authority records, legacy migration roots, and a caller-supplied Unix
//! timestamp fully determine every decision. Discovery proves availability and
//! transport identity; neither one grants authority.
//!
//! Authority v1 is one level deep. Only configured roots may sign delegation
//! and revocation records. Delegated workload keys may publish the exact access,
//! release, or package records their capabilities permit, but cannot delegate.

use std::collections::{BTreeMap, BTreeSet};

use mycelium_peer_protocol::{
    AuthorityCapability, AuthorityRecord, AuthorityStatement, PackageManifest,
};
use serde::Serialize;

/// The trust path responsible for an authorization decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthoritySource {
    /// The workload record was signed directly by a configured root.
    Root,
    /// An active root-signed delegation permits the workload signer.
    Delegation,
    /// A deprecated per-feature key setting permits the signer.
    Legacy,
    /// No active trust path permits the requested operation.
    Denied,
}

/// An auditable result returned by every authority check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AuthorityDecision {
    /// Whether the operation is permitted.
    pub authorized: bool,
    /// The trust path used, or `Denied` when no path exists.
    pub source: AuthoritySource,
    /// Public-key identity whose workload record is being checked.
    pub signer: String,
    /// Stable operation name such as `access.publish`.
    pub action: String,
    /// Delegation responsible for approval, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation_id: Option<String>,
    /// Operator-readable explanation of the decision.
    pub reason: String,
}

/// Resolves root, delegated, revoked, and legacy authorization consistently.
///
/// Invalid records are ignored. Revocation wins over delegation regardless of
/// gossip arrival order. The supplied `now` value makes decisions reproducible
/// in tests and explicit at every call site.
pub struct AuthorityResolver<'a> {
    roots: &'a BTreeSet<String>,
    legacy_access: &'a BTreeSet<String>,
    legacy_release: &'a BTreeSet<String>,
    delegations: BTreeMap<String, Delegation>,
    revoked: BTreeSet<String>,
    now: u64,
}

struct Delegation {
    subject: String,
    capabilities: Vec<AuthorityCapability>,
    not_before: u64,
    not_after: u64,
}

impl<'a> AuthorityResolver<'a> {
    /// Builds a resolver from configured roots and a converged record snapshot.
    ///
    /// `legacy_access` and `legacy_release` preserve compatibility with
    /// `MYCELIUM_ACCESS_KEYS` and `MYCELIUM_RELEASE_KEYS`; decisions using them
    /// are reported as [`AuthoritySource::Legacy`].
    pub fn new(
        roots: &'a BTreeSet<String>,
        legacy_access: &'a BTreeSet<String>,
        legacy_release: &'a BTreeSet<String>,
        records: impl IntoIterator<Item = &'a AuthorityRecord>,
        now: u64,
    ) -> Self {
        let mut delegations = BTreeMap::new();
        let mut revoked = BTreeSet::new();
        for record in records {
            if !roots.contains(&record.signer) || record.verify().is_err() {
                continue;
            }
            match &record.statement {
                AuthorityStatement::Delegate {
                    delegation_id,
                    subject,
                    capabilities,
                    not_before,
                    not_after,
                } if !delegation_id.is_empty()
                    && !subject.is_empty()
                    && !capabilities.is_empty()
                    && not_before < not_after =>
                {
                    delegations.insert(
                        delegation_id.clone(),
                        Delegation {
                            subject: subject.clone(),
                            capabilities: capabilities.clone(),
                            not_before: *not_before,
                            not_after: *not_after,
                        },
                    );
                }
                AuthorityStatement::Revoke {
                    delegation_id,
                    revoked_at,
                    ..
                } if *revoked_at <= now => {
                    revoked.insert(delegation_id.clone());
                }
                _ => {}
            }
        }
        Self {
            roots,
            legacy_access,
            legacy_release,
            delegations,
            revoked,
            now,
        }
    }

    /// Checks permission to publish signed access records.
    pub fn access(&self, signer: &str) -> AuthorityDecision {
        self.decide(
            signer,
            "access.publish",
            |capability| matches!(capability, AuthorityCapability::AccessPublish),
            self.legacy_access,
        )
    }

    /// Checks permission to publish a Mycelium self-update release.
    pub fn release(&self, signer: &str) -> AuthorityDecision {
        self.decide(
            signer,
            "release.publish",
            |capability| matches!(capability, AuthorityCapability::ReleasePublish),
            self.legacy_release,
        )
    }

    /// Checks permission to promote a signed package manifest.
    pub fn package(&self, package: &PackageManifest) -> AuthorityDecision {
        self.package_fields(
            &package.signer,
            &package.name,
            &package.channel,
            &package.target,
        )
    }

    /// Checks package promotion using its policy-relevant tuple.
    ///
    /// This supports explain/plan paths without manufacturing a signed package
    /// manifest. Matching is exact; empty constraint sets in the capability are
    /// wildcards.
    pub fn package_fields(
        &self,
        signer: &str,
        name: &str,
        channel: &str,
        target: &str,
    ) -> AuthorityDecision {
        self.decide(
            signer,
            "package.promote",
            |capability| capability.permits_package_fields(name, channel, target),
            self.legacy_release,
        )
    }

    fn decide(
        &self,
        signer: &str,
        action: &str,
        permits: impl Fn(&AuthorityCapability) -> bool,
        legacy: &BTreeSet<String>,
    ) -> AuthorityDecision {
        if self.roots.contains(signer) {
            return decision(
                true,
                AuthoritySource::Root,
                signer,
                action,
                None,
                "signer is an authority root",
            );
        }
        for (id, delegation) in &self.delegations {
            if delegation.subject != signer || self.revoked.contains(id) {
                continue;
            }
            if self.now < delegation.not_before || self.now >= delegation.not_after {
                continue;
            }
            if delegation.capabilities.iter().any(&permits) {
                return decision(
                    true,
                    AuthoritySource::Delegation,
                    signer,
                    action,
                    Some(id.clone()),
                    "valid delegated capability",
                );
            }
        }
        if legacy.contains(signer) {
            return decision(
                true,
                AuthoritySource::Legacy,
                signer,
                action,
                None,
                "signer is allowed by a legacy trust-key setting",
            );
        }
        decision(
            false,
            AuthoritySource::Denied,
            signer,
            action,
            None,
            "no active capability authorizes this signer and action",
        )
    }
}

fn decision(
    authorized: bool,
    source: AuthoritySource,
    signer: &str,
    action: &str,
    delegation_id: Option<String>,
    reason: &str,
) -> AuthorityDecision {
    AuthorityDecision {
        authorized,
        source,
        signer: signer.to_owned(),
        action: action.to_owned(),
        delegation_id,
        reason: reason.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use mycelium_peer_protocol::{AuthorityRecord, PackageManifest};

    use super::*;

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn id(key: &SigningKey) -> String {
        mycelium_peer_protocol::encode_hex(key.verifying_key().as_bytes())
    }

    fn delegation(
        root: &SigningKey,
        subject: &SigningKey,
        capability: AuthorityCapability,
    ) -> AuthorityRecord {
        AuthorityRecord::sign(
            root,
            AuthorityStatement::Delegate {
                delegation_id: "delegate-1".into(),
                subject: id(subject),
                capabilities: vec![capability],
                not_before: 10,
                not_after: 100,
            },
        )
        .unwrap()
    }

    #[test]
    fn scopes_access_and_package_authority_separately() {
        let root = key(1);
        let access = key(2);
        let package_key = key(3);
        let access_record = delegation(&root, &access, AuthorityCapability::AccessPublish);
        let package_record = AuthorityRecord::sign(
            &root,
            AuthorityStatement::Delegate {
                delegation_id: "packages".into(),
                subject: id(&package_key),
                capabilities: vec![AuthorityCapability::PackagePromote {
                    packages: BTreeSet::from(["unibus".into()]),
                    channels: BTreeSet::from(["stable".into()]),
                    targets: BTreeSet::new(),
                }],
                not_before: 10,
                not_after: 100,
            },
        )
        .unwrap();
        let roots = BTreeSet::from([id(&root)]);
        let empty = BTreeSet::new();
        let records = [&access_record, &package_record];
        let resolver = AuthorityResolver::new(&roots, &empty, &empty, records, 50);
        assert!(resolver.access(&id(&access)).authorized);
        assert!(!resolver.release(&id(&access)).authorized);

        let allowed = PackageManifest::sign(
            &package_key,
            "unibus".into(),
            "1".into(),
            "stable".into(),
            "aarch64-linux-gnu".into(),
            b"bin",
        )
        .unwrap();
        let denied = PackageManifest::sign(
            &package_key,
            "yggdrasil".into(),
            "1".into(),
            "stable".into(),
            "aarch64-linux-gnu".into(),
            b"bin",
        )
        .unwrap();
        assert!(resolver.package(&allowed).authorized);
        assert!(!resolver.package(&denied).authorized);
        assert!(!resolver.access(&id(&package_key)).authorized);
    }

    #[test]
    fn revocation_wins_and_legacy_keys_remain_compatible() {
        let root = key(1);
        let subject = key(2);
        let grant = delegation(&root, &subject, AuthorityCapability::AccessPublish);
        let revoke = AuthorityRecord::sign(
            &root,
            AuthorityStatement::Revoke {
                revocation_id: "revoke-1".into(),
                delegation_id: "delegate-1".into(),
                revoked_at: 40,
                reason: "rotation".into(),
            },
        )
        .unwrap();
        let roots = BTreeSet::from([id(&root)]);
        let legacy = BTreeSet::from([id(&subject)]);
        let empty = BTreeSet::new();
        let resolver = AuthorityResolver::new(&roots, &legacy, &empty, [&grant, &revoke], 50);
        let result = resolver.access(&id(&subject));
        assert!(result.authorized);
        assert_eq!(result.source, AuthoritySource::Legacy);
    }

    #[test]
    fn expired_delegation_is_denied() {
        let root = key(1);
        let subject = key(2);
        let grant = delegation(&root, &subject, AuthorityCapability::AccessPublish);
        let roots = BTreeSet::from([id(&root)]);
        let empty = BTreeSet::new();
        let resolver = AuthorityResolver::new(&roots, &empty, &empty, [&grant], 100);
        assert!(!resolver.access(&id(&subject)).authorized);
    }
}
