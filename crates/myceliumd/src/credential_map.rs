use std::net::IpAddr;

use mycelium_core::{
    ipv4_in_cidr, parse_cidr, CredentialRef, CredentialSet, MyceliumError, Secret,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRule {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,
    #[serde(default)]
    pub addresses: Vec<IpAddr>,
    #[serde(default)]
    pub cidrs: Vec<String>,
    /// Optional topology observer/site constraints. These disambiguate
    /// overlapping private address space without baking jump hosts into a
    /// device record.
    #[serde(default)]
    pub sites: Vec<String>,
    pub username: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_ref: Option<CredentialRef>,
    /// Pre-CredentialRef compatibility fields. New writes should use
    /// `credential_ref`; reads remain supported during migration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_env: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_path: Option<String>,
}

impl CredentialRule {
    pub fn validate(&self) -> Result<(), MyceliumError> {
        if self.name.trim().is_empty() || self.username.trim().is_empty() {
            return Err(MyceliumError::Validation(
                "credential rule needs a name and username".into(),
            ));
        }
        if self.addresses.is_empty() && self.cidrs.is_empty() {
            return Err(MyceliumError::Validation(
                "credential rule needs at least one address or CIDR".into(),
            ));
        }
        let sources = usize::from(self.credential_ref.is_some())
            + usize::from(self.password_env.is_some())
            + usize::from(self.key_path.is_some());
        if sources != 1 {
            return Err(MyceliumError::Validation(
                "credential rule needs exactly one credential reference, --password-env, or --key"
                    .into(),
            ));
        }
        if let Some(reference) = &self.credential_ref {
            CredentialRef::parse(reference.as_str()).map_err(MyceliumError::Validation)?;
        }
        for cidr in &self.cidrs {
            let (network, _) = parse_cidr(cidr)
                .ok_or_else(|| MyceliumError::Validation(format!("invalid CIDR `{cidr}`")))?;
            if !network.is_ipv4() {
                return Err(MyceliumError::Validation(
                    "credential-map CIDRs currently require IPv4".into(),
                ));
            }
        }
        if self.addresses.iter().any(|address| !address.is_ipv4()) {
            return Err(MyceliumError::Validation(
                "credential-map addresses currently require IPv4".into(),
            ));
        }
        Ok(())
    }

    pub fn matches(&self, address: IpAddr) -> bool {
        self.addresses.contains(&address)
            || self.cidrs.iter().any(|cidr| {
                parse_cidr(cidr)
                    .is_some_and(|(network, prefix)| ipv4_in_cidr(address, network, prefix))
            })
    }

    pub fn matches_site(&self, site: &str) -> bool {
        self.sites.is_empty() || self.sites.iter().any(|candidate| candidate == site)
    }

    pub fn credentials(&self) -> Result<CredentialSet, MyceliumError> {
        if let Some(reference) = &self.credential_ref {
            return crate::credential_provider::resolve(reference, Some(self.username.clone()));
        }
        Ok(CredentialSet {
            username: Some(self.username.clone()),
            password: self.password_env.clone().map(Secret::Env),
            key_path: self.key_path.clone(),
            sudo_password: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_match_without_containing_secret_material() {
        let rule = CredentialRule {
            name: "network-appliances".into(),
            driver: None,
            addresses: vec!["192.168.99.1".parse().unwrap()],
            cidrs: vec!["192.168.1.0/24".into()],
            sites: vec!["lab".into()],
            username: "operator".into(),
            credential_ref: None,
            password_env: Some("GATEWAY_PASS".into()),
            key_path: None,
        };
        rule.validate().unwrap();
        assert!(rule.matches("192.168.1.1".parse().unwrap()));
        assert!(rule.matches("192.168.99.1".parse().unwrap()));
        assert!(!rule.matches("192.168.2.1".parse().unwrap()));
        assert!(rule.matches_site("lab"));
        assert!(!rule.matches_site("home"));
        let encoded = serde_json::to_string(&rule).unwrap();
        assert!(encoded.contains("GATEWAY_PASS"));
        assert!(!encoded.contains("password\":"));
    }

    #[test]
    fn typed_reference_resolves_only_at_the_daemon_boundary() {
        let rule = CredentialRule {
            name: "router".into(),
            driver: Some("edgeos".into()),
            addresses: vec!["192.0.2.1".parse().unwrap()],
            cidrs: Vec::new(),
            sites: Vec::new(),
            username: "operator".into(),
            credential_ref: Some(CredentialRef::parse("env://ROUTER_PASSWORD").unwrap()),
            password_env: None,
            key_path: None,
        };
        rule.validate().unwrap();
        assert_eq!(
            rule.credentials().unwrap().password,
            Some(Secret::Env("ROUTER_PASSWORD".into()))
        );
    }
}
