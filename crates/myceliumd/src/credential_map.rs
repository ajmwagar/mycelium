use std::net::IpAddr;

use mycelium_core::{ipv4_in_cidr, CredentialSet, MyceliumError, Secret};
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
        if self.password_env.is_none() && self.key_path.is_none() {
            return Err(MyceliumError::Validation(
                "credential rule needs --password-env or --key".into(),
            ));
        }
        for cidr in &self.cidrs {
            let (network, _) = parse_cidr(cidr)?;
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
                    .is_ok_and(|(network, prefix)| ipv4_in_cidr(address, network, prefix))
            })
    }

    pub fn matches_site(&self, site: &str) -> bool {
        self.sites.is_empty() || self.sites.iter().any(|candidate| candidate == site)
    }

    pub fn credentials(&self) -> CredentialSet {
        CredentialSet {
            username: Some(self.username.clone()),
            password: self.password_env.clone().map(Secret::Env),
            key_path: self.key_path.clone(),
            sudo_password: None,
        }
    }
}

fn parse_cidr(value: &str) -> Result<(IpAddr, u8), MyceliumError> {
    let (network, prefix) = value
        .split_once('/')
        .ok_or_else(|| MyceliumError::Validation(format!("invalid CIDR `{value}`")))?;
    let network = network
        .parse::<IpAddr>()
        .map_err(|_| MyceliumError::Validation(format!("invalid CIDR `{value}`")))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| MyceliumError::Validation(format!("invalid CIDR `{value}`")))?;
    let maximum = if network.is_ipv4() { 32 } else { 128 };
    if prefix > maximum {
        return Err(MyceliumError::Validation(format!("invalid CIDR `{value}`")));
    }
    Ok((network, prefix))
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
}
