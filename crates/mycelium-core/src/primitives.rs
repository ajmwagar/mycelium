//! Shared, policy-free host primitives used by drivers and daemon adapters.

use std::net::IpAddr;

use crate::{MyceliumError, Params, Result, Target, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostTarget<'a> {
    pub host: &'a str,
    pub port: u16,
    pub jump: Option<&'a str>,
}

pub fn host_target<'a>(
    target: &'a Target,
    default_port: u16,
    purpose: &str,
) -> Result<HostTarget<'a>> {
    match target {
        Target::Host { host, port, jump } => Ok(HostTarget {
            host,
            port: port.unwrap_or(default_port),
            jump: jump.as_deref(),
        }),
        Target::Subnet { .. } => Err(MyceliumError::Validation(format!(
            "{purpose} needs one host target"
        ))),
    }
}

pub fn stable_slug(value: &str) -> String {
    let mut output = String::new();
    for character in value.to_ascii_lowercase().chars() {
        if character.is_ascii_alphanumeric() {
            output.push(character);
        } else if !output.ends_with('-') {
            output.push('-');
        }
    }
    output.trim_matches('-').to_owned()
}

pub fn parse_cidr(value: &str) -> Option<(IpAddr, u8)> {
    let (address, prefix) = value.split_once('/')?;
    let address = address.parse::<IpAddr>().ok()?;
    let prefix = prefix.parse::<u8>().ok()?;
    let valid = match address {
        IpAddr::V4(_) => prefix <= 32,
        IpAddr::V6(_) => prefix <= 128,
    };
    valid.then_some((address, prefix))
}

pub fn required_str<'a>(params: &'a Params, name: &str) -> Result<&'a str> {
    params
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| MyceliumError::Validation(format!("`{name}` must be a string")))
}

pub fn optional_str<'a>(params: &'a Params, name: &str) -> Result<Option<&'a str>> {
    params
        .get(name)
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| MyceliumError::Validation(format!("`{name}` must be a string")))
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_slugs_collapse_separators_and_case() {
        assert_eq!(stable_slug(" UAP AC/Pro--Office "), "uap-ac-pro-office");
    }

    #[test]
    fn cidrs_enforce_address_family_bounds() {
        assert_eq!(parse_cidr("192.168.1.4/24").unwrap().1, 24);
        assert_eq!(parse_cidr("2001:db8::1/64").unwrap().1, 64);
        assert!(parse_cidr("192.168.1.4/64").is_none());
        assert!(parse_cidr("2001:db8::1/129").is_none());
    }

    #[test]
    fn host_targets_preserve_jump_and_default_port() {
        let target = Target::host("router").with_jump(Some("gateway".into()));
        assert_eq!(
            host_target(&target, 22, "test").unwrap(),
            HostTarget {
                host: "router",
                port: 22,
                jump: Some("gateway"),
            }
        );
    }
}
