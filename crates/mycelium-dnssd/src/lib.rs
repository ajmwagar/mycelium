//! Parsers for the stable, machine-readable output of common DNS-SD clients.

use std::collections::BTreeSet;

use mycelium_core::ServiceAdvertisement;

/// Parse resolved `avahi-browse --parsable` records (`=` lines).
pub fn parse_avahi(input: &str, observed_at: u64) -> Vec<ServiceAdvertisement> {
    input
        .lines()
        .filter_map(|line| {
            let fields = line.split(';').collect::<Vec<_>>();
            if fields.first().copied() != Some("=") || fields.len() < 9 {
                return None;
            }
            let port = fields[8].parse().ok();
            Some(ServiceAdvertisement {
                instance: unescape_avahi(fields[3]),
                service_type: fields[4].trim_end_matches('.').to_owned(),
                domain: fields[5].trim_end_matches('.').to_owned(),
                target: nonempty(unescape_avahi(fields[6])),
                addresses: fields[7].parse().into_iter().collect(),
                port,
                txt: fields[9..]
                    .iter()
                    .map(|value| unescape_avahi(value.trim_matches('"')))
                    .filter(|value| !value.is_empty())
                    .collect(),
                interface: nonempty(fields[1].to_owned()),
                ttl: None,
                first_seen: observed_at,
                last_seen: observed_at,
                origins: BTreeSet::new(),
            })
        })
        .collect()
}

/// Parse `dns-sd -B` browse events. Browse output intentionally lacks target,
/// address, port, and TXT data; a later resolve pass can enrich the same key.
pub fn parse_dns_sd_browse(input: &str, observed_at: u64) -> Vec<ServiceAdvertisement> {
    input
        .lines()
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            let event = fields.iter().position(|field| *field == "Add")?;
            if fields.len() < event + 6 {
                return None;
            }
            let interface = fields[event + 2];
            let domain = fields[event + 3];
            let service_type = fields[event + 4];
            let instance = fields[event + 5..].join(" ");
            (!instance.is_empty()).then(|| ServiceAdvertisement {
                instance,
                service_type: service_type.trim_end_matches('.').to_owned(),
                domain: domain.trim_end_matches('.').to_owned(),
                target: None,
                addresses: BTreeSet::new(),
                port: None,
                txt: BTreeSet::new(),
                interface: Some(interface.to_owned()),
                ttl: None,
                first_seen: observed_at,
                last_seen: observed_at,
                origins: BTreeSet::new(),
            })
        })
        .collect()
}

/// Parse `dns-sd -Z` zone records, joining SRV and TXT facts by owner name.
pub fn parse_dns_sd_zone(input: &str, observed_at: u64) -> Vec<ServiceAdvertisement> {
    let mut records = std::collections::BTreeMap::<String, ServiceAdvertisement>::new();
    for line in input.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let Some(kind) = fields.get(1).copied() else {
            continue;
        };
        if !matches!(kind, "SRV" | "TXT") {
            continue;
        }
        let owner = fields[0];
        let Some((instance, service_type)) = split_zone_owner(owner) else {
            continue;
        };
        let key = owner.to_lowercase();
        let record = records.entry(key).or_insert_with(|| ServiceAdvertisement {
            instance: unescape_avahi(instance),
            service_type: service_type.to_owned(),
            domain: "local".into(),
            target: None,
            addresses: BTreeSet::new(),
            port: None,
            txt: BTreeSet::new(),
            interface: None,
            ttl: None,
            first_seen: observed_at,
            last_seen: observed_at,
            origins: BTreeSet::new(),
        });
        match kind {
            "SRV" if fields.len() >= 6 => {
                record.port = fields[4].parse().ok();
                record.target = Some(fields[5].trim_end_matches('.').to_owned());
            }
            "TXT" => {
                record.txt.extend(
                    fields[2..]
                        .iter()
                        .map(|value| unescape_avahi(value.trim_matches('"')))
                        .filter(|value| !value.is_empty()),
                );
            }
            _ => {}
        }
    }
    records.into_values().collect()
}

fn split_zone_owner(owner: &str) -> Option<(&str, &str)> {
    let marker = owner.find("._")?;
    Some((&owner[..marker], &owner[marker + 1..]))
}

fn nonempty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

fn unescape_avahi(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\'
            && index + 3 < bytes.len()
            && bytes[index + 1..index + 4].iter().all(u8::is_ascii_digit)
        {
            if let Ok(number) = value[index + 1..index + 4].parse::<u8>() {
                output.push(number);
                index += 4;
                continue;
            }
        }
        output.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&output).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_resolved_avahi_record() {
        let records = parse_avahi(
            "=;eth0;IPv4;Office\\032Printer;_ipp._tcp;local;printer.local;192.168.1.20;631;\"txtvers=1\"\n",
            42,
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].instance, "Office Printer");
        assert_eq!(records[0].port, Some(631));
        assert!(records[0]
            .addresses
            .contains(&"192.168.1.20".parse().unwrap()));
    }

    #[test]
    fn parses_darwin_browse_record_with_spaced_instance() {
        let records = parse_dns_sd_browse(
            " 8:44:39.040  Add 2 5 local. _airplay._tcp. Avery’s Mac Studio\n",
            42,
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].instance, "Avery’s Mac Studio");
        assert_eq!(records[0].service_type, "_airplay._tcp");
        assert_eq!(records[0].interface.as_deref(), Some("5"));
    }

    #[test]
    fn parses_and_joins_darwin_zone_records() {
        let input = "Avery’s\\032Home._hap._tcp SRV 0 0 8080 ecb5fa134f06.local.\nAvery’s\\032Home._hap._tcp TXT \"md=BSB002\" \"sf=0\"\n";
        let records = parse_dns_sd_zone(input, 42);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].instance, "Avery’s Home");
        assert_eq!(records[0].target.as_deref(), Some("ecb5fa134f06.local"));
        assert_eq!(records[0].port, Some(8080));
        assert!(records[0].txt.contains("md=BSB002"));
    }
}
