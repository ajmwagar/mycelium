use crate::{FastpathConfig, LineKind};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const INTENT_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastpathIntent {
    pub schema_version: u32,
    pub model_family: Option<String>,
    pub firmware_version: Option<String>,
    pub management_vlan: Option<u16>,
    pub vlans: BTreeMap<u16, VlanIntent>,
    pub interfaces: BTreeMap<String, InterfaceIntent>,
    pub lags: BTreeMap<u16, LagIntent>,
    pub stack: StackIntent,
    pub voice_ouis: Vec<VoiceOui>,
    pub diagnostics: Vec<Diagnostic>,
    pub opaque: Vec<OpaqueStatement>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VlanIntent {
    pub id: u16,
    pub name: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceIntent {
    pub name: String,
    pub pvid: Option<u16>,
    pub included_vlans: BTreeSet<u16>,
    pub tagged_vlans: BTreeSet<u16>,
    pub auto_participation_vlans: BTreeSet<u16>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LagIntent {
    pub id: u16,
    pub link_status_traps: Option<bool>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackIntent {
    pub members: BTreeMap<u8, u8>,
    pub slots: BTreeMap<String, u8>,
    pub powered_slots: BTreeSet<String>,
    pub enabled_slots: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoiceOui {
    pub oui: String,
    pub description: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticLevel {
    Warning,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub level: DiagnosticLevel,
    pub code: String,
    pub message: String,
    pub line: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueStatement {
    pub line: usize,
    pub raw: String,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizeError {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for NormalizeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for NormalizeError {}

enum Context {
    Global,
    VlanDatabase,
    Configure,
    Interface(String),
    Lag(u16),
    LineConfig,
}

impl FastpathIntent {
    pub fn normalize(config: &FastpathConfig) -> Result<Self, NormalizeError> {
        let (model_family, firmware_version) = config
            .header
            .as_ref()
            .map(|header| parse_header(&header.raw))
            .unwrap_or_default();
        let mut intent = Self {
            schema_version: INTENT_SCHEMA_VERSION,
            model_family,
            firmware_version,
            management_vlan: None,
            vlans: BTreeMap::new(),
            interfaces: BTreeMap::new(),
            lags: BTreeMap::new(),
            stack: StackIntent::default(),
            voice_ouis: Vec::new(),
            diagnostics: Vec::new(),
            opaque: Vec::new(),
        };
        let mut context = Context::Global;
        // Intent may be serialized, logged, or attached to plans. Never let
        // secret-bearing source text escape through an opaque statement.
        let safe_config = config.redacted();

        for line in &safe_config.lines {
            if line.kind != LineKind::Command {
                continue;
            }
            let command = line.raw.trim();
            if command.eq_ignore_ascii_case("exit") {
                context = Context::Global;
                continue;
            }
            if command.eq_ignore_ascii_case("vlan database") {
                context = Context::VlanDatabase;
                continue;
            }
            if command.eq_ignore_ascii_case("configure") {
                context = Context::Configure;
                continue;
            }
            if command.eq_ignore_ascii_case("lineconfig") {
                context = Context::LineConfig;
                continue;
            }
            if let Some(name) = command.strip_prefix("interface ") {
                if let Some(id) = name.trim().strip_prefix("lag ") {
                    let id = parse_u16(id, line.number, "LAG identifier")?;
                    intent.lags.entry(id).or_insert_with(|| LagIntent {
                        id,
                        ..LagIntent::default()
                    });
                    context = Context::Lag(id);
                } else {
                    let name = name.trim().to_owned();
                    intent
                        .interfaces
                        .entry(name.clone())
                        .or_insert_with(|| InterfaceIntent {
                            name: name.clone(),
                            ..InterfaceIntent::default()
                        });
                    context = Context::Interface(name);
                }
                continue;
            }

            match &context {
                Context::VlanDatabase => normalize_vlan_command(&mut intent, command, line.number)?,
                Context::Interface(name) => {
                    normalize_interface_command(&mut intent, name, command, line.number)?
                }
                Context::Lag(id) => normalize_lag_command(&mut intent, *id, command, line.number),
                Context::Global | Context::Configure | Context::LineConfig => {
                    normalize_global_command(&mut intent, command, line.number)?
                }
            }
        }

        validate(&mut intent);
        Ok(intent)
    }
}

fn normalize_vlan_command(
    intent: &mut FastpathIntent,
    command: &str,
    line: usize,
) -> Result<(), NormalizeError> {
    if let Some(value) = command.strip_prefix("vlan name ") {
        let (id, name) = value.split_once(' ').ok_or_else(|| NormalizeError {
            line,
            message: "VLAN name requires an identifier and quoted name".to_owned(),
        })?;
        let id = parse_vlan(id, line)?;
        let name = parse_quoted(name.trim(), line, "VLAN name")?;
        intent
            .vlans
            .entry(id)
            .or_insert_with(|| VlanIntent { id, name: None })
            .name = Some(name);
    } else if let Some(value) = command.strip_prefix("vlan ") {
        for id in parse_vlan_set(value, line)? {
            intent
                .vlans
                .entry(id)
                .or_insert_with(|| VlanIntent { id, name: None });
        }
    } else {
        preserve_opaque(intent, line, command, "unsupported VLAN-database command");
    }
    Ok(())
}

fn normalize_interface_command(
    intent: &mut FastpathIntent,
    name: &str,
    command: &str,
    line: usize,
) -> Result<(), NormalizeError> {
    let interface = intent
        .interfaces
        .get_mut(name)
        .expect("interface context exists");
    if let Some(value) = command.strip_prefix("vlan pvid ") {
        interface.pvid = Some(parse_vlan(value, line)?);
    } else if let Some(value) = command.strip_prefix("vlan participation include ") {
        interface
            .included_vlans
            .extend(parse_vlan_set(value, line)?);
    } else if let Some(value) = command.strip_prefix("vlan participation auto ") {
        interface
            .auto_participation_vlans
            .extend(parse_vlan_set(value, line)?);
    } else if let Some(value) = command.strip_prefix("vlan tagging ") {
        interface.tagged_vlans.extend(parse_vlan_set(value, line)?);
    } else {
        preserve_opaque(intent, line, command, "unsupported interface command");
    }
    Ok(())
}

fn normalize_lag_command(intent: &mut FastpathIntent, id: u16, command: &str, line: usize) {
    if command == "no snmp trap link-status" {
        intent
            .lags
            .get_mut(&id)
            .expect("LAG context exists")
            .link_status_traps = Some(false);
    } else {
        preserve_opaque(intent, line, command, "unsupported LAG command");
    }
}

fn normalize_global_command(
    intent: &mut FastpathIntent,
    command: &str,
    line: usize,
) -> Result<(), NormalizeError> {
    if let Some(value) = command.strip_prefix("network mgmt_vlan ") {
        intent.management_vlan = Some(parse_vlan(value, line)?);
    } else if command == "stack" {
        // Mode marker; member/slot commands carry the state.
    } else if let Some(value) = command.strip_prefix("member ") {
        let mut words = value.split_whitespace();
        let unit = parse_u8(
            required(words.next(), line, "stack member unit")?,
            line,
            "stack member unit",
        )?;
        let model = parse_u8(
            required(words.next(), line, "stack member type")?,
            line,
            "stack member type",
        )?;
        ensure_end(words.next(), line, "stack member")?;
        intent.stack.members.insert(unit, model);
    } else if let Some(value) = command.strip_prefix("slot ") {
        let mut words = value.split_whitespace();
        let slot = required(words.next(), line, "slot identifier")?.to_owned();
        let module = parse_u8(
            required(words.next(), line, "slot module type")?,
            line,
            "slot module type",
        )?;
        ensure_end(words.next(), line, "slot")?;
        intent.stack.slots.insert(slot, module);
    } else if let Some(slot) = command.strip_prefix("set slot power ") {
        intent.stack.powered_slots.insert(slot.trim().to_owned());
    } else if let Some(slot) = command.strip_prefix("no set slot disable ") {
        intent.stack.enabled_slots.insert(slot.trim().to_owned());
    } else if let Some(value) = command.strip_prefix("voip oui ") {
        let (oui, description) = value.split_once(" desc ").ok_or_else(|| NormalizeError {
            line,
            message: "voice OUI requires a description".to_owned(),
        })?;
        intent.voice_ouis.push(VoiceOui {
            oui: oui.to_ascii_uppercase(),
            description: description.to_owned(),
        });
    } else {
        let reason =
            if command.starts_with("username ") || command.starts_with("aaa authentication ") {
                "authentication intent requires an explicit secret/identity migration policy"
            } else if command.starts_with("spanning-tree ") {
                "spanning-tree intent is preserved but not normalized yet"
            } else if command.starts_with("no port-channel linktrap ") {
                "stack-port trap policy is preserved but not normalized yet"
            } else {
                "unsupported global command"
            };
        preserve_opaque(intent, line, command, reason);
    }
    Ok(())
}

fn validate(intent: &mut FastpathIntent) {
    if let Some(id) = intent.management_vlan {
        if !intent.vlans.contains_key(&id) {
            diagnostic(
                intent,
                DiagnosticLevel::Error,
                "unknown_management_vlan",
                format!("management VLAN {id} is not declared"),
                None,
            );
        }
    }
    for interface in intent.interfaces.values() {
        let referenced = interface
            .included_vlans
            .iter()
            .chain(&interface.tagged_vlans)
            .chain(&interface.auto_participation_vlans)
            .copied()
            .chain(interface.pvid);
        for id in referenced {
            if id != 1 && !intent.vlans.contains_key(&id) {
                intent.diagnostics.push(Diagnostic {
                    level: DiagnosticLevel::Error,
                    code: "unknown_interface_vlan".to_owned(),
                    message: format!(
                        "interface {} references undeclared VLAN {id}",
                        interface.name
                    ),
                    line: None,
                });
            }
        }
        for id in interface.tagged_vlans.difference(&interface.included_vlans) {
            if *id != 1 {
                intent.diagnostics.push(Diagnostic {
                    level: DiagnosticLevel::Warning,
                    code: "tagged_vlan_not_explicitly_included".to_owned(),
                    message: format!(
                        "interface {} tags VLAN {id} without an explicit include",
                        interface.name
                    ),
                    line: None,
                });
            }
        }
    }
    if !intent.opaque.is_empty() {
        diagnostic(
            intent,
            DiagnosticLevel::Warning,
            "opaque_statements",
            format!(
                "{} statements require migration policy",
                intent.opaque.len()
            ),
            None,
        );
    }
}

fn parse_header(raw: &str) -> (Option<String>, Option<String>) {
    let content = raw.strip_prefix("0x4e470x010x00").unwrap_or(raw);
    let mut tokens = content.split_whitespace();
    let model = tokens.next().map(str::to_owned);
    let firmware = tokens
        .find(|token| {
            token
                .chars()
                .all(|character| character.is_ascii_digit() || character == '.')
                && token.contains('.')
        })
        .map(str::to_owned);
    (model, firmware)
}

fn parse_vlan_set(value: &str, line: usize) -> Result<BTreeSet<u16>, NormalizeError> {
    let mut output = BTreeSet::new();
    for part in value.trim().split(',') {
        if let Some((start, end)) = part.split_once('-') {
            let start = parse_vlan(start, line)?;
            let end = parse_vlan(end, line)?;
            if start > end {
                return Err(NormalizeError {
                    line,
                    message: format!("descending VLAN range {start}-{end}"),
                });
            }
            output.extend(start..=end);
        } else {
            output.insert(parse_vlan(part, line)?);
        }
    }
    Ok(output)
}

fn parse_vlan(value: &str, line: usize) -> Result<u16, NormalizeError> {
    let id = parse_u16(value.trim(), line, "VLAN identifier")?;
    if !(1..=4094).contains(&id) {
        return Err(NormalizeError {
            line,
            message: format!("VLAN identifier {id} is outside 1..=4094"),
        });
    }
    Ok(id)
}

fn parse_u16(value: &str, line: usize, field: &str) -> Result<u16, NormalizeError> {
    value.parse().map_err(|_| NormalizeError {
        line,
        message: format!("invalid {field}: {value}"),
    })
}

fn parse_u8(value: &str, line: usize, field: &str) -> Result<u8, NormalizeError> {
    value.parse().map_err(|_| NormalizeError {
        line,
        message: format!("invalid {field}: {value}"),
    })
}

fn parse_quoted(value: &str, line: usize, field: &str) -> Result<String, NormalizeError> {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .map(str::to_owned)
        .ok_or_else(|| NormalizeError {
            line,
            message: format!("{field} must be quoted"),
        })
}

fn required<'a>(
    value: Option<&'a str>,
    line: usize,
    field: &str,
) -> Result<&'a str, NormalizeError> {
    value.ok_or_else(|| NormalizeError {
        line,
        message: format!("missing {field}"),
    })
}

fn ensure_end(value: Option<&str>, line: usize, field: &str) -> Result<(), NormalizeError> {
    if value.is_some() {
        Err(NormalizeError {
            line,
            message: format!("unexpected trailing value in {field}"),
        })
    } else {
        Ok(())
    }
}

fn preserve_opaque(intent: &mut FastpathIntent, line: usize, raw: &str, reason: &str) {
    intent.opaque.push(OpaqueStatement {
        line,
        raw: raw.to_owned(),
        reason: reason.to_owned(),
    });
}

fn diagnostic(
    intent: &mut FastpathIntent,
    level: DiagnosticLevel,
    code: &str,
    message: String,
    line: Option<usize>,
) {
    intent.diagnostics.push(Diagnostic {
        level,
        code: code.to_owned(),
        message,
        line,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = concat!(
        "0x4e470x010x00GS7xxTS_TPS         5.3.0.31            0x00000000\n",
        "vlan database\n",
        "vlan 10-11,99\n",
        "vlan name 10 \"Home VLAN\"\n",
        "exit\n",
        "network mgmt_vlan 99\n",
        "configure\n",
        "stack\n",
        "member 1 2\n",
        "slot 1/0 3\n",
        "set slot power 1/0\n",
        "no set slot disable 1/0\n",
        "voip oui 00:01:e3 desc SIEMENS\n",
        "username admin password hash\n",
        "interface 1/g1\n",
        "vlan pvid 99\n",
        "vlan participation include 10-11,99\n",
        "vlan tagging 10-11\n",
        "exit\n",
        "interface lag 1\n",
        "no snmp trap link-status\n",
        "exit\n",
        "exit\n",
    );

    #[test]
    fn normalizes_migration_critical_fastpath_state() {
        let config = FastpathConfig::parse(FIXTURE).unwrap();
        let intent = FastpathIntent::normalize(&config).unwrap();
        assert_eq!(intent.model_family.as_deref(), Some("GS7xxTS_TPS"));
        assert_eq!(intent.firmware_version.as_deref(), Some("5.3.0.31"));
        assert_eq!(intent.management_vlan, Some(99));
        assert_eq!(intent.vlans[&10].name.as_deref(), Some("Home VLAN"));
        assert!(intent.vlans.contains_key(&11));
        assert_eq!(intent.interfaces["1/g1"].pvid, Some(99));
        assert_eq!(
            intent.interfaces["1/g1"].tagged_vlans,
            BTreeSet::from([10, 11])
        );
        assert_eq!(intent.lags[&1].link_status_traps, Some(false));
        assert_eq!(intent.stack.members[&1], 2);
        assert!(intent.stack.powered_slots.contains("1/0"));
        assert_eq!(intent.voice_ouis[0].oui, "00:01:E3");
        assert_eq!(intent.opaque.len(), 1);
    }

    #[test]
    fn rejects_invalid_vlan_ranges() {
        let config = FastpathConfig::parse("vlan database\nvlan 20-10\n").unwrap();
        assert_eq!(FastpathIntent::normalize(&config).unwrap_err().line, 2);
    }

    #[test]
    fn reports_references_to_undeclared_vlans() {
        let config = FastpathConfig::parse("interface 1/g1\nvlan pvid 42\nexit\n").unwrap();
        let intent = FastpathIntent::normalize(&config).unwrap();
        assert!(intent
            .diagnostics
            .iter()
            .any(|item| item.code == "unknown_interface_vlan"));
    }
}
