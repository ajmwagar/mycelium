use serde::{Deserialize, Serialize};
use std::fmt;

const NSDP_PREFIX: &[u8] = b"0x4e470x01";

/// Lossless representation of a FASTPATH ASCII startup configuration.
///
/// `lines` retains every input line verbatim, including comments, blank
/// lines, unknown commands, and command ordering. Structured sections and
/// secret references are derived indexes, never replacements for the source.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastpathConfig {
    pub header: Option<Header>,
    pub lines: Vec<ConfigLine>,
    pub sections: Vec<ConfigSection>,
    pub secrets: Vec<SecretRef>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// The complete vendor header line. It is model/firmware coupled and must
    /// be preserved byte-for-byte for any future round trip.
    pub raw: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigLine {
    /// One-based source line number.
    pub number: usize,
    /// Source text without its line terminator.
    pub raw: String,
    pub kind: LineKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LineKind {
    Header,
    Blank,
    Comment,
    Command,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigSection {
    pub mode: String,
    pub start_line: usize,
    pub end_line: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRef {
    pub line: usize,
    pub kind: SecretKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    Password,
    SnmpCommunity,
    RadiusKey,
    TacacsKey,
    Certificate,
    PrivateKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
    ContainsNul { line: usize },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContainsNul { line } => write!(f, "NUL byte on configuration line {line}"),
        }
    }
}

impl std::error::Error for ParseError {}

impl FastpathConfig {
    pub fn parse(input: &str) -> Result<Self, ParseError> {
        let mut header = None;
        let mut lines = Vec::new();
        let mut sections = Vec::new();
        let mut secrets = Vec::new();
        let mut active: Option<(String, usize)> = None;
        let mut pending_secret = None;

        for (index, source) in input.lines().enumerate() {
            let number = index + 1;
            let raw = source.strip_suffix('\r').unwrap_or(source);
            if raw.contains('\0') {
                return Err(ParseError::ContainsNul { line: number });
            }
            let trimmed = raw.trim();
            let kind = if number == 1 && raw.as_bytes().starts_with(NSDP_PREFIX) {
                header = Some(Header {
                    raw: raw.to_owned(),
                });
                LineKind::Header
            } else if trimmed.is_empty() {
                LineKind::Blank
            } else if trimmed.starts_with('!') {
                LineKind::Comment
            } else {
                LineKind::Command
            };

            if kind == LineKind::Command {
                if let Some(secret) = pending_secret.take() {
                    secrets.push(SecretRef {
                        line: number,
                        kind: secret,
                    });
                }
                if trimmed.eq_ignore_ascii_case("exit") {
                    if let Some((mode, start_line)) = active.take() {
                        sections.push(ConfigSection {
                            mode,
                            start_line,
                            end_line: number,
                        });
                    }
                } else if let Some(mode) = section_mode(trimmed) {
                    if let Some((previous, start_line)) = active.replace((mode, number)) {
                        sections.push(ConfigSection {
                            mode: previous,
                            start_line,
                            end_line: number.saturating_sub(1),
                        });
                    }
                }
                if let Some(secret) = inline_secret_kind(trimmed) {
                    secrets.push(SecretRef {
                        line: number,
                        kind: secret,
                    });
                }
                pending_secret = continuation_secret_kind(trimmed);
            }
            lines.push(ConfigLine {
                number,
                raw: raw.to_owned(),
                kind,
            });
        }
        if let Some((mode, start_line)) = active {
            sections.push(ConfigSection {
                mode,
                start_line,
                end_line: lines.len(),
            });
        }

        Ok(Self {
            header,
            lines,
            sections,
            secrets,
        })
    }

    /// Re-emits the exact logical lines using a caller-selected line ending.
    /// Use the source artifact itself when byte identity, including final-newline
    /// state, matters; this method exists for deterministic normalized output.
    pub fn render(&self, newline: &str) -> String {
        self.lines
            .iter()
            .map(|line| line.raw.as_str())
            .collect::<Vec<_>>()
            .join(newline)
    }

    pub fn redacted(&self) -> Self {
        let mut copy = self.clone();
        for secret in &copy.secrets {
            if let Some(line) = copy.lines.get_mut(secret.line - 1) {
                line.raw = redact_command(&line.raw);
            }
        }
        copy
    }
}

fn section_mode(command: &str) -> Option<String> {
    let lower = command.to_ascii_lowercase();
    let begins_section = lower == "configure"
        || lower == "vlan database"
        || lower == "lineconfig"
        || lower.starts_with("interface ")
        || lower.starts_with("router ")
        || lower.starts_with("ipv6 router ");
    begins_section.then(|| command.to_owned())
}

fn inline_secret_kind(command: &str) -> Option<SecretKind> {
    let lower = command.to_ascii_lowercase();
    if lower.contains("private-key") || lower.contains("private key") {
        Some(SecretKind::PrivateKey)
    } else if lower.contains("certificate") {
        Some(SecretKind::Certificate)
    } else if (lower.starts_with("users passwd ") && !lower.ends_with(" encrypted"))
        || lower.contains(" password ")
    {
        Some(SecretKind::Password)
    } else if lower.contains("snmp") && lower.contains("community") {
        Some(SecretKind::SnmpCommunity)
    } else if lower.contains("radius") && lower.contains("key") {
        Some(SecretKind::RadiusKey)
    } else if lower.contains("tacacs") && lower.contains("key") {
        Some(SecretKind::TacacsKey)
    } else {
        None
    }
}

fn continuation_secret_kind(command: &str) -> Option<SecretKind> {
    let lower = command.to_ascii_lowercase();
    (lower.starts_with("users passwd ") && lower.ends_with(" encrypted"))
        .then_some(SecretKind::Password)
}

fn redact_command(command: &str) -> String {
    let indentation = &command[..command.len() - command.trim_start().len()];
    let mut words = command.split_whitespace();
    let Some(first) = words.next() else {
        return command.to_owned();
    };
    let name = words
        .next()
        .map_or_else(|| first.to_owned(), |second| format!("{first} {second}"));
    if name == command.trim() {
        format!("{indentation}<redacted>")
    } else {
        format!("{indentation}{name} <redacted>")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = concat!(
        "0x4e470x010x00GS752TPS            5.3.0.36            0x00000000\r\n",
        "!Current Configuration:\r\n",
        "network protocol none\r\n",
        "vlan database\r\n",
        "vlan 10\r\n",
        "exit\r\n",
        "configure\r\n",
        "! preserve this unknown vendor command\r\n",
        "vendor-specific frobnicate 7\r\n",
        "users passwd \"admin\" encrypted\r\n",
        "deadbeef\r\n",
        "interface 1/0/1\r\n",
        "description 'uplink'\r\n",
        "exit\r\n",
    );

    #[test]
    fn preserves_every_logical_line_and_unknown_command() {
        let parsed = FastpathConfig::parse(FIXTURE).unwrap();
        assert_eq!(parsed.header.as_ref().unwrap().raw, parsed.lines[0].raw);
        assert_eq!(parsed.lines[8].raw, "vendor-specific frobnicate 7");
        assert_eq!(parsed.render("\r\n"), FIXTURE.trim_end_matches("\r\n"));
    }

    #[test]
    fn indexes_modes_without_discarding_source() {
        let parsed = FastpathConfig::parse(FIXTURE).unwrap();
        assert!(parsed.sections.iter().any(|s| s.mode == "vlan database"));
        assert!(parsed.sections.iter().any(|s| s.mode == "configure"));
        assert!(parsed.sections.iter().any(|s| s.mode == "interface 1/0/1"));
    }

    #[test]
    fn identifies_and_redacts_secret_lines() {
        let parsed = FastpathConfig::parse(FIXTURE).unwrap();
        assert_eq!(
            parsed.secrets,
            vec![SecretRef {
                line: 11,
                kind: SecretKind::Password
            }]
        );
        let redacted = parsed.redacted();
        assert_eq!(redacted.lines[10].raw, "<redacted>");
        assert_eq!(parsed.lines[10].raw, "deadbeef");
    }

    #[test]
    fn rejects_embedded_nul() {
        assert_eq!(
            FastpathConfig::parse("configure\nfoo\0bar").unwrap_err(),
            ParseError::ContainsNul { line: 2 }
        );
    }
}
