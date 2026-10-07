//! wg-quick/systemd translation: no arbitrary hooks, default routes or key transport.
use mycelium_core::wireguard::WireGuardTunnel;
use mycelium_core::{MyceliumError, Params, Result, Value};

pub fn config(params: &Params) -> Result<WireGuardTunnel> {
    let text = mycelium_core::required_str(params, "config")?;
    if text.len() > 8192 {
        return Err(MyceliumError::Validation(
            "WireGuard config exceeds bound".into(),
        ));
    }
    let value: WireGuardTunnel =
        serde_json::from_str(text).map_err(|error| MyceliumError::Validation(error.to_string()))?;
    value.validate().map_err(MyceliumError::Validation)?;
    Ok(value)
}

fn body(config: &WireGuardTunnel) -> String {
    let endpoint = config
        .endpoint
        .map(|endpoint| format!("Endpoint = {endpoint}\n"))
        .unwrap_or_default();
    format!("# Mycelium owned WireGuard\n[Interface]\nAddress = {}\nListenPort = {}\nPrivateKey = $private\n\n[Peer]\nPublicKey = {}\nAllowedIPs = {}\n{}PersistentKeepalive = {}\n",
        config.address, config.listen_port, config.peer_public_key, config.allowed_ips.join(", "), endpoint, config.keepalive_seconds)
}

fn key_check(config: &WireGuardTunnel) -> String {
    format!(
        r#"key='{path}'
test -f "$key" && test ! -L "$key"
test "$(stat -c %a "$key")" = 600
test "$(wc -c < "$key")" -eq 45
test "$(wg pubkey < "$key" 2>/dev/null)" = '{public}'
"#,
        path = config.private_key_path,
        public = config.local_public_key
    )
}

fn verify(config: &WireGuardTunnel) -> String {
    let interface = &config.interface;
    let routes = config
        .allowed_ips
        .iter()
        .map(|prefix| {
            format!("test \"$(ip -4 route show exact {prefix} dev {interface} | wc -l)\" -eq 1\n")
        })
        .collect::<String>();
    let prefixes = config
        .allowed_ips
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        r#"set -eu
test "$(id -u)" = 0
{key_check}
path=/etc/wireguard/{interface}.conf
test -f "$path" && test ! -L "$path"
test "$(stat -c %a "$path")" = 600
private=$(cat "$key")
test "$(cat "$path")" = "$(printf '%s' "{body}")"
unset private
systemctl is-enabled --quiet wg-quick@{interface}
systemctl is-active --quiet wg-quick@{interface}
test "$(wg show {interface} public-key)" = '{local}'
test "$(wg show {interface} listen-port)" = '{port}'
test "$(wg show {interface} peers)" = '{peer}'
test "$(wg show {interface} allowed-ips | cut -f2 | tr ', ' '\n\n' | sed '/^$/d' | sort)" = '{prefixes}'
test "$(wg show {interface} persistent-keepalive | cut -f2)" = '{keepalive}'
ip -o -4 address show dev {interface} | grep -Fq ' {address} '
{routes}
handshake=$(wg show {interface} latest-handshakes | cut -f2)
printf '{{"interface":"{interface}","persistent":true,"active":true,"configuration_matches":true,"public_key":"{local}","peer_public_key":"{peer}","latest_handshake_unix":%s}}\n' "$handshake"
"#,
        key_check = key_check(config),
        body = body(config),
        local = config.local_public_key,
        peer = config.peer_public_key,
        port = config.listen_port,
        address = config.address,
        keepalive = if config.keepalive_seconds == 0 {
            "off".into()
        } else {
            config.keepalive_seconds.to_string()
        }
    )
}

fn privileged(script: &str) -> String {
    format!("sudo -n sh -c '{}'", script.replace('\'', "'\\''"))
}
pub fn status_command(config: &WireGuardTunnel) -> String {
    privileged(&verify(config))
}

pub fn apply_command(config: &WireGuardTunnel) -> String {
    let interface = &config.interface;
    privileged(&format!(
        r#"set -eu
test "$(id -u)" = 0
command -v wg >/dev/null
command -v wg-quick >/dev/null
command -v flock >/dev/null
umask 077
test ! -L /etc/wireguard
if test -e /etc/wireguard; then test "$(stat -c %u /etc/wireguard)" = 0; fi
install -d -m 700 /etc/wireguard
exec 9>/etc/wireguard/.{interface}.lock
flock -n 9
{key_check}
path=/etc/wireguard/{interface}.conf
test ! -L "$path"
if test -e "$path"; then test "$(head -n 1 "$path")" = '# Mycelium owned WireGuard'; fi
work=$(mktemp -d /etc/wireguard/.{interface}.XXXXXXXX)
was_active=0
was_enabled=0
systemctl is-active --quiet wg-quick@{interface} && was_active=1 || true
systemctl is-enabled --quiet wg-quick@{interface} && was_enabled=1 || true
had_config=0
if test -f "$path"; then cp -p "$path" "$work/previous.conf"; had_config=1; fi
private=$(cat "$key")
printf '%s' "{body}" > "$work/candidate.conf"
unset private
wg-quick strip "$work/candidate.conf" >/dev/null
changed=0
rollback() {{
  rc=$?
  trap - EXIT
  if test "$changed" -eq 1; then
    systemctl stop wg-quick@{interface} || exit 1
    if test "$had_config" -eq 1; then cp -p "$work/previous.conf" "$path"; else rm -f "$path"; fi
    if test "$was_enabled" -eq 0; then systemctl disable wg-quick@{interface} >/dev/null || exit 1; fi
    if test "$was_active" -eq 1; then systemctl start wg-quick@{interface} || exit 1; fi
  fi
  exit "$rc"
}}
trap rollback EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
if ! test -f "$path" || ! cmp -s "$work/candidate.conf" "$path"; then
  changed=1
  systemctl stop wg-quick@{interface}
  sync "$work/candidate.conf"
  mv "$work/candidate.conf" "$path"
  sync /etc/wireguard
fi
if test "$was_active" -eq 0 || test "$was_enabled" -eq 0; then changed=1; fi
systemctl enable wg-quick@{interface} >/dev/null
systemctl start wg-quick@{interface}
{verify}
trap - EXIT
"#,
        key_check = key_check(config),
        body = body(config),
        verify = verify(config)
    ))
}

pub fn output(text: &str) -> Result<Value> {
    let value: serde_json::Value = serde_json::from_str(text.trim())
        .map_err(|error| MyceliumError::Parse(error.to_string()))?;
    if value.get("configuration_matches") != Some(&serde_json::Value::Bool(true)) {
        return Err(MyceliumError::Validation(
            "WireGuard postcondition missing".into(),
        ));
    }
    Ok(Value::Map(Params::from_iter(
        value
            .as_object()
            .ok_or_else(|| MyceliumError::Parse("status is not an object".into()))?
            .iter()
            .map(|(key, value)| {
                (
                    key.clone(),
                    match value {
                        serde_json::Value::Bool(value) => Value::Bool(*value),
                        serde_json::Value::String(value) => Value::Str(value.clone()),
                        serde_json::Value::Number(value) => {
                            value.as_i64().map(Value::Int).unwrap_or(Value::Null)
                        }
                        _ => Value::Null,
                    },
                )
            }),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> WireGuardTunnel {
        WireGuardTunnel {
            interface: "mc-lab".into(), address: "10.253.180.1/30".into(),
            listen_port: 51820, private_key_path: "/home/operator/.mycelium/wireguard/private.key".into(),
            local_public_key: format!("{}A=", "B".repeat(42)),
            peer_public_key: format!("{}A=", "C".repeat(42)),
            allowed_ips: vec!["192.168.1.48/32".into()],
            endpoint: Some("165.227.93.206:51820".parse().unwrap()), keepalive_seconds: 25,
        }
    }
    #[test]
    fn generated_commands_are_valid_shell_and_verify_routes_without_private_output() {
        let value = fixture();
        value.validate().unwrap();
        for command in [apply_command(&value), status_command(&value)] {
            let result = std::process::Command::new("sh").args(["-n", "-c", &command]).output().unwrap();
            assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
            assert!(command.contains("route show exact 192.168.1.48/32 dev mc-lab"));
            assert!(!command.contains("wg show mc-lab dump"));
            assert!(!command.contains("PostUp"));
        }
    }
    #[test]
    fn rejects_untyped_or_hook_bearing_configuration() {
        let params = Params::from_iter([(
            "config".into(),
            Value::Str("{\"PostUp\":\"reboot\"}".into()),
        )]);
        assert!(config(&params).is_err());
    }
    #[test]
    fn rejects_missing_read_only_postcondition() {
        assert!(output("{}").is_err());
    }
}
