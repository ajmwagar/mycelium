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

// Private chains only: never save/restore the machine's entire firewall.
fn firewall_rules(config: &WireGuardTunnel) -> Vec<(String, String)> {
    let Some(flow) = &config.forward else {
        return vec![];
    };
    let chain = format!("MCWG_{}", config.interface.replace('-', "_"));
    let nat = format!("{chain}_N");
    vec![
        (chain.clone(), format!("-i {} -o {} -s {}/32 -d {}/32 -p tcp --dport {} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT", flow.ingress, flow.egress, flow.source, flow.destination, flow.tcp_port)),
        (chain.clone(), format!("-i {} -o {} -s {}/32 -d {}/32 -p tcp --sport {} -m conntrack --ctstate ESTABLISHED -j ACCEPT", flow.egress, flow.ingress, flow.destination, flow.source, flow.tcp_port)),
        (chain.clone(), format!("-i {} -j DROP", config.interface)),
        (chain, format!("-o {} -j DROP", config.interface)),
        (nat, format!("-o {} -s {}/32 -d {}/32 -p tcp --dport {} -j SNAT --to-source {}", flow.egress, flow.source, flow.destination, flow.tcp_port, flow.source_nat)),
    ]
}

fn forwarding_script(config: &WireGuardTunnel) -> String {
    let Some(flow) = &config.forward else {
        return "#!/bin/sh\n# Mycelium owned WireGuard\nset -eu\nexit 0\n".into();
    };
    let chain = format!("MCWG_{}", config.interface.replace('-', "_"));
    let nat = format!("{chain}_N");
    let rules = firewall_rules(config)
        .into_iter()
        .map(|(name, rule)| {
            let table = if name == nat { "nat" } else { "filter" };
            format!("iptables -w 5 -t {table} -A {name} {rule}\n")
        })
        .collect::<String>();
    format!(
        r#"#!/bin/sh
# Mycelium owned WireGuard
set -eu
case "${{1:-}}" in
down)
  while iptables -w 5 -C FORWARD -j {chain} 2>/dev/null; do iptables -w 5 -D FORWARD -j {chain}; done
  while iptables -w 5 -t nat -C POSTROUTING -j {nat} 2>/dev/null; do iptables -w 5 -t nat -D POSTROUTING -j {nat}; done
  if iptables -w 5 -S {chain} >/dev/null 2>&1; then iptables -w 5 -F {chain}; iptables -w 5 -X {chain}; fi
  if iptables -w 5 -t nat -S {nat} >/dev/null 2>&1; then iptables -w 5 -t nat -F {nat}; iptables -w 5 -t nat -X {nat}; fi
  ;;
up)
  test "$(cat /proc/sys/net/ipv4/ip_forward)" = 1
  ip -o -4 address show dev {egress} | grep -Fq ' {snat}/'
  ip -4 route get {destination} | grep -Fq ' dev {egress} '
  "$0" down
  iptables -w 5 -N {chain}
  iptables -w 5 -t nat -N {nat}
{rules}
  iptables -w 5 -I FORWARD 1 -j {chain}
  iptables -w 5 -t nat -I POSTROUTING 1 -j {nat}
  ;;
*) exit 2 ;;
esac
"#,
        egress = flow.egress,
        snat = flow.source_nat,
        destination = flow.destination
    )
}

fn drop_in(config: &WireGuardTunnel) -> String {
    // Keep a no-op lifecycle helper even without forwarding; this also removes
    // previously managed forwarding when an explicit new intent drops the flow.
    format!("# Mycelium owned WireGuard\n[Service]\nExecStartPost=/etc/wireguard/{}-forward up\nExecStopPost=/etc/wireguard/{}-forward down\n", config.interface, config.interface)
}

fn forwarding_verify(config: &WireGuardTunnel) -> String {
    let chain = format!("MCWG_{}", config.interface.replace('-', "_"));
    let nat = format!("{chain}_N");
    let mut checks = String::new();
    if let Some(flow) = &config.forward {
        checks.push_str(&format!("test \"$(cat /proc/sys/net/ipv4/ip_forward)\" = 1\nip -o -4 address show dev {} | grep -Fq ' {}/'\n", flow.egress, flow.source_nat));
        checks.push_str(&format!("iptables -w 5 -C FORWARD -j {chain}\niptables -w 5 -t nat -C POSTROUTING -j {nat}\ntest \"$(iptables -w 5 -S {chain} | wc -l)\" -eq 5\ntest \"$(iptables -w 5 -t nat -S {nat} | wc -l)\" -eq 2\n"));
        for (name, rule) in firewall_rules(config) {
            let table = if name == nat { "nat" } else { "filter" };
            checks.push_str(&format!("iptables -w 5 -t {table} -C {name} {rule}\n"));
        }
    } else {
        checks.push_str(&format!("if iptables -w 5 -S {chain} >/dev/null 2>&1; then exit 1; fi\nif iptables -w 5 -t nat -S {nat} >/dev/null 2>&1; then exit 1; fi\n"));
    }
    checks
}

fn verify(config: &WireGuardTunnel) -> String {
    let interface = &config.interface;
    let routes = config
        .allowed_ips
        .iter()
        .map(|prefix| {
            if let Some(address) = prefix.strip_suffix("/32") {
                // wg-quick omits redundant routes covered by a connected prefix.
                format!("ip -4 route get {address} | grep -Fq ' dev {interface} '\n")
            } else {
                format!(
                    "test \"$(ip -4 route show exact {prefix} dev {interface} | wc -l)\" -eq 1\n"
                )
            }
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
test "$(stat -c %u "$path")" = 0
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
test "$(cat /etc/wireguard/{interface}-forward)" = "$(printf '%s' '{helper}')"
test "$(stat -c %a /etc/wireguard/{interface}-forward)" = 700
test ! -L /etc/wireguard/{interface}-forward
test "$(stat -c %u /etc/wireguard/{interface}-forward)" = 0
test "$(cat /etc/systemd/system/wg-quick@{interface}.service.d/50-mycelium.conf)" = "$(printf '%s' '{drop_in}')"
{forwarding}
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
        },
        helper = forwarding_script(config).replace('\'', "'\\''"),
        drop_in = drop_in(config),
        forwarding = forwarding_verify(config),
    )
}

fn privileged(script: &str) -> String {
    format!("sudo -n sh -c '{}'", script.replace('\'', "'\\''"))
}
pub fn status_command(config: &WireGuardTunnel) -> String {
    privileged(&verify(config))
}

pub fn restart_command(config: &WireGuardTunnel) -> String {
    // Validate ownership and exact current intent before a lifecycle action.
    privileged(&format!(
        "set -eu\n(\n{}\n) >/dev/null\nsystemctl restart wg-quick@{}\n{}",
        verify(config),
        config.interface,
        verify(config)
    ))
}

fn stopped(config: &WireGuardTunnel) -> String {
    let interface = &config.interface;
    let chain = format!("MCWG_{}", interface.replace('-', "_"));
    format!(
        r#"set -eu
test "$(id -u)" = 0
if systemctl is-active --quiet wg-quick@{interface}; then exit 1; fi
if systemctl is-enabled --quiet wg-quick@{interface}; then exit 1; fi
if ip link show dev {interface} >/dev/null 2>&1; then exit 1; fi
if iptables -w 5 -S {chain} >/dev/null 2>&1; then exit 1; fi
if iptables -w 5 -t nat -S {chain}_N >/dev/null 2>&1; then exit 1; fi
printf '{{"interface":"{interface}","persistent":true,"active":false,"configuration_matches":true}}\n'
"#
    )
}

pub fn stopped_command(config: &WireGuardTunnel) -> String {
    privileged(&stopped(config))
}

pub fn stop_command(config: &WireGuardTunnel) -> String {
    privileged(&format!(
        "set -eu\n(\n{}\n) >/dev/null\nsystemctl disable --now wg-quick@{}\n{}",
        verify(config),
        config.interface,
        stopped(config)
    ))
}

pub fn apply_command(config: &WireGuardTunnel) -> String {
    let interface = &config.interface;
    privileged(&format!(
        r#"set -eu
test "$(id -u)" = 0
command -v wg >/dev/null
command -v wg-quick >/dev/null
command -v flock >/dev/null
command -v iptables >/dev/null
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
helper=/etc/wireguard/{interface}-forward
unit_dir=/etc/systemd/system/wg-quick@{interface}.service.d
unit=$unit_dir/50-mycelium.conf
test ! -L "$helper" && test ! -L "$unit_dir" && test ! -L "$unit"
had_helper=0
had_unit=0
if test -f "$helper"; then grep -Fq '# Mycelium owned WireGuard' "$helper"; cp -p "$helper" "$work/previous.helper"; had_helper=1; fi
if test -f "$unit"; then test "$(head -n 1 "$unit")" = '# Mycelium owned WireGuard'; cp -p "$unit" "$work/previous.unit"; had_unit=1; fi
if test "$had_helper" -eq 0; then
  if iptables -w 5 -S {chain} >/dev/null 2>&1; then exit 1; fi
  if iptables -w 5 -t nat -S {chain}_N >/dev/null 2>&1; then exit 1; fi
fi
printf '%s' '{helper_body}' > "$work/candidate.helper"
chmod 700 "$work/candidate.helper"
printf '%s' '{drop_in}' > "$work/candidate.unit"
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
    if test "$had_helper" -eq 1; then cp -p "$work/previous.helper" "$helper"; else rm -f "$helper"; fi
    if test "$had_unit" -eq 1; then cp -p "$work/previous.unit" "$unit"; else rm -f "$unit"; fi
    systemctl daemon-reload || exit 1
    if test "$was_enabled" -eq 0; then systemctl disable wg-quick@{interface} >/dev/null || exit 1; fi
    if test "$was_active" -eq 1; then systemctl start wg-quick@{interface} || exit 1; fi
  fi
  exit "$rc"
}}
trap rollback EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
if ! test -f "$path" || ! cmp -s "$work/candidate.conf" "$path" || ! cmp -s "$work/candidate.helper" "$helper" || ! cmp -s "$work/candidate.unit" "$unit"; then
  changed=1
  systemctl stop wg-quick@{interface}
  sync "$work/candidate.conf"
  mv "$work/candidate.conf" "$path"
  mv "$work/candidate.helper" "$helper"
  install -d -m 755 "$unit_dir"
  mv "$work/candidate.unit" "$unit"
  sync /etc/wireguard
  sync "$unit_dir"
  systemctl daemon-reload
fi
if test "$was_active" -eq 0 || test "$was_enabled" -eq 0; then changed=1; fi
systemctl enable wg-quick@{interface} >/dev/null
systemctl start wg-quick@{interface}
{verify}
trap - EXIT
"#,
        key_check = key_check(config),
        body = body(config),
        verify = verify(config),
        helper_body = forwarding_script(config).replace('\'', "'\\''"),
        drop_in = drop_in(config),
        chain = format!("MCWG_{}", interface.replace('-', "_")),
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
            interface: "mc-lab".into(),
            address: "10.253.180.1/30".into(),
            listen_port: 51820,
            private_key_path: "/home/operator/.mycelium/wireguard/private.key".into(),
            local_public_key: format!("{}A=", "B".repeat(42)),
            peer_public_key: format!("{}A=", "C".repeat(42)),
            allowed_ips: vec!["192.168.1.48/32".into()],
            endpoint: Some("165.227.93.206:51820".parse().unwrap()),
            keepalive_seconds: 25,
            forward: None,
        }
    }
    #[test]
    fn generated_commands_are_valid_shell_and_verify_routes_without_private_output() {
        let value = fixture();
        value.validate().unwrap();
        for command in [
            apply_command(&value),
            status_command(&value),
            restart_command(&value),
            stop_command(&value),
            stopped_command(&value),
        ] {
            let result = std::process::Command::new("sh")
                .args(["-n", "-c", &command])
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            if !command.contains("\"active\":false") {
                assert!(command.contains("route get 192.168.1.48 | grep -Fq"));
            }
            assert!(!command.contains("wg show mc-lab dump"));
            assert!(!command.contains("PostUp"));
        }
    }
    #[test]
    fn forwarding_is_narrow_persistent_and_blocks_other_tunnel_flows() {
        let mut value = fixture();
        value.forward = Some(mycelium_core::wireguard::WireGuardForward {
            ingress: "sh-br0".into(),
            egress: "mc-lab".into(),
            source: "172.16.0.101".parse().unwrap(),
            destination: "192.168.1.48".parse().unwrap(),
            tcp_port: 8717,
            source_nat: "10.253.180.1".parse().unwrap(),
        });
        value.validate().unwrap();
        for script in [
            forwarding_script(&value),
            apply_command(&value),
            status_command(&value),
        ] {
            let status = std::process::Command::new("sh")
                .args(["-n", "-c", &script])
                .status()
                .unwrap();
            assert!(status.success());
            assert!(!script.contains("iptables -F\n"));
        }
        let rules = firewall_rules(&value);
        assert_eq!(rules.len(), 5);
        assert!(rules[0].1.contains("-s 172.16.0.101/32 -d 192.168.1.48/32"));
        assert!(rules[0].1.contains("--dport 8717"));
        assert!(rules[1].1.contains("--ctstate ESTABLISHED"));
        assert!(rules[2].1.ends_with("-j DROP"));
        assert!(rules[4].1.contains("SNAT --to-source 10.253.180.1"));
        assert!(drop_in(&value).contains("ExecStopPost="));
        value.forward.as_mut().unwrap().destination = "192.168.1.49".parse().unwrap();
        assert!(value.validate().is_err());
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

    #[test]
    #[ignore = "disposable Linux namespaces; requires root and MYCELIUM_WG_NETNS_TEST=1"]
    fn forwarding_network_namespace_roundtrip() {
        assert_eq!(std::env::var("MYCELIUM_WG_NETNS_TEST").as_deref(), Ok("1"));
        assert!(
            std::process::Command::new("id")
                .arg("-u")
                .output()
                .unwrap()
                .stdout
                == b"0\n"
        );
        struct Lab {
            names: Vec<String>,
            helper: std::path::PathBuf,
            server: Option<std::process::Child>,
        }
        impl Drop for Lab {
            fn drop(&mut self) {
                if let Some(server) = &mut self.server {
                    let _ = server.kill();
                    let _ = server.wait();
                }
                for name in &self.names {
                    let _ = std::process::Command::new("ip")
                        .args(["netns", "del", name])
                        .status();
                }
                let _ = std::fs::remove_file(&self.helper);
            }
        }
        fn run(args: &[&str]) -> std::process::Output {
            let out = std::process::Command::new(args[0])
                .args(&args[1..])
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            out
        }
        let pid = std::process::id();
        let client = format!("mcwt-c-{pid}");
        let router = format!("mcwt-r-{pid}");
        let server = format!("mcwt-s-{pid}");
        let mut lab = Lab {
            names: vec![],
            helper: std::env::temp_dir().join(format!("mcwt-{pid}.sh")),
            server: None,
        };
        for name in [&client, &router, &server] {
            run(&["ip", "netns", "add", name]);
            lab.names.push(name.clone());
        }
        let ns = |name: &str, args: &[&str]| {
            let mut command = vec!["ip", "netns", "exec", name];
            command.extend_from_slice(args);
            run(&command)
        };
        ns(
            &client,
            &[
                "ip", "link", "add", "cp", "type", "veth", "peer", "name", "sh-br0",
            ],
        );
        ns(&client, &["ip", "link", "set", "sh-br0", "netns", &router]);
        ns(
            &router,
            &[
                "ip", "link", "add", "mc-lab", "type", "veth", "peer", "name", "sp",
            ],
        );
        ns(&router, &["ip", "link", "set", "sp", "netns", &server]);
        for (name, interface, address) in [
            (&client, "cp", "172.16.0.101/24"),
            (&router, "sh-br0", "172.16.0.1/24"),
            (&router, "mc-lab", "10.253.180.1/30"),
            (&server, "sp", "10.253.180.2/30"),
        ] {
            ns(name, &["ip", "addr", "add", address, "dev", interface]);
            ns(name, &["ip", "link", "set", interface, "up"]);
            ns(name, &["ip", "link", "set", "lo", "up"]);
        }
        ns(
            &client,
            &["ip", "route", "add", "default", "via", "172.16.0.1"],
        );
        ns(
            &router,
            &[
                "ip",
                "route",
                "add",
                "192.168.1.48/32",
                "via",
                "10.253.180.2",
                "dev",
                "mc-lab",
            ],
        );
        ns(
            &server,
            &["ip", "addr", "add", "192.168.1.48/32", "dev", "lo"],
        );
        ns(&router, &["sysctl", "-w", "net.ipv4.ip_forward=1"]);
        ns(&router, &["iptables", "-P", "FORWARD", "DROP"]);
        ns(&router, &["iptables", "-N", "UNRELATED"]);
        ns(&router, &["iptables", "-A", "FORWARD", "-j", "UNRELATED"]);
        let mut value = fixture();
        value.forward = Some(mycelium_core::wireguard::WireGuardForward {
            ingress: "sh-br0".into(),
            egress: "mc-lab".into(),
            source: "172.16.0.101".parse().unwrap(),
            destination: "192.168.1.48".parse().unwrap(),
            tcp_port: 8717,
            source_nat: "10.253.180.1".parse().unwrap(),
        });
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lab.helper)
            .and_then(|mut file| {
                std::io::Write::write_all(&mut file, forwarding_script(&value).as_bytes())
            })
            .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&lab.helper, std::fs::Permissions::from_mode(0o700)).unwrap();
        let helper = lab.helper.to_str().unwrap();
        ns(&router, &[helper, "up"]);
        ns(&router, &["sh", "-c", &forwarding_verify(&value)]);
        // The isolated child runs the same Rust test executable, not a new daemon.
        lab.server = Some(
            std::process::Command::new("ip")
                .args(["netns", "exec", &server])
                .arg(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "wireguard::tests::namespace_http_server",
                    "--nocapture",
                ])
                .env("MYCELIUM_WG_SERVER", "1")
                .spawn()
                .unwrap(),
        );
        let mut ready = false;
        for _ in 0..40 {
            if String::from_utf8_lossy(&ns(&server, &["ss", "-Hln", "sport", "=", ":8717"]).stdout)
                .contains("8717")
            {
                ready = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        assert!(ready);
        let response = ns(
            &client,
            &[
                "curl",
                "--noproxy",
                "*",
                "-fsS",
                "--max-time",
                "2",
                "http://192.168.1.48:8717",
            ],
        );
        assert_eq!(response.stdout, b"ok");
        ns(&router, &[helper, "up"]);
        ns(&router, &["sh", "-c", &forwarding_verify(&value)]);
        ns(
            &client,
            &["ip", "addr", "del", "172.16.0.101/24", "dev", "cp"],
        );
        ns(
            &client,
            &["ip", "addr", "add", "172.16.0.102/24", "dev", "cp"],
        );
        ns(
            &client,
            &["ip", "route", "replace", "default", "via", "172.16.0.1"],
        );
        assert!(!std::process::Command::new("ip")
            .args([
                "netns",
                "exec",
                &client,
                "curl",
                "--noproxy",
                "*",
                "-fsS",
                "--max-time",
                "1",
                "http://192.168.1.48:8717"
            ])
            .output()
            .unwrap()
            .status
            .success());
        let counts = ns(
            &router,
            &["iptables", "-L", "MCWG_mc_lab", "-n", "-v", "-x"],
        );
        assert!(
            String::from_utf8_lossy(&counts.stdout).lines().any(|line| {
                let fields: Vec<_> = line.split_whitespace().collect();
                fields.get(2) == Some(&"DROP")
                    && fields
                        .first()
                        .and_then(|value| value.parse::<u64>().ok())
                        .is_some_and(|packets| packets > 0)
            }),
            "denial must reach the managed drop rule, not fail for missing routes"
        );
        ns(
            &client,
            &["ip", "addr", "del", "172.16.0.102/24", "dev", "cp"],
        );
        ns(
            &client,
            &["ip", "addr", "add", "172.16.0.101/24", "dev", "cp"],
        );
        ns(
            &client,
            &["ip", "route", "replace", "default", "via", "172.16.0.1"],
        );
        assert_eq!(
            ns(
                &client,
                &[
                    "curl",
                    "--noproxy",
                    "*",
                    "-fsS",
                    "--max-time",
                    "2",
                    "http://192.168.1.48:8717"
                ]
            )
            .stdout,
            b"ok"
        );
        ns(&router, &[helper, "down"]);
        ns(&router, &[helper, "down"]);
        ns(&router, &["iptables", "-C", "FORWARD", "-j", "UNRELATED"]);
        assert!(
            !String::from_utf8_lossy(&ns(&router, &["iptables", "-S"]).stdout).contains("MCWG_")
        );
    }

    #[test]
    #[ignore = "child of forwarding_network_namespace_roundtrip"]
    fn namespace_http_server() {
        assert_eq!(std::env::var("MYCELIUM_WG_SERVER").as_deref(), Ok("1"));
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("192.168.1.48:8717").unwrap();
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            assert_eq!(stream.peer_addr().unwrap().ip().to_string(), "10.253.180.1");
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            let mut buffer = [0; 2048];
            let _ = stream.read(&mut buffer).unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .unwrap();
        }
    }
}
