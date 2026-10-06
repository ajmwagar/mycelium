//! Bounded Kubo discovery through an observed host-local RPC listener.
//!
//! Only `/api/v0/version` is invoked. No config, keys, pins, content or swarm
//! operations are read or modified. Loopback RPC endpoints must not be projected
//! as LAN endpoints. Docker's commonly remapped 5002 listener is supported.
//!
//! Manual runbook: on the host, inspect `ss -H -lntup`; POST the version
//! endpoint of its loopback 5001/5002 listener with `curl -q --noproxy '*'`.
//! Run `mycelium scan --json`, then `mycelium services --json`. A verified
//! response appears as kind `ipfs`, role `rpc`, implementation `kubo`, with
//! `endpoint_scope=host-local` and no routable endpoint. Process-only hints
//! have unknown endpoint scope. Default ports alone never establish identity.
//!
//! Each scan probes at most four observed listeners, with a two-second request
//! deadline and 4097-byte output ceiling. A custom loopback port is eligible
//! when the observer can see the `ipfs` or `kubo` owning process. No curl means
//! no version identification; no sudo, Docker grants, API exposure or service
//! configuration is added. The API grants admin access even though this probe
//! is read-only: <https://docs.ipfs.tech/reference/kubo/rpc/>.

use std::collections::BTreeSet;
use std::net::IpAddr;

/// Select at most four already-observed loopback TCP listeners, never scan a LAN.
pub(crate) fn candidates(listeners: &str) -> Vec<(IpAddr, u16)> {
    let mut out = BTreeSet::new();
    for line in listeners.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.first() != Some(&"tcp") {
            continue;
        }
        let Some((host, port)) = fields.get(4).and_then(|value| value.rsplit_once(':')) else {
            continue;
        };
        let Ok(address) = host.trim_matches(['[', ']']).parse::<IpAddr>() else {
            continue;
        };
        let Ok(port) = port.parse::<u16>() else {
            continue;
        };
        let known_process =
            line.contains("users:((\"ipfs\",") || line.contains("users:((\"kubo\",");
        if address.is_loopback() && (matches!(port, 5001 | 5002) || known_process) {
            out.insert((address, port));
        }
    }
    let mut out = out.into_iter().collect::<Vec<_>>();
    out.sort_by_key(|(address, port)| (!matches!(port, 5001 | 5002), *address, *port));
    out.into_iter().take(4).collect()
}

pub(crate) fn version_command(address: IpAddr, port: u16) -> String {
    assert!(address.is_loopback(), "Kubo discovery is host-local only");
    let host = match address {
        IpAddr::V4(_) => address.to_string(),
        IpAddr::V6(_) => format!("[{address}]"),
    };
    format!("curl -q --noproxy '*' --proto '=http' --connect-timeout 1 --max-time 2 --max-filesize 4096 -fsS -X POST 'http://{host}:{port}/api/v0/version' | head -c 4097")
}

/// Require the Kubo version response shape, not just a port or arbitrary JSON.
pub(crate) fn parse_version(body: &str) -> Option<String> {
    if body.len() > 4096 {
        return None;
    }
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let version = value.get("Version")?.as_str()?;
    let repo = value.get("Repo")?.as_str()?;
    let system = value.get("System")?.as_str()?;
    let golang = value.get("Golang")?.as_str()?;
    if version.is_empty()
        || version.len() > 64
        || !version.as_bytes()[0].is_ascii_digit()
        || !version
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'+'))
        || repo.is_empty()
        || !repo.bytes().all(|c| c.is_ascii_digit())
        || system.len() > 64
        || !system.contains('/')
        || !golang.starts_with("go")
        || golang.len() > 64
    {
        return None;
    }
    Some(version.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn observed_loopback_only_and_custom_process_port() {
        let text = "tcp LISTEN 0 4096 127.0.0.1:5002 0.0.0.0:*\n\
                    tcp LISTEN 0 4096 0.0.0.0:5001 0.0.0.0:*\n\
                    tcp LISTEN 0 4096 [::1]:5010 [::]:* users:((\"ipfs\",pid=1,fd=2))\n\
                    tcp LISTEN 0 4096 127.0.0.1:9000 0.0.0.0:*\n\
                    udp UNCONN 0 0 127.0.0.1:5001 0.0.0.0:*";
        assert_eq!(
            candidates(text),
            vec![
                ("127.0.0.1".parse().unwrap(), 5002),
                ("::1".parse().unwrap(), 5010)
            ]
        );
    }
    #[test]
    fn candidate_budget_and_deduplication() {
        let text = (5001..5020)
            .map(|port| {
                format!("tcp LISTEN 0 0 127.0.0.1:{port} *:* users:((\"ipfs\",pid=1,fd=2))\n")
            })
            .collect::<String>();
        assert_eq!(candidates(&(text.clone() + &text)).len(), 4);
    }
    #[test]
    fn accepts_live_shape_and_ignores_unrelated_or_unsafe_json() {
        assert_eq!(parse_version(r#"{"Version":"0.43.1","Commit":"acc53c0","Repo":"18","System":"amd64/linux","Golang":"go1.26.5"}"#).as_deref(), Some("0.43.1"));
        for body in [
            r#"{"Version":"0.43.1"}"#,
            r#"{"Version":"bad\nversion","Repo":"18","System":"amd64/linux","Golang":"go1"}"#,
            "not json",
        ] {
            assert!(parse_version(body).is_none());
        }
        assert!(parse_version(&"x".repeat(4097)).is_none());
    }
    #[test]
    fn command_is_a_bounded_read_only_loopback_request() {
        let cmd = version_command("::1".parse().unwrap(), 5002);
        assert!(cmd.contains("http://[::1]:5002/api/v0/version"));
        assert!(cmd.contains("--noproxy '*'"));
        assert!(cmd.contains("--max-time 2"));
        assert!(!cmd.contains("--location"));
        assert!(!cmd.contains("/config"));
    }
}
