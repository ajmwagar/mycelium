//! Bounded Kubo discovery through an observed host-local RPC listener.
//!
//! Only `/api/v0/version` and `/api/v0/id` are invoked. No config, keys, pins, content or swarm
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
//! deadline per request, 4097-byte version and 16385-byte identity ceilings.
//! Identity is requested only after successful version recognition. A custom loopback port is eligible
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
    rpc_command(address, port, "version", 4096)
}

pub(crate) fn identity_command(address: IpAddr, port: u16) -> String {
    rpc_command(address, port, "id", 16384)
}

fn rpc_command(address: IpAddr, port: u16, operation: &str, limit: usize) -> String {
    assert!(address.is_loopback(), "Kubo discovery is host-local only");
    let host = match address {
        IpAddr::V4(_) => address.to_string(),
        IpAddr::V6(_) => format!("[{address}]"),
    };
    format!("curl -q --noproxy '*' --proto '=http' --connect-timeout 1 --max-time 2 --max-filesize {limit} -fsS -X POST 'http://{host}:{port}/api/v0/{operation}' | head -c {}", limit + 1)
}

/// Require the Kubo version response shape, not just a port or arbitrary JSON.
pub(crate) fn parse_version(body: &str) -> Result<Option<String>, String> {
    if body.len() > 4096 {
        return Err("Kubo version response exceeds bound".into());
    }
    let value = project(body, "version")?;
    Ok(value
        .get("version")
        .and_then(|v| v.as_str())
        .map(str::to_owned))
}

fn project(body: &str, operation: &str) -> Result<serde_json::Value, String> {
    let source = include_str!("../../mycelium-plugins-lua/plugins/kubo.lua");
    let provider =
        mycelium_plugins_lua::ServiceProvider::load(source).map_err(|e| e.to_string())?;
    provider
        .project(
            body,
            serde_json::json!({"operation":operation,"empty_array":[]}),
        )
        .map_err(|e| e.to_string())
}

pub(crate) fn parse_identity(
    body: &str,
) -> Result<std::collections::BTreeMap<String, String>, String> {
    if body.len() > 16384 {
        return Err("Kubo identity response exceeds bound".into());
    }
    #[derive(serde::Deserialize)]
    struct Identity {
        peer_id: String,
        swarm_addresses: Vec<String>,
    }
    let identity: Identity = serde_json::from_value(project(body, "identity")?)
        .map_err(|_| "invalid Kubo identity projection")?;
    Ok(std::collections::BTreeMap::from([
        ("peer_id".into(), identity.peer_id),
        (
            "swarm_addresses".into(),
            serde_json::to_string(&identity.swarm_addresses).map_err(|e| e.to_string())?,
        ),
    ]))
}

/// The existing listener catalog is port-keyed. Conflicting IPv4/IPv6 RPC
/// identities must not become whichever reply happened to arrive last.
pub(crate) fn merge_identity(
    identities: &mut std::collections::BTreeMap<u16, std::collections::BTreeMap<String, String>>,
    port: u16,
    facts: std::collections::BTreeMap<String, String>,
) -> bool {
    match identities.get(&port) {
        Some(previous) => previous == &facts,
        None => {
            identities.insert(port, facts);
            true
        }
    }
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
        assert_eq!(parse_version(r#"{"Version":"0.43.1","Commit":"acc53c0","Repo":"18","System":"amd64/linux","Golang":"go1.26.5"}"#).unwrap().as_deref(), Some("0.43.1"));
        for body in [
            r#"{"Version":"0.43.1"}"#,
            r#"{"Version":"bad\nversion","Repo":"18","System":"amd64/linux","Golang":"go1"}"#,
            "not json",
        ] {
            assert!(parse_version(body).ok().flatten().is_none());
        }
        assert!(parse_version(&"x".repeat(4097)).is_err());
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
    #[test]
    fn identity_facts_are_whitelisted_bounded_and_not_gateway_routes() {
        let id = "12D3KooWMpYT6jzj2k2EmKuC7Gat4NJfvxyjEy88To482Fx8Xhvf";
        let address = format!("/p2p/{id}");
        let body=serde_json::json!({"ID":id,"Addresses":[address.clone(),address.clone()],"PublicKey":"never-export","Config":{"secret":"never-export"}}).to_string();
        let facts = parse_identity(&body).unwrap();
        assert_eq!(facts.len(), 2);
        assert_eq!(facts["peer_id"], id);
        assert_eq!(
            facts["swarm_addresses"],
            serde_json::to_string(&vec![address]).unwrap()
        );
        assert!(!format!("{facts:?}").contains("never-export"));
        assert!(parse_identity(&serde_json::json!({"ID":id,"Addresses":[]}).to_string()).is_ok());
        for addresses in [
            serde_json::json!(["/p2p/wrong"]),
            serde_json::json!(["http://gateway"]),
            serde_json::json!(["/ip4/1.2.3.4\n"]),
            serde_json::json!(vec!["/p2p/anything"; 33]),
        ] {
            assert!(parse_identity(
                &serde_json::json!({"ID":id,"Addresses":addresses}).to_string()
            )
            .is_err());
        }
        assert!(parse_identity(&"x".repeat(16385)).is_err());
        let cmd = identity_command("127.0.0.1".parse().unwrap(), 5002);
        assert!(cmd.contains("/api/v0/id"));
        assert!(cmd.contains("--max-time 2"));
        assert!(!cmd.contains("--location"));
        assert!(!cmd.contains("/config"));
    }
    #[test]
    fn same_port_conflicting_identities_are_not_last_writer_wins() {
        let mut identities = std::collections::BTreeMap::new();
        let a = std::collections::BTreeMap::from([("peer_id".into(), "a".into())]);
        let b = std::collections::BTreeMap::from([("peer_id".into(), "b".into())]);
        assert!(merge_identity(&mut identities, 5002, a.clone()));
        assert!(merge_identity(&mut identities, 5002, a.clone()));
        assert!(!merge_identity(&mut identities, 5002, b));
        assert_eq!(identities[&5002], a);
    }
}
