//! Narrow read-only discovery presentation, not a second peer registry.
use mycelium_peer_protocol::{PeerEvent, SignedEnvelope};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Serialize)]
pub(crate) struct Index {
    pub observed_at: u64,
    pub sites: BTreeMap<String, Vec<Host>>,
}
#[derive(Serialize)]
pub(crate) struct Host {
    pub node_id: String,
    pub hostname: String,
    pub platform: String,
    pub architecture: String,
    pub last_observed_at: u64,
    pub fresh: bool,
}

pub(crate) fn project<'a>(
    events: impl Iterator<Item = &'a SignedEnvelope>,
    now: u64,
) -> Result<Index, String> {
    let mut peers = BTreeMap::new();
    let mut seen = BTreeMap::<&str, u64>::new();
    for event in events {
        seen.entry(event.origin.as_str())
            .and_modify(|at| *at = (*at).max(event.emitted_at))
            .or_insert(event.emitted_at);
        if let PeerEvent::Hello(hello) = &event.event {
            if hello.node_id != event.origin {
                continue;
            }
            let entry = peers
                .entry(event.origin.as_str())
                .or_insert((event.emitted_at, hello));
            if event.emitted_at > entry.0 {
                *entry = (event.emitted_at, hello);
            }
            if peers.len() > 512 {
                return Err("discovery index exceeds 512 peers".into());
            }
        }
    }
    let mut index = Index {
        observed_at: now,
        sites: BTreeMap::new(),
    };
    for (node, (_, hello)) in peers {
        let last_observed_at = seen[node];
        index
            .sites
            .entry(hello.site.clone())
            .or_default()
            .push(Host {
                node_id: node.into(),
                hostname: hello.hostname.clone(),
                platform: format!("{:?}", hello.platform),
                architecture: hello.architecture.clone(),
                last_observed_at,
                fresh: last_observed_at <= now && now.saturating_sub(last_observed_at) < 300,
            });
    }
    for hosts in index.sites.values_mut() {
        hosts.sort_by(|a, b| a.hostname.cmp(&b.hostname).then(a.node_id.cmp(&b.node_id)));
    }
    Ok(index)
}

pub(crate) fn page(index: &Index) -> String {
    let mut body = String::from(
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Mycelium · Sites</title><style>body{background:#252d27;color:#e5ece3;font:16px monospace;max-width:85ch;margin:3rem auto;padding:1rem}table{width:100%;text-align:left;border-collapse:collapse}td,th{padding:.7rem;border-bottom:1px solid #435044}a{color:#d3e6c6}small{color:#b3c4af}</style><h1>Mycelium</h1><p>Sites and peers observed by this node. Discovery is not access authority.</p><nav><a href=\"/host\">This host</a> · <a href=\"/api/sites\">JSON</a></nav>",
    );
    for (site, hosts) in &index.sites {
        body.push_str(&format!("<section><h2>{}</h2><table><tr><th scope=\"col\">Host</th><th scope=\"col\">Platform</th><th scope=\"col\">Observation</th></tr>", crate::host_web::escape_html(site)));
        for host in hosts {
            body.push_str(&format!("<tr><td>{}<br><small>{}</small></td><td>{} / {}</td><td>{}<br><small>Unix {}</small></td></tr>", crate::host_web::escape_html(&host.hostname), crate::host_web::escape_html(&host.node_id), crate::host_web::escape_html(&host.platform), crate::host_web::escape_html(&host.architecture), if host.fresh {"Fresh"} else {"Stale"}, host.last_observed_at));
        }
        body.push_str("</table></section>");
    }
    if index.sites.is_empty() {
        body.push_str("<p>No peer identities observed.</p>");
    }
    body.push_str("</html>");
    body
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hello(node: &str, site: &str, at: u64) -> SignedEnvelope {
        SignedEnvelope {
            origin: node.into(),
            sequence: at,
            emitted_at: at,
            signature: String::new(),
            event: PeerEvent::Hello(mycelium_peer_protocol::PeerHello {
                node_id: node.into(),
                protocol_version: 1,
                site: site.into(),
                hostname: node.into(),
                platform: mycelium_peer_protocol::Platform::Linux,
                architecture: "aarch64".into(),
                daemon_version: "test".into(),
                capabilities: vec![],
                interfaces: vec![],
            }),
        }
    }
    #[test]
    fn latest_identity_grouping_freshness_and_bound() {
        let events = vec![
            hello("a", "old", 1),
            hello("b", "lab", 2),
            hello("a", "home", 500),
        ];
        let index = project(events.iter(), 501).unwrap();
        assert!(!index.sites.contains_key("old"));
        assert!(index.sites["home"][0].fresh);
        assert!(!index.sites["lab"][0].fresh);
        let too_many = (0..513)
            .map(|i| hello(&i.to_string(), "home", 1))
            .collect::<Vec<_>>();
        assert!(project(too_many.iter(), 2).is_err());
    }
    #[test]
    fn empty_and_escaped_presentation() {
        assert!(page(&project(std::iter::empty(), 10).unwrap()).contains("No peer identities"));
        let index = Index {
            observed_at: 10,
            sites: BTreeMap::from([(
                "<script>".into(),
                vec![Host {
                    node_id: "id".into(),
                    hostname: "<img>".into(),
                    platform: "Darwin".into(),
                    architecture: "arm64".into(),
                    last_observed_at: 1,
                    fresh: false,
                }],
            )]),
        };
        let html = page(&index);
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;img&gt;"));
        assert!(html.contains("Stale"));
    }
}
