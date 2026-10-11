//! Narrow read-only discovery presentation, not a second peer registry.
use mycelium_peer_protocol::{PeerEvent, PeerHello, SignedEnvelope};
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

pub(crate) fn identities<'a>(
    events: impl Iterator<Item = &'a SignedEnvelope>,
) -> Result<Vec<(&'a PeerHello, u64)>, String> {
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
    Ok(peers
        .into_iter()
        .map(|(node, (_, hello))| (hello, seen[node]))
        .collect())
}

pub(crate) fn project<'a>(
    events: impl Iterator<Item = &'a SignedEnvelope>,
    now: u64,
) -> Result<Index, String> {
    let mut index = Index {
        observed_at: now,
        sites: BTreeMap::new(),
    };
    for (hello, last_observed_at) in identities(events)? {
        index
            .sites
            .entry(hello.site.clone())
            .or_default()
            .push(Host {
                node_id: hello.node_id.clone(),
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
    body.push_str("<nav aria-label=\"Sites\"><h2>Sites</h2>");
    for (number, (site, _)) in index.sites.iter().enumerate() {
        body.push_str(&format!(
            "<a href=\"#site-{number}\">{}</a> · ",
            crate::host_web::escape_html(site)
        ));
    }
    body.push_str("</nav><h2>Site membership</h2><p><small>This tree shows observed site membership, not network connectivity. Select a node for its observation.</small></p>");
    for (number, (site, hosts)) in index.sites.iter().enumerate() {
        body.push_str(&format!(
            "<details><summary>{} · {} peers</summary><ul>",
            crate::host_web::escape_html(site),
            hosts.len()
        ));
        for (peer, host) in hosts.iter().enumerate() {
            body.push_str(&format!(
                "<li><a href=\"#node-{number}-{peer}\">{}</a> · {}</li>",
                crate::host_web::escape_html(&host.hostname),
                if host.fresh { "Fresh" } else { "Stale" }
            ));
        }
        body.push_str("</ul></details>");
    }
    for (number, (site, hosts)) in index.sites.iter().enumerate() {
        body.push_str(&format!("<section id=\"site-{number}\"><h2>{}</h2><table><tr><th scope=\"col\">Host</th><th scope=\"col\">Platform</th><th scope=\"col\">Observation</th></tr>", crate::host_web::escape_html(site)));
        for (peer, host) in hosts.iter().enumerate() {
            body.push_str(&format!("<tr id=\"node-{number}-{peer}\"><td><a href=\"#node-{number}-{peer}\">{}</a><br><small>{}</small></td><td>{} / {}</td><td>{}<br><small>Unix {}</small></td></tr>", crate::host_web::escape_html(&host.hostname), crate::host_web::escape_html(&host.node_id), crate::host_web::escape_html(&host.platform), crate::host_web::escape_html(&host.architecture), if host.fresh {"Fresh"} else {"Stale"}, host.last_observed_at));
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
    fn naming_identity_rejects_origin_mismatch_and_uses_latest_hello() {
        let mut impostor = hello("wrong", "home", 100);
        impostor.origin = "other".into();
        let events = vec![hello("a", "old", 1), hello("a", "new", 2), impostor];
        let names = identities(events.iter()).unwrap();
        assert_eq!(names.len(), 1);
        assert_eq!(names[0].0.site, "new");
        assert_eq!(names[0].1, 2);
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
        assert!(html.contains("href=\"#site-0\""));
        assert!(html.contains("id=\"site-0\""));
        assert!(html.contains("href=\"#node-0-0\""));
        assert!(html.contains("id=\"node-0-0\""));
        assert!(html.contains("not network connectivity"));
    }
}
