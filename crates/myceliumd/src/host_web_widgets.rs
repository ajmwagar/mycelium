//! Presentation only: shared Coherence contract/renderer, existing host observations.
use super::{escape_html, Snapshot};
use coherence_widget_contract::{Metric, Snapshot as WidgetSnapshot};
use std::io::Read;

pub(super) fn snapshot(host: &Snapshot) -> WidgetSnapshot {
    let observed = host
        .health_observed_at
        .into_iter()
        .chain(host.hardware_observed_at)
        .min()
        .unwrap_or(0)
        .saturating_mul(1000);
    let memory = match (host.memory_available_bytes, host.memory_total_bytes) {
        (Some(free), Some(total)) if total > 0 && free <= total => {
            Some(((total - free) as f64 / total as f64 * 100.) as f32)
        }
        _ => None,
    };
    let metric = |id: &str, label: &str, unit: &str, value, maximum| Metric {
        id: id.into(),
        label: label.into(),
        unit: unit.into(),
        value,
        maximum,
        history: vec![],
    };
    WidgetSnapshot {
        schema_version: 1,
        widget_id: "host".into(),
        observed_at_unix_ms: observed,
        expires_at_unix_ms: observed.saturating_add(120_000),
        metrics: vec![
            metric("memory", "Memory used", "%", memory, Some(100.)),
            metric(
                "uptime",
                "Uptime",
                "h",
                host.uptime_seconds.map(|v| v as f32 / 3600.),
                None,
            ),
            metric(
                "hardware",
                "Indexed devices",
                "devices",
                host.hardware_devices.map(|v| v as f32),
                None,
            ),
        ],
        model_catalog: None,
    }
}

pub(super) fn asset(directory: &str, route: &str) -> super::Result<(Vec<u8>, &'static str)> {
    let (name, mime) = match route {
        "/widgets/coherence-widgets.js" => ("coherence-widgets.js", "text/javascript"),
        "/widgets/coherence_widget_web.js" => ("coherence_widget_web.js", "text/javascript"),
        "/widgets/coherence_widget_web_bg.wasm" => {
            ("coherence_widget_web_bg.wasm", "application/wasm")
        }
        "/widgets/widgets.css" => ("widgets.css", "text/css"),
        _ => return Err("unknown widget asset".into()),
    };
    let mut bytes = vec![];
    std::fs::File::open(std::path::Path::new(directory).join(name))?
        .take(2 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 2 * 1024 * 1024 {
        return Err("widget asset exceeds 2 MiB".into());
    }
    Ok((bytes, mime))
}

pub(super) fn page(host: &Snapshot, gpu: bool) -> String {
    let name = escape_html(&host.hostname);
    let site = escape_html(&host.site);
    let identity = escape_html(&host.node_id);
    let platform = escape_html(&format!("{} / {}", host.platform, host.architecture));
    let url = match (
        mycelium_dns_policy::canonical_domain(&host.hostname),
        mycelium_dns_policy::canonical_domain(&host.site),
    ) {
        (Ok(name), Ok(site)) if !name.contains('.') && !site.contains('.') => {
            Some(format!("https://{name}.{site}.myc/"))
        }
        _ => None,
    };
    let qr = url
        .as_ref()
        .and_then(|url| qrcode::QrCode::new(url.as_bytes()).ok())
        .map(|code| {
            code.render::<qrcode::render::svg::Color>()
                .min_dimensions(176, 176)
                .build()
        })
        .unwrap_or_else(|| "<p>Viewer address unavailable</p>".into());
    let url_label = escape_html(url.as_deref().unwrap_or("No canonical viewer address"));
    let ips = if host.addresses.is_empty() {
        "<li>Not observed</li>".into()
    } else {
        host.addresses
            .iter()
            .map(|ip| format!("<li><code>{}</code></li>", escape_html(ip)))
            .collect::<String>()
    };
    let css = include_str!("viewer-shell/coherence-product.css");
    let widgets = if gpu {
        "<link rel=\"stylesheet\" href=\"/widgets/widgets.css\"><div class=\"co-widget\" data-co-widget=\"host\"><canvas aria-label=\"Host telemetry\"></canvas><div class=\"co-widget__labels\" data-co-labels></div><p data-co-status>Connecting to owner observations…</p></div><script type=\"module\" src=\"/widgets/coherence-widgets.js\"></script>".to_owned()
    } else {
        "<p>GPU widgets are not installed on this host. <a href=\"/api/widgets/host\">Telemetry JSON</a></p>".into()
    };
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{name} · Mycelium</title><style>{css}
body{{margin:0;background:var(--co-color-background,#151b18);color:var(--co-color-text,#e5ece3);font:15px system-ui,sans-serif}}main{{max-width:1200px;margin:auto;padding:32px}}header{{display:flex;justify-content:space-between;align-items:center;gap:20px;border-bottom:1px solid var(--co-color-border,#3b493f);padding-bottom:24px}}h1{{font-size:38px;margin:8px 0}}h2{{font-size:18px;margin:0 0 16px}}p{{line-height:1.6;color:var(--co-color-text-muted,#b3c4af)}}a{{color:var(--co-color-brand,#cae8ac)}}.grid{{display:grid;grid-template-columns:minmax(0,2fr) minmax(260px,1fr);gap:24px;margin-top:24px}}section,aside{{padding:24px;background:var(--co-color-surface,#202922);border:1px solid var(--co-color-border,#3b493f);border-radius:16px}}.qr{{background:white;width:176px;padding:12px;border-radius:12px}}.qr svg{{display:block;width:176px;height:176px}}code{{overflow-wrap:anywhere}}ul{{padding-left:20px;line-height:1.9}}.identity{{font-size:12px}}@media(max-width:760px){{.grid{{grid-template-columns:1fr}}main{{padding:16px}}}}</style></head><body><main><header><div><p>MYCELIUM · {site}</p><h1>{name}</h1><p>{platform}</p></div><a href="/api/host">Host JSON ↗</a></header><div class="grid"><section><h2>Owner telemetry</h2>{widgets}<p>Retained observations, not a connection guarantee. Missing values remain unavailable.</p></section><aside><h2>Connect to this host</h2><div class="qr">{qr}</div><p><code>{url_label}</code></p><p>Viewer-link QR only. Not an invitation or access grant. HTTPS ingress and DNS must be configured.</p><h2>Observed IP addresses</h2><ul>{ips}</ul><p>Interface addresses are not necessarily reachable from your device.</p><h2>Node identity</h2><code class="identity">{identity}</code></aside></div></main></body></html>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn contract_keeps_missing_values_and_real_observation_time() {
        let host = Snapshot::default();
        let empty = snapshot(&host);
        empty.validate().unwrap();
        assert!(empty.metrics.iter().all(|m| m.value.is_none()));
        assert_eq!(empty.observed_at_unix_ms, 0);
        let host = Snapshot {
            health_observed_at: Some(100),
            hardware_observed_at: Some(90),
            memory_available_bytes: Some(25),
            memory_total_bytes: Some(100),
            ..Default::default()
        };
        let rich = snapshot(&host);
        rich.validate().unwrap();
        assert_eq!(rich.observed_at_unix_ms, 90_000);
        assert_eq!(rich.metrics[0].value, Some(75.));
    }
    #[test]
    fn identity_page_escapes_data_and_labels_qr_as_non_authority() {
        let host = Snapshot {
            hostname: "titan".into(),
            site: "titan".into(),
            addresses: vec!["<script>".into()],
            ..Default::default()
        };
        let html = page(&host, true);
        assert!(html.contains("<svg"));
        assert!(html.contains("https://titan.titan.myc/"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("data-co-widget=\"host\""));
        assert!(asset("/tmp", "/widgets/../node.key").is_err());
    }
}
