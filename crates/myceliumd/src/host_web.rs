//! Optional, read-only host presentation. Transport membership is NOT viewer authority.
//! Human certificate bindings are explicit bootstrap identity evidence; signed access
//! grants remain the authority and are re-evaluated for each request.

use std::{collections::BTreeMap, error::Error, net::SocketAddr, sync::Arc, time::Duration};

use mycelium_peer_protocol::AccessStatement;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    sync::Semaphore,
};
use tokio_rustls::TlsAcceptor;

use crate::peer::{AccessStateView, Mesh};

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
const MAX_CONFIG: u64 = 16 * 1024;
const MAX_HEADER: usize = 8192;
const DEADLINE: Duration = Duration::from_secs(10);

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub listen: SocketAddr,
    /// Publish only an explicit non-loopback page entrance; off by default.
    #[serde(default)]
    pub advertise: bool,
    /// Optional HTTPS-only identity; does not replace the peer identity or CA.
    #[serde(default)]
    pub server_identity: Option<ServerIdentity>,
    /// Explicit human leaf trust, only for this listener; not a peer CA change.
    #[serde(default)]
    pub bootstrap_viewer_certificates: Vec<String>,
    /// Temporary, administrator-installed certificate-to-human bindings, NOT ACLs.
    pub bootstrap_viewer_bindings: BTreeMap<String, String>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServerIdentity {
    pub certificate: String,
    pub private_key: String,
}

impl Config {
    fn validate(&self) -> Result<()> {
        if self.advertise && (self.listen.ip().is_loopback() || self.listen.ip().is_unspecified()) {
            return Err("host web advertisement requires a non-loopback explicit address".into());
        }
        if self.bootstrap_viewer_certificates.len() > 64 {
            return Err("host web permits at most 64 bootstrap viewer certificates".into());
        }
        for path in &self.bootstrap_viewer_certificates {
            if !std::path::Path::new(path).is_absolute()
                || path.len() > 4096
                || path.chars().any(char::is_control)
            {
                return Err("host web viewer certificates require absolute paths".into());
            }
        }
        if let Some(identity) = &self.server_identity {
            for path in [&identity.certificate, &identity.private_key] {
                if !std::path::Path::new(path).is_absolute()
                    || path.len() > 4096
                    || path.chars().any(char::is_control)
                {
                    return Err(
                        "host web server identity requires absolute certificate/key paths".into(),
                    );
                }
            }
        }
        if self.listen.port() == 0 || self.listen.port() == 80 || self.listen.ip().is_multicast() {
            return Err("host web requires an explicit HTTPS port (not HTTP port 80)".into());
        }
        if self.bootstrap_viewer_bindings.is_empty() || self.bootstrap_viewer_bindings.len() > 64 {
            return Err("host web requires 1..64 bootstrap viewer bindings".into());
        }
        for (digest, principal) in &self.bootstrap_viewer_bindings {
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
                || principal.is_empty()
                || principal.len() > 256
                || principal.chars().any(char::is_control)
            {
                return Err("invalid host web certificate digest or principal".into());
            }
        }
        Ok(())
    }

    pub(crate) fn viewer_roots(&self) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
        use std::io::Read;
        let mut roots = Vec::new();
        for path in &self.bootstrap_viewer_certificates {
            let file = std::fs::File::open(path)?;
            let mut bytes = Vec::new();
            file.take(64 * 1024 + 1).read_to_end(&mut bytes)?;
            if bytes.len() > 64 * 1024 {
                return Err("bootstrap viewer certificate exceeds 64 KiB".into());
            }
            let certificates =
                rustls_pemfile::certs(&mut std::io::BufReader::new(bytes.as_slice()))
                    .collect::<std::result::Result<Vec<_>, _>>()?;
            if certificates.len() != 1 {
                return Err("bootstrap viewer file must contain exactly one certificate".into());
            }
            let certificate = certificates
                .into_iter()
                .next()
                .expect("one certificate checked");
            let digest = mycelium_peer_protocol::sha256_hex(certificate.as_ref());
            if !self.bootstrap_viewer_bindings.contains_key(&digest) {
                return Err(
                    "bootstrap viewer certificate lacks an explicit principal binding".into(),
                );
            }
            roots.push(certificate);
        }
        Ok(roots)
    }
}

pub(crate) fn load_optional() -> Result<Option<Config>> {
    let path = crate::home_dir().join("host-web.json");
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    use std::io::Read;
    let mut bytes = Vec::new();
    (&mut file).take(MAX_CONFIG + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CONFIG {
        return Err("host web configuration exceeds 16 KiB".into());
    }
    let config: Config =
        serde_json::from_slice(&bytes).map_err(|_| "invalid host web configuration JSON")?;
    config.validate()?;
    Ok(Some(config))
}

fn authorized(
    config: &Config,
    digest: &str,
    state: &AccessStateView,
    node_id: &str,
    at: u64,
) -> bool {
    let Some(principal) = config.bootstrap_viewer_bindings.get(digest) else {
        return false;
    };
    let scope = format!("host-web:{node_id}");
    state.grants.iter().any(|grant| {
        grant.active
            && grant.revoked_by.is_empty()
            && matches!(&grant.record.statement,
            AccessStatement::Grant { principal: subject, roles, scopes, not_before, not_after, .. }
            if subject == principal && roles.iter().any(|role| role == "host-viewer")
                && scopes.iter().any(|candidate| candidate == &scope)
                && *not_before <= at && at < *not_after)
    })
}

pub(crate) async fn start(mesh: Arc<Mesh>, config: Config, acceptor: TlsAcceptor) -> Result<()> {
    let listener = TcpListener::bind(config.listen).await?;
    let address = config.listen;
    if config.advertise {
        crate::page_advertisement::publish(&crate::home_dir(),mesh.node_id(),address)?;
        let owner = mesh.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                if !load_optional().ok().flatten().is_some_and(|c| c.advertise && c.listen == address) {
                    eprintln!("myceliumd: host web advertisement changed; renewal stopped");
                    break;
                }
                if let Err(error) = crate::page_advertisement::publish(&crate::home_dir(),owner.node_id(),address) {
                    eprintln!("myceliumd: host web advertisement renewal failed: {error}");
                    break;
                }
            }
        });
    }
    let viewer_certificates = config.bootstrap_viewer_certificates;
    let permits = Arc::new(Semaphore::new(32));
    eprintln!("myceliumd: authenticated host web listening on https://{address}");
    tokio::spawn(async move {
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(connection) => connection,
                Err(error) => {
                    eprintln!("myceliumd: host web listener failed: {error}");
                    break;
                }
            };
            let Ok(permit) = permits.clone().try_acquire_owned() else {
                continue;
            };
            let mesh = mesh.clone();
            let acceptor = acceptor.clone();
            let viewer_certificates = viewer_certificates.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let result = tokio::time::timeout(DEADLINE, async {
                    let mut stream = acceptor.accept(tcp).await?;
                    let digest = stream
                        .get_ref()
                        .1
                        .peer_certificates()
                        .and_then(|chain| chain.first())
                        .map(|cert| mycelium_peer_protocol::sha256_hex(cert.as_ref()))
                        .ok_or("host web requires a client certificate")?;
                    let route = match read_authorized_route(&mut stream, || async {
                        // Evaluate after headers arrive: slow clients cannot retain
                        // authorization obtained before their binding was removed.
                        let decision = async {
                            let fresh = load_optional()?.ok_or("host web disabled")?;
                            if fresh.listen != address {
                                return Err("host web listener changed; restart required".into());
                            }
                            if fresh.bootstrap_viewer_certificates != viewer_certificates {
                                return Err(
                                    "host web viewer trust changed; restart required".into()
                                );
                            }
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)?
                                .as_secs();
                            Ok::<_, Box<dyn Error + Send + Sync>>(authorized(
                                &fresh,
                                &digest,
                                &mesh.access_view(now).await,
                                mesh.node_id(),
                                now,
                            ))
                        }
                        .await;
                        match decision {
                            Ok(allowed) => allowed,
                            Err(error) => {
                                eprintln!("myceliumd: host web authorization failed: {error}");
                                false
                            }
                        }
                    })
                    .await
                    {
                        Ok(route) => route,
                        Err(status) => {
                            return respond(
                                &mut stream,
                                status,
                                "text/plain",
                                "Request rejected.\n",
                            )
                            .await
                        }
                    };
                    let snapshot = local_snapshot(&mesh).await;
                    let json = serde_json::to_string_pretty(&snapshot)?;
                    if json.len() > 256 * 1024 {
                        return Err("host web projection exceeds response bound".into());
                    }
                    if route == "/api/host" {
                        respond(&mut stream, 200, "application/json", &json).await
                    } else {
                        respond(
                            &mut stream,
                            200,
                            "text/html; charset=utf-8",
                            &page(&snapshot),
                        )
                        .await
                    }
                })
                .await;
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => eprintln!("myceliumd: host web request failed: {error}"),
                    Err(_) => eprintln!("myceliumd: host web request timed out"),
                }
            });
        }
    });
    Ok(())
}

#[derive(Default, Serialize)]
struct Snapshot {
    node_id: String,
    hostname: String,
    site: String,
    platform: String,
    architecture: String,
    daemon_version: String,
    /// Retained observations are not claimed to be fresh or live connections.
    health_observed_at: Option<u64>,
    uptime_seconds: Option<u64>,
    memory_available_bytes: Option<u64>,
    memory_total_bytes: Option<u64>,
    hardware_observed_at: Option<u64>,
    hardware_devices: Option<usize>,
}

async fn local_snapshot(mesh: &Mesh) -> Snapshot {
    let hello = mesh.local_hello().await;
    mesh.project_local(|health, hardware| Snapshot {
        node_id: hello.node_id,
        hostname: hello.hostname,
        site: hello.site,
        platform: format!("{:?}", hello.platform),
        architecture: hello.architecture,
        daemon_version: hello.daemon_version,
        health_observed_at: health.map(|value| value.observed_at),
        uptime_seconds: health.map(|value| value.uptime_seconds),
        memory_available_bytes: health.map(|value| value.memory_available_bytes),
        memory_total_bytes: health.map(|value| value.memory_total_bytes),
        hardware_observed_at: hardware.map(|value| value.observed_at),
        hardware_devices: hardware.map(|value| value.devices.len()),
    })
    .await
}

async fn read_route<S: AsyncRead + Unpin>(stream: &mut S) -> std::result::Result<String, u16> {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() >= MAX_HEADER {
            return Err(431);
        }
        header.push(stream.read_u8().await.map_err(|_| 400u16)?);
    }
    let text = std::str::from_utf8(&header).map_err(|_| 400u16)?;
    let mut request = text.lines().next().ok_or(400u16)?.split_whitespace();
    let method = request.next().ok_or(400u16)?;
    let path = request.next().ok_or(400u16)?;
    let version = request.next().ok_or(400u16)?;
    if request.next().is_some() || version != "HTTP/1.1" {
        return Err(400);
    }
    if method != "GET" {
        return Err(405);
    }
    if !matches!(path, "/" | "/api/host") {
        return Err(404);
    }
    Ok(path.into())
}

async fn read_authorized_route<S, F, Fut>(
    stream: &mut S,
    authorize: F,
) -> std::result::Result<String, u16>
where
    S: AsyncRead + Unpin,
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let route = read_route(stream).await?;
    if !authorize().await {
        return Err(403);
    }
    Ok(route)
}

async fn respond<S: AsyncWrite + Unpin>(
    stream: &mut S,
    status: u16,
    content_type: &str,
    body: &str,
) -> Result<()> {
    let reason = match status {
        200 => "OK",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        431 => "Request Header Fields Too Large",
        _ => "Bad Request",
    };
    let header = format!("HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'\r\n\r\n", body.len());
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}

fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn page(snapshot: &Snapshot) -> String {
    let mut rows = String::new();
    let mut row = |label: &str, value: String| {
        rows.push_str(&format!("<dt>{label}</dt><dd>{}</dd>", escape_html(&value)));
    };
    row("Site", snapshot.site.clone());
    row(
        "Platform",
        format!("{} / {}", snapshot.platform, snapshot.architecture),
    );
    row("Mycelium", snapshot.daemon_version.clone());
    row("Node identity", snapshot.node_id.clone());
    row(
        "Uptime",
        snapshot
            .uptime_seconds
            .map(|value| format!("{value} seconds"))
            .unwrap_or_else(|| "Not observed".into()),
    );
    row(
        "Memory available / total",
        match (snapshot.memory_available_bytes, snapshot.memory_total_bytes) {
            (Some(available), Some(total)) => format!(
                "{} / {} MiB",
                available / (1024 * 1024),
                total / (1024 * 1024)
            ),
            _ => "Not observed".into(),
        },
    );
    row(
        "Health observed",
        snapshot
            .health_observed_at
            .map(|value| format!("Unix timestamp {value}"))
            .unwrap_or_else(|| "Not observed".into()),
    );
    row(
        "Hardware devices",
        snapshot
            .hardware_devices
            .map(|value| value.to_string())
            .unwrap_or_else(|| "Not observed".into()),
    );
    row(
        "Hardware observed",
        snapshot
            .hardware_observed_at
            .map(|value| format!("Unix timestamp {value}"))
            .unwrap_or_else(|| "Not observed".into()),
    );
    let hostname = escape_html(&snapshot.hostname);
    format!("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{hostname} · Mycelium</title><style>body{{background:#252d27;color:#e5ece3;font:16px monospace;max-width:70ch;margin:4rem auto;padding:1rem}}dl{{display:grid;grid-template-columns:minmax(10ch,1fr) 2fr;gap:1rem}}dd{{margin:0;overflow-wrap:anywhere}}dt,p{{color:#b3c4af}}a{{color:#d3e6c6}}</style><header><p>Mycelium · read-only</p><h1>{hostname}</h1></header><main><dl>{rows}</dl><p>Timestamps describe retained observations, not a live connection guarantee.</p><a href=\"/api/host\">JSON observation</a></main></html>")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::AccessGrantView;
    use mycelium_peer_protocol::AccessRecord;

    fn config() -> Config {
        Config {
            listen: "127.0.0.1:8443".parse().unwrap(),
            advertise: false,
            server_identity: None,
            bootstrap_viewer_certificates: Vec::new(),
            bootstrap_viewer_bindings: [("a".repeat(64), "alice".into())].into(),
        }
    }

    #[test]
    fn config_is_bounded_and_fail_closed() {
        config().validate().unwrap();
        let mut value = config();
        value.listen.set_port(80);
        assert!(value.validate().is_err());
        value = config();
        value.server_identity = Some(ServerIdentity {
            certificate: "relative.pem".into(),
            private_key: "/private/key.pem".into(),
        });
        assert!(value.validate().is_err());
        value = config();
        value.bootstrap_viewer_bindings.clear();
        assert!(value.validate().is_err());
        assert!(serde_json::from_str::<Config>(
            r#"{"listen":"127.0.0.1:8443","bootstrap_viewer_bindings":{},"oidc":true}"#
        )
        .is_err());
    }

    #[test]
    fn transport_pin_requires_active_targeted_signed_authority_grant() {
        let mut state = AccessStateView {
            grants: vec![],
            revocations: vec![],
        };
        let digest = "a".repeat(64);
        assert!(!authorized(&config(), &digest, &state, "node", 50));
        state.grants.push(AccessGrantView {
            active: true,
            revoked_by: vec![],
            record: AccessRecord {
                protocol_version: 1,
                signer: "issuer".into(),
                signature: "verified by access_view".into(),
                statement: AccessStatement::Grant {
                    grant_id: "grant".into(),
                    principal: "alice".into(),
                    serial: 1,
                    roles: vec!["host-viewer".into()],
                    scopes: vec!["host-web:node".into()],
                    unix_users: vec![],
                    ssh_public_keys: vec![],
                    oidc_audiences: vec![],
                    oidc_ssh_key_exchange: false,
                    not_before: 0,
                    not_after: 100,
                },
            },
        });
        assert!(authorized(&config(), &digest, &state, "node", 50));
        assert!(!authorized(&config(), &digest, &state, "node", 100));
        assert!(!authorized(&config(), &digest, &state, "other", 50));
        assert!(!authorized(&config(), &"b".repeat(64), &state, "node", 50));
        state.grants[0].active = false;
        assert!(!authorized(&config(), &digest, &state, "node", 50));
        state.grants[0].active = true;
        state.grants[0].revoked_by.push("revocation".into());
        assert!(!authorized(&config(), &digest, &state, "node", 50));
        state.grants[0].revoked_by.clear();
        let mut wrong_identity = config();
        wrong_identity
            .bootstrap_viewer_bindings
            .insert(digest.clone(), "bob".into());
        assert!(!authorized(&wrong_identity, &digest, &state, "node", 50));
        if let AccessStatement::Grant { roles, .. } = &mut state.grants[0].record.statement {
            roles.clear();
        }
        assert!(!authorized(&config(), &digest, &state, "node", 50));
    }

    #[tokio::test]
    async fn parser_rejects_mutations_and_oversized_headers() {
        assert_eq!(
            read_route(&mut &b"GET /api/host HTTP/1.1\r\nHost: node.myc\r\n\r\n"[..])
                .await
                .unwrap(),
            "/api/host"
        );
        assert_eq!(
            read_route(&mut &b"POST / HTTP/1.1\r\n\r\n"[..]).await,
            Err(405)
        );
        assert_eq!(
            read_route(&mut &b"GET /secrets HTTP/1.1\r\n\r\n"[..]).await,
            Err(404)
        );
        assert_eq!(
            read_route(&mut &vec![b'a'; MAX_HEADER + 1][..]).await,
            Err(431)
        );
    }

    #[test]
    fn hostile_observations_are_text_not_markup() {
        let rendered = page(&Snapshot {
            hostname: "<script>alert('x')</script>&".into(),
            ..Snapshot::default()
        });
        assert!(!rendered.contains("<script>"));
        assert!(rendered.contains("&lt;script&gt;"));
        assert!(rendered.contains("<dt>Hardware devices</dt>"));
        assert!(rendered.contains("Not observed"));
    }

    #[test]
    fn bootstrap_leaf_trust_requires_exact_configured_identity_binding() {
        let certificate =
            rcgen::generate_simple_self_signed(vec!["viewer.example".into()]).unwrap();
        let directory = std::env::temp_dir().join(format!(
            "mycelium-viewer-roots-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("viewer.pem");
        std::fs::write(&path, certificate.cert.pem()).unwrap();
        let mut value = config();
        value
            .bootstrap_viewer_certificates
            .push(path.to_str().unwrap().into());
        assert!(value.viewer_roots().is_err());
        value.bootstrap_viewer_bindings.insert(
            mycelium_peer_protocol::sha256_hex(certificate.cert.der()),
            "alice".into(),
        );
        assert_eq!(value.viewer_roots().unwrap().len(), 1);
        std::fs::write(
            &path,
            format!("{}{}", certificate.cert.pem(), certificate.cert.pem()),
        )
        .unwrap();
        assert!(value.viewer_roots().is_err());
        std::fs::write(&path, vec![b'a'; 64 * 1024 + 1]).unwrap();
        assert!(value.viewer_roots().is_err());
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn revoked_access_issuer_cannot_supply_viewer_authority() {
        use crate::authority::AuthorityResolver;
        use ed25519_dalek::SigningKey;
        use mycelium_peer_protocol::{AuthorityCapability, AuthorityRecord, AuthorityStatement};
        use std::collections::BTreeSet;
        let root = SigningKey::from_bytes(&[71; 32]);
        let issuer = SigningKey::from_bytes(&[72; 32]);
        let hex = |key: &SigningKey| {
            key.verifying_key()
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        let delegation = AuthorityRecord::sign(
            &root,
            AuthorityStatement::Delegate {
                delegation_id: "web-issuer".into(),
                subject: hex(&issuer),
                capabilities: vec![AuthorityCapability::AccessPublish],
                not_before: 0,
                not_after: 100,
            },
        )
        .unwrap();
        let revocation = AuthorityRecord::sign(
            &root,
            AuthorityStatement::Revoke {
                revocation_id: "withdraw-web-issuer".into(),
                delegation_id: "web-issuer".into(),
                revoked_at: 40,
                reason: "test".into(),
            },
        )
        .unwrap();
        let roots = BTreeSet::from([hex(&root)]);
        let empty = BTreeSet::new();
        let before = AuthorityResolver::new(&roots, &empty, &empty, [&delegation], 50);
        assert!(before.access(&hex(&issuer)).authorized);
        let after = AuthorityResolver::new(&roots, &empty, &empty, [&delegation, &revocation], 50);
        assert!(!after.access(&hex(&issuer)).authorized);
        // Mesh::access_view filters that issuer's grants out, leaving no viewer grant.
        let state = AccessStateView {
            grants: vec![],
            revocations: vec![],
        };
        assert!(!authorized(&config(), &"a".repeat(64), &state, "node", 50));
    }

    #[tokio::test]
    async fn slow_headers_cannot_retain_earlier_viewer_authorization() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let allowed = Arc::new(AtomicBool::new(true));
        let (mut writer, mut reader) = tokio::io::duplex(128);
        let access = allowed.clone();
        let task = tokio::spawn(async move {
            read_authorized_route(&mut reader, || async { access.load(Ordering::SeqCst) }).await
        });
        writer.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        tokio::task::yield_now().await;
        allowed.store(false, Ordering::SeqCst);
        writer.write_all(b"Host: node.myc\r\n\r\n").await.unwrap();
        assert_eq!(task.await.unwrap(), Err(403));
    }

    #[tokio::test]
    async fn responses_are_closed_uncacheable_and_script_free() {
        let (mut writer, mut reader) = tokio::io::duplex(4096);
        respond(&mut writer, 403, "text/plain", "Viewer access denied.\n")
            .await
            .unwrap();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).await.unwrap();
        let response = String::from_utf8(bytes).unwrap();
        assert!(response.starts_with("HTTP/1.1 403 Forbidden\r\n"));
        assert!(response.contains("Cache-Control: no-store\r\n"));
        assert!(response.contains("frame-ancestors 'none'"));
        assert!(response.ends_with("Viewer access denied.\n"));
        assert!(!response.contains("hostname"));
    }
}
