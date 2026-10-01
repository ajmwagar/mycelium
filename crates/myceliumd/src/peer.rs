use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::io::BufReader as StdBufReader;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::IpAddr;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use mycelium_peer_protocol::{
    decode_hex, encode_hex, sha256_hex, AccessRecord, AccessStatement, FilesystemHealth,
    HostHealth, PeerEvent, PeerHello, PeerMessage, Platform, ProcessHealth, ReleaseManifest,
    SignedEnvelope, PROTOCOL_VERSION,
};
use rand_core::OsRng;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_rustls::{TlsAcceptor, TlsConnector};

type AnyError = Box<dyn Error + Send + Sync>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerView {
    pub origin: String,
    pub hello: Option<PeerHello>,
    pub health: Option<HostHealth>,
    pub last_seen: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct AccessGrantView {
    pub record: AccessRecord,
    pub active: bool,
    pub revoked_by: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AccessStateView {
    pub grants: Vec<AccessGrantView>,
    pub revocations: Vec<AccessRecord>,
}

#[derive(Debug, Deserialize)]
struct ReleaseSetFile {
    version: String,
    channel: String,
    artifacts: Vec<ReleaseSetArtifact>,
}

#[derive(Debug, Deserialize)]
struct ReleaseSetArtifact {
    target: String,
    binary: String,
}

pub struct Mesh {
    key: SigningKey,
    hello: PeerHello,
    sequence: AtomicU64,
    observations: Mutex<BTreeMap<String, SignedEnvelope>>,
    allowed_origins: Option<BTreeSet<String>>,
    trusted_release_keys: BTreeSet<String>,
    trusted_access_keys: BTreeSet<String>,
}

impl Mesh {
    #[cfg(test)]
    pub fn ephemeral_for_test() -> Arc<Self> {
        let key = SigningKey::from_bytes(&[3; 32]);
        let node_id = encode_hex(key.verifying_key().as_bytes());
        Arc::new(Self {
            key,
            hello: PeerHello {
                node_id,
                protocol_version: PROTOCOL_VERSION,
                site: "test".into(),
                hostname: "test".into(),
                platform: Platform::Linux,
                architecture: "test".into(),
                daemon_version: crate::VERSION.into(),
                capabilities: vec!["system.health".into()],
            },
            sequence: AtomicU64::new(0),
            observations: Mutex::new(BTreeMap::new()),
            allowed_origins: None,
            trusted_release_keys: BTreeSet::new(),
            trusted_access_keys: BTreeSet::new(),
        })
    }

    pub fn boot() -> Result<Arc<Self>, AnyError> {
        let key = load_or_create_key(&crate::peer_key_path())?;
        let node_id = encode_hex(key.verifying_key().as_bytes());
        let hostname = output("hostname", &["-s"])?.trim().to_owned();
        let site = std::env::var("MYCELIUM_SITE").unwrap_or_else(|_| hostname.clone());
        let hello = PeerHello {
            node_id,
            protocol_version: PROTOCOL_VERSION,
            site,
            hostname,
            platform: platform(),
            architecture: std::env::consts::ARCH.into(),
            daemon_version: crate::VERSION.into(),
            capabilities: vec!["system.health".into()],
        };
        let allowed_origins = std::env::var("MYCELIUM_PEER_ALLOW").ok().map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(str::to_owned)
                .collect::<BTreeSet<_>>()
        });
        let trusted_release_keys = csv_set("MYCELIUM_RELEASE_KEYS");
        let trusted_access_keys = csv_set("MYCELIUM_ACCESS_KEYS");
        let observations = match std::fs::read_to_string(crate::peer_observations_path()) {
            Ok(text) => serde_json::from_str::<Vec<SignedEnvelope>>(&text)?
                .into_iter()
                .filter(|envelope| {
                    let release_allowed = match &envelope.event {
                        PeerEvent::Release(release) => {
                            trusted_release_keys.contains(&release.signer)
                                && release.verify().is_ok()
                        }
                        PeerEvent::Access(record) => {
                            trusted_access_keys.contains(&record.signer) && record.verify().is_ok()
                        }
                        _ => true,
                    };
                    release_allowed
                        && envelope.verify().is_ok()
                        && (envelope.origin == hello.node_id
                            || allowed_origins
                                .as_ref()
                                .is_none_or(|allowed| allowed.contains(&envelope.origin)))
                })
                .map(|envelope| (event_key(&envelope), envelope))
                .collect(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(error) => return Err(error.into()),
        };
        let sequence = observations
            .values()
            .filter(|envelope| envelope.origin == hello.node_id)
            .map(|envelope| envelope.sequence)
            .max()
            .unwrap_or(0);
        Ok(Arc::new(Self {
            key,
            hello,
            sequence: AtomicU64::new(sequence),
            observations: Mutex::new(observations),
            allowed_origins,
            trusted_release_keys,
            trusted_access_keys,
        }))
    }

    pub async fn start(self: &Arc<Self>) -> Result<(), AnyError> {
        self.publish(PeerEvent::Hello(self.hello.clone())).await?;
        let collector = self.clone();
        tokio::spawn(async move {
            loop {
                match tokio::task::spawn_blocking(collect_health).await {
                    Ok(Ok(health)) => {
                        if let Err(error) = collector.publish(PeerEvent::Health(health)).await {
                            eprintln!("myceliumd: publish local health: {error}");
                        }
                    }
                    Ok(Err(error)) => eprintln!("myceliumd: collect local health: {error}"),
                    Err(error) => eprintln!("myceliumd: health task: {error}"),
                }
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });

        if let Some(tls) = TlsSettings::from_env()? {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
            if let Some(address) = tls.listen.clone() {
                let mesh = self.clone();
                let acceptor = TlsAcceptor::from(Arc::new(tls.server_config()?));
                tokio::spawn(async move {
                    if let Err(error) = mesh.listen(&address, acceptor).await {
                        eprintln!("myceliumd: peer listener failed: {error}");
                    }
                });
            }
            for seed in &tls.seeds {
                let mesh = self.clone();
                let seed = seed.clone();
                let connector = TlsConnector::from(Arc::new(tls.client_config()?));
                tokio::spawn(async move { mesh.dial_forever(seed, connector).await });
            }
        }
        Ok(())
    }

    pub async fn views(&self) -> Vec<PeerView> {
        let observations = self.observations.lock().await;
        let mut views = BTreeMap::<String, PeerView>::new();
        for envelope in observations.values() {
            let view = views.entry(envelope.origin.clone()).or_insert(PeerView {
                origin: envelope.origin.clone(),
                hello: None,
                health: None,
                last_seen: 0,
            });
            view.last_seen = view.last_seen.max(envelope.emitted_at);
            match &envelope.event {
                PeerEvent::Hello(hello) => view.hello = Some(hello.clone()),
                PeerEvent::Health(health) => view.health = Some(health.clone()),
                PeerEvent::Release(_) => {}
                PeerEvent::Access(_) => {}
            }
        }
        views.into_values().collect()
    }

    pub async fn releases(&self) -> Vec<ReleaseManifest> {
        self.observations
            .lock()
            .await
            .values()
            .filter_map(|envelope| match &envelope.event {
                PeerEvent::Release(release) => Some(release.clone()),
                _ => None,
            })
            .collect()
    }

    pub async fn access_records(&self) -> Vec<AccessRecord> {
        self.observations
            .lock()
            .await
            .values()
            .filter_map(|envelope| match &envelope.event {
                PeerEvent::Access(record) => Some(record.clone()),
                _ => None,
            })
            .collect()
    }

    pub async fn access_view(&self, at: u64) -> AccessStateView {
        let records = self.access_records().await;
        let revocations = records
            .iter()
            .filter(|record| matches!(record.statement, AccessStatement::Revoke { .. }))
            .cloned()
            .collect::<Vec<_>>();
        let grants = records
            .into_iter()
            .filter(|record| matches!(record.statement, AccessStatement::Grant { .. }))
            .map(|record| {
                let revoked_by = revocations
                    .iter()
                    .filter(|revocation| revocation.statement.revokes(&record.statement))
                    .filter_map(|revocation| match &revocation.statement {
                        AccessStatement::Revoke { revocation_id, .. } => {
                            Some(revocation_id.clone())
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                let in_window = match &record.statement {
                    AccessStatement::Grant {
                        not_before,
                        not_after,
                        ..
                    } => *not_before <= at && at < *not_after,
                    _ => false,
                };
                AccessGrantView {
                    active: in_window && revoked_by.is_empty(),
                    record,
                    revoked_by,
                }
            })
            .collect();
        AccessStateView {
            grants,
            revocations,
        }
    }

    pub async fn publish_access(
        &self,
        statement_path: &Path,
        signing_key: &Path,
    ) -> Result<AccessRecord, AnyError> {
        let statement: AccessStatement = serde_json::from_slice(&std::fs::read(statement_path)?)?;
        validate_access_statement(&statement)?;
        let key_bytes = std::fs::read(signing_key)?;
        let key = SigningKey::from_bytes(
            key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| "access signing key must be exactly 32 bytes")?,
        );
        let record = AccessRecord::sign(&key, statement)?;
        if !self.trusted_access_keys.contains(&record.signer) {
            return Err("access signer is not in MYCELIUM_ACCESS_KEYS".into());
        }
        self.publish(PeerEvent::Access(record.clone())).await?;
        Ok(record)
    }

    pub async fn publish_release(&self, release: ReleaseManifest) -> Result<(), AnyError> {
        if !self.trusted_release_keys.contains(&release.signer) {
            return Err("release signer is not in MYCELIUM_RELEASE_KEYS".into());
        }
        release
            .verify()
            .map_err(|error| format!("release signature: {error}"))?;
        self.publish(PeerEvent::Release(release)).await
    }

    pub async fn publish_artifact(
        &self,
        binary: &Path,
        signing_key: &Path,
        version: String,
        channel: String,
        target: Option<String>,
    ) -> Result<ReleaseManifest, AnyError> {
        validate_release_label("version", &version)?;
        validate_release_label("channel", &channel)?;
        let target = target.unwrap_or_else(local_target);
        validate_release_label("target", &target)?;
        let bytes = std::fs::read(binary)?;
        let key_bytes = std::fs::read(signing_key)?;
        let key = SigningKey::from_bytes(
            key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| "release signing key must be exactly 32 bytes")?,
        );
        let release = ReleaseManifest::sign(&key, version, channel, target, &bytes)?;
        std::fs::create_dir_all(crate::artifacts_dir())?;
        let final_path = artifact_path(&release.artifact_digest)?;
        if !final_path.is_file() {
            let temp = final_path.with_extension("tmp");
            std::fs::write(&temp, &bytes)?;
            std::fs::rename(temp, &final_path)?;
        }
        self.publish_release(release.clone()).await?;
        Ok(release)
    }

    pub async fn publish_artifact_set(
        &self,
        manifest: &Path,
        signing_key: &Path,
    ) -> Result<Vec<ReleaseManifest>, AnyError> {
        let definition: ReleaseSetFile = serde_json::from_slice(&std::fs::read(manifest)?)?;
        validate_release_label("version", &definition.version)?;
        validate_release_label("channel", &definition.channel)?;
        if definition.artifacts.is_empty() {
            return Err("release set must contain at least one artifact".into());
        }
        let key_bytes = std::fs::read(signing_key)?;
        let key = SigningKey::from_bytes(
            key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| "release signing key must be exactly 32 bytes")?,
        );
        let base = manifest.parent().unwrap_or_else(|| Path::new("."));
        let mut targets = BTreeSet::new();
        let mut prepared = Vec::with_capacity(definition.artifacts.len());
        for artifact in definition.artifacts {
            validate_release_label("target", &artifact.target)?;
            if !targets.insert(artifact.target.clone()) {
                return Err(format!("duplicate release target `{}`", artifact.target).into());
            }
            let path = {
                let path = Path::new(&artifact.binary);
                if path.is_absolute() {
                    path.to_owned()
                } else {
                    base.join(path)
                }
            };
            let bytes = std::fs::read(&path)
                .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
            let release = ReleaseManifest::sign(
                &key,
                definition.version.clone(),
                definition.channel.clone(),
                artifact.target,
                &bytes,
            )?;
            prepared.push((release, bytes));
        }

        // No release becomes visible until every input has been read, validated,
        // hashed, and signed successfully.
        std::fs::create_dir_all(crate::artifacts_dir())?;
        for (release, bytes) in &prepared {
            let final_path = artifact_path(&release.artifact_digest)?;
            if !final_path.is_file() {
                let temp = final_path.with_extension(format!("tmp-{}", std::process::id()));
                std::fs::write(&temp, bytes)?;
                std::fs::rename(temp, final_path)?;
            }
        }
        let releases = prepared
            .into_iter()
            .map(|(release, _)| release)
            .collect::<Vec<_>>();
        for release in &releases {
            self.publish_release(release.clone()).await?;
        }
        Ok(releases)
    }

    pub fn generate_release_key(path: &Path) -> Result<String, AnyError> {
        if path.exists() {
            return Err("release signing key already exists".into());
        }
        let key = SigningKey::generate(&mut OsRng);
        std::fs::write(path, key.to_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(encode_hex(key.verifying_key().as_bytes()))
    }

    async fn publish(&self, event: PeerEvent) -> Result<(), AnyError> {
        let sequence = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
        let envelope = SignedEnvelope::sign(&self.key, sequence, now(), event)?;
        self.merge(vec![envelope]).await
    }

    async fn merge(&self, incoming: Vec<SignedEnvelope>) -> Result<(), AnyError> {
        let mut changed = false;
        let mut observations = self.observations.lock().await;
        for envelope in incoming {
            let authorized = envelope.origin == self.hello.node_id
                || self
                    .allowed_origins
                    .as_ref()
                    .is_none_or(|allowed| allowed.contains(&envelope.origin));
            let event_authorized = match &envelope.event {
                PeerEvent::Release(release) => {
                    self.trusted_release_keys.contains(&release.signer) && release.verify().is_ok()
                }
                PeerEvent::Access(record) => {
                    self.trusted_access_keys.contains(&record.signer) && record.verify().is_ok()
                }
                _ => true,
            };
            if !authorized
                || !event_authorized
                || envelope.verify().is_err()
                || !event_origin_matches(&envelope)
            {
                continue;
            }
            let key = event_key(&envelope);
            let replace = observations
                .get(&key)
                .map(|current| envelope.sequence > current.sequence)
                .unwrap_or(true);
            if replace {
                observations.insert(key, envelope);
                changed = true;
            }
        }
        if changed {
            let values = observations.values().cloned().collect::<Vec<_>>();
            persist_observations(&values)?;
        }
        Ok(())
    }

    async fn listen(self: Arc<Self>, address: &str, acceptor: TlsAcceptor) -> Result<(), AnyError> {
        let listener = TcpListener::bind(address).await?;
        eprintln!("myceliumd: peer mesh listening on {address}");
        loop {
            let (tcp, peer) = listener.accept().await?;
            let mesh = self.clone();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                match acceptor.accept(tcp).await {
                    Ok(stream) => {
                        if let Err(error) = mesh.run_stream(stream).await {
                            eprintln!("myceliumd: peer {peer}: {error}");
                        }
                    }
                    Err(error) => eprintln!("myceliumd: peer TLS {peer}: {error}"),
                }
            });
        }
    }

    async fn dial_forever(self: Arc<Self>, seed: String, connector: TlsConnector) {
        let mut delay = Duration::from_secs(1);
        loop {
            match self.dial(&seed, connector.clone()).await {
                Ok(()) => delay = Duration::from_secs(1),
                Err(error) => eprintln!("myceliumd: peer seed {seed}: {error}"),
            }
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(Duration::from_secs(60));
        }
    }

    async fn dial(&self, seed: &str, connector: TlsConnector) -> Result<(), AnyError> {
        let tcp = TcpStream::connect(seed).await?;
        let host = seed
            .rsplit_once(':')
            .map(|(host, _)| host)
            .ok_or("seed must be host:port")?;
        let name = server_name(host.trim_matches(&['[', ']'][..]))?;
        let stream = connector.connect(name, tcp).await?;
        self.run_stream(stream).await
    }

    async fn run_stream<S>(&self, stream: S) -> Result<(), AnyError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let (reader, mut writer) = tokio::io::split(stream);
        send(&mut writer, &PeerMessage::Hello(self.hello.clone())).await?;
        let mut lines = BufReader::new(reader).lines();
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            tokio::select! {
                result = lines.next_line() => {
                    let Some(line) = result? else { return Ok(()); };
                    if line.len() > 1_048_576 { return Err("peer message exceeds 1 MiB".into()); }
                    match serde_json::from_str::<PeerMessage>(line.trim())? {
                        PeerMessage::Observations(values) => self.merge(values).await?,
                        PeerMessage::Digest(remote) => {
                            let newer = self
                                .observations
                                .lock()
                                .await
                                .iter()
                                .filter(|(key, envelope)| {
                                    remote.get(*key).copied().unwrap_or(0) < envelope.sequence
                                })
                                .map(|(_, envelope)| envelope.clone())
                                .collect::<Vec<_>>();
                            if !newer.is_empty() {
                                send(&mut writer, &PeerMessage::Observations(newer)).await?;
                            }
                        }
                        PeerMessage::Hello(hello) if hello.protocol_version != PROTOCOL_VERSION => {
                            return Err(format!("protocol {} is unsupported", hello.protocol_version).into());
                        }
                        PeerMessage::ArtifactRequest { digest, offset, length } => {
                            if let Some(chunk) = artifact_chunk(&digest, offset, length)? {
                                send(&mut writer, &chunk).await?;
                            }
                        }
                        PeerMessage::ArtifactChunk { digest, offset, data, complete } => {
                            accept_artifact_chunk(
                                &digest,
                                offset,
                                &data,
                                complete,
                                &self.releases().await,
                            )?;
                            if !complete {
                                if let Some(request) = self.next_artifact_request().await? {
                                    send(&mut writer, &request).await?;
                                }
                            }
                        }
                        PeerMessage::Hello(_) | PeerMessage::Ping { .. } => {}
                    }
                }
                _ = interval.tick() => {
                    let digest = self
                        .observations
                        .lock()
                        .await
                        .iter()
                        .map(|(key, envelope)| (key.clone(), envelope.sequence))
                        .collect();
                    send(&mut writer, &PeerMessage::Digest(digest)).await?;
                    if let Some(request) = self.next_artifact_request().await? {
                        send(&mut writer, &request).await?;
                    }
                }
            }
        }
    }

    async fn next_artifact_request(&self) -> Result<Option<PeerMessage>, AnyError> {
        let target = local_target();
        let channel = std::env::var("MYCELIUM_UPDATE_CHANNEL").unwrap_or_else(|_| "canary".into());
        let release = self
            .releases()
            .await
            .into_iter()
            .filter(|release| release.target == target && release.channel == channel)
            .max_by(|left, right| left.version.cmp(&right.version));
        let Some(release) = release else {
            return Ok(None);
        };
        if artifact_path(&release.artifact_digest)?.is_file() {
            return Ok(None);
        }
        let partial = partial_artifact_path(&release.artifact_digest)?;
        let offset = std::fs::metadata(partial)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        if offset > release.artifact_size {
            return Err("partial artifact exceeds signed size".into());
        }
        Ok(Some(PeerMessage::ArtifactRequest {
            digest: release.artifact_digest,
            offset,
            length: 65_536,
        }))
    }
}

#[derive(Clone)]
struct TlsSettings {
    listen: Option<String>,
    seeds: Vec<String>,
    ca: String,
    cert: String,
    key: String,
}

impl TlsSettings {
    fn from_env() -> Result<Option<Self>, AnyError> {
        let listen = std::env::var("MYCELIUM_PEER_LISTEN").ok();
        let seeds = std::env::var("MYCELIUM_PEERS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if listen.is_none() && seeds.is_empty() {
            return Ok(None);
        }
        let required = |name| -> Result<String, AnyError> {
            std::env::var(name).map_err(|_| format!("{name} is required").into())
        };
        Ok(Some(Self {
            listen,
            seeds,
            ca: required("MYCELIUM_PEER_CA")?,
            cert: required("MYCELIUM_PEER_CERT")?,
            key: required("MYCELIUM_PEER_KEY")?,
        }))
    }

    fn roots(&self) -> Result<RootCertStore, AnyError> {
        let mut roots = RootCertStore::empty();
        for cert in certs(&self.ca)? {
            roots.add(cert)?;
        }
        Ok(roots)
    }

    fn client_config(&self) -> Result<ClientConfig, AnyError> {
        Ok(ClientConfig::builder()
            .with_root_certificates(self.roots()?)
            .with_client_auth_cert(certs(&self.cert)?, private_key(&self.key)?)?)
    }

    fn server_config(&self) -> Result<ServerConfig, AnyError> {
        let verifier = WebPkiClientVerifier::builder(Arc::new(self.roots()?)).build()?;
        Ok(ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs(&self.cert)?, private_key(&self.key)?)?)
    }
}

async fn send<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    message: &PeerMessage,
) -> Result<(), AnyError> {
    writer.write_all(&serde_json::to_vec(message)?).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

fn event_key(envelope: &SignedEnvelope) -> String {
    match &envelope.event {
        PeerEvent::Hello(_) => format!("{}:hello", envelope.origin),
        PeerEvent::Health(_) => format!("{}:health", envelope.origin),
        PeerEvent::Release(release) => format!(
            "{}:release:{}:{}",
            envelope.origin, release.channel, release.target
        ),
        PeerEvent::Access(record) => match &record.statement {
            AccessStatement::Grant { grant_id, .. } => {
                format!("access:{}:grant:{grant_id}", record.signer)
            }
            AccessStatement::Revoke { revocation_id, .. } => {
                format!("access:{}:revoke:{revocation_id}", record.signer)
            }
        },
    }
}

fn event_origin_matches(envelope: &SignedEnvelope) -> bool {
    match &envelope.event {
        PeerEvent::Hello(hello) => hello.node_id == envelope.origin,
        PeerEvent::Health(_) | PeerEvent::Release(_) | PeerEvent::Access(_) => true,
    }
}

fn csv_set(name: &str) -> BTreeSet<String> {
    std::env::var(name)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

fn local_target() -> String {
    #[cfg(target_os = "macos")]
    let os = "apple-darwin";
    #[cfg(target_os = "linux")]
    let os = "unknown-linux-gnu";
    format!("{}-{os}", std::env::consts::ARCH)
}

fn validate_digest(digest: &str) -> Result<(), AnyError> {
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("artifact digest must be 64 hexadecimal characters".into());
    }
    Ok(())
}

fn validate_release_label(name: &str, value: &str) -> Result<(), AnyError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
    {
        return Err(format!("{name} must contain 1-128 safe ASCII characters").into());
    }
    Ok(())
}

fn validate_access_principal(value: &str) -> Result<(), AnyError> {
    // Principals are opaque identity-provider identifiers, not local labels.
    // In particular, the OIDC adapter emits `oidc:<issuer>#<subject>` values.
    if value.is_empty() || value.len() > 512 || !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(
            "principal must contain 1-512 printable ASCII characters without whitespace".into(),
        );
    }
    Ok(())
}

fn validate_access_selector(name: &str, value: &str) -> Result<(), AnyError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+:-/".contains(&byte))
    {
        return Err(format!("{name} must contain 1-128 safe ASCII selector characters").into());
    }
    Ok(())
}

fn validate_access_statement(statement: &AccessStatement) -> Result<(), AnyError> {
    match statement {
        AccessStatement::Grant {
            grant_id,
            principal,
            roles,
            scopes,
            unix_users,
            ssh_public_keys,
            not_before,
            not_after,
            ..
        } => {
            validate_release_label("grant_id", grant_id)?;
            validate_access_principal(principal)?;
            for (name, values) in [("role", roles), ("scope", scopes)] {
                for value in values {
                    validate_access_selector(name, value)?;
                }
            }
            for value in unix_users {
                validate_release_label("unix_user", value)?;
            }
            if ssh_public_keys.len() > 32
                || ssh_public_keys.iter().any(|key| {
                    key.len() > 16_384
                        || !(key.starts_with("ssh-ed25519 ")
                            || key.starts_with("ecdsa-sha2-")
                            || key.starts_with("sk-ssh-ed25519@openssh.com "))
                })
            {
                return Err("grant contains an invalid SSH public key".into());
            }
            if not_after <= not_before {
                return Err("grant not_after must be later than not_before".into());
            }
        }
        AccessStatement::Revoke {
            revocation_id,
            grant_id,
            principal,
            serial,
            reason,
            ..
        } => {
            validate_release_label("revocation_id", revocation_id)?;
            if grant_id.is_none() && principal.is_none() && serial.is_none() {
                return Err("revocation needs grant_id, principal, or serial".into());
            }
            if let Some(value) = grant_id {
                validate_release_label("grant_id", value)?;
            }
            if let Some(value) = principal {
                validate_access_principal(value)?;
            }
            if reason.is_empty() || reason.len() > 512 || reason.contains(['\n', '\r']) {
                return Err("revocation reason must be 1-512 characters on one line".into());
            }
        }
    }
    Ok(())
}

fn artifact_path(digest: &str) -> Result<std::path::PathBuf, AnyError> {
    validate_digest(digest)?;
    Ok(crate::artifacts_dir().join(digest))
}

fn partial_artifact_path(digest: &str) -> Result<std::path::PathBuf, AnyError> {
    validate_digest(digest)?;
    Ok(crate::artifacts_dir().join(format!("{digest}.part")))
}

fn artifact_chunk(digest: &str, offset: u64, length: u32) -> Result<Option<PeerMessage>, AnyError> {
    if length == 0 || length > 65_536 {
        return Err("artifact request length must be 1 through 65536".into());
    }
    let path = artifact_path(digest)?;
    let Ok(mut file) = std::fs::File::open(path) else {
        return Ok(None);
    };
    let size = file.metadata()?.len();
    if offset > size {
        return Err("artifact request offset exceeds file size".into());
    }
    file.seek(SeekFrom::Start(offset))?;
    let mut data = vec![0; length as usize];
    let count = file.read(&mut data)?;
    data.truncate(count);
    Ok(Some(PeerMessage::ArtifactChunk {
        digest: digest.into(),
        offset,
        data: encode_hex(&data),
        complete: offset + count as u64 == size,
    }))
}

fn accept_artifact_chunk(
    digest: &str,
    offset: u64,
    encoded: &str,
    complete: bool,
    releases: &[ReleaseManifest],
) -> Result<(), AnyError> {
    let release = releases
        .iter()
        .find(|release| release.artifact_digest == digest)
        .ok_or("artifact has no trusted release manifest")?;
    let data = decode_hex(encoded).map_err(|error| format!("artifact chunk: {error}"))?;
    if data.len() > 65_536 || offset + data.len() as u64 > release.artifact_size {
        return Err("artifact chunk exceeds signed bounds".into());
    }
    std::fs::create_dir_all(crate::artifacts_dir())?;
    let partial = partial_artifact_path(digest)?;
    let current = std::fs::metadata(&partial)
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    if current != offset {
        return Ok(());
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&partial)?;
    file.write_all(&data)?;
    file.sync_data()?;
    if complete {
        let bytes = std::fs::read(&partial)?;
        if bytes.len() as u64 != release.artifact_size || sha256_hex(&bytes) != digest {
            return Err("completed artifact does not match signed size and digest".into());
        }
        std::fs::rename(partial, artifact_path(digest)?)?;
    }
    Ok(())
}

fn persist_observations(values: &[SignedEnvelope]) -> Result<(), AnyError> {
    let path = crate::peer_observations_path();
    let temp = path.with_extension("json.tmp");
    std::fs::write(&temp, serde_json::to_vec_pretty(values)?)?;
    std::fs::rename(temp, path)?;
    Ok(())
}

fn load_or_create_key(path: &Path) -> Result<SigningKey, AnyError> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(SigningKey::from_bytes(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| "peer.key must be exactly 32 bytes")?,
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let key = SigningKey::generate(&mut OsRng);
            std::fs::write(path, key.to_bytes())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            }
            Ok(key)
        }
        Err(error) => Err(error.into()),
    }
}

fn certs(path: &str) -> Result<Vec<CertificateDer<'static>>, AnyError> {
    rustls_pemfile::certs(&mut StdBufReader::new(std::fs::File::open(path)?))
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn private_key(path: &str) -> Result<PrivateKeyDer<'static>, AnyError> {
    rustls_pemfile::private_key(&mut StdBufReader::new(std::fs::File::open(path)?))?
        .ok_or_else(|| "PEM file contains no private key".into())
}

fn server_name(name: &str) -> Result<ServerName<'static>, AnyError> {
    if let Ok(ip) = name.parse::<IpAddr>() {
        Ok(ServerName::IpAddress(ip.into()))
    } else {
        Ok(ServerName::try_from(name.to_owned())?)
    }
}

fn platform() -> Platform {
    #[cfg(target_os = "macos")]
    return Platform::Darwin;
    #[cfg(not(target_os = "macos"))]
    Platform::Linux
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn collect_health() -> Result<HostHealth, AnyError> {
    #[cfg(target_os = "linux")]
    return collect_linux();
    #[cfg(target_os = "macos")]
    return collect_darwin();
    #[allow(unreachable_code)]
    Err("health collection supports Linux and Darwin".into())
}

#[cfg(target_os = "linux")]
fn collect_linux() -> Result<HostHealth, AnyError> {
    let uptime_seconds = first_number(&std::fs::read_to_string("/proc/uptime")?)? as u64;
    let load_average = three_numbers(&std::fs::read_to_string("/proc/loadavg")?)?;
    let memory = parse_linux_memory(&std::fs::read_to_string("/proc/meminfo")?);
    let mut platform_metrics = BTreeMap::new();
    for kind in ["cpu", "memory", "io"] {
        if let Ok(value) = std::fs::read_to_string(format!("/proc/pressure/{kind}")) {
            platform_metrics.insert(format!("pressure_{kind}"), value.trim().into());
        }
    }
    if let Some((overflows, drops)) =
        linux_listen_drops(&std::fs::read_to_string("/proc/net/netstat").unwrap_or_default())
    {
        platform_metrics.insert("tcp_listen_overflows".into(), overflows.to_string());
        platform_metrics.insert("tcp_listen_drops".into(), drops.to_string());
    }
    let ssh = output("ss", &["-H", "-lnt"])?;
    let sessions = output("ss", &["-H", "-nt", "state", "established"])?;
    Ok(HostHealth {
        observed_at: now(),
        uptime_seconds,
        load_average,
        logical_cpus: std::thread::available_parallelism()?.get() as u32,
        memory_total_bytes: memory.get("MemTotal").copied().unwrap_or(0) * 1024,
        memory_available_bytes: memory.get("MemAvailable").copied().unwrap_or(0) * 1024,
        swap_total_bytes: memory.get("SwapTotal").copied().unwrap_or(0) * 1024,
        swap_free_bytes: memory.get("SwapFree").copied().unwrap_or(0) * 1024,
        filesystems: root_filesystem()?,
        process_leaders: process_leaders(&["-eo", "pid=,pcpu=,pmem=,comm=", "--sort=-pcpu"])?,
        ssh_listening: ssh.lines().any(|line| local_port(line, 22)),
        established_ssh_sessions: sessions.lines().filter(|line| local_port(line, 22)).count()
            as u32,
        platform_metrics,
    })
}

#[cfg(target_os = "macos")]
fn collect_darwin() -> Result<HostHealth, AnyError> {
    let boot = output("/usr/sbin/sysctl", &["-n", "kern.boottime"])?;
    let boot_seconds = boot
        .split("sec =")
        .nth(1)
        .and_then(|v| v.trim().split(',').next())
        .and_then(|v| v.parse().ok())
        .ok_or("cannot parse kern.boottime")?;
    let load_average = three_numbers(
        output("/usr/sbin/sysctl", &["-n", "vm.loadavg"])?.trim_matches(|c| c == '{' || c == '}'),
    )?;
    let page_size = output("/usr/sbin/sysctl", &["-n", "hw.pagesize"])?
        .trim()
        .parse::<u64>()?;
    let memory_total_bytes = output("/usr/sbin/sysctl", &["-n", "hw.memsize"])?
        .trim()
        .parse::<u64>()?;
    let vm = output("/usr/bin/vm_stat", &[])?;
    let memory_available_bytes = (darwin_pages(&vm, "Pages free")
        + darwin_pages(&vm, "Pages inactive")
        + darwin_pages(&vm, "Pages speculative")
        + darwin_pages(&vm, "Pages purgeable"))
        * page_size;
    let (swap_total_bytes, swap_free_bytes) =
        parse_darwin_swap(&output("/usr/sbin/sysctl", &["-n", "vm.swapusage"])?);
    let sockets = output("/usr/sbin/lsof", &["-nP", "-iTCP:22"]).unwrap_or_default();
    Ok(HostHealth {
        observed_at: now(),
        uptime_seconds: now().saturating_sub(boot_seconds),
        load_average,
        logical_cpus: std::thread::available_parallelism()?.get() as u32,
        memory_total_bytes,
        memory_available_bytes,
        swap_total_bytes,
        swap_free_bytes,
        filesystems: root_filesystem()?,
        process_leaders: process_leaders(&["-axo", "pid=,pcpu=,pmem=,comm=", "-r"])?,
        ssh_listening: sockets
            .lines()
            .any(|line| line.contains("(LISTEN)") && darwin_local_port(line, 22)),
        established_ssh_sessions: sockets
            .lines()
            .filter(|line| line.contains("(ESTABLISHED)") && darwin_local_port(line, 22))
            .count() as u32,
        platform_metrics: BTreeMap::new(),
    })
}

fn output(command: &str, args: &[&str]) -> Result<String, AnyError> {
    let result = Command::new(command).args(args).output()?;
    if !result.status.success() {
        return Err(format!("{command} exited {}", result.status).into());
    }
    Ok(String::from_utf8(result.stdout)?)
}
#[cfg(target_os = "linux")]
fn first_number(text: &str) -> Result<f64, AnyError> {
    Ok(text
        .split_whitespace()
        .next()
        .ok_or("missing number")?
        .parse()?)
}
fn three_numbers(text: &str) -> Result<[f64; 3], AnyError> {
    text.split_whitespace()
        .filter_map(|v| v.parse().ok())
        .take(3)
        .collect::<Vec<f64>>()
        .try_into()
        .map_err(|_| "expected three load averages".into())
}
#[cfg(target_os = "linux")]
fn parse_linux_memory(text: &str) -> BTreeMap<String, u64> {
    text.lines()
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.into(), value.split_whitespace().next()?.parse().ok()?))
        })
        .collect()
}
#[cfg(any(target_os = "linux", test))]
fn linux_listen_drops(text: &str) -> Option<(u64, u64)> {
    for pair in text.lines().collect::<Vec<_>>().windows(2) {
        if pair[0].starts_with("TcpExt:") && pair[1].starts_with("TcpExt:") {
            let names = pair[0].split_whitespace().skip(1).collect::<Vec<_>>();
            let values = pair[1].split_whitespace().skip(1).collect::<Vec<_>>();
            let get = |name| {
                values
                    .get(names.iter().position(|item| *item == name)?)?
                    .parse()
                    .ok()
            };
            return Some((get("ListenOverflows")?, get("ListenDrops")?));
        }
    }
    None
}
fn root_filesystem() -> Result<Vec<FilesystemHealth>, AnyError> {
    let text = output("df", &["-Pk", "/"])?;
    let fields = text
        .lines()
        .last()
        .ok_or("df returned no filesystem")?
        .split_whitespace()
        .collect::<Vec<_>>();
    if fields.len() < 6 {
        return Err("unexpected df output".into());
    }
    Ok(vec![FilesystemHealth {
        mount: fields[5].into(),
        total_bytes: fields[1].parse::<u64>()? * 1024,
        available_bytes: fields[3].parse::<u64>()? * 1024,
    }])
}
fn process_leaders(args: &[&str]) -> Result<Vec<ProcessHealth>, AnyError> {
    Ok(output("ps", args)?
        .lines()
        .filter_map(|line| {
            let mut f = line.split_whitespace();
            Some(ProcessHealth {
                pid: f.next()?.parse().ok()?,
                cpu_percent: f.next()?.parse().ok()?,
                memory_percent: f.next()?.parse().ok()?,
                name: f.collect::<Vec<_>>().join(" "),
            })
        })
        .take(10)
        .collect())
}
#[cfg(target_os = "linux")]
fn local_port(line: &str, port: u16) -> bool {
    line.split_whitespace()
        .any(|field| field.ends_with(&format!(":{port}")) || field.ends_with(&format!(".{port}")))
}
#[cfg(target_os = "macos")]
fn darwin_local_port(line: &str, port: u16) -> bool {
    line.split_whitespace()
        .find(|field| field.contains(':'))
        .and_then(|field| field.split("->").next())
        .map(|local| local.ends_with(&format!(":{port}")))
        .unwrap_or(false)
}
#[cfg(target_os = "macos")]
fn darwin_pages(text: &str, name: &str) -> u64 {
    text.lines()
        .find(|line| line.starts_with(name))
        .and_then(|line| line.split(':').nth(1))
        .map(|v| v.trim().trim_end_matches('.'))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}
#[cfg(target_os = "macos")]
fn parse_darwin_swap(text: &str) -> (u64, u64) {
    let words = text.split_whitespace().collect::<Vec<_>>();
    let mib = |label| {
        words
            .iter()
            .position(|word| *word == label)
            .and_then(|i| words.get(i + 2))
            .and_then(|v| v.trim_end_matches('M').parse::<f64>().ok())
            .map(|v| (v * 1_048_576.0) as u64)
            .unwrap_or(0)
    };
    (mib("total"), mib("free"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oidc_grant(principal: &str) -> AccessStatement {
        AccessStatement::Grant {
            grant_id: "grant-1".into(),
            principal: principal.into(),
            serial: 1,
            roles: vec!["operator".into()],
            scopes: vec!["site:home".into()],
            unix_users: vec!["avery".into()],
            ssh_public_keys: vec![],
            not_before: 1,
            not_after: 2,
        }
    }

    #[test]
    fn access_validation_accepts_normalized_oidc_principal() {
        validate_access_statement(&oidc_grant("oidc:https://identity.example#subject-42")).unwrap();
    }

    #[test]
    fn access_validation_rejects_principal_with_whitespace() {
        assert!(validate_access_statement(&oidc_grant(
            "oidc:https://identity.example#bad\nsubject"
        ))
        .is_err());
    }

    #[test]
    fn listen_drop_parser_maps_header_to_values() {
        assert_eq!(
            linux_listen_drops("TcpExt: Foo ListenOverflows ListenDrops\nTcpExt: 1 7 9\n"),
            Some((7, 9))
        );
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_ssh_count_uses_local_endpoint() {
        assert!(!darwin_local_port(
            "ssh 1 user 3u IPv4 x TCP 10.0.0.2:50000->10.0.0.3:22 (ESTABLISHED)",
            22
        ));
        assert!(darwin_local_port(
            "sshd 1 root 3u IPv4 x TCP 10.0.0.2:22->10.0.0.3:50000 (ESTABLISHED)",
            22
        ));
    }
}
