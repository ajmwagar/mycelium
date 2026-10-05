#![forbid(unsafe_code)]

//! Durable local state and a read-only HTTP projection for Genesis.
//!
//! Mutations enter through [`Store`], where contract validation, digest
//! verification, and atomic replacement are enforced. The HTTP surface only
//! projects already-validated state and immutable artifact bytes.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use axum::{
    body::Body,
    extract::{Path as AxumPath, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use fpl_boot_contract::{
    BootArtifactKind, BootIntentV1, BootProfileV1, BootReceiptState, BootReceiptV1,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug)]
pub struct Store {
    root: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("invalid {kind}: {message}")]
    Invalid { kind: &'static str, message: String },
    #[error("invalid lowercase SHA-256 digest `{0}`")]
    InvalidDigest(String),
    #[error("artifact digest mismatch: expected {expected}, observed {observed}")]
    DigestMismatch { expected: String, observed: String },
    #[error("state already exists with different bytes: {0}")]
    Conflict(PathBuf),
    #[error("invalid receipt transition for {machine}: {from:?} -> {to:?}")]
    ReceiptTransition {
        machine: String,
        from: BootReceiptState,
        to: BootReceiptState,
    },
    #[error("receipt for {machine} changed immutable intent or profile identity")]
    ReceiptIdentityChanged { machine: String },
    #[error("state not found: {0}")]
    NotFound(PathBuf),
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("JSON error at {path}: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

impl Store {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let store = Self { root: root.into() };
        for directory in ["profiles", "intents", "receipts", "artifacts", "boot"] {
            let path = store.root.join(directory);
            fs::create_dir_all(&path).map_err(|source| StoreError::Io { path, source })?;
        }
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn put_profile(&self, profile: &BootProfileV1) -> Result<String, StoreError> {
        profile.validate().map_err(|error| StoreError::Invalid {
            kind: "boot profile",
            message: error.to_string(),
        })?;
        let digest = profile.digest();
        self.put_json("profiles", &format!("{digest}.json"), profile)?;
        Ok(digest)
    }

    pub fn profile(&self, digest: &str) -> Result<BootProfileV1, StoreError> {
        validate_digest(digest)?;
        self.read_json("profiles", &format!("{digest}.json"))
    }

    pub fn put_intent(&self, intent: &BootIntentV1) -> Result<String, StoreError> {
        intent.validate().map_err(|error| StoreError::Invalid {
            kind: "boot intent",
            message: error.to_string(),
        })?;
        let digest = intent.digest();
        self.put_json("intents", &format!("{digest}.json"), intent)?;
        Ok(digest)
    }

    pub fn intent(&self, digest: &str) -> Result<BootIntentV1, StoreError> {
        validate_digest(digest)?;
        self.read_json("intents", &format!("{digest}.json"))
    }

    pub fn put_receipt(&self, receipt: &BootReceiptV1) -> Result<(), StoreError> {
        receipt.validate().map_err(|error| StoreError::Invalid {
            kind: "boot receipt",
            message: error.to_string(),
        })?;
        let machine = safe_component(&receipt.machine).ok_or_else(|| StoreError::Invalid {
            kind: "boot receipt",
            message: "machine must be a safe filename component".into(),
        })?;
        let path = self.root.join("receipts").join(format!("{machine}.json"));
        if path.exists() {
            let existing: BootReceiptV1 = self.read_json("receipts", &format!("{machine}.json"))?;
            if existing.intent_digest != receipt.intent_digest
                || existing.profile_digest != receipt.profile_digest
            {
                return Err(StoreError::ReceiptIdentityChanged {
                    machine: receipt.machine.clone(),
                });
            }
            if !valid_receipt_transition(existing.state, receipt.state) {
                return Err(StoreError::ReceiptTransition {
                    machine: receipt.machine.clone(),
                    from: existing.state,
                    to: receipt.state,
                });
            }
        }
        self.replace_json("receipts", &format!("{machine}.json"), receipt)
    }

    pub fn receipt(&self, machine: &str) -> Result<BootReceiptV1, StoreError> {
        let machine = safe_component(machine).ok_or_else(|| StoreError::Invalid {
            kind: "machine",
            message: "must be a safe filename component".into(),
        })?;
        self.read_json("receipts", &format!("{machine}.json"))
    }

    pub fn import_artifact(&self, expected: &str, source: &Path) -> Result<PathBuf, StoreError> {
        validate_digest(expected)?;
        let bytes = fs::read(source).map_err(|source_error| StoreError::Io {
            path: source.to_path_buf(),
            source: source_error,
        })?;
        let observed = sha256(&bytes);
        if observed != expected {
            return Err(StoreError::DigestMismatch {
                expected: expected.into(),
                observed,
            });
        }
        let destination = self.root.join("artifacts").join(expected);
        write_once(&destination, &bytes)?;
        Ok(destination)
    }

    pub fn artifact(&self, digest: &str) -> Result<Vec<u8>, StoreError> {
        validate_digest(digest)?;
        let path = self.root.join("artifacts").join(digest);
        let bytes = fs::read(&path).map_err(|source| match source.kind() {
            std::io::ErrorKind::NotFound => StoreError::NotFound(path.clone()),
            _ => StoreError::Io {
                path: path.clone(),
                source,
            },
        })?;
        let observed = sha256(&bytes);
        if observed != digest {
            return Err(StoreError::DigestMismatch {
                expected: digest.into(),
                observed,
            });
        }
        Ok(bytes)
    }

    /// Install a deterministic, non-secret iPXE file under a stable boot name.
    ///
    /// Boot files are desired-state projections and may be atomically replaced
    /// when an operator applies a new reviewed intent. Credentials and
    /// enrollment claims must never be placed in this surface.
    pub fn put_boot_file(&self, name: &str, content: &str) -> Result<(), StoreError> {
        let name = safe_boot_name(name)?;
        if !content.starts_with("#!ipxe\n") {
            return Err(StoreError::Invalid {
                kind: "boot file",
                message: "iPXE files must start with #!ipxe".into(),
            });
        }
        atomic_replace(&self.root.join("boot").join(name), content.as_bytes())
    }

    pub fn boot_file(&self, name: &str) -> Result<Vec<u8>, StoreError> {
        let name = safe_boot_name(name)?;
        let path = self.root.join("boot").join(name);
        fs::read(&path).map_err(|source| match source.kind() {
            std::io::ErrorKind::NotFound => StoreError::NotFound(path.clone()),
            _ => StoreError::Io {
                path: path.clone(),
                source,
            },
        })
    }

    fn put_json<T: Serialize>(
        &self,
        directory: &str,
        name: &str,
        value: &T,
    ) -> Result<(), StoreError> {
        let bytes = serde_json::to_vec_pretty(value).expect("validated contract serializes");
        write_once(&self.root.join(directory).join(name), &bytes)
    }

    fn replace_json<T: Serialize>(
        &self,
        directory: &str,
        name: &str,
        value: &T,
    ) -> Result<(), StoreError> {
        let bytes = serde_json::to_vec_pretty(value).expect("validated contract serializes");
        atomic_replace(&self.root.join(directory).join(name), &bytes)
    }

    fn read_json<T: DeserializeOwned>(&self, directory: &str, name: &str) -> Result<T, StoreError> {
        let path = self.root.join(directory).join(name);
        let bytes = fs::read(&path).map_err(|source| match source.kind() {
            std::io::ErrorKind::NotFound => StoreError::NotFound(path.clone()),
            _ => StoreError::Io {
                path: path.clone(),
                source,
            },
        })?;
        serde_json::from_slice(&bytes).map_err(|source| StoreError::Json { path, source })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaterializationPlan {
    pub intent_digest: String,
    pub profile_digest: String,
    pub machine: String,
    pub profile: String,
    pub network: String,
    pub artifacts: Vec<PlannedArtifact>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedArtifact {
    pub kind: String,
    pub url: String,
    pub sha256: String,
}

pub fn plan(
    intent: &BootIntentV1,
    profile: &BootProfileV1,
) -> Result<MaterializationPlan, StoreError> {
    intent.validate().map_err(|error| StoreError::Invalid {
        kind: "boot intent",
        message: error.to_string(),
    })?;
    profile.validate().map_err(|error| StoreError::Invalid {
        kind: "boot profile",
        message: error.to_string(),
    })?;
    if intent.profile != profile.id {
        return Err(StoreError::Invalid {
            kind: "materialization plan",
            message: format!(
                "intent requests profile `{}` but supplied profile is `{}`",
                intent.profile, profile.id
            ),
        });
    }
    Ok(MaterializationPlan {
        intent_digest: intent.digest(),
        profile_digest: profile.digest(),
        machine: intent.machine.clone(),
        profile: profile.id.clone(),
        network: intent.network.clone(),
        artifacts: profile
            .artifacts
            .iter()
            .map(|(kind, artifact)| PlannedArtifact {
                kind: artifact_kind_name(*kind).into(),
                url: artifact.url.clone(),
                sha256: artifact.sha256.clone(),
            })
            .collect(),
    })
}

fn artifact_kind_name(kind: BootArtifactKind) -> &'static str {
    match kind {
        BootArtifactKind::Bootloader => "bootloader",
        BootArtifactKind::Kernel => "kernel",
        BootArtifactKind::Initrd => "initrd",
        BootArtifactKind::RootFilesystem => "root_filesystem",
        BootArtifactKind::Installer => "installer",
        BootArtifactKind::Signature => "signature",
    }
}

pub fn router(store: Store) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/profiles/{digest}", get(get_profile))
        .route("/v1/intents/{digest}", get(get_intent))
        .route("/v1/receipts/{machine}", get(get_receipt))
        .route("/v1/artifacts/{digest}", get(get_artifact))
        .route("/v1/boot/{name}", get(get_boot_file))
        .with_state(Arc::new(store))
}

async fn health() -> &'static str {
    "ok\n"
}

async fn get_profile(
    State(store): State<Arc<Store>>,
    AxumPath(digest): AxumPath<String>,
) -> Result<Json<BootProfileV1>, HttpError> {
    Ok(Json(store.profile(&digest)?))
}

async fn get_intent(
    State(store): State<Arc<Store>>,
    AxumPath(digest): AxumPath<String>,
) -> Result<Json<BootIntentV1>, HttpError> {
    Ok(Json(store.intent(&digest)?))
}

async fn get_receipt(
    State(store): State<Arc<Store>>,
    AxumPath(machine): AxumPath<String>,
) -> Result<Json<BootReceiptV1>, HttpError> {
    Ok(Json(store.receipt(&machine)?))
}

async fn get_artifact(
    State(store): State<Arc<Store>>,
    AxumPath(digest): AxumPath<String>,
) -> Result<Response, HttpError> {
    let bytes = store.artifact(&digest)?;
    let mut response = Body::from(bytes).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(&format!("\"sha256:{digest}\"")).expect("digest is an HTTP value"),
    );
    Ok(response)
}

async fn get_boot_file(
    State(store): State<Arc<Store>>,
    AxumPath(name): AxumPath<String>,
) -> Result<Response, HttpError> {
    let bytes = store.boot_file(&name)?;
    let mut response = Body::from(bytes).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

#[derive(Debug)]
struct HttpError(StoreError);

impl From<StoreError> for HttpError {
    fn from(error: StoreError) -> Self {
        Self(error)
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            StoreError::NotFound(_) => StatusCode::NOT_FOUND,
            StoreError::Invalid { .. } | StoreError::InvalidDigest(_) => StatusCode::BAD_REQUEST,
            StoreError::Conflict(_)
            | StoreError::ReceiptTransition { .. }
            | StoreError::ReceiptIdentityChanged { .. } => StatusCode::CONFLICT,
            StoreError::DigestMismatch { .. } | StoreError::Io { .. } | StoreError::Json { .. } => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        (status, self.0.to_string()).into_response()
    }
}

fn safe_component(value: &str) -> Option<&str> {
    (!value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
    .then_some(value)
}

fn safe_boot_name(value: &str) -> Result<&str, StoreError> {
    let value = safe_component(value).ok_or_else(|| StoreError::Invalid {
        kind: "boot file name",
        message: "must be a safe filename component".into(),
    })?;
    if !value.ends_with(".ipxe") {
        return Err(StoreError::Invalid {
            kind: "boot file name",
            message: "must end with .ipxe".into(),
        });
    }
    Ok(value)
}

fn validate_digest(value: &str) -> Result<(), StoreError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(StoreError::InvalidDigest(value.into()))
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn valid_receipt_transition(from: BootReceiptState, to: BootReceiptState) -> bool {
    from == to
        || matches!(
            (from, to),
            (BootReceiptState::Planned, BootReceiptState::Booting)
                | (BootReceiptState::Booting, BootReceiptState::Installed)
                | (BootReceiptState::Installed, BootReceiptState::Enrolled)
                | (BootReceiptState::Installed, BootReceiptState::Verified)
                | (BootReceiptState::Enrolled, BootReceiptState::Verified)
                | (BootReceiptState::Planned, BootReceiptState::Failed)
                | (BootReceiptState::Booting, BootReceiptState::Failed)
                | (BootReceiptState::Installed, BootReceiptState::Failed)
                | (BootReceiptState::Enrolled, BootReceiptState::Failed)
        )
}

fn write_once(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    if path.exists() {
        let existing = fs::read(path).map_err(|source| StoreError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        return if existing == bytes {
            Ok(())
        } else {
            Err(StoreError::Conflict(path.to_path_buf()))
        };
    }
    let temporary = write_temporary(path, bytes)?;
    let link_result = fs::hard_link(&temporary, path);
    let _ = fs::remove_file(&temporary);
    match link_result {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = fs::read(path).map_err(|source| StoreError::Io {
                path: path.to_path_buf(),
                source,
            })?;
            if existing == bytes {
                Ok(())
            } else {
                Err(StoreError::Conflict(path.to_path_buf()))
            }
        }
        Err(source) => Err(StoreError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let temporary = write_temporary(path, bytes)?;
    let result = (|| {
        fs::rename(&temporary, path).map_err(|source| StoreError::Io {
            path: path.to_path_buf(),
            source,
        })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn write_temporary(path: &Path, bytes: &[u8]) -> Result<PathBuf, StoreError> {
    let (temporary, mut file) = loop {
        let temporary = path.with_extension(format!(
            "tmp-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
        {
            Ok(file) => break (temporary, file),
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(StoreError::Io {
                    path: temporary,
                    source,
                });
            }
        }
    };
    file.write_all(bytes).map_err(|source| StoreError::Io {
        path: temporary.clone(),
        source,
    })?;
    file.sync_all().map_err(|source| StoreError::Io {
        path: temporary.clone(),
        source,
    })?;
    Ok(temporary)
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, path::Path, sync::atomic::AtomicU64};

    use axum::{
        body::to_bytes,
        http::{Request, StatusCode},
    };
    use fpl_boot_contract::{
        BootArtifact, BootArtifactKind, BootFirmware, BootIntentMode, BootMachineSelector,
        BootPostInstall, BootProfileV1, BootSecurityPolicy, SecureBootPolicy,
        BOOT_CONTRACT_SCHEMA_VERSION,
    };
    use tower::ServiceExt;

    use super::*;

    static TEST_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "genesisd-test-{}-{}",
                std::process::id(),
                TEST_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn profile() -> BootProfileV1 {
        BootProfileV1 {
            schema_version: BOOT_CONTRACT_SCHEMA_VERSION,
            id: "fungos-base-amd64".into(),
            architecture: "amd64".into(),
            firmware: BootFirmware::Uefi,
            artifacts: BTreeMap::from([(
                BootArtifactKind::Kernel,
                BootArtifact {
                    url: "https://boot.example/vmlinuz".into(),
                    sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .into(),
                },
            )]),
            kernel_arguments: vec![],
        }
    }

    fn intent() -> BootIntentV1 {
        BootIntentV1 {
            schema_version: BOOT_CONTRACT_SCHEMA_VERSION,
            machine: "qemu-01".into(),
            selector: BootMachineSelector {
                system_uuid: Some("qemu-01".into()),
                ..BootMachineSelector::default()
            },
            profile: "fungos-base-amd64".into(),
            mode: BootIntentMode::InstallOnce,
            network: "build-lab".into(),
            security: BootSecurityPolicy {
                secure_boot: SecureBootPolicy::Preferred,
                tang: None,
            },
            post_install: BootPostInstall::default(),
        }
    }

    fn receipt(state: BootReceiptState) -> BootReceiptV1 {
        BootReceiptV1 {
            schema_version: BOOT_CONTRACT_SCHEMA_VERSION,
            machine: "qemu-01".into(),
            intent_digest: intent().digest(),
            profile_digest: profile().digest(),
            state,
            observed_at: 1,
            mycelium_peer_id: (state == BootReceiptState::Verified).then(|| "peer-01".into()),
            error: None,
        }
    }

    #[test]
    fn state_survives_reopen_and_rejects_conflicting_immutable_state() {
        let temporary = TestDirectory::new();
        let store = Store::open(temporary.path()).unwrap();
        let digest = store.put_profile(&profile()).unwrap();
        drop(store);

        let reopened = Store::open(temporary.path()).unwrap();
        assert_eq!(reopened.profile(&digest).unwrap(), profile());

        let profile_path = temporary
            .path()
            .join("profiles")
            .join(format!("{digest}.json"));
        fs::write(&profile_path, b"different").unwrap();
        assert!(matches!(
            reopened.put_profile(&profile()),
            Err(StoreError::Conflict(_))
        ));
    }

    #[test]
    fn artifact_import_is_digest_pinned() {
        let temporary = TestDirectory::new();
        let source = temporary.path().join("artifact");
        fs::write(&source, b"fungos").unwrap();
        let store = Store::open(temporary.path().join("state")).unwrap();
        let digest = sha256(b"fungos");
        store.import_artifact(&digest, &source).unwrap();
        assert_eq!(store.artifact(&digest).unwrap(), b"fungos");
        assert!(matches!(
            store.import_artifact(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                &source
            ),
            Err(StoreError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn receipt_state_only_moves_forward() {
        let temporary = TestDirectory::new();
        let store = Store::open(temporary.path()).unwrap();
        store
            .put_receipt(&receipt(BootReceiptState::Planned))
            .unwrap();
        store
            .put_receipt(&receipt(BootReceiptState::Booting))
            .unwrap();
        assert!(matches!(
            store.put_receipt(&receipt(BootReceiptState::Planned)),
            Err(StoreError::ReceiptTransition { .. })
        ));
    }

    #[test]
    fn plan_is_deterministic_and_uses_contract_names() {
        let first = plan(&intent(), &profile()).unwrap();
        let second = plan(&intent(), &profile()).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.artifacts[0].kind, "kernel");
    }

    #[tokio::test]
    async fn http_projection_is_read_only_and_content_addressed() {
        let temporary = TestDirectory::new();
        let store = Store::open(temporary.path()).unwrap();
        let digest = store.put_profile(&profile()).unwrap();
        let response = router(store)
            .oneshot(
                Request::get(format!("/v1/profiles/{digest}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<BootProfileV1>(&body).unwrap(),
            profile()
        );
    }

    #[tokio::test]
    async fn boot_projection_serves_only_explicit_ipxe_files() {
        let temporary = TestDirectory::new();
        let store = Store::open(temporary.path()).unwrap();
        store
            .put_boot_file("bootstrap.ipxe", "#!ipxe\necho genesis\n")
            .unwrap();
        assert!(store.put_boot_file("../secret", "#!ipxe\n").is_err());
        assert!(store.put_boot_file("not-ipxe.txt", "hello\n").is_err());

        let response = router(store)
            .oneshot(
                Request::get("/v1/boot/bootstrap.ipxe")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"#!ipxe\necho genesis\n");
    }
}
