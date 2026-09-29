//! Minimal SSH transport for EdgeOS appliances.
//!
//! One live SSH session per device, commands serialized through a mutex:
//! vyos config sessions (`configure`/`commit`) are not safe to interleave,
//! and a device is a serial resource anyway.
//!
//! HOST KEY POLICY (v0): trust-on-first-connect, no persistence. This is a
//! knowingly open seam; host key pinning belongs in the daemon's state
//! store (see docs/adr/0001), not in each driver.

use std::sync::Arc;
use std::time::Duration;

use mycelium_core::{CredentialSet, ExecOutcome, MyceliumError, Result, Secret};
use russh::client::{self, Handle};
use russh::{ChannelMsg, Disconnect, Preferred};
use tokio::sync::Mutex;
use zeroize::Zeroize;

/// A connected SSH session. Cheap to clone (shared handle).
#[derive(Clone)]
pub struct SshSession {
    inner: Arc<Mutex<Handle<Verifier>>>,
}

struct Verifier;

impl client::Handler for Verifier {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        // TOFU: see module docs.
        Ok(true)
    }
}

fn transport_err(e: russh::Error) -> MyceliumError {
    MyceliumError::Transport(e.to_string())
}

fn transport_str(msg: &str) -> MyceliumError {
    MyceliumError::Transport(msg.to_owned())
}

fn auth_err(msg: impl Into<String>) -> MyceliumError {
    MyceliumError::Auth(msg.into())
}

impl SshSession {
    pub async fn connect(
        host: &str,
        port: u16,
        creds: &CredentialSet,
        timeout: Duration,
    ) -> Result<Self> {
        let user = creds
            .username()
            .ok_or_else(|| auth_err("edgeos driver requires a username"))?
            .to_owned();

        let config = Arc::new(client::Config {
            inactivity_timeout: Some(timeout),
            preferred: Preferred::default(),
            ..Default::default()
        });

        let mut handle =
            match tokio::time::timeout(timeout, client::connect(config, (host, port), Verifier))
            .await
            {
                Err(_) => return Err(transport_str("tcp/kex timed out")),
                Ok(Err(e)) => return Err(transport_err(e)),
                Ok(Ok(h)) => h,
            };

        let password = creds.password.as_ref().and_then(|s| match s {
            Secret::Literal(_) => s.resolve(),
            // env secret not set: try the remaining methods anyway, fail loud
            Secret::Env(_) => None,
        });

        let mut tried: Vec<String> = Vec::new();

        // 1. private key file (passphrase-protected keys use the password)
        if let Some(key_path) = &creds.key_path {
            let passphrase = password.clone();
            match russh::keys::load_secret_key(key_path, passphrase.as_deref()) {
                Ok(key_pair) => {
                    let hash = handle
                        .best_supported_rsa_hash()
                        .await
                        .map_err(transport_err)?
                        .flatten();
                    let signer = russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key_pair), hash);
                    let res = handle.authenticate_publickey(user.clone(), signer).await;
                    match res {
                        Ok(a) if a.success() => return Ok(Self::shared(handle)),
                        Ok(_) => tried.push("publickey".into()),
                        Err(e) => return Err(transport_err(e)),
                    }
                }
                Err(e) => tried.push(format!("publickey(unreadable: {e})")),
            }
        }

        // 2. password
        if let Some(mut pw) = password {
            let res = handle.authenticate_password(user.clone(), pw.clone()).await;
            pw.zeroize();
            match res {
                Ok(a) if a.success() => return Ok(Self::shared(handle)),
                Ok(_) => tried.push("password".into()),
                Err(e) => return Err(transport_err(e)),
            }
        }

        Err(auth_err(format!(
            "no offered auth method succeeded for `{user}@{host}` (tried: {}; \
             provide key_path or password via MYCELIUM_* env secrets)",
            if tried.is_empty() { "nothing usable".into() } else { tried.join(", ") }
        )))
    }

    fn shared(handle: Handle<Verifier>) -> Self {
        SshSession { inner: Arc::new(Mutex::new(handle)) }
    }

    /// Run one command, returning raw stdout/stderr/exit.
    pub async fn exec(&self, command: &str) -> Result<ExecOutcome> {
        let guard = self.inner.lock().await;
        let mut channel = guard
            .channel_open_session()
            .await
            .map_err(transport_err)?;
        channel
            .exec(true, command)
            .await
            .map_err(transport_err)?;

        let mut out = ExecOutcome { exit_code: -1, stdout: String::new(), stderr: String::new() };
        let mut exited = None;

        loop {
            let Some(msg) = channel.wait().await else {
                break;
            };
            match msg {
                ChannelMsg::Data { ref data } => {
                    out.stdout.push_str(&String::from_utf8_lossy(data));
                }
                ChannelMsg::ExtendedData { ref data, ext } if ext == 1 => {
                    out.stderr.push_str(&String::from_utf8_lossy(data));
                }
                ChannelMsg::ExitStatus { exit_status } => exited = Some(exit_status),
                _ => {}
            }
        }

        out.exit_code = exited.ok_or_else(|| {
            transport_str("channel closed without exit status")
        })? as i32;
        Ok(out)
    }

    pub async fn disconnect(self) {
        if let Ok(arc) = Arc::try_unwrap(self.inner) {
            let handle = arc.into_inner();
            let _ = handle
                .disconnect(Disconnect::ByApplication, "", "English")
                .await;
        }
    }
}
