//! SSH transport for EdgeOS appliances.
//!
//! Two modes, chosen by what the connection needs:
//! - **Native** (russh): direct host, persistent session, our own state
//!   machine, with reconnect-on-dead-session (appliances drop idle TCP).
//! - **OpenSSH subprocess**: used whenever a ProxyJump is requested —
//!   `ssh -J` brings mature jump chaining, ssh-agent, config, and
//!   certificates for free (tenet #10: call, don't rebuild). One `ssh`
//!   process per command; the appliance stays serialized per device.
//!
//! vyos config sessions (`configure`/`commit`) are not safe to interleave,
//! so commands are serialized per device.
//!
//! HOST KEY POLICY: native mode is trust-on-first-connect with no
//! persistence (seam noted in docs/adr/0001); OpenSSH mode delegates to the
//! user's own `~/.ssh/config` / known_hosts, unchanged.

use std::sync::Arc;
use std::time::Duration;

use mycelium_core::{CredentialSet, ExecOutcome, MyceliumError, Result, Secret};
use russh::client::{self, Handle};
use russh::{ChannelMsg, Disconnect, Preferred};
use tokio::process::Command;
use tokio::sync::Mutex;
use zeroize::Zeroize;

#[derive(Clone)]
pub struct SshSession {
    mode: Mode,
}

#[derive(Clone)]
enum Mode {
    Native(Arc<Mutex<Native>>),
    OpenSsh(Arc<OpenSsh>),
}

/// Reconnectable native session.
struct Native {
    handle: Handle<Verifier>,
    host: String,
    port: u16,
    creds: CredentialSet,
    timeout: Duration,
}

#[derive(Debug)]
struct OpenSsh {
    dest: String,
    jump: Option<String>,
    args: Vec<String>,
    password: Option<String>,
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
        jump: Option<&str>,
    ) -> Result<Self> {
        let user = creds
            .username()
            .ok_or_else(|| auth_err("edgeos driver requires a username"))?;
        // An Env secret whose variable is unset resolves to None; auth then
        // fails loudly with the list of tried methods.
        let password = creds.password.as_ref().and_then(Secret::resolve);

        if let Some(jump) = jump.filter(|j| !j.is_empty()) {
            let mut args = vec![
                "-o".to_owned(),
                "BatchMode=yes".to_owned(),
                "-o".to_owned(),
                "ConnectTimeout=8".to_owned(),
                "-p".to_owned(),
                port.to_string(),
            ];
            if let Some(key_path) = &creds.key_path {
                args.push("-i".to_owned());
                args.push(key_path.clone());
                args.push("-o".to_owned());
                args.push("IdentitiesOnly=yes".to_owned());
            }
            return Ok(Self {
                mode: Mode::OpenSsh(Arc::new(OpenSsh {
                    dest: format!("{user}@{host}"),
                    jump: Some(jump.to_owned()),
                    args,
                    password,
                })),
            });
        }

        let handle = connect_native(host, port, user, creds, password).await?;
        Ok(Self {
            mode: Mode::Native(Arc::new(Mutex::new(Native {
                handle,
                host: host.to_owned(),
                port,
                creds: creds.clone(),
                timeout,
            }))),
        })
    }

    /// Run a vyos CLI command. EdgeOS parses exec'd strings with plain
    /// vbash, where `show`/`configure` are login-interactive shell
    /// functions — bare `show version` dies with `command not found`.
    pub async fn cli(&self, command: &str) -> Result<ExecOutcome> {
        self.exec(&wrap_cli(command)).await
    }

    pub async fn exec(&self, command: &str) -> Result<ExecOutcome> {
        match &self.mode {
            Mode::Native(cell) => {
                let mut guard = cell.lock().await;
                // retry once on a dead session; the mutex keeps config
                // sequences atomic across the retry
                let mut attempts = 0;
                loop {
                    attempts += 1;
                    match guard.run(command).await {
                        Ok(out) => return Ok(out),
                        Err(e)
                            if attempts == 1
                                && is_dead_session(&e) =>
                        {
                            eprintln!("edgeos: session to {} was dead, reconnecting", guard.host);
                            match reconnect(&mut guard).await {
                                Ok(()) => continue,
                                Err(re) => return Err(re),
                            }
                        }
                        Err(e) => return Err(e),
                    }
                }
            }
            Mode::OpenSsh(o) => o.exec(command).await,
        }
    }

    pub async fn disconnect(self) {
        if let Mode::Native(cell) = &self.mode {
            if let Ok(mut guard) = cell.try_lock() {
                let _ = guard
                    .handle
                    .disconnect(Disconnect::ByApplication, "", "English")
                    .await;
            }
        }
    }
}

fn is_dead_session(e: &MyceliumError) -> bool {
    matches!(e, MyceliumError::Transport(_))
}

async fn reconnect(native: &mut Native) -> Result<()> {
    let password = native.creds.password.as_ref().and_then(Secret::resolve);
    let user = native
        .creds
        .username()
        .ok_or_else(|| auth_err("edgeos driver requires a username"))?
        .to_owned();
    let handle = connect_native(&native.host, native.port, &user, &native.creds, password.clone()).await?;
    native.handle = handle;
    Ok(())
}

async fn connect_native(
    host: &str,
    port: u16,
    user: &str,
    creds: &CredentialSet,
    mut password: Option<String>,
) -> Result<Handle<Verifier>> {
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(30)),
        preferred: Preferred::default(),
        ..Default::default()
    });

    let timeout = Duration::from_secs(8);
    let mut handle = match tokio::time::timeout(timeout, client::connect(config, (host, port), Verifier))
        .await
    {
        Err(_) => return Err(transport_str("tcp/kex timed out")),
        Ok(Err(e)) => return Err(transport_err(e)),
        Ok(Ok(h)) => h,
    };

    let mut tried: Vec<String> = Vec::new();

    // 1. private key file (passphrase-protected keys use the password)
    if let Some(key_path) = &creds.key_path {
        match russh::keys::load_secret_key(key_path, password.as_deref()) {
            Ok(key_pair) => {
                let hash = handle
                    .best_supported_rsa_hash()
                    .await
                    .map_err(transport_err)?
                    .flatten();
                let signer = russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key_pair), hash);
                let res = handle.authenticate_publickey(user.to_owned(), signer).await;
                match res {
                    Ok(a) if a.success() => return Ok(handle),
                    Ok(_) => tried.push("publickey".into()),
                    Err(e) => return Err(transport_err(e)),
                }
            }
            Err(e) => tried.push(format!("publickey(unreadable: {e})")),
        }
    }

    // 2. password
    if let Some(pw) = password.as_deref() {
        let res = handle.authenticate_password(user.to_owned(), pw.to_owned()).await;
        match res {
            Ok(a) if a.success() => {
                if let Some(p) = password.as_mut() {
                    p.zeroize();
                }
                return Ok(handle);
            }
            Ok(_) => tried.push("password".into()),
            Err(e) => return Err(transport_err(e)),
        }
    }

    Err(auth_err(format!(
        "no offered auth method succeeded for `{user}@{host}` (tried: {}; \
         provide key_path or password via env secrets)",
        if tried.is_empty() { "nothing usable".into() } else { tried.join(", ") }
    )))
}

impl Native {
    async fn run(&self, command: &str) -> Result<ExecOutcome> {
        if self.handle.is_closed() {
            return Err(transport_str("session closed by peer"));
        }
        let mut channel = self
            .handle
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

        out.exit_code = exited
            .ok_or_else(|| transport_str("channel closed without exit status"))?
            as i32;
        Ok(out)
    }
}

impl OpenSsh {
    async fn exec(&self, command: &str) -> Result<ExecOutcome> {
        let mut argv: Vec<String> = vec!["-J".to_owned(), self.jump.clone().unwrap_or_default()];
        argv.extend(self.args.iter().cloned());
        argv.push(self.dest.clone());
        argv.push(command.to_owned());

        let (prog, argv_final) = match &self.password {
            Some(_) if which("sshpass").is_some() => {
                let mut a = vec!["-e".to_owned()];
                a.extend(argv);
                ("sshpass", a)
            }
            Some(_) => {
                return Err(auth_err(
                    "jump mode with a password needs `sshpass` on PATH (or rely on ssh-agent keys)",
                ))
            }
            None => ("ssh", argv),
        };

        let mut cmd = Command::new(&prog);
        if let Some(pw) = &self.password {
            cmd.env("SSHPASS", pw);
        }
        let out = cmd
            .args(&argv_final)
            .output()
            .await
            .map_err(|e| transport_str(&format!("spawn {prog}: {e}")))?;
        Ok(ExecOutcome {
            exit_code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }
}

fn which(bin: &str) -> Option<std::path::PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|p| p.join(bin))
        .find(|p| p.is_file())
}

/// Wrap a vyos CLI command string for non-interactive exec.
pub fn wrap_cli(command: &str) -> String {
    let escaped = command
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('$', "\\$")
        .replace('`', "\\`");
    format!("vbash -lic \"{escaped}\"")
}


#[cfg(test)]
mod tests {
    use super::wrap_cli;

    #[test]
    fn escapes_dollar_and_quotes() {
        assert_eq!(wrap_cli("show version"), "vbash -lic \"show version\"");
        assert_eq!(
            wrap_cli("set interfaces ethernet eth0 vif 35 address \"10.0.35.1/24\""),
            "vbash -lic \"set interfaces ethernet eth0 vif 35 address \\\"10.0.35.1/24\\\"\""
        );
        assert_eq!(wrap_cli("echo $HOME"), "vbash -lic \"echo \\$HOME\"");
    }
}

/// The SSH session doubles as a plugin-host transport: Lua plugins for
/// vyos-family appliances borrow exactly the same gated command runner.
#[async_trait::async_trait]
impl mycelium_core::Transport for SshSession {
    async fn exec(&self, command: &str) -> Result<ExecOutcome> {
        SshSession::exec(self, command).await
    }
}
