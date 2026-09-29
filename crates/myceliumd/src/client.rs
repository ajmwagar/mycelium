use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufStream};
use tokio::net::UnixStream;

use crate::protocol::{Request, Response};

pub struct Client {
    stream: BufStream<UnixStream>,
}

impl Client {
    /// Connect to the daemon; if the socket is dead/absent, spawn
    /// `myceliumd` detached (unless disabled) and wait for it to answer.
    pub async fn connect() -> Result<Self, ClientError> {
        match Self::try_connect().await {
            Ok(c) => Ok(c),
            Err(e @ ClientError::Connect(_)) => {
                if std::env::var_os("MYCELIUM_NO_AUTOSTART").is_some() {
                    return Err(e);
                }
                Self::spawn_daemon()?;
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    match Self::try_connect().await {
                        Ok(c) => return Ok(c),
                        Err(_) if Instant::now() > deadline => {
                            return Err(ClientError::DaemonUnresponsive)
                        }
                        Err(_) => {}
                    }
                }
            }
            Err(e) => Err(e),
        }
    }

    pub async fn try_connect() -> Result<Self, ClientError> {
        let socket = crate::socket_path();
        let stream = UnixStream::connect(&socket)
            .await
            .map_err(ClientError::Connect)?;
        Ok(Self { stream: BufStream::new(stream) })
    }

    /// Detached spawn: process group leader, logs to $MYCELIUM_HOME.
    /// Runs `self <exe> _serve` so the same binary can host the daemon
    /// (the CLI and daemon ship together; PATH never consulted).
    pub fn spawn_daemon() -> Result<(), ClientError> {
        let exe = std::env::current_exe().map_err(|e| ClientError::Spawn(e.to_string()))?;
        let home = crate::home_dir();
        std::fs::create_dir_all(&home).map_err(|e| ClientError::Spawn(e.to_string()))?;
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(home.join("daemon.log"))
            .map_err(|e| ClientError::Spawn(e.to_string()))?;
        let log_err = log.try_clone().map_err(|e| ClientError::Spawn(e.to_string()))?;
        use std::os::unix::process::CommandExt;
        let mut cmd = std::process::Command::new(exe);
        cmd.arg("_serve")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::from(log))
            .stderr(std::process::Stdio::from(log_err));
        cmd.process_group(0);
        cmd.spawn().map_err(|e| ClientError::Spawn(e.to_string()))?;
        Ok(())
    }

    pub async fn request(&mut self, req: &Request) -> Result<Response, ClientError> {
        let line = serde_json::to_string(req).expect("Request is serializable");
        self.stream.write_all(line.as_bytes()).await?;
        self.stream.write_all(b"\n").await?;
        self.stream.flush().await?;
        let mut buf = String::new();
        let n = self.stream.read_line(&mut buf).await?;
        if n == 0 {
            return Err(ClientError::Protocol("daemon closed the connection".into()));
        }
        serde_json::from_str(&buf).map_err(|e| ClientError::Protocol(e.to_string()))
    }

    /// Send, and unwrap ok/error into a value error.
    pub async fn call(&mut self, req: &Request) -> Result<serde_json::Value, ClientError> {
        let resp = self.request(req).await?;
        if resp.ok {
            Ok(resp.result.unwrap_or(serde_json::Value::Null))
        } else {
            Err(ClientError::Rpc {
                message: resp.error.unwrap_or_else(|| "unspecified".into()),
                kind: resp.kind.unwrap_or_else(|| "daemon".into()),
            })
        }
    }
}

#[derive(Debug)]
pub enum ClientError {
    Connect(std::io::Error),
    Io(std::io::Error),
    Protocol(String),
    Spawn(String),
    DaemonUnresponsive,
    Rpc { message: String, kind: String },
}

impl From<std::io::Error> for ClientError {
    fn from(e: std::io::Error) -> Self {
        ClientError::Io(e)
    }
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Connect(e) => write!(f, "cannot reach myceliumd socket ({}): {e}", crate::socket_path().display()),
            ClientError::Io(e) => write!(f, "socket io: {e}"),
            ClientError::Protocol(e) => write!(f, "protocol error: {e}"),
            ClientError::Spawn(e) => write!(f, "could not spawn myceliumd: {e}"),
            ClientError::DaemonUnresponsive => {
                write!(f, "myceliumd did not come up within 5s (see ~/.mycelium/daemon.log)")
            }
            ClientError::Rpc { message, kind } => write!(f, "[{kind}] {message}"),
        }
    }
}
