//! Locally authorized native service activation. Release manifests never supply
//! commands, service names, or health probes. This adapter manages only an
//! explicitly bound systemd unit whose executable is the package's current link.
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

type Error = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceBinding {
    pub unit: String,
    #[serde(default)]
    pub user_manager: bool,
    pub readiness: Readiness,
    #[serde(default = "startup_timeout")]
    pub timeout_secs: u64,
}

fn startup_timeout() -> u64 {
    10
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Readiness {
    Unix {
        path: PathBuf,
        request: String,
        expect_prefix: String,
    },
    Tcp {
        address: SocketAddr,
        request: String,
        expect_prefix: String,
    },
}

/// Narrow lifecycle boundary. Tests and future native adapters use the same
/// stop/start/verify transaction without changing artifact verification.
pub(crate) trait Lifecycle {
    fn preflight(&self, executable: &Path) -> Result<(), Error>;
    fn stop(&self) -> Result<(), Error>;
    fn start(&self) -> Result<(), Error>;
    fn verify(&self, digest: &str) -> Result<(), Error>;
}

pub fn binding(name: &str) -> Result<Option<ServiceBinding>, Error> {
    let path = crate::home_dir().join("software-services.json");
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::symlink_metadata(&path)?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return Err("software-services.json must be owner-only".into());
        }
    }
    let bindings: BTreeMap<String, ServiceBinding> = serde_json::from_slice(&bytes)?;
    let binding = bindings.get(name).cloned();
    if let Some(binding) = &binding {
        binding.validate()?;
    }
    Ok(binding)
}

impl ServiceBinding {
    pub fn validate(&self) -> Result<(), Error> {
        if self.unit.len() > 128
            || !self.unit.ends_with(".service")
            || !self
                .unit
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !self
                .unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b))
            || !(1..=60).contains(&self.timeout_secs)
        {
            return Err("invalid native service binding".into());
        }
        let (request, prefix) = match &self.readiness {
            Readiness::Unix {
                path,
                request,
                expect_prefix,
            } => {
                if !path.is_absolute() {
                    return Err("health socket must be absolute".into());
                }
                (request, expect_prefix)
            }
            Readiness::Tcp {
                address,
                request,
                expect_prefix,
            } => {
                if !address.ip().is_loopback() {
                    return Err("health TCP address must be loopback".into());
                }
                (request, expect_prefix)
            }
        };
        if request.is_empty() || request.len() > 4096 || prefix.is_empty() || prefix.len() > 4096 {
            return Err("health probe needs bounded request and expected response".into());
        }
        Ok(())
    }

    fn command(&self) -> Command {
        let mut command = Command::new("systemctl");
        if self.user_manager {
            command.arg("--user");
        }
        command
    }

    fn property(&self, property: &str) -> Result<String, Error> {
        let output = self
            .command()
            .args(["show", &self.unit, "--value"])
            .arg(format!("--property={property}"))
            .output()?;
        if !output.status.success() {
            return Err("native unit inspection failed".into());
        }
        Ok(String::from_utf8(output.stdout)?.trim().into())
    }

    fn action(&self, action: &str) -> Result<(), Error> {
        if !self
            .command()
            .args(["--no-block", action, &self.unit])
            .status()?
            .success()
        {
            return Err(format!("native unit {action} failed").into());
        }
        Ok(())
    }

    fn probe(&self, pid: &str) -> Result<(), Error> {
        if !self.owns_listener(pid)? {
            return Err("readiness listener is not owned by the supervised service".into());
        }
        let timeout = Duration::from_millis(250);
        match &self.readiness {
            Readiness::Unix {
                path,
                request,
                expect_prefix,
            } => {
                let mut stream = std::os::unix::net::UnixStream::connect(path)?;
                stream.set_read_timeout(Some(timeout))?;
                stream.set_write_timeout(Some(timeout))?;
                exchange(&mut stream, request, expect_prefix)
            }
            Readiness::Tcp {
                address,
                request,
                expect_prefix,
            } => {
                let mut stream = TcpStream::connect_timeout(address, timeout)?;
                stream.set_read_timeout(Some(timeout))?;
                stream.set_write_timeout(Some(timeout))?;
                exchange(&mut stream, request, expect_prefix)
            }
        }
    }

    fn owns_listener(&self, pid: &str) -> Result<bool, Error> {
        let inodes: Vec<String> = match &self.readiness {
            Readiness::Unix { path, .. } => {
                std::fs::read_to_string(format!("/proc/{pid}/net/unix"))?
                    .lines()
                    .filter_map(|line| {
                        let fields: Vec<_> = line.split_whitespace().collect();
                        (fields.len() >= 8 && Path::new(&fields[7..].join(" ")) == path)
                            .then(|| fields[6].to_owned())
                    })
                    .collect()
            }
            Readiness::Tcp { address, .. } => {
                let (file, encoded) = match address.ip() {
                    std::net::IpAddr::V4(ip) => {
                        ("tcp", format!("{:08X}", u32::from_ne_bytes(ip.octets())))
                    }
                    std::net::IpAddr::V6(ip) => (
                        "tcp6",
                        ip.octets()
                            .chunks_exact(4)
                            .map(|chunk| {
                                format!("{:08X}", u32::from_ne_bytes(chunk.try_into().unwrap()))
                            })
                            .collect::<String>(),
                    ),
                };
                let endpoint = format!("{encoded}:{:04X}", address.port());
                let wildcard = format!("{}:{:04X}", "0".repeat(encoded.len()), address.port());
                std::fs::read_to_string(format!("/proc/{pid}/net/{file}"))?
                    .lines()
                    .filter_map(|line| {
                        let fields: Vec<_> = line.split_whitespace().collect();
                        (fields.len() >= 10
                            && fields[3] == "0A"
                            && (fields[1] == endpoint || fields[1] == wildcard))
                            .then(|| fields[9].to_owned())
                    })
                    .collect()
            }
        };
        for fd in std::fs::read_dir(format!("/proc/{pid}/fd"))? {
            let Ok(link) = std::fs::read_link(fd?.path()) else {
                continue;
            };
            if inodes
                .iter()
                .any(|inode| link.as_os_str() == std::ffi::OsStr::new(&format!("socket:[{inode}]")))
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

pub fn exec_start_matches(exec_start: &str, executable: &Path) -> bool {
    let Some(executable) = executable.to_str() else {
        return false;
    };
    exec_start.split(';').any(|field| {
        field
            .trim()
            .trim_start_matches('{')
            .trim()
            .strip_prefix("path=")
            .is_some_and(|path| path.trim() == executable)
    })
}

impl Lifecycle for ServiceBinding {
    fn preflight(&self, executable: &Path) -> Result<(), Error> {
        self.validate()?;
        if !cfg!(target_os = "linux") {
            return Err(
                "native package service activation currently requires Linux systemd".into(),
            );
        }
        if !exec_start_matches(&self.property("ExecStart")?, executable) {
            return Err("native unit must execute this package's current binary directly".into());
        }
        Ok(())
    }
    fn stop(&self) -> Result<(), Error> {
        self.action("stop")?;
        let deadline = Instant::now() + Duration::from_secs(self.timeout_secs);
        loop {
            if matches!(
                self.property("ActiveState")?.as_str(),
                "inactive" | "failed"
            ) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("native service did not stop within its activation deadline".into());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    fn start(&self) -> Result<(), Error> {
        if self.property("ActiveState")? == "failed" {
            self.action("reset-failed")?;
        }
        self.action("start")
    }
    fn verify(&self, digest: &str) -> Result<(), Error> {
        let deadline = Instant::now() + Duration::from_secs(self.timeout_secs);
        let mut consecutive = 0;
        let mut stable_pid = String::new();
        loop {
            let pid = self.property("MainPID")?;
            let healthy = pid != "0"
                && pid.bytes().all(|b| b.is_ascii_digit())
                && self.property("ActiveState")? == "active"
                && std::fs::read(format!("/proc/{pid}/exe"))
                    .is_ok_and(|bytes| mycelium_peer_protocol::sha256_hex(&bytes) == digest)
                && self.probe(&pid).is_ok();
            if healthy {
                consecutive = if stable_pid == pid {
                    consecutive + 1
                } else {
                    1
                };
                stable_pid = pid;
                if consecutive >= 3 {
                    return Ok(());
                }
            } else {
                consecutive = 0;
            }
            if Instant::now() >= deadline {
                return Err("native service failed readiness/stability check".into());
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
}

fn exchange(stream: &mut (impl Read + Write), request: &str, prefix: &str) -> Result<(), Error> {
    stream.write_all(request.as_bytes())?;
    stream.flush()?;
    let mut reply = vec![0; prefix.len()];
    stream.read_exact(&mut reply)?;
    if reply != prefix.as_bytes() {
        return Err("health response did not match".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[cfg(target_os = "linux")]
    fn readiness_requires_the_managed_process_to_own_the_listener() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let binding = ServiceBinding {
            unit: "edge-test.service".into(),
            user_manager: false,
            readiness: Readiness::Tcp {
                address: listener.local_addr().unwrap(),
                request: "ping\n".into(),
                expect_prefix: "pong".into(),
            },
            timeout_secs: 2,
        };
        assert!(binding
            .owns_listener(&std::process::id().to_string())
            .unwrap());
        assert!(!matches!(binding.owns_listener("1"), Ok(true)));
    }
    #[test]
    fn bindings_reject_remote_probes_and_empty_health() {
        let mut binding = ServiceBinding {
            unit: "unibus.service".into(),
            user_manager: false,
            readiness: Readiness::Tcp {
                address: "127.0.0.1:9999".parse().unwrap(),
                request: "ping\n".into(),
                expect_prefix: "pong".into(),
            },
            timeout_secs: 2,
        };
        assert!(binding.validate().is_ok());
        binding.unit = "--help.service".into();
        assert!(binding.validate().is_err());
        binding.unit = "../evil.service".into();
        assert!(binding.validate().is_err());
        binding.unit = "unibus.service".into();
        binding.readiness = Readiness::Tcp {
            address: "192.168.1.1:9999".parse().unwrap(),
            request: "ping".into(),
            expect_prefix: "pong".into(),
        };
        assert!(binding.validate().is_err());
    }
    #[test]
    fn executable_match_never_accepts_an_argument_as_the_unit_binary() {
        let binary = Path::new("/state/software/unibus/current/unibus");
        assert!(exec_start_matches(
            "{ path=/state/software/unibus/current/unibus ; argv[]=unibus ; }",
            binary
        ));
        assert!(!exec_start_matches(
            "{ path=/bin/sh ; argv[]=/state/software/unibus/current/unibus ; }",
            binary
        ));
    }
}
