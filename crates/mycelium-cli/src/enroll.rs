use std::path::{Path, PathBuf};
use std::process::Command;

use myceliumd::client::ClientError;

pub struct Issue<'a> {
    pub name: &'a str,
    pub site: &'a str,
    pub address: &'a str,
    pub target: &'a str,
    pub binary: &'a Path,
    pub peers: &'a [String],
    pub output: &'a Path,
}

pub fn init(path: &Path) -> Result<Vec<String>, ClientError> {
    if path.join("ca-key.pem").exists() || path.join("ca.pem").exists() {
        return Err(usage("enrollment CA already exists"));
    }
    std::fs::create_dir_all(path).map_err(ClientError::Io)?;
    openssl(&[
        "genpkey",
        "-algorithm",
        "ED25519",
        "-out",
        &display(path.join("ca-key.pem"))?,
    ])?;
    openssl(&[
        "req",
        "-x509",
        "-new",
        "-key",
        &display(path.join("ca-key.pem"))?,
        "-out",
        &display(path.join("ca.pem"))?,
        "-subj",
        "/CN=Mycelium Mesh CA",
        "-days",
        "3650",
    ])?;
    owner_only(&path.join("ca-key.pem"))?;
    Ok(vec![format!(
        "initialized enrollment CA at {}; back up ca-key.pem offline",
        path.display()
    )])
}

pub fn issue(ca: &Path, request: Issue<'_>) -> Result<Vec<String>, ClientError> {
    validate_label("name", request.name)?;
    validate_label("site", request.site)?;
    validate_label("target", request.target)?;
    validate_address(request.address)?;
    if !ca.join("ca-key.pem").is_file() || !ca.join("ca.pem").is_file() {
        return Err(usage("enrollment CA is missing ca.pem or ca-key.pem"));
    }
    if !request.binary.is_file() {
        return Err(usage("enrollment binary does not exist"));
    }
    if request.output.exists() {
        return Err(usage("enrollment output already exists"));
    }
    std::fs::create_dir_all(request.output).map_err(ClientError::Io)?;
    let key = request.output.join("node-key.pem");
    let csr = request.output.join("node.csr");
    let cert = request.output.join("node.pem");
    let san = if request.address.parse::<std::net::IpAddr>().is_ok() {
        format!("subjectAltName=IP:{}", request.address)
    } else {
        format!("subjectAltName=DNS:{}", request.address)
    };
    openssl(&["genpkey", "-algorithm", "ED25519", "-out", &display(&key)?])?;
    openssl(&[
        "req",
        "-new",
        "-key",
        &display(&key)?,
        "-out",
        &display(&csr)?,
        "-subj",
        &format!("/CN={}", request.name),
        "-addext",
        &san,
        "-addext",
        "extendedKeyUsage=serverAuth,clientAuth",
    ])?;
    openssl(&[
        "x509",
        "-req",
        "-in",
        &display(&csr)?,
        "-CA",
        &display(ca.join("ca.pem"))?,
        "-CAkey",
        &display(ca.join("ca-key.pem"))?,
        "-CAcreateserial",
        "-copy_extensions",
        "copy",
        "-out",
        &display(&cert)?,
        "-days",
        "365",
    ])?;
    std::fs::copy(ca.join("ca.pem"), request.output.join("ca.pem")).map_err(ClientError::Io)?;
    std::fs::copy(request.binary, request.output.join("mycelium")).map_err(ClientError::Io)?;
    owner_only(&key)?;
    executable(&request.output.join("mycelium"))?;
    let release_keys = std::env::var("MYCELIUM_RELEASE_KEYS").unwrap_or_default();
    let peer_list = request.peers.join(",");
    std::fs::write(
        request.output.join("node.env"),
        format!(
            "MYCELIUM_SITE={}\nMYCELIUM_PEER_LISTEN=0.0.0.0:7443\nMYCELIUM_PEERS={}\nMYCELIUM_PEER_CA=pki/ca.pem\nMYCELIUM_PEER_CERT=pki/node.pem\nMYCELIUM_PEER_KEY=pki/node-key.pem\nMYCELIUM_RELEASE_KEYS={}\nMYCELIUM_UPDATE_CHANNEL=canary\n",
            request.site, peer_list, release_keys
        ),
    )
    .map_err(ClientError::Io)?;
    std::fs::write(
        request.output.join("manifest.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "name": request.name,
            "site": request.site,
            "address": request.address,
            "target": request.target,
            "peers": request.peers,
        }))
        .map_err(|error| usage(&error.to_string()))?,
    )
    .map_err(ClientError::Io)?;
    std::fs::write(request.output.join("mycelium.service"), systemd_unit())
        .map_err(ClientError::Io)?;
    std::fs::write(
        request.output.join("dev.fpl.mycelium.plist"),
        launchd_plist(request.site, &peer_list, &release_keys),
    )
    .map_err(ClientError::Io)?;
    let _ = std::fs::remove_file(csr);
    Ok(vec![format!(
        "issued {} ({}) enrollment bundle at {}",
        request.name,
        request.target,
        request.output.display()
    )])
}

pub fn install(bundle: &Path, home: &Path) -> Result<Vec<String>, ClientError> {
    for name in [
        "mycelium",
        "ca.pem",
        "node.pem",
        "node-key.pem",
        "manifest.json",
    ] {
        if !bundle.join(name).is_file() {
            return Err(usage(&format!("enrollment bundle is missing {name}")));
        }
    }
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(bundle.join("manifest.json")).map_err(ClientError::Io)?,
    )
    .map_err(|error| usage(&format!("invalid enrollment manifest: {error}")))?;
    let site = manifest["site"]
        .as_str()
        .ok_or_else(|| usage("manifest is missing site"))?;
    validate_label("site", site)?;
    let peers = manifest["peers"]
        .as_array()
        .ok_or_else(|| usage("manifest is missing peers"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| usage("manifest peer is not text"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    for peer in &peers {
        validate_peer(peer)?;
    }

    let bin = home.join("bin/mycelium");
    let pki = home.join("pki");
    std::fs::create_dir_all(bin.parent().unwrap()).map_err(ClientError::Io)?;
    std::fs::create_dir_all(&pki).map_err(ClientError::Io)?;
    copy_mode(&bundle.join("mycelium"), &bin, 0o755)?;
    copy_mode(&bundle.join("ca.pem"), &pki.join("ca.pem"), 0o644)?;
    copy_mode(&bundle.join("node.pem"), &pki.join("node.pem"), 0o644)?;
    copy_mode(
        &bundle.join("node-key.pem"),
        &pki.join("node-key.pem"),
        0o600,
    )?;

    let release_keys = std::env::var("MYCELIUM_RELEASE_KEYS").unwrap_or_default();
    let peers = peers.join(",");
    std::fs::write(
        home.join("node.env"),
        resolved_env(home, site, &peers, &release_keys)?,
    )
    .map_err(ClientError::Io)?;
    let service = if cfg!(target_os = "macos") {
        let path = user_home()?.join("Library/LaunchAgents/dev.fpl.mycelium.plist");
        std::fs::create_dir_all(path.parent().unwrap()).map_err(ClientError::Io)?;
        std::fs::write(&path, resolved_launchd(home, site, &peers, &release_keys)?)
            .map_err(ClientError::Io)?;
        path
    } else if cfg!(target_os = "linux") {
        let path = user_home()?.join(".config/systemd/user/mycelium.service");
        std::fs::create_dir_all(path.parent().unwrap()).map_err(ClientError::Io)?;
        std::fs::write(&path, resolved_systemd(home)?).map_err(ClientError::Io)?;
        path
    } else {
        return Err(usage("enrollment install supports Darwin and Linux"));
    };
    Ok(vec![
        format!("installed enrolled peer under {}", home.display()),
        format!("wrote {}; service was not started", service.display()),
    ])
}

fn resolved_env(home: &Path, site: &str, peers: &str, keys: &str) -> Result<String, ClientError> {
    let home = display(home)?;
    Ok(format!("MYCELIUM_HOME={home}\nMYCELIUM_SITE={site}\nMYCELIUM_PEER_LISTEN=0.0.0.0:7443\nMYCELIUM_PEERS={peers}\nMYCELIUM_PEER_CA={home}/pki/ca.pem\nMYCELIUM_PEER_CERT={home}/pki/node.pem\nMYCELIUM_PEER_KEY={home}/pki/node-key.pem\nMYCELIUM_RELEASE_KEYS={keys}\nMYCELIUM_UPDATE_CHANNEL=canary\n"))
}

fn resolved_systemd(home: &Path) -> Result<String, ClientError> {
    let home = display(home)?;
    Ok(format!("[Unit]\nDescription=Mycelium peer\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nExecStart={home}/bin/mycelium _serve\nEnvironmentFile={home}/node.env\nRestart=always\nRestartSec=5\nNoNewPrivileges=true\nPrivateTmp=true\n\n[Install]\nWantedBy=default.target\n"))
}

fn resolved_launchd(
    home: &Path,
    site: &str,
    peers: &str,
    keys: &str,
) -> Result<String, ClientError> {
    let home = xml(&display(home)?);
    Ok(format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>dev.fpl.mycelium</string>\n<key>ProgramArguments</key><array><string>{home}/bin/mycelium</string><string>_serve</string></array>\n<key>EnvironmentVariables</key><dict>\n<key>MYCELIUM_HOME</key><string>{home}</string>\n<key>MYCELIUM_SITE</key><string>{}</string>\n<key>MYCELIUM_PEER_LISTEN</key><string>0.0.0.0:7443</string>\n<key>MYCELIUM_PEERS</key><string>{}</string>\n<key>MYCELIUM_PEER_CA</key><string>{home}/pki/ca.pem</string>\n<key>MYCELIUM_PEER_CERT</key><string>{home}/pki/node.pem</string>\n<key>MYCELIUM_PEER_KEY</key><string>{home}/pki/node-key.pem</string>\n<key>MYCELIUM_RELEASE_KEYS</key><string>{}</string>\n<key>MYCELIUM_UPDATE_CHANNEL</key><string>canary</string>\n</dict><key>RunAtLoad</key><true/><key>KeepAlive</key><true/>\n<key>StandardOutPath</key><string>{home}/daemon.log</string>\n<key>StandardErrorPath</key><string>{home}/daemon.log</string>\n</dict></plist>\n", xml(site), xml(peers), xml(keys)))
}

fn validate_peer(peer: &str) -> Result<(), ClientError> {
    if peer.is_empty()
        || peer.len() > 320
        || peer.bytes().any(|b| b.is_ascii_whitespace() || b == b',')
    {
        return Err(usage("peer address contains unsafe characters"));
    }
    Ok(())
}

fn copy_mode(from: &Path, to: &Path, mode: u32) -> Result<(), ClientError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::copy(from, to).map_err(ClientError::Io)?;
    std::fs::set_permissions(to, std::fs::Permissions::from_mode(mode)).map_err(ClientError::Io)
}

fn user_home() -> Result<PathBuf, ClientError> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| usage("HOME is not set"))
}

fn xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn systemd_unit() -> &'static str {
    "[Unit]\nDescription=Mycelium peer\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nExecStart=%h/.mycelium/bin/mycelium _serve\nEnvironment=MYCELIUM_HOME=%h/.mycelium\nEnvironmentFile=%h/.mycelium/node.env\nRestart=always\nRestartSec=5\nNoNewPrivileges=true\nPrivateTmp=true\n\n[Install]\nWantedBy=default.target\n"
}

fn launchd_plist(site: &str, peers: &str, release_keys: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>dev.fpl.mycelium</string>\n<key>ProgramArguments</key><array><string>MYCELIUM_HOME/bin/mycelium</string><string>_serve</string></array>\n<key>EnvironmentVariables</key><dict>\n<key>MYCELIUM_HOME</key><string>MYCELIUM_HOME</string>\n<key>MYCELIUM_SITE</key><string>{site}</string>\n<key>MYCELIUM_PEER_LISTEN</key><string>0.0.0.0:7443</string>\n<key>MYCELIUM_PEERS</key><string>{peers}</string>\n<key>MYCELIUM_PEER_CA</key><string>MYCELIUM_HOME/pki/ca.pem</string>\n<key>MYCELIUM_PEER_CERT</key><string>MYCELIUM_HOME/pki/node.pem</string>\n<key>MYCELIUM_PEER_KEY</key><string>MYCELIUM_HOME/pki/node-key.pem</string>\n<key>MYCELIUM_RELEASE_KEYS</key><string>{release_keys}</string>\n<key>MYCELIUM_UPDATE_CHANNEL</key><string>canary</string>\n</dict><key>RunAtLoad</key><true/><key>KeepAlive</key><true/>\n<key>StandardOutPath</key><string>MYCELIUM_HOME/daemon.log</string>\n<key>StandardErrorPath</key><string>MYCELIUM_HOME/daemon.log</string>\n</dict></plist>\n"
    )
}

fn openssl(args: &[&str]) -> Result<(), ClientError> {
    let output = Command::new("openssl")
        .args(args)
        .output()
        .map_err(ClientError::Io)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(usage(&format!(
            "openssl failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

fn validate_label(name: &str, value: &str) -> Result<(), ClientError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
    {
        return Err(usage(&format!("{name} contains unsafe characters")));
    }
    Ok(())
}

fn validate_address(value: &str) -> Result<(), ClientError> {
    if value.is_empty()
        || value.len() > 253
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':'))
    {
        return Err(usage("address is not a safe IP address or DNS name"));
    }
    Ok(())
}

fn display(path: impl AsRef<Path>) -> Result<String, ClientError> {
    path.as_ref()
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| usage("enrollment paths must be UTF-8"))
}

fn owner_only(path: &Path) -> Result<(), ClientError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(ClientError::Io)
}

fn executable(path: &Path) -> Result<(), ClientError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).map_err(ClientError::Io)
}

fn usage(message: &str) -> ClientError {
    ClientError::Protocol(message.into())
}

pub fn default_ca() -> PathBuf {
    myceliumd::home_dir().join("pki")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrollment_names_and_addresses_are_shell_independent() {
        assert!(validate_label("name", "home-pi").is_ok());
        assert!(validate_label("name", "x;reboot").is_err());
        assert!(validate_address("home-pi.tail.example").is_ok());
        assert!(validate_address("x $(reboot)").is_err());
    }
}
