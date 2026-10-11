//! Browser PKI lifecycle. Peer identity proves the CSR; local CA custody authorizes
//! issuance. Server trust is deliberately separate from viewer authorization.
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use mycelium_peer_protocol::{decode_array, encode_hex};
use myceliumd::{client::Client, protocol::Request};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CertificateRequest {
    node_id: String,
    issued_at: u64,
    csr: String,
    signature: String,
}
impl CertificateRequest {
    fn payload(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(&(
            "mycelium/web-certificate-request",
            &self.node_id,
            self.issued_at,
            &self.csr,
        ))
        .map_err(|e| e.to_string())
    }
    fn verify(&self, now: u64) -> Result<(), String> {
        if self.issued_at > now
            || now.saturating_sub(self.issued_at) > 600
            || self.csr.len() > 16384
        {
            return Err("web CSR is expired, future-dated or oversized".into());
        }
        let key = VerifyingKey::from_bytes(&decode_array::<32>(&self.node_id)?)
            .map_err(|e| e.to_string())?;
        key.verify_strict(
            &self.payload()?,
            &Signature::from_bytes(&decode_array::<64>(&self.signature)?),
        )
        .map_err(|_| "web CSR peer signature invalid".into())
    }
}
fn now() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|e| e.to_string())
}
fn ssl(args: &[&str]) -> Result<String, String> {
    let out = Command::new("openssl")
        .args(args)
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!(
            "openssl failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    String::from_utf8(out.stdout).map_err(|e| e.to_string())
}
fn path(path: &Path) -> Result<&str, String> {
    path.to_str().ok_or("PKI paths must be UTF-8".into())
}
fn private_dir(dir: &Path) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    }
    Ok(())
}
fn new_private_dir(dir: &Path) -> Result<(), String> {
    // Exclusive creation serializes CA initialization and issuance generations.
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir).map_err(|e| e.to_string())
}
fn private_file(file: &Path) -> Result<(), String> {
    if !fs::symlink_metadata(file)
        .map_err(|e| e.to_string())?
        .file_type()
        .is_file()
    {
        return Err("PKI key must be a regular file, not a symlink".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(file, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    }
    Ok(())
}
fn verify_web_certificate(cert: &Path, ca: &Path, hostname: &str) -> Result<(), String> {
    use rustls::client::danger::ServerCertVerifier;
    let read = |file: &Path| -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, String> {
        let bytes = fs::read(file).map_err(|e| e.to_string())?;
        if bytes.len() > 65536 {
            return Err("web certificate file exceeds 64 KiB".into());
        }
        rustls_pemfile::certs(&mut std::io::Cursor::new(bytes))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    };
    let certificates = read(cert)?;
    if certificates.len() != 1 {
        return Err("web leaf file must contain exactly one certificate".into());
    }
    let roots = read(ca)?;
    if roots.len() != 1 {
        return Err("web trust file must contain exactly one root".into());
    }
    let mut store = rustls::RootCertStore::empty();
    store.add(roots[0].clone()).map_err(|e| e.to_string())?;
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
        std::sync::Arc::new(store),
        std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
    )
    .build()
    .map_err(|e| e.to_string())?;
    verifier
        .verify_server_cert(
            &certificates[0],
            &[],
            &rustls::pki_types::ServerName::try_from(hostname.to_owned())
                .map_err(|e| e.to_string())?,
            &[],
            rustls::pki_types::UnixTime::now(),
        )
        .map_err(|e| e.to_string())?;
    Ok(())
}
fn label(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 63
        || value.starts_with('-')
        || value.ends_with('-')
        || !value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err("web DNS names require lowercase DNS labels".into());
    }
    Ok(())
}
fn names(host: &str, site: &str, index: bool) -> Result<Vec<String>, String> {
    label(host)?;
    label(site)?;
    let mut names = vec![
        format!("{host}.{site}.myc"),
        format!("mycelium.{host}.{site}.myc"),
    ];
    if index {
        names.push("mycelium.myc".into());
    }
    Ok(names)
}
fn option(args: &[String], name: &str) -> Result<PathBuf, String> {
    let i = args
        .iter()
        .position(|a| a == name)
        .ok_or_else(|| format!("missing {name}"))?;
    args.get(i + 1)
        .filter(|v| !v.starts_with("--"))
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing value for {name}"))
}
fn validate_args(args: &[String], valued: &[&str], flags: &[&str]) -> Result<(), String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut i = 1;
    while i < args.len() {
        let arg = args[i].as_str();
        if !seen.insert(arg) {
            return Err(format!("duplicate {arg}"));
        }
        if valued.contains(&arg) {
            option(args, arg)?;
            i += 2;
        } else if flags.contains(&arg) {
            i += 1;
        } else {
            return Err(format!("unexpected argument {arg}"));
        }
    }
    if !seen.contains("--write") {
        return Err("web-ca mutations require --write".into());
    }
    Ok(())
}
pub async fn run(args: &[String]) -> Result<Vec<String>, String> {
    match args.first().map(String::as_str) {
        Some("init") => {
            validate_args(args, &["--path"], &["--write"])?;
            let dir = option(args, "--path")?;
            if dir.exists() {
                return Err("web CA directory already exists; refusing replacement".into());
            }
            new_private_dir(&dir)?;
            ssl(&[
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out",
                path(&dir.join("ca-key.pem"))?,
            ])?;
            private_file(&dir.join("ca-key.pem"))?;
            let config = dir.join("ca.cnf");
            fs::write(&config,"[req]\ndistinguished_name=dn\nx509_extensions=ca\nprompt=no\n[dn]\nCN=Mycelium Web CA\n[ca]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n").map_err(|e|e.to_string())?;
            ssl(&[
                "req",
                "-new",
                "-x509",
                "-sha256",
                "-key",
                path(&dir.join("ca-key.pem"))?,
                "-config",
                path(&config)?,
                "-days",
                "3650",
                "-out",
                path(&dir.join("ca.pem"))?,
            ])?;
            Ok(vec![format!("created browser web CA at {}; trust ca.pem once, keep ca-key.pem on the issuer only",dir.display())])
        }
        Some("request") => {
            validate_args(args, &["--path"], &["--write"])?;
            let mut client = Client::connect().await.map_err(|e| e.to_string())?;
            let node = client
                .call(&Request::NodeObserve)
                .await
                .map_err(|e| e.to_string())?;
            let node_id = node["hello"]["node_id"]
                .as_str()
                .ok_or("missing local peer identity")?
                .to_owned();
            let bytes = fs::read(myceliumd::peer_key_path()).map_err(|e| e.to_string())?;
            let key = SigningKey::from_bytes(
                bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| "peer key must be 32 bytes")?,
            );
            if encode_hex(key.verifying_key().as_bytes()) != node_id {
                return Err("local peer key does not match daemon".into());
            }
            let dir = option(args, "--path")?;
            private_dir(&dir)?;
            let key_path = dir.join("server-key.pem");
            if !key_path.exists() {
                ssl(&[
                    "ecparam",
                    "-name",
                    "prime256v1",
                    "-genkey",
                    "-noout",
                    "-out",
                    path(&key_path)?,
                ])?;
            }
            private_file(&key_path)?;
            let csr = dir.join("server.csr");
            ssl(&[
                "req",
                "-new",
                "-sha256",
                "-key",
                path(&key_path)?,
                "-subj",
                &format!("/CN={node_id}"),
                "-out",
                path(&csr)?,
            ])?;
            let mut request = CertificateRequest {
                node_id,
                issued_at: now()?,
                csr: fs::read_to_string(&csr).map_err(|e| e.to_string())?,
                signature: String::new(),
            };
            request.signature = encode_hex(&key.sign(&request.payload()?).to_bytes());
            fs::write(
                dir.join("request.json"),
                serde_json::to_vec_pretty(&request).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            Ok(vec![format!(
                "created peer-signed {}; share only request.json, never server-key.pem",
                dir.join("request.json").display()
            )])
        }
        Some("issue") => {
            validate_args(
                args,
                &["--ca", "--request", "--output"],
                &["--write", "--index"],
            )?;
            let request_path = option(args, "--request")?;
            if fs::metadata(&request_path)
                .map_err(|e| e.to_string())?
                .len()
                > 32768
            {
                return Err("web request exceeds 32 KiB".into());
            }
            let request: CertificateRequest =
                serde_json::from_slice(&fs::read(request_path).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
            let at = now()?;
            request.verify(at)?;
            let mut client = Client::connect().await.map_err(|e| e.to_string())?;
            let peers = client
                .call(&Request::PeerNames)
                .await
                .map_err(|e| e.to_string())?;
            let peer = peers
                .as_array()
                .ok_or("invalid peer names response")?
                .iter()
                .find(|p| p["origin"].as_str() == Some(request.node_id.as_str()))
                .ok_or("CSR peer is not in authenticated fleet observations")?;
            let seen = peer["last_seen"]
                .as_u64()
                .ok_or("peer observation lacks timestamp")?;
            if seen > at || at.saturating_sub(seen) >= 300 {
                return Err("CSR peer observation is stale".into());
            }
            let hello = &peer["hello"];
            let sans = names(
                hello["hostname"].as_str().ok_or("missing hostname")?,
                hello["site"].as_str().ok_or("missing site")?,
                args.iter().any(|a| a == "--index"),
            )?;
            let ca = option(args, "--ca")?;
            let output = option(args, "--output")?;
            if output.exists() {
                return Err(
                    "issuance output already exists; use a new generation directory".into(),
                );
            }
            new_private_dir(&output)?;
            let csr = output.join("server.csr");
            fs::write(&csr, &request.csr).map_err(|e| e.to_string())?;
            ssl(&["req", "-in", path(&csr)?, "-noout", "-verify"])?;
            let subject = ssl(&[
                "req",
                "-in",
                path(&csr)?,
                "-noout",
                "-subject",
                "-nameopt",
                "RFC2253",
            ])?;
            if subject.trim() != format!("subject=CN={}", request.node_id) {
                return Err("CSR subject does not match signing peer".into());
            }
            let extensions = output.join("server.cnf");
            fs::write(&extensions,format!("[server]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName={}\n",sans.iter().map(|s|format!("DNS:{s}")).collect::<Vec<_>>().join(","))).map_err(|e|e.to_string())?;
            let serial = ssl(&["rand", "-hex", "16"])?;
            ssl(&[
                "x509",
                "-req",
                "-sha256",
                "-in",
                path(&csr)?,
                "-CA",
                path(&ca.join("ca.pem"))?,
                "-CAkey",
                path(&ca.join("ca-key.pem"))?,
                "-set_serial",
                &format!("0x{}", serial.trim()),
                "-extfile",
                path(&extensions)?,
                "-extensions",
                "server",
                "-days",
                "7",
                "-out",
                path(&output.join("server.pem"))?,
            ])?;
            ssl(&[
                "verify",
                "-CAfile",
                path(&ca.join("ca.pem"))?,
                path(&output.join("server.pem"))?,
            ])?;
            fs::copy(ca.join("ca.pem"), output.join("ca.pem")).map_err(|e| e.to_string())?;
            Ok(vec![format!("issued seven-day HTTPS certificate for {}: {}; no peer or viewer authority changed",request.node_id,sans.join(", "))])
        }
        Some("install") => {
            validate_args(
                args,
                &["--path", "--certificate", "--ca", "--hostname"],
                &["--write"],
            )?;
            let dir = option(args, "--path")?;
            let cert = option(args, "--certificate")?;
            let ca = option(args, "--ca")?;
            let hostname = option(args, "--hostname")?;
            let hostname = path(&hostname)?;
            if hostname.len() > 253 || !hostname.ends_with(".myc") {
                return Err("web install requires a .myc hostname".into());
            }
            for part in hostname.split('.') {
                label(part)?;
            }
            verify_web_certificate(&cert, &ca, hostname)?;
            ssl(&["x509", "-in", path(&cert)?, "-noout", "-checkend", "172800"])?;
            let public = ssl(&["x509", "-in", path(&cert)?, "-noout", "-pubkey"])?;
            let own = ssl(&["pkey", "-in", path(&dir.join("server-key.pem"))?, "-pubout"])?;
            if public.trim() != own.trim() {
                return Err("issued web certificate does not match this host's private key".into());
            }
            let installed = dir.join("server.pem");
            let next = dir.join("server.pem.next");
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&next)
                .map_err(|e| e.to_string())?;
            use std::io::Write;
            file.write_all(&fs::read(&cert).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
            if installed.exists() {
                fs::copy(&installed, dir.join("server.pem.previous")).map_err(|e| e.to_string())?;
            }
            fs::rename(&next, &installed).map_err(|e| e.to_string())?;
            Ok(vec![format!("verified and installed {}; new web handshakes reload it without restarting peer sync",installed.display())])
        }
        _ => Err("web-ca expects init, request, issue or install (see mycelium help)".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn names_are_derived_and_no_wildcards_or_injection() {
        assert_eq!(
            names("neo", "lab", false).unwrap(),
            vec!["neo.lab.myc", "mycelium.neo.lab.myc"]
        );
        for bad in ["*", "lab\nDNS:evil", "a.b", "-lab", "LAB", ""] {
            assert!(names("neo", bad, true).is_err());
        }
        assert!(names("neo", "lab", true)
            .unwrap()
            .contains(&"mycelium.myc".into()));
    }
    #[test]
    fn request_binding_expiry_and_tampering() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut request = CertificateRequest {
            node_id: encode_hex(key.verifying_key().as_bytes()),
            issued_at: 100,
            csr: "test CSR".into(),
            signature: String::new(),
        };
        request.signature = encode_hex(&key.sign(&request.payload().unwrap()).to_bytes());
        assert!(request.verify(100).is_ok());
        assert!(request.verify(99).is_err());
        assert!(request.verify(701).is_err());
        request.csr.push('x');
        assert!(request.verify(101).is_err());
    }
    #[tokio::test]
    async fn real_ca_install_checks_chain_hostname_key_and_retains_rollback() {
        let random = ssl(&["rand", "-hex", "12"]).unwrap();
        let dir = std::env::temp_dir().join(format!("mycelium-web-ca-test-{}", random.trim()));
        private_dir(&dir).unwrap();
        let ca = dir.join("authority");
        run(&[
            "init".into(),
            "--path".into(),
            path(&ca).unwrap().into(),
            "--write".into(),
        ])
        .await
        .unwrap();
        let host = dir.join("host");
        private_dir(&host).unwrap();
        let key = host.join("server-key.pem");
        ssl(&[
            "ecparam",
            "-name",
            "prime256v1",
            "-genkey",
            "-noout",
            "-out",
            path(&key).unwrap(),
        ])
        .unwrap();
        let csr = dir.join("leaf.csr");
        ssl(&[
            "req",
            "-new",
            "-key",
            path(&key).unwrap(),
            "-subj",
            "/CN=fixture",
            "-out",
            path(&csr).unwrap(),
        ])
        .unwrap();
        let ext = dir.join("leaf.cnf");
        fs::write(&ext,"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:neo.home.myc\n").unwrap();
        let cert = dir.join("leaf.pem");
        ssl(&[
            "x509",
            "-req",
            "-sha256",
            "-in",
            path(&csr).unwrap(),
            "-CA",
            path(&ca.join("ca.pem")).unwrap(),
            "-CAkey",
            path(&ca.join("ca-key.pem")).unwrap(),
            "-set_serial",
            "1",
            "-days",
            "7",
            "-extfile",
            path(&ext).unwrap(),
            "-out",
            path(&cert).unwrap(),
        ])
        .unwrap();
        let mut args = vec![
            "install".into(),
            "--path".into(),
            path(&host).unwrap().into(),
            "--certificate".into(),
            path(&cert).unwrap().into(),
            "--ca".into(),
            path(&ca.join("ca.pem")).unwrap().into(),
            "--hostname".into(),
            "neo.home.myc".into(),
            "--write".into(),
        ];
        args[8] = "other.home.myc".into();
        assert!(run(&args).await.is_err());
        assert!(!host.join("server.pem").exists());
        args[8] = "neo.home.myc".into();
        run(&args).await.unwrap();
        run(&args).await.unwrap();
        assert_eq!(
            fs::read(host.join("server.pem.previous")).unwrap(),
            fs::read(&cert).unwrap()
        );
        ssl(&[
            "ecparam",
            "-name",
            "prime256v1",
            "-genkey",
            "-noout",
            "-out",
            path(&key).unwrap(),
        ])
        .unwrap();
        assert!(run(&args).await.is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
