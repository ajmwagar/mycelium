use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub async fn run(args: &[String]) -> Result<Vec<String>, String> {
    if args.iter().any(|argument| argument == "--repair") {
        let home = value(args, "--path")
            .map(expand_home)
            .unwrap_or_else(myceliumd::home_dir);
        return crate::enroll::repair_peer_service(&home, value(args, "--site"));
    }
    let claim = value(args, "--claim");
    let embedded = claim
        .map(crate::invite::decode_pair_claim)
        .transpose()?
        .flatten();
    let gateway = embedded
        .as_ref()
        .map(|(endpoint, _, _, _)| endpoint.clone())
        .or_else(|| value(args, "--gateway").map(str::to_owned))
        .or_else(|| std::env::var("MYCELIUM_GATEWAY").ok())
        .ok_or_else(|| "setup needs a pairing claim or --gateway HTTPS-URL".to_owned())?;
    if embedded
        .as_ref()
        .is_some_and(|(_, _, _, kind)| *kind == crate::invite::InvitationKind::Peer)
    {
        return setup_peer(
            embedded.as_ref().expect("checked above"),
            value(args, "--path").map(expand_home),
        )
        .await;
    }
    let ssh_dir = user_home()?.join(".ssh");
    let private_key = value(args, "--key")
        .map(expand_home)
        .unwrap_or_else(|| ssh_dir.join("id_ed25519"));
    let public_key = PathBuf::from(format!("{}.pub", private_key.display()));
    let certificate = value(args, "--certificate")
        .map(expand_home)
        .unwrap_or_else(|| myceliumd::home_dir().join("ssh/user-cert.pub"));

    if !private_key.is_file() || !public_key.is_file() {
        if private_key.exists() || public_key.exists() {
            return Err(format!(
                "SSH identity is incomplete: expected both {} and {}",
                private_key.display(),
                public_key.display()
            ));
        }
        if let Some(parent) = private_key.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("create {}: {error}", parent.display()))?;
        }
        let status = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&private_key)
            .status()
            .map_err(|error| format!("run ssh-keygen: {error}"))?;
        if !status.success() {
            return Err(format!("ssh-keygen exited with {status}"));
        }
    }

    let mut request = vec![
        "--gateway".to_owned(),
        gateway,
        "--public-key".to_owned(),
        path_string(&public_key)?,
        "--certificate".to_owned(),
        path_string(&certificate)?,
        "--write".to_owned(),
    ];
    let mut lines = if let Some(claim) = claim {
        let secret = embedded
            .as_ref()
            .map_or(claim, |(_, secret, _, _)| secret.as_str());
        request.extend(["--claim".to_owned(), secret.to_owned()]);
        crate::oidc_gateway::redeem(&request).await?
    } else {
        request.extend([
            "join".to_owned(),
            "--ttl".to_owned(),
            value(args, "--ttl").unwrap_or("8h").to_owned(),
        ]);
        copy_option(args, "--grant", &mut request);
        copy_option(args, "--provider", &mut request);
        copy_option(args, "--providers", &mut request);
        copy_option(args, "--token-env", &mut request);
        crate::oidc_gateway::join(&request).await?
    };
    lines.push(format!(
        "setup complete; SSH identity: {}, certificate: {}",
        private_key.display(),
        certificate.display()
    ));
    Ok(lines)
}

async fn setup_peer(
    claim: &(String, String, String, crate::invite::InvitationKind),
    home: Option<PathBuf>,
) -> Result<Vec<String>, String> {
    let home = home.unwrap_or_else(myceliumd::home_dir);
    let staging = home.join("enrollment-staging");
    fs::create_dir_all(&staging)
        .map_err(|error| format!("create {}: {error}", staging.display()))?;
    let key = staging.join("node-key.pem");
    let csr = staging.join("node.csr");
    if key.exists() || csr.exists() {
        return Err(format!(
            "peer enrollment staging already exists at {}; remove it after checking whether an earlier enrollment completed",
            staging.display()
        ));
    }
    let key_text = path_string(&key)?;
    let csr_text = path_string(&csr)?;
    command(
        "openssl",
        &["genpkey", "-algorithm", "ED25519", "-out", &key_text],
    )?;
    command(
        "openssl",
        &[
            "req",
            "-new",
            "-key",
            &key_text,
            "-out",
            &csr_text,
            "-subj",
            &format!("/CN={}", claim.2),
            "-addext",
            "extendedKeyUsage=serverAuth,clientAuth",
        ],
    )?;
    let ssh_dir = user_home()?.join(".ssh");
    let ssh_key = ssh_dir.join("id_ed25519");
    let ssh_public = PathBuf::from(format!("{}.pub", ssh_key.display()));
    if !ssh_key.is_file() || !ssh_public.is_file() {
        if ssh_key.exists() || ssh_public.exists() {
            return Err(
                "SSH identity is incomplete; expected id_ed25519 and id_ed25519.pub".into(),
            );
        }
        fs::create_dir_all(&ssh_dir)
            .map_err(|error| format!("create {}: {error}", ssh_dir.display()))?;
        let status = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&ssh_key)
            .status()
            .map_err(|error| format!("run ssh-keygen: {error}"))?;
        if !status.success() {
            return Err(format!("ssh-keygen exited with {status}"));
        }
    }
    let ssh_certificate = home.join("ssh/user-cert.pub");
    let request = vec![
        "--gateway".into(),
        claim.0.clone(),
        "--claim".into(),
        claim.1.clone(),
        "--peer-csr".into(),
        path_string(&csr)?,
        "--public-key".into(),
        path_string(&ssh_public)?,
        "--certificate".into(),
        path_string(&ssh_certificate)?,
        "--peer-key".into(),
        path_string(&key)?,
        "--home".into(),
        path_string(&home)?,
        "--write".into(),
    ];
    let result = crate::oidc_gateway::redeem(&request).await;
    if result.is_ok() {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

fn command(program: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| format!("run {program}: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{program} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter()
        .position(|arg| arg == flag)
        .and_then(|index| args.get(index + 1))
        .map(String::as_str)
}

fn copy_option(source: &[String], flag: &str, destination: &mut Vec<String>) {
    if let Some(option) = value(source, flag) {
        destination.extend([flag.to_owned(), option.to_owned()]);
    }
}

fn expand_home(value: &str) -> PathBuf {
    value.strip_prefix("~/").map_or_else(
        || PathBuf::from(value),
        |suffix| user_home().unwrap_or_default().join(suffix),
    )
}
fn user_home() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".to_owned())
}

fn path_string(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("path is not UTF-8: {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_join_arguments_are_forwarded_without_a_shell() {
        let source = vec!["--provider".to_owned(), "company-sso".to_owned()];
        let mut destination = Vec::new();
        copy_option(&source, "--provider", &mut destination);
        assert_eq!(destination, source);
    }
}
