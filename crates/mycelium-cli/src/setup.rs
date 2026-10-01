use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub async fn run(args: &[String]) -> Result<Vec<String>, String> {
    let gateway = value(args, "--gateway")
        .map(str::to_owned)
        .or_else(|| std::env::var("MYCELIUM_GATEWAY").ok())
        .ok_or_else(|| {
            "setup needs --gateway HTTPS-URL (or the MYCELIUM_GATEWAY environment variable)"
                .to_owned()
        })?;
    let ttl = value(args, "--ttl").unwrap_or("8h");
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

    let mut join = vec![
        "join".to_owned(),
        "--gateway".to_owned(),
        gateway,
        "--public-key".to_owned(),
        path_string(&public_key)?,
        "--certificate".to_owned(),
        path_string(&certificate)?,
        "--ttl".to_owned(),
        ttl.to_owned(),
        "--write".to_owned(),
    ];
    copy_option(args, "--grant", &mut join);
    copy_option(args, "--provider", &mut join);
    copy_option(args, "--providers", &mut join);
    copy_option(args, "--token-env", &mut join);

    let mut lines = crate::oidc_gateway::join(&join).await?;
    lines.push(format!(
        "setup complete; SSH identity: {}, certificate: {}",
        private_key.display(),
        certificate.display()
    ));
    Ok(lines)
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
