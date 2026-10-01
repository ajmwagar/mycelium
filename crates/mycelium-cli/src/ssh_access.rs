use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use mycelium_peer_protocol::AccessStatement;
use serde_json::Value;

pub fn run(args: &[String], state: &Value) -> Result<Vec<String>, String> {
    match args.first().map(String::as_str) {
        Some("ca-init") => ca_init(args),
        Some("issue") => issue(args, state),
        Some("krl") => krl(args, state),
        Some("host-bundle") => host_bundle(args),
        Some("host-apply") => host_apply(args),
        Some("client-config") => client_config(args),
        Some(action) => Err(format!("unknown access ssh action `{action}`")),
        None => Err(
            "access ssh needs ca-init, issue, krl, host-bundle, host-apply, or client-config"
                .into(),
        ),
    }
}

fn host_apply(args: &[String]) -> Result<Vec<String>, String> {
    require_write(args)?;
    let bundle = Path::new(required(args, "--bundle")?);
    validate_host_bundle(bundle)?;
    if !cfg!(any(target_os = "linux", target_os = "macos")) {
        return Err("SSH host bundle application currently supports Linux and macOS only".into());
    }
    let uid = Command::new("id")
        .arg("-u")
        .output()
        .map_err(|e| format!("determine effective user: {e}"))?;
    if !uid.status.success() || String::from_utf8_lossy(&uid.stdout).trim() != "0" {
        return Err("SSH host bundle application needs root; run this command through sudo".into());
    }

    let ssh = Path::new("/etc/ssh");
    let managed = ssh.join("mycelium");
    let drop_in = ssh.join("sshd_config.d/60-mycelium-access.conf");
    let backup = ssh.join(format!("mycelium.pre-{}", now()?));
    fs::create_dir_all(&backup)
        .map_err(|e| format!("create rollback directory {}: {e}", backup.display()))?;
    let prior = [
        (managed.join("user_ca.pub"), "user_ca.pub"),
        (managed.join("revoked.krl"), "revoked.krl"),
        (drop_in.clone(), "60-mycelium-access.conf"),
    ];
    for (source, name) in &prior {
        if source.is_file() {
            fs::copy(source, backup.join(name))
                .map_err(|e| format!("back up {}: {e}", source.display()))?;
        }
    }
    let prior_principals = managed.join("principals");
    if prior_principals.is_dir() {
        copy_directory_files(&prior_principals, &backup.join("principals"))?;
    }
    fs::create_dir_all(&managed).map_err(|e| format!("create {}: {e}", managed.display()))?;
    fs::create_dir_all(drop_in.parent().expect("drop-in has parent"))
        .map_err(|e| format!("create sshd drop-in directory: {e}"))?;
    let install = || -> Result<(), String> {
        install_mode(
            &bundle.join("user_ca.pub"),
            &managed.join("user_ca.pub"),
            0o644,
        )?;
        install_mode(
            &bundle.join("revoked.krl"),
            &managed.join("revoked.krl"),
            0o644,
        )?;
        install_mode(&bundle.join("60-mycelium-access.conf"), &drop_in, 0o644)?;
        let principals = managed.join("principals");
        if principals.exists() {
            fs::remove_dir_all(&principals)
                .map_err(|e| format!("replace {}: {e}", principals.display()))?;
        }
        fs::create_dir_all(&principals)
            .map_err(|e| format!("create {}: {e}", principals.display()))?;
        for entry in fs::read_dir(bundle.join("principals"))
            .map_err(|e| format!("read host principals: {e}"))?
        {
            let entry = entry.map_err(|e| format!("read host principal entry: {e}"))?;
            if entry.file_type().map_err(|e| e.to_string())?.is_file() {
                install_mode(&entry.path(), &principals.join(entry.file_name()), 0o644)?;
            }
        }
        command("sshd", &["-t"])?;
        reload_sshd()?;
        Ok(())
    };
    if let Err(error) = install() {
        for (destination, name) in &prior {
            let saved = backup.join(name);
            if saved.is_file() {
                let _ = install_mode(&saved, destination, 0o644);
            } else {
                let _ = fs::remove_file(destination);
            }
        }
        let principals = managed.join("principals");
        let _ = fs::remove_dir_all(&principals);
        if backup.join("principals").is_dir() {
            let _ = copy_directory_files(&backup.join("principals"), &principals);
        }
        let _ = command("sshd", &["-t"]);
        let _ = reload_sshd();
        return Err(format!(
            "SSH host bundle failed and prior files were restored from {}: {error}",
            backup.display()
        ));
    }
    Ok(vec![format!(
        "installed SSH trust bundle; rollback copy retained at {}",
        backup.display()
    )])
}

fn copy_directory_files(source: &Path, destination: &Path) -> Result<(), String> {
    fs::create_dir_all(destination)
        .map_err(|e| format!("create {}: {e}", destination.display()))?;
    for entry in fs::read_dir(source).map_err(|e| format!("read {}: {e}", source.display()))? {
        let entry = entry.map_err(|e| format!("read directory entry: {e}"))?;
        if entry.file_type().map_err(|e| e.to_string())?.is_file() {
            fs::copy(entry.path(), destination.join(entry.file_name()))
                .map_err(|e| format!("copy principal policy: {e}"))?;
        }
    }
    Ok(())
}

fn reload_sshd() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        if command("systemctl", &["reload", "sshd"]).is_err() {
            command("systemctl", &["reload", "ssh"])?;
        }
    }
    // launchd invokes sshd for each inbound macOS connection, so the next
    // connection picks up the validated configuration without a restart.
    Ok(())
}

fn validate_host_bundle(bundle: &Path) -> Result<(), String> {
    for name in [
        "user_ca.pub",
        "revoked.krl",
        "60-mycelium-access.conf",
        "manifest.json",
    ] {
        if !bundle.join(name).is_file() {
            return Err(format!(
                "SSH host bundle {} is missing {name}",
                bundle.display()
            ));
        }
    }
    if !bundle.join("principals").is_dir() {
        return Err(format!(
            "SSH host bundle {} is missing principals directory",
            bundle.display()
        ));
    }
    Ok(())
}

fn install_mode(source: &Path, destination: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let staged = destination.with_extension(format!("mycelium-install-{}", std::process::id()));
    fs::copy(source, &staged).map_err(|e| format!("stage {}: {e}", destination.display()))?;
    fs::set_permissions(&staged, fs::Permissions::from_mode(mode))
        .map_err(|e| format!("set permissions on {}: {e}", staged.display()))?;
    fs::rename(&staged, destination).map_err(|e| format!("install {}: {e}", destination.display()))
}

fn client_config(args: &[String]) -> Result<Vec<String>, String> {
    require_write(args)?;
    let alias = config_atom(args, "--host")?;
    let hostname = config_atom(args, "--hostname")?;
    let user = config_atom(args, "--user")?;
    let identity = config_value(args, "--identity")?;
    let certificate = config_value(args, "--certificate")?;
    let port = value(args, "--port")
        .map(|port| {
            port.parse::<u16>()
                .map_err(|_| format!("invalid SSH port `{port}`"))
        })
        .transpose()?;
    let destination = Path::new(required(args, "--path")?);
    if destination.exists() {
        return Err(format!(
            "refusing to replace existing SSH client config {}",
            destination.display()
        ));
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let mut config = format!(
        "# Managed by Mycelium. Include this file from ~/.ssh/config.\n\
         Host {alias}\n\
           HostName {hostname}\n\
           User {user}\n"
    );
    if let Some(port) = port {
        config.push_str(&format!("  Port {port}\n"));
    }
    config.push_str(&format!(
        "  IdentityFile {identity}\n\
           CertificateFile {certificate}\n\
           IdentitiesOnly yes\n"
    ));
    let staging = temporary_key_path(destination.to_string_lossy().as_ref());
    fs::write(&staging, config)
        .map_err(|e| format!("write staged SSH client config {}: {e}", staging.display()))?;
    fs::rename(&staging, destination)
        .map_err(|e| format!("install SSH client config {}: {e}", destination.display()))?;
    Ok(vec![format!(
        "wrote SSH client config {}; add `Include {}` to ~/.ssh/config",
        destination.display(),
        destination.display()
    )])
}

fn host_bundle(args: &[String]) -> Result<Vec<String>, String> {
    require_write(args)?;
    let ca_public = required(args, "--ca-public")?;
    let krl = required(args, "--krl")?;
    let destination = Path::new(required(args, "--path")?);
    if destination.exists() {
        return Err(format!(
            "refusing to replace existing SSH host bundle {}",
            destination.display()
        ));
    }
    let staging = temporary_key_path(destination.to_string_lossy().as_ref());
    if staging.exists() {
        fs::remove_dir_all(&staging)
            .map_err(|e| format!("remove stale staging directory {}: {e}", staging.display()))?;
    }
    fs::create_dir_all(&staging)
        .map_err(|e| format!("create staging directory {}: {e}", staging.display()))?;
    let result = (|| {
        let principals = staging.join("principals");
        fs::create_dir_all(&principals).map_err(|e| format!("create principals directory: {e}"))?;
        for assignment in repeated(args, "--allow") {
            let (user, role) = assignment
                .split_once('=')
                .ok_or_else(|| format!("invalid --allow `{assignment}`; expected USER=ROLE"))?;
            config_atom_value("Unix user", user)?;
            config_atom_value("role", role)?;
            let path = principals.join(user);
            let mut contents = fs::read_to_string(&path).unwrap_or_default();
            contents.push_str(&format!("mycelium-role-{role}\n"));
            fs::write(path, contents).map_err(|e| format!("write role principal: {e}"))?;
        }
        fs::copy(ca_public, staging.join("user_ca.pub"))
            .map_err(|e| format!("copy SSH CA public key: {e}"))?;
        fs::copy(krl, staging.join("revoked.krl"))
            .map_err(|e| format!("copy SSH revocation list: {e}"))?;
        fs::write(
            staging.join("60-mycelium-access.conf"),
            "# Managed by Mycelium; existing SSH authentication remains enabled.\n\
             TrustedUserCAKeys /etc/ssh/mycelium/user_ca.pub\n\
             RevokedKeys /etc/ssh/mycelium/revoked.krl\n\
             AuthorizedPrincipalsFile /etc/ssh/mycelium/principals/%u\n\
             PubkeyAuthentication yes\n",
        )
        .map_err(|e| format!("write sshd drop-in: {e}"))?;
        fs::write(
            staging.join("manifest.json"),
            "{\n  \"version\": 1,\n  \"install\": {\n    \"user_ca.pub\": \"/etc/ssh/mycelium/user_ca.pub\",\n    \"revoked.krl\": \"/etc/ssh/mycelium/revoked.krl\",\n    \"60-mycelium-access.conf\": \"/etc/ssh/sshd_config.d/60-mycelium-access.conf\"\n  },\n  \"validate\": [\"sshd\", \"-t\"],\n  \"reload_after_validation\": true\n}\n",
        )
        .map_err(|e| format!("write host bundle manifest: {e}"))?;
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
        }
        fs::rename(&staging, destination)
            .map_err(|e| format!("install host bundle {}: {e}", destination.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result?;
    Ok(vec![format!(
        "wrote SSH host bundle {}; validate with `sshd -t` before installation",
        destination.display()
    )])
}

fn ca_init(args: &[String]) -> Result<Vec<String>, String> {
    require_write(args)?;
    let path = required(args, "--path")?;
    if Path::new(path).exists() || PathBuf::from(format!("{path}.pub")).exists() {
        return Err(format!("refusing to replace existing SSH CA at {path}"));
    }
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    command(
        "ssh-keygen",
        &[
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "mycelium access authority",
            "-f",
            path,
        ],
    )?;
    Ok(vec![format!(
        "created SSH user CA {path} (public key: {path}.pub)"
    )])
}

fn issue(args: &[String], state: &Value) -> Result<Vec<String>, String> {
    issue_bound(args, state, None, None, None)
}

pub(crate) fn issue_for_invite(
    public_key_path: &Path,
    ca: &Path,
    output: &Path,
    invitation_id: &str,
    name: &str,
    serial: u64,
    unix_users: &[String],
    roles: &[String],
    ttl: u64,
) -> Result<(), String> {
    if unix_users.is_empty() || ttl == 0 {
        return Err("invitation has no Unix principals or credential lifetime".into());
    }
    let public_key = fs::read_to_string(public_key_path)
        .map_err(|error| format!("read SSH public key {}: {error}", public_key_path.display()))?;
    key_material(&public_key)?;
    let temp = temporary_key_path(&public_key_path.to_string_lossy());
    fs::copy(public_key_path, &temp)
        .map_err(|error| format!("prepare certificate input {}: {error}", temp.display()))?;
    // A role-bound certificate must not also carry its Unix account as a
    // principal: older hosts that trust the CA without AuthorizedPrincipalsFile
    // would otherwise accept it and bypass the host's role policy.
    let principals = if roles.is_empty() {
        unix_users.to_vec()
    } else {
        roles
            .iter()
            .map(|role| format!("mycelium-role-{role}"))
            .collect()
    };
    let principals = principals.join(",");
    let validity = format!("+0s:+{ttl}s");
    let serial = serial.to_string();
    let identity = format!("mycelium:invite:{invitation_id}:{name}");
    let result = command(
        "ssh-keygen",
        &[
            "-q",
            "-s",
            path_str(ca)?,
            "-I",
            &identity,
            "-n",
            &principals,
            "-V",
            &validity,
            "-z",
            &serial,
            path_str(&temp)?,
        ],
    );
    let generated = PathBuf::from(format!(
        "{}-cert.pub",
        temp.to_string_lossy()
            .strip_suffix(".pub")
            .unwrap_or(&temp.to_string_lossy())
    ));
    if let Err(error) = result {
        let _ = fs::remove_file(&temp);
        let _ = fs::remove_file(&generated);
        return Err(error);
    }
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    fs::rename(&generated, output)
        .map_err(|error| format!("install certificate {}: {error}", output.display()))?;
    let _ = fs::remove_file(&temp);
    Ok(())
}

fn path_str(path: &Path) -> Result<&str, String> {
    path.to_str()
        .ok_or_else(|| format!("path is not UTF-8: {}", path.display()))
}

pub(crate) fn issue_for_oidc(
    args: &[String],
    state: &Value,
    principal: &str,
    audience: &str,
    _identity_expires_at: u64,
) -> Result<Vec<String>, String> {
    let grant_id = if let Some(grant_id) = value(args, "--grant") {
        grant_id.to_owned()
    } else {
        let matches = state["grants"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|entry| {
                entry["active"].as_bool() == Some(true)
                    && entry["record"]["statement"]["principal"].as_str() == Some(principal)
                    && entry["record"]["statement"]["oidc_audiences"]
                        .as_array()
                        .is_some_and(|audiences| audiences.iter().any(|value| value == audience))
            })
            .filter_map(|entry| entry["record"]["statement"]["grant_id"].as_str())
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [grant_id] => (*grant_id).to_owned(),
            [] => return Err(format!("no active grant matches OIDC principal `{principal}`")),
            _ => {
                return Err(format!(
                    "multiple active grants match OIDC principal `{principal}`; select one with --grant"
                ))
            }
        }
    };
    let mut bound_args = args.to_vec();
    if value(args, "--grant").is_none() {
        bound_args.push("--grant".into());
        bound_args.push(grant_id);
    }
    issue_bound(&bound_args, state, Some(principal), Some(audience), None)
}

fn issue_bound(
    args: &[String],
    state: &Value,
    expected_principal: Option<&str>,
    expected_audience: Option<&str>,
    identity_expires_at: Option<u64>,
) -> Result<Vec<String>, String> {
    require_write(args)?;
    let grant_id = required(args, "--grant")?;
    let public_key_path = required(args, "--public-key")?;
    let ca = required(args, "--ca")?;
    let output = required(args, "--path")?;
    let requested_ttl = parse_duration(value(args, "--ttl").unwrap_or("8h"))?;
    let now = now()?;

    let grant = state["grants"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|entry| {
            entry["active"].as_bool() == Some(true)
                && entry["record"]["statement"]["grant_id"].as_str() == Some(grant_id)
        })
        .ok_or_else(|| format!("grant `{grant_id}` is missing, inactive, or revoked"))?;
    let statement: AccessStatement = serde_json::from_value(grant["record"]["statement"].clone())
        .map_err(|e| format!("decode grant `{grant_id}`: {e}"))?;
    let AccessStatement::Grant {
        principal,
        serial,
        unix_users,
        ssh_public_keys,
        oidc_audiences,
        oidc_ssh_key_exchange,
        not_before,
        not_after,
        ..
    } = statement
    else {
        return Err(format!("record `{grant_id}` is not a grant"));
    };
    if expected_principal.is_some_and(|expected| expected != principal) {
        return Err(format!(
            "grant `{grant_id}` belongs to `{principal}`, not authenticated principal `{}`",
            expected_principal.unwrap_or_default()
        ));
    }
    if expected_audience
        .is_some_and(|expected| !oidc_audiences.iter().any(|value| value == expected))
    {
        return Err(format!(
            "grant `{grant_id}` does not authorize OIDC audience `{}`",
            expected_audience.unwrap_or_default()
        ));
    }
    if unix_users.is_empty() {
        return Err(format!("grant `{grant_id}` has no unix_users principals"));
    }
    if now < not_before || now >= not_after {
        return Err(format!("grant `{grant_id}` is outside its validity window"));
    }
    let public_key = fs::read_to_string(public_key_path)
        .map_err(|e| format!("read SSH public key {public_key_path}: {e}"))?;
    let key_fingerprint = key_material(&public_key)?;
    let key_is_enrolled = ssh_public_keys
        .iter()
        .filter_map(|key| key_material(key).ok())
        .any(|allowed| allowed == key_fingerprint);
    if !key_is_enrolled && !(expected_principal.is_some() && oidc_ssh_key_exchange) {
        return Err(format!(
            "public key is not authorized by grant `{grant_id}`"
        ));
    }
    let expires_at =
        identity_expires_at.map_or(not_after, |token_expiry| not_after.min(token_expiry));
    let ttl = requested_ttl.min(expires_at.saturating_sub(now));
    if ttl == 0 {
        return Err(format!(
            "grant `{grant_id}` or authenticated identity has expired"
        ));
    }

    let temp = temporary_key_path(public_key_path);
    fs::copy(public_key_path, &temp)
        .map_err(|e| format!("prepare certificate input {}: {e}", temp.display()))?;
    let principals = unix_users.join(",");
    let validity = format!("+0s:+{ttl}s");
    let serial = serial.to_string();
    let identity = format!("mycelium:{grant_id}:{principal}");
    let result = command(
        "ssh-keygen",
        &[
            "-q",
            "-s",
            ca,
            "-I",
            &identity,
            "-n",
            &principals,
            "-V",
            &validity,
            "-z",
            &serial,
            temp.to_str().ok_or("temporary path is not UTF-8")?,
        ],
    );
    let generated = PathBuf::from(format!(
        "{}-cert.pub",
        temp.to_string_lossy()
            .strip_suffix(".pub")
            .unwrap_or(&temp.to_string_lossy())
    ));
    if let Err(error) = result {
        let _ = fs::remove_file(&temp);
        let _ = fs::remove_file(&generated);
        return Err(error);
    }
    if let Some(parent) = Path::new(output).parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    fs::rename(&generated, output).map_err(|e| format!("install certificate {output}: {e}"))?;
    let _ = fs::remove_file(&temp);
    Ok(vec![format!(
        "issued {output} for grant={grant_id} serial={serial} principals={principals} ttl={ttl}s"
    )])
}

fn krl(args: &[String], state: &Value) -> Result<Vec<String>, String> {
    require_write(args)?;
    let ca_public = required(args, "--ca-public")?;
    let output = required(args, "--path")?;
    let mut serials: BTreeSet<u64> = state["revocations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|record| record["statement"]["serial"].as_u64())
        .collect();
    // Principal- and grant-wide revocations need to become concrete OpenSSH
    // serial revocations too. The converged view already performed the
    // selector matching, so derive the affected serials instead of requiring
    // the authority to duplicate them in the revoke statement.
    serials.extend(
        state["grants"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|grant| {
                grant["revoked_by"]
                    .as_array()
                    .is_some_and(|records| !records.is_empty())
            })
            .filter_map(|grant| grant["record"]["statement"]["serial"].as_u64()),
    );
    let spec = temporary_key_path(output);
    let contents = serials
        .iter()
        .map(|serial| format!("serial: {serial}\n"))
        .collect::<String>();
    fs::write(&spec, contents).map_err(|e| format!("write {}: {e}", spec.display()))?;
    if let Some(parent) = Path::new(output).parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let result = command(
        "ssh-keygen",
        &[
            "-q",
            "-k",
            "-f",
            output,
            "-s",
            ca_public,
            spec.to_str().ok_or("temporary path is not UTF-8")?,
        ],
    );
    let _ = fs::remove_file(&spec);
    result?;
    Ok(vec![format!(
        "wrote {output} with {} revoked serial(s)",
        serials.len()
    )])
}

fn value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter()
        .position(|arg| arg == flag)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn repeated<'a>(args: &'a [String], flag: &str) -> Vec<&'a str> {
    args.iter()
        .enumerate()
        .filter(|(_, argument)| argument.as_str() == flag)
        .filter_map(|(index, _)| args.get(index + 1).map(String::as_str))
        .collect()
}

fn config_atom_value(name: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
    {
        return Err(format!("{name} contains unsafe characters"));
    }
    Ok(())
}

fn required<'a>(args: &'a [String], flag: &str) -> Result<&'a str, String> {
    value(args, flag).ok_or_else(|| format!("access ssh needs {flag}"))
}

fn config_atom<'a>(args: &'a [String], flag: &str) -> Result<&'a str, String> {
    let value = required(args, flag)?;
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !b"#*?![]".contains(&byte))
    {
        return Err(format!("SSH config {flag} contains unsafe characters"));
    }
    Ok(value)
}

fn config_value<'a>(args: &'a [String], flag: &str) -> Result<&'a str, String> {
    let value = required(args, flag)?;
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'#')
    {
        return Err(format!("SSH config {flag} contains unsafe characters"));
    }
    Ok(value)
}

fn require_write(args: &[String]) -> Result<(), String> {
    args.iter()
        .any(|arg| arg == "--write")
        .then_some(())
        .ok_or_else(|| "SSH access changes require --write".into())
}

fn key_material(value: &str) -> Result<String, String> {
    let mut fields = value.split_whitespace();
    let kind = fields.next().ok_or("SSH public key has no algorithm")?;
    let body = fields.next().ok_or("SSH public key has no key material")?;
    Ok(format!("{kind} {body}"))
}

fn parse_duration(value: &str) -> Result<u64, String> {
    let split = value
        .find(|c: char| !c.is_ascii_digit())
        .ok_or_else(|| format!("duration `{value}` needs a suffix: s, m, h, or d"))?;
    let amount = value[..split]
        .parse::<u64>()
        .map_err(|_| format!("invalid duration `{value}`"))?;
    let factor = match &value[split..] {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => return Err(format!("invalid duration suffix in `{value}`")),
    };
    amount
        .checked_mul(factor)
        .ok_or_else(|| format!("duration `{value}` is too large"))
}

fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| format!("system clock: {e}"))
}

fn temporary_key_path(seed: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    std::env::temp_dir().join(format!(
        "mycelium-ssh-{}-{nonce}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed),
        Path::new(seed)
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("key")
    ))
}

fn command(program: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("run {program}: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    Err(format!("{program} failed ({}): {stderr}", output.status))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_are_explicit_and_bounded() {
        assert_eq!(parse_duration("8h").unwrap(), 28_800);
        assert_eq!(parse_duration("15m").unwrap(), 900);
        assert!(parse_duration("8").is_err());
        assert!(parse_duration("1fortnight").is_err());
    }

    #[test]
    fn comments_do_not_change_key_identity() {
        assert_eq!(
            key_material("ssh-ed25519 AAAA alice").unwrap(),
            "ssh-ed25519 AAAA"
        );
    }

    #[test]
    fn host_bundle_validation_requires_the_complete_contract() {
        let root = std::env::temp_dir().join(format!(
            "mycelium-host-bundle-test-{}-{}",
            std::process::id(),
            now().unwrap()
        ));
        fs::create_dir_all(&root).unwrap();
        assert!(validate_host_bundle(&root)
            .unwrap_err()
            .contains("user_ca.pub"));
        for name in [
            "user_ca.pub",
            "revoked.krl",
            "60-mycelium-access.conf",
            "manifest.json",
        ] {
            fs::write(root.join(name), "test").unwrap();
        }
        fs::create_dir(root.join("principals")).unwrap();
        validate_host_bundle(&root).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn host_bundle_maps_roles_and_defaults_to_no_certificate_principals() {
        let root = std::env::temp_dir().join(format!(
            "mycelium-host-role-test-{}-{}",
            std::process::id(),
            now().unwrap()
        ));
        fs::create_dir_all(&root).unwrap();
        let ca = root.join("ca.pub");
        let krl = root.join("revoked.krl");
        fs::write(&ca, "ssh-ed25519 AAAA test").unwrap();
        fs::write(&krl, "krl").unwrap();
        let denied = root.join("denied");
        host_bundle(&[
            "--ca-public".into(),
            ca.to_string_lossy().into_owned(),
            "--krl".into(),
            krl.to_string_lossy().into_owned(),
            "--path".into(),
            denied.to_string_lossy().into_owned(),
            "--write".into(),
        ])
        .unwrap();
        assert_eq!(fs::read_dir(denied.join("principals")).unwrap().count(), 0);

        let allowed = root.join("allowed");
        host_bundle(&[
            "--ca-public".into(),
            ca.to_string_lossy().into_owned(),
            "--krl".into(),
            krl.to_string_lossy().into_owned(),
            "--allow".into(),
            "mames=home-operator".into(),
            "--path".into(),
            allowed.to_string_lossy().into_owned(),
            "--write".into(),
        ])
        .unwrap();
        assert_eq!(
            fs::read_to_string(allowed.join("principals/mames")).unwrap(),
            "mycelium-role-home-operator\n"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn client_config_is_scoped_to_one_alias() {
        let root = std::env::temp_dir().join(format!(
            "mycelium-ssh-config-test-{}-{}",
            std::process::id(),
            now().unwrap()
        ));
        let path = root.join("buddy.conf");
        let args = vec![
            "client-config",
            "--host",
            "mycelium-lab",
            "--hostname",
            "lab.example.test",
            "--user",
            "buddy",
            "--identity",
            "~/.ssh/id_ed25519",
            "--certificate",
            "~/.ssh/id_ed25519-cert.pub",
            "--port",
            "2222",
            "--path",
            path.to_str().unwrap(),
            "--write",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        client_config(&args).unwrap();
        let config = fs::read_to_string(&path).unwrap();
        assert!(config.contains("Host mycelium-lab\n"));
        assert!(config.contains("HostName lab.example.test\n"));
        assert!(config.contains("User buddy\n"));
        assert!(config.contains("Port 2222\n"));
        assert!(config.contains("CertificateFile ~/.ssh/id_ed25519-cert.pub\n"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn invitation_issues_a_bounded_openssh_certificate() {
        if Command::new("ssh-keygen").arg("-h").output().is_err() {
            return;
        }
        let root = std::env::temp_dir().join(format!(
            "mycelium-invite-ssh-test-{}-{}",
            std::process::id(),
            now().unwrap()
        ));
        fs::create_dir_all(&root).unwrap();
        let ca = root.join("ca");
        let user = root.join("user");
        let certificate = root.join("user-cert.pub");
        for key in [&ca, &user] {
            command(
                "ssh-keygen",
                &[
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-f",
                    path_str(key).unwrap(),
                ],
            )
            .unwrap();
        }
        issue_for_invite(
            &user.with_extension("pub"),
            &ca,
            &certificate,
            "invite-1",
            "buddy",
            42,
            &["operator".into()],
            &["home-operator".into()],
            3600,
        )
        .unwrap();
        let inspected = Command::new("ssh-keygen")
            .args(["-L", "-f"])
            .arg(&certificate)
            .output()
            .unwrap();
        let output = String::from_utf8_lossy(&inspected.stdout);
        assert!(inspected.status.success());
        assert!(output.contains("mycelium-role-home-operator"));
        assert!(output.contains("mycelium:invite:invite-1:buddy"));
        assert!(output.contains("operator"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn openssh_issues_and_revokes_a_granted_key() {
        if Command::new("ssh-keygen").arg("-h").output().is_err() {
            return;
        }
        let root = std::env::temp_dir().join(format!(
            "mycelium-ssh-test-{}-{}",
            std::process::id(),
            now().unwrap()
        ));
        fs::create_dir_all(&root).unwrap();
        let ca = root.join("ca");
        let user = root.join("user");
        let cert = root.join("user-cert.pub");
        command(
            "ssh-keygen",
            &["-q", "-t", "ed25519", "-N", "", "-f", ca.to_str().unwrap()],
        )
        .unwrap();
        command(
            "ssh-keygen",
            &[
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-f",
                user.to_str().unwrap(),
            ],
        )
        .unwrap();
        let public_key = fs::read_to_string(user.with_extension("pub")).unwrap();
        let timestamp = now().unwrap();
        let mut state = serde_json::json!({
            "grants": [{
                "active": true,
                "revoked_by": [],
                "record": { "statement": {
                    "kind": "grant", "grant_id": "grant-1", "principal": "oidc:https://issuer.example#user-42",
                    "serial": 42, "roles": [], "scopes": ["site:home"], "unix_users": ["avery"],
                    "ssh_public_keys": [public_key], "oidc_audiences": ["mycelium"],
                    "oidc_ssh_key_exchange": false,
                    "not_before": timestamp - 1, "not_after": timestamp + 3600
                }}
            }],
            "revocations": []
        });
        let issue_args = vec![
            "issue",
            "--grant",
            "grant-1",
            "--public-key",
            user.with_extension("pub").to_str().unwrap(),
            "--ca",
            ca.to_str().unwrap(),
            "--path",
            cert.to_str().unwrap(),
            "--ttl",
            "10m",
            "--write",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        issue(&issue_args, &state).unwrap();
        assert!(cert.exists());
        let oidc_cert = root.join("oidc-user-cert.pub");
        let oidc_args = vec![
            "ssh-issue",
            "--public-key",
            user.with_extension("pub").to_str().unwrap(),
            "--ca",
            ca.to_str().unwrap(),
            "--path",
            oidc_cert.to_str().unwrap(),
            "--ttl",
            "10m",
            "--write",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let issued = issue_for_oidc(
            &oidc_args,
            &state,
            "oidc:https://issuer.example#user-42",
            "mycelium",
            timestamp + 300,
        )
        .unwrap();
        assert!(oidc_cert.exists());
        assert!(
            issued[0].contains("ttl=600s"),
            "the exchanged SSH credential must not inherit the JWT's remaining 300 seconds"
        );

        let mut wrong_principal_args = oidc_args.clone();
        wrong_principal_args.extend(["--grant".into(), "grant-1".into()]);
        assert!(issue_for_oidc(
            &wrong_principal_args,
            &state,
            "oidc:https://issuer.example#someone-else",
            "mycelium",
            timestamp + 300,
        )
        .unwrap_err()
        .contains("not authenticated principal"));
        assert!(issue_for_oidc(
            &wrong_principal_args,
            &state,
            "oidc:https://issuer.example#user-42",
            "some-other-client",
            timestamp + 300,
        )
        .unwrap_err()
        .contains("does not authorize OIDC audience"));
        state["grants"][0]["active"] = serde_json::json!(false);
        state["grants"][0]["revoked_by"] = serde_json::json!(["revoke-1"]);
        state["revocations"] = serde_json::json!([{
            "statement": { "kind": "revoke", "revocation_id": "revoke-1", "grant_id": "grant-1", "revoked_at": timestamp, "reason": "test" }
        }]);
        let krl_path = root.join("revoked.krl");
        let krl_args = vec![
            "krl",
            "--ca-public",
            ca.with_extension("pub").to_str().unwrap(),
            "--path",
            krl_path.to_str().unwrap(),
            "--write",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        krl(&krl_args, &state).unwrap();
        let query = Command::new("ssh-keygen")
            .args([
                "-Q",
                "-f",
                krl_path.to_str().unwrap(),
                cert.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            !query.status.success(),
            "certificate serial 42 should be revoked"
        );
        fs::remove_dir_all(root).unwrap();
    }
}
