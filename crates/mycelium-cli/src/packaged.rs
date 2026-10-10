//! Debian owns the executable/unit; enrollment owns only private peer state.
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

pub const BINARY: &str = "/usr/bin/mycelium";
pub const UNIT: &str = "/usr/lib/systemd/system/mycelium.service";
pub const HOME: &str = "/var/lib/mycelium";
pub const SERVICE: &str = include_str!("../../../packaging/linux/assets/mycelium.service");

fn query(args: &[&str]) -> Result<String, String> {
    let output = Command::new("dpkg-query")
        .args(args)
        .env("LC_ALL", "C")
        .output()
        .map_err(|error| format!("verify Debian Mycelium installation: {error}"))?;
    if !output.status.success() {
        return Err("cannot verify installed Mycelium Debian package".into());
    }
    String::from_utf8(output.stdout).map_err(|error| error.to_string())
}

/// Recognize only the canonical package path. A missing ownership tool there
/// is an error, never permission to copy it into a mutable native installation.
pub fn current() -> Result<bool, String> {
    if !cfg!(target_os = "linux") {
        return Ok(false);
    }
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let executable = fs::canonicalize(executable).map_err(|error| error.to_string())?;
    if executable != Path::new(BINARY) {
        return Ok(false);
    }
    for path in [BINARY, UNIT] {
        let owner = myceliumd::software_apt::package_owner(Path::new(path))
            .map_err(|error| error.to_string())?;
        if !matches!(
            owner.as_deref(),
            Some("mycelium" | "mycelium:amd64" | "mycelium:arm64")
        ) {
            return Err(format!(
                "{path} is not exclusively owned by the Mycelium Debian package"
            ));
        }
    }
    if query(&["-W", "-f=${db:Status-Status}", "mycelium"])?.trim() != "installed" {
        return Err("Mycelium Debian package is not installed".into());
    }
    if fs::read_to_string(UNIT).map_err(|error| error.to_string())? != SERVICE {
        return Err("packaged Mycelium unit differs from its owner contract".into());
    }
    for shadow in [
        "/etc/systemd/system/mycelium.service",
        "/run/systemd/system/mycelium.service",
    ] {
        if fs::symlink_metadata(shadow).is_ok() {
            return Err(format!(
                "{shadow} shadows the package unit; reconcile ownership before enrollment"
            ));
        }
    }
    Ok(true)
}

pub fn root() -> Result<(), String> {
    let output = Command::new("id")
        .arg("-u")
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() || String::from_utf8_lossy(&output.stdout).trim() != "0" {
        return Err("packaged peer enrollment requires root".into());
    }
    Ok(())
}

pub fn configure_cli() -> Result<(), String> {
    if current()? {
        std::env::set_var("MYCELIUM_NO_AUTOSTART", "1");
        if std::env::var_os("MYCELIUM_HOME").is_some() {
            return Ok(());
        }
        let output = Command::new("id")
            .arg("-u")
            .output()
            .map_err(|error| error.to_string())?;
        if !output.status.success() {
            return Err("cannot determine packaged CLI account".into());
        }
        if String::from_utf8_lossy(&output.stdout).trim() == "0" {
            std::env::set_var("MYCELIUM_HOME", HOME);
        }
    }
    Ok(())
}

pub fn validate(home: &Path, system_service: bool) -> Result<(), String> {
    if home != Path::new(HOME) || !system_service {
        return Err(
            "packaged peers require --path /var/lib/mycelium --system-service (or --packaged)"
                .into(),
        );
    }
    root()?;
    if fs::symlink_metadata(home.join("bin/mycelium")).is_ok() {
        return Err("native Mycelium installation already exists in packaged peer state; migrate explicitly".into());
    }
    if let Ok(metadata) = fs::symlink_metadata(home) {
        if !metadata.file_type().is_dir() {
            return Err("packaged peer home must be a real directory".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != 0 {
                return Err("packaged peer home must be root-owned".into());
            }
        }
    }
    bindings(home)?;
    Ok(())
}

fn bindings(
    home: &Path,
) -> Result<std::collections::BTreeMap<String, myceliumd::software_service::ServiceBinding>, String>
{
    let path = home.join("software-services.json");
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Default::default()),
        Err(error) => return Err(error.to_string()),
    };
    if !metadata.file_type().is_file() {
        return Err("software-services.json must be a regular nonsymlink file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != 0 || metadata.permissions().mode() & 0o077 != 0 {
            return Err("packaged software-services.json must be root-owned and private".into());
        }
    }
    let entries: std::collections::BTreeMap<String, myceliumd::software_service::ServiceBinding> =
        serde_json::from_slice(&fs::read(path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    for entry in entries.values() {
        entry.validate().map_err(|error| error.to_string())?;
    }
    Ok(entries)
}

fn default_binding() -> myceliumd::software_service::ServiceBinding {
    myceliumd::software_service::ServiceBinding {
        unit: Path::new(UNIT)
            .file_name()
            .expect("unit basename")
            .to_string_lossy()
            .into_owned(),
        user_manager: false,
        readiness: myceliumd::software_service::Readiness::UnixJson {
            path: Path::new(HOME).join("myceliumd.sock"),
            request: serde_json::json!({ "method": "hello" }),
            expect: std::collections::BTreeMap::from([("/ok".into(), serde_json::json!(true))]),
        },
        timeout_secs: 30,
    }
}

/// Explicit enrollment owns bootstrap health policy, never the APT executable.
/// Existing operator bindings, including Mycelium's, are preserved unchanged.
pub fn ensure_binding(home: &Path) -> Result<(), String> {
    use std::io::Write;
    let mut entries = bindings(home)?;
    if entries.contains_key("mycelium") {
        return Ok(());
    }
    entries.insert("mycelium".into(), default_binding());
    let temporary = home.join(format!(
        ".software-services.package-{}.tmp",
        std::process::id()
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|error| error.to_string())?;
    let bytes = serde_json::to_vec_pretty(&entries).map_err(|error| error.to_string())?;
    file.write_all(&bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    fs::rename(&temporary, home.join("software-services.json")).map_err(|error| error.to_string())
}

pub fn private_home(home: &Path) -> Result<(), String> {
    fs::create_dir_all(home).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(home, fs::Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

pub fn validate_new_peer(home: &Path, system_service: bool) -> Result<(), String> {
    validate(home, system_service)?;
    for path in ["pki", "node.env", "iroh-sync.json", "enrollment-staging"] {
        if fs::symlink_metadata(home.join(path)).is_ok() {
            return Err(format!("packaged peer state already contains {path}; repair an enrolled peer or inspect a failed enrollment, do not replace its identity"));
        }
    }
    Ok(())
}

pub fn service_path() -> PathBuf {
    PathBuf::from(UNIT)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unit_has_one_package_owned_binary_and_private_state() {
        assert!(SERVICE.contains("ExecStart=/usr/bin/mycelium _serve"));
        assert!(SERVICE.contains("User=root"));
        assert!(SERVICE.contains("StateDirectoryMode=0700"));
        assert!(SERVICE.contains("ConditionPathExists=/var/lib/mycelium/node.env"));
        assert!(!SERVICE.contains("/bin/mycelium _serve\nEnvironmentFile=%h"));
    }
    #[test]
    fn packaged_home_is_not_configurable_to_user_state() {
        assert!(validate(Path::new("/home/someone/.mycelium"), true).is_err());
        assert!(validate(Path::new(HOME), false).is_err());
    }
    #[test]
    fn default_apt_binding_reuses_existing_health_contract() {
        let binding = default_binding();
        binding.validate().unwrap();
        assert_eq!(
            binding.unit,
            Path::new(UNIT).file_name().unwrap().to_string_lossy()
        );
        assert!(!binding.user_manager);
        let value = serde_json::to_value(binding).unwrap();
        assert_eq!(
            value["readiness"]["path"],
            Path::new(HOME)
                .join("myceliumd.sock")
                .to_string_lossy()
                .to_string()
        );
    }
}
