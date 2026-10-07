//! Restricted to the existing disposable Unibus qualification QEMU image.
use std::{
    fs,
    net::TcpStream,
    process::Command,
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const REPO: &str = "/opt/fungos-apt/repository";
fn command(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .env("DEBIAN_FRONTEND", "noninteractive")
        .env("NEEDRESTART_MODE", "l")
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "{program}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?)
}
fn apt(args: &[&str]) -> Result<String> {
    let mut all = vec![
        "-o",
        "Dir::Etc::sourcelist=/etc/apt/fungos-test.sources",
        "-o",
        "Dir::Etc::sourceparts=-",
        "-o",
        "Dir::State::lists=/var/lib/fungos-apt-lists",
        "-o",
        "APT::Get::List-Cleanup=0",
        "-o",
        "Dpkg::Options::=--force-confold",
    ];
    all.extend_from_slice(args);
    command("apt-get", &all)
}
fn ready() -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if TcpStream::connect("127.0.0.1:18790").is_ok()
            && command("systemctl", &["is-active", "unibus-router"]).is_ok()
        {
            return Ok(());
        }
        if Instant::now() > deadline {
            return Err("Unibus readiness failed".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
fn main() -> Result<()> {
    if command("id", &["-u"])?.trim() != "0"
        || fs::read_to_string("/sys/class/dmi/id/product_name")?.trim()
            != "unibus-package-validation"
        || fs::read_to_string("/run/unibus-package-validation")?.trim()
            != "unibus-package-validation"
    {
        return Err("refusing package changes outside marked disposable guest".into());
    }
    fs::create_dir_all("/var/lib/fungos-apt-lists/partial")?;
    if std::path::Path::new("/var/lib/fungos-apt-proof/conffile").exists() {
        ready()?;
        if fs::read("/etc/unibus/hub.json")? != fs::read("/var/lib/fungos-apt-proof/conffile")?
            || command("dpkg-query", &["-W", "-f=${Version}", "unibus-core"])? != "0.1.0"
        {
            return Err("reboot persistence verification failed".into());
        }
        println!("FUNGOS_APT_REBOOT_VERIFIED");
        command("systemctl", &["--no-block", "poweroff"])?;
        return Ok(());
    }
    fs::write("/etc/apt/fungos-test.sources", "Types: deb\nURIs: file:/opt/fungos-apt/repository\nSuites: testing\nComponents: main\nArchitectures: amd64\nSigned-By: /opt/fungos-apt/test-signing-key.gpg\n")?;
    apt(&["update"])?;
    println!("FUNGOS_APT_SIGNATURE_OK");
    let index = format!("{REPO}/dists/testing/main/binary-amd64/Packages");
    let original = fs::read(&index)?;
    let mut corrupt = original.clone();
    corrupt.extend_from_slice(b"\nCORRUPTED\n");
    fs::write(&index, corrupt)?;
    // Force reacquisition; do not accidentally accept a cached good index.
    for entry in fs::read_dir("/var/lib/fungos-apt-lists")? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            fs::remove_file(entry.path())?;
        }
    }
    let rejected = apt(&["update"]).is_err();
    fs::write(&index, original)?;
    if !rejected {
        return Err("APT accepted tampered Packages".into());
    }
    println!("FUNGOS_APT_TAMPER_REJECTED");
    apt(&["update"])?;
    command("systemctl", &["stop", "unibus-router"])?;
    command("dpkg", &["--purge", "unibus-core"])?;
    apt(&["install", "-y", "unibus-core=0.1.0"])?;
    command("systemctl", &["daemon-reload"])?;
    command("systemctl", &["reset-failed", "unibus-router"])?;
    command("systemctl", &["enable", "--now", "unibus-router"])?;
    ready()?;
    let mut config = fs::read("/etc/unibus/hub.json")?;
    config.push(b'\n');
    fs::write("/etc/unibus/hub.json", &config)?;
    for version in ["0.1.1", "0.1.0"] {
        let pid = command(
            "systemctl",
            &["show", "unibus-router", "-p", "MainPID", "--value"],
        )?;
        apt(&[
            "install",
            "-y",
            "--allow-downgrades",
            &format!("unibus-core={version}"),
        ])?;
        if command(
            "systemctl",
            &["show", "unibus-router", "-p", "MainPID", "--value"],
        )? != pid
        {
            return Err("unexpected package-driven service restart".into());
        }
        if fs::read("/etc/unibus/hub.json")? != config {
            return Err("operator conffile changed".into());
        }
        if command("dpkg-query", &["-W", "-f=${Version}", "unibus-core"])? != version {
            return Err("wrong installed version".into());
        }
        command("systemctl", &["restart", "unibus-router"])?;
        ready()?;
        println!("FUNGOS_APT_VERSION_VERIFIED {version}");
    }
    println!("FUNGOS_APT_SMOKE_OK");
    fs::create_dir_all("/var/lib/fungos-apt-proof")?;
    fs::write("/var/lib/fungos-apt-proof/conffile", config)?;
    command("sync", &[])?;
    command("systemctl", &["--no-block", "reboot"])?;
    Ok(())
}
