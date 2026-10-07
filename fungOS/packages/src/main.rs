//! Publish immutable signed APT repository generations using Debian's tools.
//! Package construction stays with the component's owning project.
use std::{env, fs, path::Path, process::Command};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn run(root: &Path, program: &str, args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new(program)
        .args(args)
        .current_dir(root)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "{program} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(output.stdout)
}

fn fingerprint(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 6 || args[1] != "--write" {
        return Err("usage: fungos-apt-repository --write NEW_OUTPUT SIGNER_FINGERPRINT testing|stable PACKAGE.deb... (GNUPGHOME selects signer)".into());
    }
    let root = Path::new(&args[2]);
    if !fingerprint(&args[3]) || !matches!(args[4].as_str(), "testing" | "stable") {
        return Err("expected full signing fingerprint and testing|stable suite".into());
    }
    // Refuse existing generations. Errors leave an unpublished directory for inspection.
    fs::create_dir(root)?;
    let root = root.canonicalize()?;
    fs::create_dir(root.join("pool"))?;
    let mut architectures = std::collections::BTreeSet::new();
    for argument in &args[5..] {
        let package = Path::new(argument).canonicalize()?;
        if !fs::symlink_metadata(argument)?.is_file()
            || package.extension().and_then(|s| s.to_str()) != Some("deb")
        {
            return Err("packages must be regular non-symlink .deb files".into());
        }
        let arch = String::from_utf8(run(
            &root,
            "dpkg-deb",
            &[
                "-f",
                package.to_str().ok_or("non-UTF8 path")?,
                "Architecture",
            ],
        )?)?;
        let arch = arch.trim();
        if !matches!(arch, "amd64" | "arm64") {
            return Err(format!("unsupported architecture {arch}").into());
        }
        architectures.insert(arch.to_owned());
        let name = String::from_utf8(run(
            &root,
            "dpkg-deb",
            &["-f", package.to_str().ok_or("non-UTF8 path")?, "Package"],
        )?)?;
        let version = String::from_utf8(run(
            &root,
            "dpkg-deb",
            &["-f", package.to_str().ok_or("non-UTF8 path")?, "Version"],
        )?)?;
        let name = name.trim();
        let version = version.trim();
        if ![name, version].iter().all(|value| {
            !value.is_empty()
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".+-:~".contains(&b))
        }) {
            return Err("unsafe package name/version".into());
        }
        let destination = root
            .join("pool")
            .join(format!("{name}_{version}_{arch}.deb"));
        let mut output = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(destination)?;
        std::io::copy(&mut fs::File::open(package)?, &mut output)?;
        output.sync_all()?;
    }
    for arch in &architectures {
        let directory = root.join(format!("dists/{}/main/binary-{arch}", args[4]));
        fs::create_dir_all(&directory)?;
        let packages = run(
            &root,
            "dpkg-scanpackages",
            &["--multiversion", "--arch", arch, "pool"],
        )?;
        if !packages.windows(9).any(|window| window == b"Package: ") {
            return Err(format!("empty package index for {arch}").into());
        }
        fs::write(directory.join("Packages"), packages)?;
    }
    let distribution = format!("dists/{}", args[4]);
    let suite = format!("APT::FTPArchive::Release::Suite={}", args[4]);
    let codename = format!("APT::FTPArchive::Release::Codename={}", args[4]);
    let arches = format!(
        "APT::FTPArchive::Release::Architectures={}",
        architectures.into_iter().collect::<Vec<_>>().join(" ")
    );
    let expiration = String::from_utf8(run(&root, "date", &["-u", "-R", "-d", "+7 days"])?)?;
    let expiration = format!(
        "APT::FTPArchive::Release::Valid-Until={}",
        expiration.trim()
    );
    let release = run(
        &root,
        "apt-ftparchive",
        &[
            "-o",
            "APT::FTPArchive::Release::Origin=fungOS",
            "-o",
            "APT::FTPArchive::Release::Components=main",
            "-o",
            &suite,
            "-o",
            &codename,
            "-o",
            &arches,
            "-o",
            &expiration,
            "release",
            &distribution,
        ],
    )?;
    fs::write(root.join(&distribution).join("Release"), release)?;
    let release = format!("{distribution}/Release");
    let signed = format!("{distribution}/InRelease");
    run(
        &root,
        "gpg",
        &[
            "--batch",
            "--local-user",
            &args[3],
            "--digest-algo",
            "SHA256",
            "--output",
            &signed,
            "--clearsign",
            &release,
        ],
    )?;
    run(&root, "gpg", &["--batch", "--verify", &signed])?;
    fs::write(
        root.join("READY"),
        b"Signed generation verified; publish this whole directory atomically.\n",
    )?;
    println!("{}", root.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_fingerprint_only() {
        assert!(fingerprint(&"a".repeat(40)));
        assert!(fingerprint(&"F".repeat(64)));
        assert!(!fingerprint("12345678"));
        assert!(!fingerprint(&"z".repeat(40)));
        assert!(!fingerprint("--default-key"));
    }
    #[test]
    fn failed_command_is_not_success() {
        assert!(run(Path::new("/"), "false", &[]).is_err());
    }
}
