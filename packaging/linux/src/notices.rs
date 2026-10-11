//! Explicit, digest-bound public notice input. Coverage is reviewed evidence,
//! not a legal certification, and is independent of runtime source distribution.
use crate::Result;
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Component, Path},
    process::{Command, Stdio},
};

pub struct Notices {
    pub files: Vec<(String, Vec<u8>)>,
    pub inventory_sha256: String,
    pub lock_sha256: String,
}

pub fn digest(bytes: &[u8]) -> Result<String> {
    let mut child = Command::new("sha256sum")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("sha256sum stdin missing")?
        .write_all(bytes)?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err("sha256sum failed".into());
    }
    let value = String::from_utf8(output.stdout)?
        .split_whitespace()
        .next()
        .ok_or("digest missing")?
        .to_owned();
    if !hash(&value) {
        return Err("invalid sha256sum result".into());
    }
    Ok(value)
}
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn regular(root: &Path, relative: &str) -> Result<Vec<u8>> {
    for ancestor in root
        .ancestors()
        .filter(|value| !value.as_os_str().is_empty())
    {
        if fs::symlink_metadata(ancestor)?.file_type().is_symlink() {
            return Err("notice root must not traverse symlinks".into());
        }
    }
    if !fs::symlink_metadata(root)?.is_dir() {
        return Err("notice root must be a nonsymlink directory".into());
    }
    let mut path = root.to_path_buf();
    for part in Path::new(relative).components() {
        let Component::Normal(part) = part else {
            return Err("unsafe notice path".into());
        };
        path.push(part);
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err("notice paths must not traverse symlinks".into());
        }
    }
    if !fs::symlink_metadata(&path)?.is_file() {
        return Err("notice input must be a regular file".into());
    }
    Ok(fs::read(path)?)
}
fn metadata(bytes: &[u8]) -> Result<BTreeMap<String, String>> {
    let mut fields = BTreeMap::new();
    for line in std::str::from_utf8(bytes)?.lines() {
        let (key, value) = line.split_once('=').ok_or("malformed notice metadata")?;
        if !matches!(
            key,
            "schema_version"
                | "executable_sha256"
                | "source_commit"
                | "cargo_lock_sha256"
                | "inventory_sha256"
                | "coverage"
                | "legal_clearance"
        ) || value.is_empty()
            || fields.insert(key.to_owned(), value.to_owned()).is_some()
        {
            return Err("unknown, empty or duplicate notice metadata".into());
        }
    }
    Ok(fields)
}
pub fn load(root: &Path, binary: &str, source: &str, lock: &str) -> Result<Notices> {
    let metadata_bytes = regular(root, "metadata.txt")?;
    let fields = metadata(&metadata_bytes)?;
    for (key, value) in [
        ("schema_version", "1"),
        ("executable_sha256", binary),
        ("source_commit", source),
        ("cargo_lock_sha256", lock),
        ("coverage", "reviewed-complete"),
    ] {
        if fields.get(key).map(String::as_str) != Some(value) {
            return Err(format!("notice binding/coverage mismatch: {key}").into());
        }
    }
    if fields.get("legal_clearance").map(String::as_str) != Some("not-asserted") {
        return Err("notice metadata cannot assert legal clearance".into());
    }
    let inventory = regular(root, "inventory.tsv")?;
    let inventory_sha256 = digest(&inventory)?;
    if fields.get("inventory_sha256") != Some(&inventory_sha256) {
        return Err("notice inventory digest mismatch".into());
    }
    let mut lines = std::str::from_utf8(&inventory)?.lines();
    if lines.next() != Some("sha256\tpath") {
        return Err("notice inventory header mismatch".into());
    }
    let mut notices = BTreeMap::new();
    for line in lines {
        let (expected, path) = line.split_once('\t').ok_or("malformed notice inventory")?;
        if !hash(expected)
            || !path.starts_with("notices/")
            || path.contains('\\')
            || path.bytes().any(|c| c.is_ascii_control())
            || path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err("unsafe notice inventory entry".into());
        }
        let bytes = regular(root, path)?;
        if bytes.is_empty() {
            return Err("raw notice is empty".into());
        }
        if digest(&bytes)? != expected {
            return Err(format!("notice digest mismatch: {path}").into());
        }
        if notices.insert(path.to_owned(), bytes).is_some() {
            return Err("duplicate notice inventory path".into());
        }
    }
    if notices.is_empty() {
        return Err("notice inventory is empty".into());
    }
    let mut files = vec![
        ("metadata.txt".into(), metadata_bytes),
        ("inventory.tsv".into(), inventory),
    ];
    files.extend(notices);
    Ok(Notices {
        files,
        inventory_sha256,
        lock_sha256: lock.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    struct Fixture(std::path::PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn fixture() -> Fixture {
        let path = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "mycelium-notice-test-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        fs::create_dir_all(path.join("notices/test")).unwrap();
        fs::write(path.join("notices/test/LICENSE"), b"raw notice").unwrap();
        inventory(
            &path,
            &format!("{}\tnotices/test/LICENSE\n", digest(b"raw notice").unwrap()),
            "reviewed-complete",
        );
        Fixture(path)
    }
    fn inventory(path: &Path, rows: &str, coverage: &str) {
        let bytes = format!("sha256\tpath\n{rows}");
        fs::write(path.join("inventory.tsv"), &bytes).unwrap();
        fs::write(path.join("metadata.txt"), format!("schema_version=1\nexecutable_sha256={}\nsource_commit={}\ncargo_lock_sha256={}\ninventory_sha256={}\ncoverage={coverage}\nlegal_clearance=not-asserted\n", "a".repeat(64), "b".repeat(40), "c".repeat(64), digest(bytes.as_bytes()).unwrap())).unwrap();
    }
    fn load_fixture(path: &Path) -> Result<Notices> {
        load(path, &"a".repeat(64), &"b".repeat(40), &"c".repeat(64))
    }
    #[test]
    fn exact_binding_and_raw_bytes() {
        let f = fixture();
        let value = load_fixture(&f.0).unwrap();
        assert_eq!(value.files.len(), 3);
        assert_eq!(value.files[2].1, b"raw notice");
        assert!(load(&f.0, &"d".repeat(64), &"b".repeat(40), &"c".repeat(64)).is_err());
        assert!(load(&f.0, &"a".repeat(64), &"d".repeat(40), &"c".repeat(64)).is_err());
        assert!(load(&f.0, &"a".repeat(64), &"b".repeat(40), &"d".repeat(64)).is_err());
    }
    #[test]
    fn rejects_unknown_coverage_and_changed_missing_bytes() {
        let f = fixture();
        fs::write(f.0.join("notices/test/LICENSE"), b"changed").unwrap();
        assert!(load_fixture(&f.0).is_err());
        fs::remove_file(f.0.join("notices/test/LICENSE")).unwrap();
        assert!(load_fixture(&f.0).is_err());
        inventory(&f.0, "", "unknown");
        assert!(load_fixture(&f.0).is_err());
    }
    #[test]
    fn rejects_symlinks_and_unsafe_paths() {
        let f = fixture();
        fs::remove_file(f.0.join("notices/test/LICENSE")).unwrap();
        symlink("/etc/passwd", f.0.join("notices/test/LICENSE")).unwrap();
        assert!(load_fixture(&f.0).is_err());
        for path in [
            "notices/../metadata.txt",
            "notices//LICENSE",
            "/etc/passwd",
            "notices/./LICENSE",
            "notices/x\\y",
        ] {
            inventory(
                &f.0,
                &format!("{}\t{path}\n", "a".repeat(64)),
                "reviewed-complete",
            );
            assert!(load_fixture(&f.0).is_err());
        }
    }
    #[test]
    fn rejects_symlink_parents_empty_notices_and_legal_assertions() {
        let f = fixture();
        symlink(f.0.join("notices/test"), f.0.join("notices/link")).unwrap();
        inventory(
            &f.0,
            &format!("{}\tnotices/link/LICENSE\n", digest(b"raw notice").unwrap()),
            "reviewed-complete",
        );
        assert!(load_fixture(&f.0).is_err());
        inventory(
            &f.0,
            &format!("{}\tnotices/test/LICENSE\n", digest(b"").unwrap()),
            "reviewed-complete",
        );
        fs::write(f.0.join("notices/test/LICENSE"), b"").unwrap();
        assert!(load_fixture(&f.0).is_err());
        let text = fs::read_to_string(f.0.join("metadata.txt")).unwrap();
        fs::write(
            f.0.join("metadata.txt"),
            text.replace("legal_clearance=not-asserted", "legal_clearance=approved"),
        )
        .unwrap();
        assert!(load_fixture(&f.0).is_err());
    }
    #[test]
    fn rejects_duplicate_and_metadata_or_inventory_drift() {
        let f = fixture();
        let row = format!("{}\tnotices/test/LICENSE\n", digest(b"raw notice").unwrap());
        inventory(&f.0, &(row.clone() + &row), "reviewed-complete");
        assert!(load_fixture(&f.0).is_err());
        inventory(&f.0, &row, "reviewed-complete");
        fs::write(f.0.join("inventory.tsv"), b"tampered").unwrap();
        assert!(load_fixture(&f.0).is_err());
        assert!(metadata(b"schema_version=1\nschema_version=1\n").is_err());
        assert!(metadata(b"unexpected=1\n").is_err());
    }
}
