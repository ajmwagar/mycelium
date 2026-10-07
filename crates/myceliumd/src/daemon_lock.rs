//! Kernel-owned, crash-releasing exclusion for one daemon per state directory.
//!
//! The lock file deliberately survives exit. Unlinking it would allow another
//! process to lock a different inode while an existing daemon still owns one.
use std::{fs::File, io, path::Path};

pub(crate) fn acquire(home: &Path) -> io::Result<File> {
    let path = home.join("daemon.lock");
    if let Ok(metadata) = std::fs::symlink_metadata(&path) {
        if !metadata.is_file() {
            return Err(io::Error::other("daemon lock must be a regular file"));
        }
    }
    let mut options = std::fs::OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(&path)?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "a myceliumd already owns state directory {}",
                home.display()
            ),
        )),
        Err(std::fs::TryLockError::Error(error)) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufRead;

    struct Scratch(std::path::PathBuf);
    impl Scratch {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "mycelium-daemon-lock-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn rejects_competing_owner_and_releases_without_unlinking() {
        let home = Scratch::new();
        let owner = acquire(&home.0).unwrap();
        assert_eq!(
            acquire(&home.0).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert!(home.0.join("daemon.lock").is_file());
        drop(owner);
        let _replacement = acquire(&home.0).unwrap();
    }

    #[test]
    fn independent_state_directories_can_run_together() {
        let a = Scratch::new();
        let b = Scratch::new();
        let _a = acquire(&a.0).unwrap();
        let _b = acquire(&b.0).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn rejects_symlink_and_protects_new_lock() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let home = Scratch::new();
        symlink("target", home.0.join("daemon.lock")).unwrap();
        assert!(acquire(&home.0).is_err());
        assert!(!home.0.join("target").exists());
        std::fs::remove_file(home.0.join("daemon.lock")).unwrap();
        let _owner = acquire(&home.0).unwrap();
        assert_eq!(
            std::fs::metadata(home.0.join("daemon.lock"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    #[ignore = "child-process fixture; invoked by crash recovery test"]
    fn child_holds_lock() {
        use std::io::Write;
        let path = std::env::var_os("MYCELIUM_LOCK_TEST_HOME").unwrap();
        let _owner = acquire(Path::new(&path)).unwrap();
        println!("LOCK_READY");
        std::io::stdout().flush().unwrap();
        std::io::stdin().read_line(&mut String::new()).unwrap();
    }

    #[test]
    fn process_crash_releases_lock() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let home = Scratch::new();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "daemon_lock::tests::child_holds_lock",
                    "--ignored",
                    "--nocapture",
                ])
                .env("MYCELIUM_LOCK_TEST_HOME", &home.0)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let output = child.0.stdout.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(output).lines() {
                if line.is_ok_and(|line| line.contains("LOCK_READY")) {
                    let _ = tx.send(());
                    break;
                }
            }
        });
        rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
        assert_eq!(
            acquire(&home.0).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        let _replacement = acquire(&home.0).unwrap();
    }
}
