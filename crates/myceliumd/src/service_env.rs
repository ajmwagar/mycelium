use std::io;
use std::path::Path;

/// Load service-scoped variables which are not already supplied by the
/// supervisor. systemd reads this file itself; launchd does not have an
/// EnvironmentFile equivalent, so the daemon applies the same contract.
///
/// This runs once, before the daemon starts any worker threads. Environment
/// mutation after threads start would be unsound on Unix.
pub(crate) fn load_missing(path: &Path) -> io::Result<()> {
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };

    for (index, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, value) = line.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}:{}: expected NAME=VALUE", path.display(), index + 1),
            )
        })?;
        if !valid_name(name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}:{}: invalid environment name", path.display(), index + 1),
            ));
        }
        if std::env::var_os(name).is_none() {
            // SAFETY: serve() calls this before constructing the daemon or
            // spawning any worker task/thread. No concurrent environment
            // readers exist yet.
            unsafe { std::env::set_var(name, unquote(value)?) };
        }
    }
    Ok(())
}

fn valid_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn unquote(value: &str) -> io::Result<&str> {
    let value = value.trim();
    if value.starts_with(['\'', '"']) {
        let quote = value.as_bytes()[0];
        if value.len() < 2 || value.as_bytes()[value.len() - 1] != quote {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unterminated quoted environment value",
            ));
        }
        Ok(&value[1..value.len() - 1])
    } else {
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_names() {
        assert!(valid_name("GATEWAY_PASS"));
        assert!(valid_name("_private2"));
        assert!(!valid_name("2FAST"));
        assert!(!valid_name("WITH-DASH"));
    }

    #[test]
    fn removes_matching_quotes_only() {
        assert_eq!(unquote("plain").unwrap(), "plain");
        assert_eq!(unquote("'space value'").unwrap(), "space value");
        assert_eq!(unquote("\"space value\"").unwrap(), "space value");
        assert!(unquote("'broken").is_err());
    }
}
