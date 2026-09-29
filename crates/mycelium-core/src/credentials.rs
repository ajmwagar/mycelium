use serde::{Deserialize, Serialize};

/// Credentials a driver may use against an appliance.
///
/// Secrets are redacted in every display path, and resolution is lazy:
/// an `Env` value is read at use time so nothing sensitive is cached in
/// long-lived structures or serialized to disk.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Secret {
    Literal(String),
    Env(String),
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Even Debug must not leak the literal.
        match self {
            Secret::Literal(_) => f.write_str("Secret(***redacted***)"),
            Secret::Env(var) => write!(f, "Secret(env:{var})"),
        }
    }
}

impl Secret {
    pub fn resolve(&self) -> Option<String> {
        match self {
            Secret::Literal(s) => Some(s.clone()),
            Secret::Env(var) => std::env::var(var).ok(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialSet {
    pub username: Option<String>,
    pub password: Option<Secret>,
    /// Path to a private key file (OpenSSH format).
    pub key_path: Option<String>,
    pub sudo_password: Option<Secret>,
}

impl CredentialSet {
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.username = Some(user.into());
        self
    }

    pub fn with_password(mut self, secret: Secret) -> Self {
        self.password = Some(secret);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_are_redacted_in_debug() {
        let creds = CredentialSet {
            username: Some("admin".into()),
            password: Some(Secret::Literal("hunter2".into())),
            ..Default::default()
        };
        let shown = format!("{creds:?}");
        assert!(!shown.contains("hunter2"));
        assert!(shown.contains("redacted"));
    }
}
