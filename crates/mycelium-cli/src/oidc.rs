use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Deserialize)]
struct Discovery {
    issuer: String,
    jwks_uri: String,
}

/// Stable output contract between any OIDC provider and Mycelium's access
/// authority. Bearer and ID tokens never enter peer gossip or persistence.
#[derive(Debug, Serialize)]
pub(crate) struct Identity {
    pub(crate) principal: String,
    pub(crate) issuer: String,
    pub(crate) subject: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    groups: Vec<String>,
    pub(crate) expires_at: u64,
}

pub async fn run(args: &[String], state: Option<&Value>) -> Result<Vec<String>, String> {
    match args.first().map(String::as_str) {
        Some("verify") => verify(args).await,
        Some("ssh-issue") => {
            ssh_issue(args, state.ok_or("OIDC SSH issuance needs access state")?).await
        }
        Some("gateway") => crate::oidc_gateway::serve(args).await,
        Some("join") => crate::oidc_gateway::join(args).await,
        Some(action) => Err(format!("unknown access oidc action `{action}`")),
        None => Err("access oidc needs verify".into()),
    }
}

async fn verify(args: &[String]) -> Result<Vec<String>, String> {
    let identity = verify_identity(args).await?;
    let json = serde_json::to_string_pretty(&identity)
        .map_err(|e| format!("encode OIDC identity: {e}"))?;
    Ok(vec![json])
}

async fn ssh_issue(args: &[String], state: &Value) -> Result<Vec<String>, String> {
    let identity = verify_identity(args).await?;
    let audience = required(args, "--audience")?;
    let mut output = crate::ssh_access::issue_for_oidc(
        args,
        state,
        &identity.principal,
        audience,
        identity.expires_at,
    )?;
    output.push(format!(
        "authenticated OIDC principal {} (token expires at {})",
        identity.principal, identity.expires_at
    ));
    Ok(output)
}

async fn verify_identity(args: &[String]) -> Result<Identity, String> {
    let issuer = required(args, "--issuer")?.trim_end_matches('/');
    let audience = required(args, "--audience")?;
    let token_env = required(args, "--token-env")?;
    let token = std::env::var(token_env)
        .map_err(|_| format!("OIDC token environment variable `{token_env}` is not set"))?;
    verify_token(issuer, audience, &token, value(args, "--discovery")).await
}

pub(crate) async fn verify_token(
    issuer: &str,
    audience: &str,
    token: &str,
    discovery_override: Option<&str>,
) -> Result<Identity, String> {
    let issuer = issuer.trim_end_matches('/');
    let discovery_url = discovery_override
        .map(str::to_owned)
        .unwrap_or_else(|| format!("{issuer}/.well-known/openid-configuration"));
    let client = reqwest::Client::builder()
        .https_only(true)
        .build()
        .map_err(|e| format!("build OIDC client: {e}"))?;
    let discovery: Discovery = fetch_json(&client, &discovery_url, "OIDC discovery").await?;
    if discovery.issuer.trim_end_matches('/') != issuer {
        return Err(format!(
            "OIDC discovery issuer mismatch: expected `{issuer}`, got `{}`",
            discovery.issuer
        ));
    }
    let jwks: jsonwebtoken::jwk::JwkSet =
        fetch_json(&client, &discovery.jwks_uri, "OIDC JWKS").await?;
    let header = decode_header(&token).map_err(|e| format!("decode OIDC token header: {e}"))?;
    ensure_algorithm(header.alg)?;
    let kid = header
        .kid
        .as_deref()
        .ok_or("OIDC token header has no kid")?;
    let jwk = jwks
        .find(kid)
        .ok_or_else(|| format!("OIDC JWKS has no key `{kid}`"))?;
    let key = DecodingKey::from_jwk(jwk).map_err(|e| format!("decode OIDC JWK `{kid}`: {e}"))?;
    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);
    validation.set_required_spec_claims(&["exp", "iss", "sub", "aud"]);
    validation.leeway = 30;
    let claims = decode::<Value>(&token, &key, &validation)
        .map_err(|e| format!("verify OIDC token: {e}"))?
        .claims;
    normalize_identity(issuer, claims)
}

async fn fetch_json<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
    label: &str,
) -> Result<T, String> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("fetch {label}: {e}"))?;
    if !response.status().is_success() {
        return Err(format!("fetch {label}: HTTP {}", response.status()));
    }
    response
        .json()
        .await
        .map_err(|e| format!("decode {label}: {e}"))
}

fn normalize_identity(issuer: &str, claims: Value) -> Result<Identity, String> {
    let subject = string_claim(&claims, "sub")?;
    let expires_at = claims["exp"]
        .as_u64()
        .ok_or("OIDC claim `exp` is not an unsigned integer")?;
    let email = claims["email"].as_str().map(str::to_owned);
    let groups = ["groups", "roles"]
        .into_iter()
        .find_map(|name| claims[name].as_array())
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    Ok(Identity {
        principal: format!("oidc:{issuer}#{subject}"),
        issuer: issuer.into(),
        subject,
        email,
        groups,
        expires_at,
    })
}

fn string_claim(claims: &Value, name: &str) -> Result<String, String> {
    claims[name]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("OIDC claim `{name}` is missing or not a string"))
}

fn ensure_algorithm(algorithm: Algorithm) -> Result<(), String> {
    match algorithm {
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512
        | Algorithm::ES256
        | Algorithm::ES384
        | Algorithm::EdDSA => Ok(()),
        other => Err(format!("OIDC signing algorithm `{other:?}` is not allowed")),
    }
}

fn value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter()
        .position(|arg| arg == flag)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn required<'a>(args: &'a [String], flag: &str) -> Result<&'a str, String> {
    value(args, flag).ok_or_else(|| format!("access oidc verify needs {flag}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_claims_normalize_to_stable_principal() {
        let claims = serde_json::json!({
            "sub": "user-42", "exp": 1234, "email": "a@example.test", "groups": ["operators"]
        });
        let identity = normalize_identity("https://issuer.example", claims).unwrap();
        assert_eq!(identity.principal, "oidc:https://issuer.example#user-42");
        assert_eq!(identity.groups, vec!["operators"]);
    }

    #[test]
    fn symmetric_tokens_are_rejected() {
        assert!(ensure_algorithm(Algorithm::HS256).is_err());
    }
}
