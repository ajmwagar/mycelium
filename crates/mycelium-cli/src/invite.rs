use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Invitation {
    pub id: String,
    pub code_hash: String,
    pub name: String,
    pub unix_users: Vec<String>,
    pub expires_at: u64,
    pub credential_ttl: u64,
    pub remaining_uses: u32,
    pub serial: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct InviteStore {
    pub invitations: Vec<Invitation>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RedeemRequest {
    pub claim: String,
    pub public_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RedeemResponse {
    pub certificate: String,
    pub invitation: String,
    pub principal: String,
    pub expires_at: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct CreatedInvitation {
    pub code: String,
    pub id: String,
    pub expires_at: u64,
    pub uses: u32,
}

#[derive(Serialize, Deserialize)]
struct PairClaim {
    endpoint: String,
    secret: String,
}

pub(crate) fn run(args: &[String]) -> Result<Vec<String>, String> {
    match args.first().map(String::as_str) {
        Some("create") => render_created(create(args)?),
        Some(action) => Err(format!("unknown invite action `{action}`")),
        None => Err("invite needs create".into()),
    }
}

pub(crate) fn create(args: &[String]) -> Result<CreatedInvitation, String> {
    require_write(args)?;
    let name = required(args, "--name")?;
    validate_atom("name", name)?;
    let unix_users = repeated(args, "--unix-user");
    if unix_users.is_empty() {
        return Err("invite create needs at least one --unix-user".into());
    }
    for user in &unix_users {
        validate_atom("Unix user", user)?;
    }
    let now = now()?;
    let ttl = parse_duration(value(args, "--ttl").unwrap_or("15m"))?;
    let credential_ttl = parse_duration(value(args, "--credential-ttl").unwrap_or("8h"))?;
    if ttl == 0 || ttl > 7 * 24 * 60 * 60 {
        return Err("invite TTL must be between 1 second and 7 days".into());
    }
    if credential_ttl == 0 || credential_ttl > 30 * 24 * 60 * 60 {
        return Err("credential TTL must be between 1 second and 30 days".into());
    }
    let uses = value(args, "--uses")
        .unwrap_or("1")
        .parse::<u32>()
        .map_err(|_| "invite --uses must be a positive integer".to_owned())?;
    if uses == 0 {
        return Err("invite --uses must be greater than zero".into());
    }
    let store_path = store_path(args);
    let mut store = load(&store_path)?;
    store
        .invitations
        .retain(|invite| invite.expires_at > now && invite.remaining_uses > 0);
    let secret = random_bytes::<16>();
    let code = format_code(&secret);
    let id = hex(&random_bytes::<8>());
    let serial = u64::from_be_bytes(random_bytes::<8>());
    store.invitations.push(Invitation {
        id: id.clone(),
        code_hash: claim_hash(&code),
        name: name.to_owned(),
        unix_users,
        expires_at: now.saturating_add(ttl),
        credential_ttl,
        remaining_uses: uses,
        serial,
    });
    save(&store_path, &store)?;
    Ok(CreatedInvitation {
        code,
        id,
        expires_at: now.saturating_add(ttl),
        uses,
    })
}

fn render_created(created: CreatedInvitation) -> Result<Vec<String>, String> {
    Ok(vec![
        format!("Claim code: {}", created.code),
        format!("Invitation: {}", created.id),
        format!("Expires: {}", created.expires_at),
        format!("Uses: {}", created.uses),
    ])
}

pub(crate) fn encode_pair_claim(endpoint: &str, secret: &str) -> Result<String, String> {
    let payload = serde_json::to_vec(&PairClaim {
        endpoint: endpoint.to_owned(),
        secret: secret.to_owned(),
    })
    .map_err(|error| format!("encode pairing claim: {error}"))?;
    Ok(format!("MYC1-{}", hex(payload)))
}

pub(crate) fn decode_pair_claim(claim: &str) -> Result<Option<(String, String)>, String> {
    let Some(encoded) = claim.strip_prefix("MYC1-") else {
        return Ok(None);
    };
    if encoded.len() % 2 != 0 || encoded.len() > 4096 {
        return Err("invalid pairing claim encoding".into());
    }
    let bytes = (0..encoded.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&encoded[index..index + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "invalid pairing claim encoding".to_owned())?;
    let payload: PairClaim =
        serde_json::from_slice(&bytes).map_err(|error| format!("decode pairing claim: {error}"))?;
    Ok(Some((payload.endpoint, payload.secret)))
}

pub(crate) fn store_path(args: &[String]) -> PathBuf {
    value(args, "--invite-store")
        .map(PathBuf::from)
        .unwrap_or_else(|| myceliumd::home_dir().join("invites.json"))
}

pub(crate) fn load(path: &Path) -> Result<InviteStore, String> {
    if !path.exists() {
        return Ok(InviteStore::default());
    }
    serde_json::from_slice(
        &fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?,
    )
    .map_err(|error| format!("parse {}: {error}", path.display()))
}

pub(crate) fn save(path: &Path, store: &InviteStore) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    let staged = path.with_extension(format!("mycelium-staging-{}", std::process::id()));
    fs::write(
        &staged,
        serde_json::to_vec_pretty(store).map_err(|error| format!("encode invitations: {error}"))?,
    )
    .map_err(|error| format!("stage {}: {error}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("protect {}: {error}", staged.display()))?;
    }
    fs::rename(&staged, path).map_err(|error| format!("install {}: {error}", path.display()))
}

pub(crate) fn claim_hash(claim: &str) -> String {
    hex(&Sha256::digest(
        claim.trim().to_ascii_uppercase().as_bytes(),
    ))
}

pub(crate) fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| format!("system clock is before Unix epoch: {error}"))
}

fn format_code(secret: &[u8; 16]) -> String {
    let encoded = hex(secret).to_ascii_uppercase();
    format!(
        "MYC-{}-{}-{}-{}-{}-{}-{}-{}",
        &encoded[0..4],
        &encoded[4..8],
        &encoded[8..12],
        &encoded[12..16],
        &encoded[16..20],
        &encoded[20..24],
        &encoded[24..28],
        &encoded[28..32]
    )
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn parse_duration(raw: &str) -> Result<u64, String> {
    let split = raw
        .find(|character: char| !character.is_ascii_digit())
        .ok_or_else(|| format!("duration `{raw}` needs a unit (s, m, h, or d)"))?;
    let amount = raw[..split]
        .parse::<u64>()
        .map_err(|_| format!("invalid duration `{raw}`"))?;
    let multiplier = match &raw[split..] {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        _ => return Err(format!("invalid duration `{raw}`")),
    };
    amount
        .checked_mul(multiplier)
        .ok_or_else(|| format!("duration `{raw}` is too large"))
}

fn repeated(args: &[String], flag: &str) -> Vec<String> {
    args.windows(2)
        .filter(|pair| pair[0] == flag)
        .map(|pair| pair[1].clone())
        .collect()
}

fn validate_atom(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-@".contains(character))
    {
        return Err(format!("{label} contains unsupported characters"));
    }
    Ok(())
}

fn value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter()
        .position(|arg| arg == flag)
        .and_then(|index| args.get(index + 1))
        .map(String::as_str)
}

fn required<'a>(args: &'a [String], flag: &str) -> Result<&'a str, String> {
    value(args, flag).ok_or_else(|| format!("invite create needs {flag}"))
}

fn require_write(args: &[String]) -> Result<(), String> {
    args.iter()
        .any(|arg| arg == "--write")
        .then_some(())
        .ok_or_else(|| "invite creation needs --write".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claims_are_high_entropy_and_normalized_for_hashing() {
        let code = format_code(&[0xab; 16]);
        assert_eq!(code.len(), 43);
        assert_eq!(claim_hash(&code), claim_hash(&code.to_ascii_lowercase()));
    }

    #[test]
    fn durations_require_explicit_units() {
        assert_eq!(parse_duration("15m").unwrap(), 900);
        assert_eq!(parse_duration("2d").unwrap(), 172_800);
        assert!(parse_duration("15").is_err());
    }

    #[test]
    fn create_persists_only_the_claim_hash() {
        let root = std::env::temp_dir().join(format!(
            "mycelium-invite-test-{}-{}",
            std::process::id(),
            now().unwrap()
        ));
        let store_path = root.join("invites.json");
        let args = [
            "create",
            "--name",
            "buddy",
            "--unix-user",
            "operator",
            "--ttl",
            "15m",
            "--credential-ttl",
            "8h",
            "--invite-store",
            store_path.to_str().unwrap(),
            "--write",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let output = create(&args).unwrap();
        let claim = &output.code;
        let raw = fs::read_to_string(&store_path).unwrap();
        assert!(!raw.contains(claim));
        let store = load(&store_path).unwrap();
        assert_eq!(store.invitations.len(), 1);
        assert_eq!(store.invitations[0].code_hash, claim_hash(claim));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pairing_claim_carries_rendezvous_without_changing_secret() {
        let encoded = encode_pair_claim("http://192.168.1.2:8788", "MYC-SECRET").unwrap();
        let decoded = decode_pair_claim(&encoded).unwrap().unwrap();
        assert_eq!(decoded.0, "http://192.168.1.2:8788");
        assert_eq!(decoded.1, "MYC-SECRET");
    }
}
