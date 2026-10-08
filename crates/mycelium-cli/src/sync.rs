//! Explicit rendezvous import/export for already-enrolled peers.
#[cfg(feature = "iroh-sync")]
pub fn run(args: &[String]) -> Result<Vec<String>, String> {
    use myceliumd::peer::{SyncConfig, SyncRendezvous};
    use std::io::Read;
    let home = myceliumd::home_dir();
    let read = |path: &std::path::Path| -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .map_err(|e| e.to_string())?
            .take(65537)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() > 65536 {
            return Err("sync document exceeds 64 KiB".into());
        }
        Ok(bytes)
    };
    let at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    match args.first().map(String::as_str) {
        Some("export") if args.len() == 1 || args == ["export", "--qr"] => {
            let rendezvous: SyncRendezvous =
                serde_json::from_slice(&read(&home.join("iroh-rendezvous.json"))?)
                    .map_err(|e| e.to_string())?;
            rendezvous.validate(Some(at))?;
            let json = serde_json::to_string(&rendezvous).map_err(|e| e.to_string())?;
            if args.len() == 2 {
                let qr = qrcode::QrCode::new(json.as_bytes()).map_err(|e| e.to_string())?;
                Ok(vec![
                    qr.render::<qrcode::render::unicode::Dense1x2>().build(),
                    json,
                ])
            } else {
                Ok(vec![json])
            }
        }
        Some("enable") if args.len() == 2 && args[1] == "--write" => {
            std::fs::create_dir_all(&home).map_err(|e| e.to_string())?;
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(home.join("iroh-sync.json"))
                .map_err(|e| e.to_string())?;
            file.write_all(b"{\"public_relays\":false,\"seeds\":[]}\n")
                .map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
            Ok(vec!["Iroh enabled; set MYCELIUM_IROH_SERVER_NAME to your certificate SAN and restart myceliumd".into()])
        }
        Some("join") if args.len() == 3 && args[2] == "--write" => {
            let seed: SyncRendezvous =
                serde_json::from_slice(&read(std::path::Path::new(&args[1]))?)
                    .map_err(|e| e.to_string())?;
            seed.validate(Some(at))?;
            let path = home.join("iroh-sync.json");
            let mut config: SyncConfig =
                serde_json::from_slice(&read(&path)?).map_err(|e| e.to_string())?;
            config
                .seeds
                .retain(|s| s.endpoint.endpoint_id != seed.endpoint.endpoint_id);
            config.seeds.push(seed);
            config.validate()?;
            let temporary = home.join("iroh-sync.json.tmp");
            std::fs::write(
                &temporary,
                serde_json::to_vec_pretty(&config).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            std::fs::rename(temporary, path).map_err(|e| e.to_string())?;
            Ok(vec!["sync seed saved; restart myceliumd to connect (enrollment and trust are unchanged)".into()])
        }
        _ => Err(
            "usage: mycelium sync enable --write | export [--qr] | join <rendezvous.json> --write"
                .into(),
        ),
    }
}

#[cfg(not(feature = "iroh-sync"))]
pub fn run(_: &[String]) -> Result<Vec<String>, String> {
    Err("this binary lacks Iroh sync; install with --features iroh-sync".into())
}
