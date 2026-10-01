use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::PathBuf;

pub async fn run(args: &[String]) -> Result<Vec<String>, String> {
    let listen = value(args, "--listen")
        .unwrap_or("0.0.0.0:8788")
        .parse::<SocketAddr>()
        .map_err(|error| format!("invalid pairing listen address: {error}"))?;
    let advertise = value(args, "--advertise")
        .map(str::to_owned)
        .unwrap_or_else(|| default_advertise(listen));
    validate_advertise(&advertise)?;
    let ca = value(args, "--ca")
        .map(PathBuf::from)
        .unwrap_or_else(|| myceliumd::home_dir().join("ssh/user_ca"));
    if !ca.is_file() {
        return Err(format!(
            "SSH CA private key {} does not exist; pass --ca or select the authority MYCELIUM_HOME",
            ca.display()
        ));
    }
    let store = crate::invite::store_path(args);
    let mut create_args = vec!["create".to_owned()];
    create_args.extend_from_slice(args);
    if value(args, "--invite-store").is_none() {
        create_args.extend([
            "--invite-store".to_owned(),
            store.to_string_lossy().into_owned(),
        ]);
    }
    if !create_args.iter().any(|argument| argument == "--write") {
        create_args.push("--write".into());
    }
    let created = crate::invite::create(&create_args)?;
    let claim = crate::invite::encode_pair_claim(&advertise, &created.code)?;
    println!("Pairing claim: {claim}");
    println!("Expires: {}", created.expires_at);
    println!("Waiting for one redemption at {advertise} ...");
    crate::oidc_gateway::serve_pairing(listen, ca, store, created.id, created.expires_at).await?;
    Ok(vec!["pairing complete; listener closed".into()])
}

fn default_advertise(listen: SocketAddr) -> String {
    let ip = if listen.ip().is_unspecified() {
        local_ip().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
    } else {
        listen.ip()
    };
    format!("http://{ip}:{}", listen.port())
}

fn local_ip() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("1.1.1.1:80").ok()?;
    socket.local_addr().ok().map(|address| address.ip())
}

fn validate_advertise(value: &str) -> Result<(), String> {
    let url =
        reqwest::Url::parse(value).map_err(|error| format!("invalid advertise URL: {error}"))?;
    if url.scheme() == "https" {
        return Ok(());
    }
    let private = url.scheme() == "http"
        && url.host_str().is_some_and(|host| {
            host == "localhost" || host.parse::<IpAddr>().is_ok_and(private_transport_ip)
        });
    if private {
        Ok(())
    } else {
        Err(
            "pairing advertise URL must use HTTPS unless it is a private or loopback address"
                .into(),
        )
    }
}

pub(crate) fn private_transport_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            ip.is_private() || ip.is_loopback() || (octets[0] == 100 && (octets[1] & 0xc0) == 0x40)
        }
        IpAddr::V6(ip) => ip.is_unique_local() || ip.is_loopback(),
    }
}

fn value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter()
        .position(|argument| argument == flag)
        .and_then(|index| args.get(index + 1))
        .map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_plaintext_pairing_is_rejected() {
        assert!(validate_advertise("http://192.168.1.2:8788").is_ok());
        assert!(validate_advertise("http://100.120.101.5:8788").is_ok());
        assert!(validate_advertise("http://127.0.0.1:8788").is_ok());
        assert!(validate_advertise("http://203.0.113.4:8788").is_err());
        assert!(validate_advertise("https://pair.example.test").is_ok());
    }
}
