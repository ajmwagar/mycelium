//! Disposable native-service fixture, not Unibus or Canvas. Used only to prove
//! package activation/rollback in QEMU before enabling real edge applications.
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::time::Duration;

fn main() {
    #[cfg(broken)] {
        eprintln!("deliberately broken edge update fixture");
        std::process::exit(42);
    }
    let socket = std::env::args().nth(1).expect("socket path");
    match std::fs::remove_file(&socket) {
        Ok(()) => {},
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
        Err(error) => panic!("remove old socket: {}", error),
    }
    let listener = UnixListener::bind(&socket).expect("bind readiness socket");
    let version = if cfg!(next_release) { "next" } else { "initial" };
    eprintln!("edge fixture {version} ready");
    for client in listener.incoming() {
        let mut client = client.expect("accept readiness request");
        client.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        client.set_write_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut request = [0; 7];
        if client.read_exact(&mut request).is_ok() && &request == b"health\n" {
            client.write_all(format!("READY {version}\n").as_bytes()).unwrap();
        }
    }
}
