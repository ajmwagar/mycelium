use std::{env, net::SocketAddr, path::PathBuf};

use genesisd::{router, Store};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut root = PathBuf::from("./genesis-state");
    let mut listen: SocketAddr = "127.0.0.1:8088".parse()?;
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--root" => root = arguments.next().ok_or("--root requires a path")?.into(),
            "--listen" => {
                listen = arguments
                    .next()
                    .ok_or("--listen requires an address")?
                    .parse()?
            }
            "--help" | "-h" => {
                println!("usage: genesisd [--root PATH] [--listen ADDRESS]");
                return Ok(());
            }
            _ => return Err(format!("unknown argument `{argument}`").into()),
        }
    }

    let store = Store::open(root)?;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    println!("genesisd listening on {}", listener.local_addr()?);
    axum::serve(listener, router(store)).await?;
    Ok(())
}
