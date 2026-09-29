use myceliumd::rpc::serve;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(|s| s.as_str()) {
        Some("serve") | None => serve().await,
        other => {
            eprintln!("myceliumd: unknown argument {other:?}; only `serve` exists (the CLI drives everything else)");
            std::process::exit(2);
        }
    };
    if let Err(e) = result {
        eprintln!("myceliumd: {e}");
        std::process::exit(1);
    }
}
