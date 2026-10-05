//! Signed, deliberately broken daemon fixture for the isolated QEMU rollback test.
//! Never publish this fixture to a fleet release channel.
fn main() {
    if std::env::args().nth(1).as_deref() == Some("_self-check") {
        return;
    }
    eprintln!("intentional fungOS rollback-test daemon failure");
    std::process::exit(42);
}
