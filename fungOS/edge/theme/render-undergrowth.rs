//! Compatibility entry point for the local legacy fungOS theme builder.
//! The procedural artwork is owned by the public fungOS repository.
#[path = "../../../../fungos/brand/render-undergrowth.rs"]
mod artwork;

fn main() -> std::process::ExitCode {
    artwork::main()
}
