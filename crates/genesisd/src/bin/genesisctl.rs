use std::{env, fs, path::PathBuf};

use fpl_boot_contract::{BootIntentV1, BootProfileV1};
use genesisd::{plan, Store};
use serde::de::DeserializeOwned;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut root = PathBuf::from("./genesis-state");
    let mut arguments = env::args().skip(1).collect::<Vec<_>>();
    if arguments.first().map(String::as_str) == Some("--root") {
        if arguments.len() < 3 {
            return Err("--root requires a path and command".into());
        }
        root = arguments[1].clone().into();
        arguments.drain(0..2);
    }
    let store = Store::open(root)?;
    match arguments.as_slice() {
        [kind, command, path] if command == "put" && kind == "profile" => {
            println!("{}", store.put_profile(&read_json(path)?)?);
        }
        [kind, command, path] if command == "put" && kind == "intent" => {
            println!("{}", store.put_intent(&read_json(path)?)?);
        }
        [kind, command, path] if command == "put" && kind == "receipt" => {
            store.put_receipt(&read_json(path)?)?;
            println!("ok");
        }
        [kind, command, digest, path] if command == "put" && kind == "artifact" => {
            println!(
                "{}",
                store
                    .import_artifact(digest, PathBuf::from(path).as_path())?
                    .display()
            );
        }
        [kind, command, digest] if command == "get" && kind == "profile" => {
            print_json(&store.profile(digest)?)?;
        }
        [kind, command, digest] if command == "get" && kind == "intent" => {
            print_json(&store.intent(digest)?)?;
        }
        [kind, command, machine] if command == "get" && kind == "receipt" => {
            print_json(&store.receipt(machine)?)?;
        }
        [command, intent_path, profile_path] if command == "plan" => {
            let intent: BootIntentV1 = read_json(intent_path)?;
            let profile: BootProfileV1 = read_json(profile_path)?;
            print_json(&plan(&intent, &profile)?)?;
        }
        [flag] if flag == "--help" || flag == "-h" => print_help(),
        _ => {
            print_help();
            return Err("invalid command".into());
        }
    }
    Ok(())
}

fn read_json<T: DeserializeOwned>(path: &str) -> Result<T, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<(), serde_json::Error> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn print_help() {
    println!(
        "usage: genesisctl [--root PATH] \
         <profile put FILE|profile get DIGEST|intent put FILE|intent get DIGEST|\
         receipt put FILE|receipt get MACHINE|artifact put SHA256 FILE|\
         plan INTENT_FILE PROFILE_FILE>"
    );
}
