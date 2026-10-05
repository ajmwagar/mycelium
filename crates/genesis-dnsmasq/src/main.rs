use std::{env, fs};

use genesis_dnsmasq::{plan, verify, AdapterRequest, ProxyDhcpObservation, ProxyDhcpPlan};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [command, request] if command == "plan" => {
            let request: AdapterRequest = read_json(request)?;
            println!("{}", serde_json::to_string_pretty(&plan(&request)?)?);
        }
        [command, plan_path, observation] if command == "verify" => {
            let plan: ProxyDhcpPlan = read_json(plan_path)?;
            let observation: ProxyDhcpObservation = read_json(observation)?;
            let report = verify(&plan, &observation);
            println!("{}", serde_json::to_string_pretty(&report)?);
            if !report.satisfied {
                return Err("ProxyDHCP postconditions were not satisfied".into());
            }
        }
        [flag] if flag == "--help" || flag == "-h" => print_help(),
        _ => {
            print_help();
            return Err("invalid command".into());
        }
    }
    Ok(())
}

fn read_json<T: serde::de::DeserializeOwned>(path: &str) -> Result<T, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn print_help() {
    println!("usage: genesis-dnsmasq <plan REQUEST.json|verify PLAN.json OBSERVATION.json>");
}
