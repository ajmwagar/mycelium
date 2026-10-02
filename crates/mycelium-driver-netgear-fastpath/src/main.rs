use mycelium_driver_netgear_fastpath::{
    FastpathConfig, FastpathIntent, FastpathMigrationProposal, ReconcileOptions, SnmpSwitchState,
};
use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut arguments = env::args_os().skip(1);
    let source = arguments.next().map(PathBuf::from).ok_or_else(usage)?;
    let mut redacted_output = None;
    let mut intent_output = None;
    let mut observed_intent = None;
    let mut observed_snmp = None;
    let mut plan_output = None;
    let mut allow_deletes = false;
    let mut allow_model_mismatch = false;

    while let Some(argument) = arguments.next() {
        if argument == "--redacted-output" {
            redacted_output = Some(arguments.next().map(PathBuf::from).ok_or_else(usage)?);
        } else if argument == "--intent-output" {
            intent_output = Some(arguments.next().map(PathBuf::from).ok_or_else(usage)?);
        } else if argument == "--observed-intent" {
            observed_intent = Some(arguments.next().map(PathBuf::from).ok_or_else(usage)?);
        } else if argument == "--observed-snmp" {
            observed_snmp = Some(arguments.next().map(PathBuf::from).ok_or_else(usage)?);
        } else if argument == "--plan-output" {
            plan_output = Some(arguments.next().map(PathBuf::from).ok_or_else(usage)?);
        } else if argument == "--allow-deletes" {
            allow_deletes = true;
        } else if argument == "--allow-model-mismatch" {
            allow_model_mismatch = true;
        } else {
            return Err(usage());
        }
    }

    let bytes =
        fs::read(&source).map_err(|error| format!("cannot read {}: {error}", source.display()))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| format!("{} is not UTF-8 text: {error}", source.display()))?;
    let config = FastpathConfig::parse(text)
        .map_err(|error| format!("cannot parse {}: {error}", source.display()))?;

    println!("source={}", source.display());
    println!("bytes={}", bytes.len());
    println!("lines={}", config.lines.len());
    println!("header={}", config.header.is_some());
    println!("sections={}", config.sections.len());
    println!("secret_records={}", config.secrets.len());

    let intent = FastpathIntent::normalize(&config)
        .map_err(|error| format!("cannot normalize {}: {error}", source.display()))?;
    println!("vlans={}", intent.vlans.len());
    println!("interfaces={}", intent.interfaces.len());
    println!("lags={}", intent.lags.len());
    println!("opaque_statements={}", intent.opaque.len());
    println!("diagnostics={}", intent.diagnostics.len());

    if let Some(destination) = redacted_output {
        let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
        fs::write(&destination, config.redacted().render(newline))
            .map_err(|error| format!("cannot write {}: {error}", destination.display()))?;
        println!("redacted_output={}", destination.display());
    }

    if let Some(destination) = intent_output {
        let json = serde_json::to_vec_pretty(&intent)
            .map_err(|error| format!("cannot serialize intent: {error}"))?;
        fs::write(&destination, json)
            .map_err(|error| format!("cannot write {}: {error}", destination.display()))?;
        println!("intent_output={}", destination.display());
    }

    match (observed_intent, observed_snmp, plan_output) {
        (Some(observed_path), None, Some(destination)) => {
            let observed_bytes = fs::read(&observed_path).map_err(|error| {
                format!(
                    "cannot read observed intent {}: {error}",
                    observed_path.display()
                )
            })?;
            let observed: FastpathIntent =
                serde_json::from_slice(&observed_bytes).map_err(|error| {
                    format!(
                        "cannot parse observed intent {}: {error}",
                        observed_path.display()
                    )
                })?;
            let plan = FastpathMigrationProposal::build(
                &intent,
                &observed,
                ReconcileOptions {
                    allow_deletes,
                    allow_model_mismatch,
                },
            );
            let json = serde_json::to_vec_pretty(&plan)
                .map_err(|error| format!("cannot serialize reconciliation plan: {error}"))?;
            fs::write(&destination, json)
                .map_err(|error| format!("cannot write {}: {error}", destination.display()))?;
            println!("plan_steps={}", plan.steps.len());
            println!("plan_blockers={}", plan.blockers.len());
            println!("ready_to_lower={}", plan.ready_to_lower);
            println!("plan_output={}", destination.display());
        }
        (None, Some(observed_path), Some(destination)) => {
            let observed_bytes = fs::read(&observed_path).map_err(|error| {
                format!(
                    "cannot read SNMP observation {}: {error}",
                    observed_path.display()
                )
            })?;
            let observed: SnmpSwitchState =
                serde_json::from_slice(&observed_bytes).map_err(|error| {
                    format!(
                        "cannot parse SNMP observation {}: {error}",
                        observed_path.display()
                    )
                })?;
            let device = observed_path
                .file_stem()
                .and_then(|name| name.to_str())
                .unwrap_or("netgear-switch");
            let plan = observed.plan(device, &intent);
            let json = serde_json::to_vec_pretty(&plan)
                .map_err(|error| format!("cannot serialize action plan: {error}"))?;
            fs::write(&destination, json)
                .map_err(|error| format!("cannot write {}: {error}", destination.display()))?;
            println!("plan_actions={}", plan.actions.len());
            println!("plan_blockers={}", plan.blockers.len());
            println!("ready_to_apply={}", plan.ready_to_apply());
            println!("plan_output={}", destination.display());
        }
        (None, None, None) => {}
        _ => {
            return Err(
                "choose one of --observed-intent or --observed-snmp and supply --plan-output"
                    .to_owned(),
            )
        }
    }

    Ok(())
}

fn usage() -> String {
    concat!(
        "usage: mycelium-driver-netgear-fastpath <startup-config> ",
        "[--redacted-output <path>] [--intent-output <path>] ",
        "[(--observed-intent <path> | --observed-snmp <path>) --plan-output <path> ",
        "[--allow-deletes] [--allow-model-mismatch]]"
    )
    .to_owned()
}
