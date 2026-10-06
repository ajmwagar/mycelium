//! A bounded profiler for the existing isolated fungos-smoke Shroud fixture.
//! Uses Shroud's control socket; does not implement workload orchestration.
use serde_json::{json, Value};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    time::{Duration, Instant},
};

const SOCKET: &str = "/var/lib/shroud/control.sock";
const LOG: &str = "/var/lib/shroud/logs/fc_fungos-smoke.log";
const VM: &str = "fungos-smoke";
const MARKER: &str = "FUNGOS_MICROVM_OK";
const LIMIT: u64 = 1_048_576;
const TIMEOUT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(10);

fn rpc(action: &str) -> Result<Value, String> {
    let mut stream = UnixStream::connect(SOCKET).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(TIMEOUT))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(TIMEOUT))
        .map_err(|e| e.to_string())?;
    writeln!(stream, "{}", json!({"action":action,"vm":VM})).map_err(|e| e.to_string())?;
    let mut response = Vec::new();
    BufReader::new(stream)
        .take(LIMIT)
        .read_until(b'\n', &mut response)
        .map_err(|e| e.to_string())?;
    if response.last() != Some(&b'\n') {
        return Err("unterminated or oversized Shroud response".into());
    }
    let response: Value = serde_json::from_slice(&response).map_err(|e| e.to_string())?;
    if response["protocol"].as_str() != Some("shroud.control.v1") {
        return Err("unsupported Shroud control protocol".into());
    }
    if response["ok"].as_bool() != Some(true) {
        return Err(format!("Shroud {action} failed: {}", response["message"]));
    }
    Ok(response)
}

fn stopped(response: &Value) -> Result<bool, String> {
    // The existing v1 response omits empty VM arrays.
    if response.get("vms").is_none()
        && response["ok"].as_bool() == Some(true)
        && response["protocol"].as_str() == Some("shroud.control.v1")
    {
        return Ok(true);
    }
    let vms = response["vms"].as_array().ok_or("missing Shroud VM list")?;
    Ok(!vms.iter().any(|vm| vm["name"].as_str() == Some(VM)))
}

fn marker_present(bytes: &[u8]) -> bool {
    bytes
        .split(|byte| *byte == b'\n')
        .any(|line| line.strip_suffix(b"\r").unwrap_or(line) == MARKER.as_bytes())
}

fn guest_marker(start: Instant) -> Result<f64, String> {
    // The owning Shroud start path truncates this fixture's log before it
    // starts Firecracker and acknowledges the request. Read only after ACK:
    // a marker from an earlier run must not count. This is an observation
    // upper bound, not the precise instant of execution inside the guest.
    loop {
        let mut bytes = Vec::new();
        fs::File::open(LOG)
            .map_err(|e| e.to_string())?
            .take(LIMIT + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() as u64 > LIMIT {
            return Err("fixture serial log exceeds bounded observation size".into());
        }
        if marker_present(&bytes) {
            return Ok(start.elapsed().as_secs_f64() * 1000.0);
        }
        if start.elapsed() >= TIMEOUT {
            return Err("timed out waiting for fresh guest execution marker".into());
        }
        std::thread::sleep(POLL);
    }
}

fn sample() -> Result<Value, String> {
    if !stopped(&rpc("list")?)? {
        return Err("fixture is already running; refusing to interrupt it".into());
    }
    let start = Instant::now();
    rpc("start").map_err(|error| {
        format!(
        "start failed; ownership/state is uncertain, inspect fixture before manual cleanup: {error}"
    )
    })?;
    let ack_ms = start.elapsed().as_secs_f64() * 1000.0;
    // This is an explicitly owned, previously stopped disposable fixture.
    // Always attempt cleanup after acknowledged start, including marker failure.
    // An unacknowledged start does not prove ownership; never stop another VM.
    let observed = guest_marker(start);
    let stop_start = Instant::now();
    let cleanup = rpc("stop");
    let stop_ms = stop_start.elapsed().as_secs_f64() * 1000.0;
    cleanup
        .map_err(|error| format!("fixture cleanup failed: {error}; observation={observed:?}"))?;
    if !stopped(&rpc("list")?)? {
        return Err("fixture remains running after stop".into());
    }
    let marker_ms = observed?;
    Ok(json!({"start_ack_ms":ack_ms,"guest_marker_observed_ms":marker_ms,"stop_ack_ms":stop_ms}))
}

fn percentile(values: &[f64], percentile: f64) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let index = ((sorted.len() as f64 * percentile).ceil() as usize).saturating_sub(1);
    sorted[index.min(sorted.len() - 1)]
}

fn iterations(args: &[String]) -> Result<usize, String> {
    if args.len() != 3 || args[0] != "--write" || args[1] != "--iterations" {
        return Err("usage: fungos-boot-profile --write --iterations N (1..20); starts/stops only fungos-smoke".into());
    }
    let count: usize = args[2].parse().map_err(|_| "invalid iteration count")?;
    if !(1..=20).contains(&count) {
        return Err("iterations must be 1..20".into());
    }
    Ok(count)
}

fn run() -> Result<(), String> {
    let count = iterations(&std::env::args().skip(1).collect::<Vec<_>>())?;
    if !Path::new("/dev/kvm").exists() {
        return Err("KVM unavailable; no emulation fallback".into());
    }
    let mut samples = Vec::new();
    for iteration in 1..=count {
        let mut result = sample()?;
        result["iteration"] = json!(iteration);
        eprintln!("sample {iteration}: {result}");
        samples.push(result);
    }
    let latency = samples
        .iter()
        .map(|sample| sample["guest_marker_observed_ms"].as_f64().unwrap())
        .collect::<Vec<_>>();
    println!("{}", serde_json::to_string_pretty(&json!({
        "fixture":VM,"samples":samples,"cache_state":"uncontrolled; no host cache eviction",
        "measurement":"fresh microVM start request to observed guest execution marker; not application health",
        "poll_interval_ms":POLL.as_millis(),"guest_marker_median_ms":percentile(&latency,0.5),
        "guest_marker_p95_ms":percentile(&latency,0.95),"fixture_stopped_after_run":true
    })).map_err(|e| e.to_string())?);
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("boot profiling failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn marker_is_an_exact_guest_output_line() {
        assert!(marker_present(b"init\nFUNGOS_MICROVM_OK\r\nx86_64\n"));
        assert!(!marker_present(b"echo FUNGOS_MICROVM_OK\n"));
        assert!(!marker_present(b"FUNGOS_MICROVM_OK_EXTRA\n"));
    }
    #[test]
    fn bounded_explicit_write_only() {
        assert!(iterations(&[]).is_err());
        for count in [0, 21] {
            assert!(
                iterations(&["--write".into(), "--iterations".into(), count.to_string()]).is_err()
            );
        }
        assert_eq!(
            iterations(&["--write".into(), "--iterations".into(), "5".into()]).unwrap(),
            5
        );
    }
    #[test]
    fn list_requires_evidence_and_will_not_interrupt_existing_vm() {
        assert!(stopped(&json!({})).is_err());
        assert!(stopped(&json!({"ok":true,"protocol":"shroud.control.v1"})).unwrap());
        assert!(!stopped(&json!({"vms":[{"name":VM}]})).unwrap());
        assert!(stopped(&json!({"vms":[{"name":"other"}]})).unwrap());
    }
    #[test]
    fn nearest_rank_percentiles_are_deterministic() {
        assert_eq!(percentile(&[3., 1., 2.], 0.5), 2.);
        assert_eq!(percentile(&[3., 1., 2.], 0.95), 3.);
    }
}
