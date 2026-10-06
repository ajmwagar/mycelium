//! Read-only QEMU framebuffer capture. Never sends input or alters VM state.
use std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    time::Duration,
};
fn response(reader: &mut BufReader<UnixStream>) -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..100 {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Err("QMP disconnected".into());
        }
        if line.len() > 65536 {
            return Err("QMP response exceeds limit".into());
        }
        if line.contains("\"error\"") {
            return Err(line.into());
        }
        if line.contains("\"return\"") {
            return Ok(());
        }
    }
    Err("QMP returned too many unrelated events".into())
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err("usage: capture-qmp QMP_SOCKET OUTPUT.ppm".into());
    }
    let output = &args[2];
    if !output.starts_with('/')
        || !output
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/-_.".contains(&b))
    {
        return Err(
            "output requires an absolute ASCII path without shell/JSON metacharacters".into(),
        );
    }
    let mut stream = UnixStream::connect(&args[1])?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut greeting = String::new();
    reader.read_line(&mut greeting)?;
    if !greeting.contains("\"QMP\"") {
        return Err("not a QMP socket".into());
    }
    stream.write_all(b"{\"execute\":\"qmp_capabilities\"}\n")?;
    response(&mut reader)?;
    writeln!(
        stream,
        "{{\"execute\":\"screendump\",\"arguments\":{{\"filename\":\"{output}\"}}}}"
    )?;
    response(&mut reader)?;
    if std::fs::metadata(output)?.len() < 20 {
        return Err("empty screendump".into());
    }
    Ok(())
}
