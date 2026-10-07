//! Loopback-only, no-auth RFB framebuffer read. No keyboard/pointer messages.
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::Duration,
};
fn u16be(s: &mut TcpStream) -> std::io::Result<u16> {
    let mut b = [0; 2];
    s.read_exact(&mut b)?;
    Ok(u16::from_be_bytes(b))
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let a: Vec<_> = std::env::args().collect();
    if a.len() != 3 {
        return Err("usage: capture-vnc 127.0.0.1:PORT OUTPUT.ppm".into());
    }
    let address: SocketAddr = a[1].parse()?;
    if !address.ip().is_loopback() {
        return Err("only loopback VNC is allowed".into());
    }
    let mut s = TcpStream::connect_timeout(&address, Duration::from_secs(10))?;
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    s.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut b = [0; 12];
    s.read_exact(&mut b)?;
    if &b != b"RFB 003.008\n" {
        return Err("requires RFB3.8".into());
    }
    s.write_all(&b)?;
    let mut n = [0];
    s.read_exact(&mut n)?;
    let mut methods = vec![0; n[0] as usize];
    s.read_exact(&mut methods)?;
    if !methods.contains(&1) {
        return Err("no-auth loopback VNC unavailable".into());
    }
    s.write_all(&[1])?;
    let mut result = [0; 4];
    s.read_exact(&mut result)?;
    if result != [0; 4] {
        return Err("VNC security rejected".into());
    }
    s.write_all(&[1])?;
    let w = u16be(&mut s)? as usize;
    let h = u16be(&mut s)? as usize;
    if w == 0 || h == 0 || w > 4096 || h > 4096 {
        return Err("invalid framebuffer dimensions".into());
    }
    let mut format = [0; 16];
    s.read_exact(&mut format)?;
    let mut len = [0; 4];
    s.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > 65536 {
        return Err("VNC name too long".into());
    }
    let mut name = vec![0; len];
    s.read_exact(&mut name)?;
    // 32bpp little-endian true-color BGRA; request Raw only and whole framebuffer.
    s.write_all(&[
        0, 0, 0, 0, 32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0,
    ])?;
    s.write_all(&[2, 0, 0, 1, 0, 0, 0, 0])?;
    let mut request = vec![3, 0, 0, 0, 0, 0];
    request.extend_from_slice(&(w as u16).to_be_bytes());
    request.extend_from_slice(&(h as u16).to_be_bytes());
    s.write_all(&request)?;
    let mut ty = [0; 2];
    s.read_exact(&mut ty)?;
    if ty[0] != 0 {
        return Err("expected framebuffer update".into());
    }
    let count = u16be(&mut s)?;
    let mut pixels = vec![0; w * h * 3];
    let mut coverage = vec![false; w * h];
    for _ in 0..count {
        let x = u16be(&mut s)? as usize;
        let y = u16be(&mut s)? as usize;
        let rw = u16be(&mut s)? as usize;
        let rh = u16be(&mut s)? as usize;
        let mut enc = [0; 4];
        s.read_exact(&mut enc)?;
        if enc != [0; 4] || x + rw > w || y + rh > h {
            return Err("unexpected framebuffer rectangle".into());
        }
        let mut raw = vec![0; rw * rh * 4];
        s.read_exact(&mut raw)?;
        for row in 0..rh {
            for col in 0..rw {
                let source = (row * rw + col) * 4;
                let target = (y + row) * w + x + col;
                pixels[target * 3..target * 3 + 3].copy_from_slice(&[
                    raw[source + 2],
                    raw[source + 1],
                    raw[source],
                ]);
                coverage[target] = true;
            }
        }
    }
    if !coverage.iter().all(|v| *v) {
        return Err("incomplete framebuffer; refusing partial screenshot".into());
    }
    let mut output = std::fs::File::create(&a[2])?;
    write!(output, "P6\n{w} {h}\n255\n")?;
    output.write_all(&pixels)?;
    Ok(())
}
