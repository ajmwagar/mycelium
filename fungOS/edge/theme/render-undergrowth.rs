//! Original shader-style distance-field kernel, frozen on the CPU at build time.
//! No Shadertoy source is used. License: MIT (same as this repository).
use std::{
    fs::File,
    io::{BufWriter, Write},
    process::ExitCode,
};

fn hash(x: i32, y: i32) -> f64 {
    let mut n = (x as u32).wrapping_mul(374761393) ^ (y as u32).wrapping_mul(668265263);
    n = (n ^ (n >> 13)).wrapping_mul(1274126177);
    (n ^ (n >> 16)) as f64 / u32::MAX as f64
}
fn noise(x: f64, y: f64) -> f64 {
    let (i, j) = (x.floor() as i32, y.floor() as i32);
    let (u, v) = (x - x.floor(), y - y.floor());
    let (u, v) = (u * u * (3.0 - 2.0 * u), v * v * (3.0 - 2.0 * v));
    let a = hash(i, j) * (1.0 - u) + hash(i + 1, j) * u;
    let b = hash(i, j + 1) * (1.0 - u) + hash(i + 1, j + 1) * u;
    a * (1.0 - v) + b * v
}
fn smooth(a: f64, b: f64, v: f64) -> f64 {
    let t = ((v - a) / (b - a)).clamp(0.0, 1.0);
    t * t * (3.0 - 2.0 * t)
}
fn pixel(x: f64, y: f64) -> [u8; 3] {
    let n = noise(x * 5.0, y * 5.0) * 0.6
        + noise(x * 17.0, y * 17.0) * 0.3
        + noise(x * 61.0, y * 61.0) * 0.1;
    let mut c = [16.0 + n * 10.0, 21.0 + n * 12.0, 20.0 + n * 9.0];
    // Off-center bracket-fungus rosettes: irregular growth contours, gills and
    // quiet lichen edges leave the upper-left desktop calm for windows/icons.
    for (cx, cy, scale, phase) in [
        (1.20, 0.66, 0.51, 1.2),
        (1.01, 0.87, 0.33, 3.0),
        (1.49, 0.91, 0.39, 4.8),
    ] {
        let dx = x - cx;
        let dy = (y - cy) * 1.24;
        let theta = dy.atan2(dx);
        let r = (dx * dx + dy * dy).sqrt() / scale;
        let warp = (theta * 7.0 + phase).sin() * 0.035
            + (theta * 13.0 - phase).cos() * 0.013
            + noise(x * 23.0, y * 23.0) * 0.045;
        let d = r + warp;
        let mask = 1.0 - smooth(0.98, 1.015, d);
        let rings = (d * 53.0 + (theta * 4.0).sin() * 0.7).sin() * 0.5 + 0.5;
        let ridge = rings.powf(8.0);
        let edge = smooth(0.88, 0.98, d) * (1.0 - smooth(0.98, 1.015, d));
        let light = (0.52 - dy * 0.6 - dx * 0.2).clamp(0.2, 0.85);
        let tone = [
            28.0 + light * 35.0 + ridge * 12.0 + edge * 40.0,
            35.0 + light * 34.0 + ridge * 14.0 + edge * 41.0,
            29.0 + light * 26.0 + ridge * 10.0 + edge * 26.0,
        ];
        for i in 0..3 {
            c[i] = c[i] * (1.0 - mask) + tone[i] * mask;
        }
    }
    let vignette = 1.0 - 0.24 * ((x - 0.8).powi(2) + (y - 0.5).powi(2));
    c.map(|v| (v * vignette).clamp(0.0, 255.0) as u8)
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 {
        return Err("usage: render-undergrowth WIDTH HEIGHT OUTPUT.ppm".into());
    }
    let w: usize = args[1].parse()?;
    let h: usize = args[2].parse()?;
    if w == 0 || h == 0 || w > 4096 || h > 4096 {
        return Err("dimensions must be 1..4096".into());
    }
    let mut out = BufWriter::new(File::create(&args[3])?);
    write!(out, "P6\n{w} {h}\n255\n")?;
    for y in 0..h {
        for x in 0..w {
            out.write_all(&pixel(x as f64 / h as f64, y as f64 / h as f64))?;
        }
    }
    out.flush()?;
    Ok(())
}
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn repeatable() {
        assert_eq!(pixel(1.0, 0.7), pixel(1.0, 0.7));
    }
    #[test]
    fn texture_not_flat() {
        assert_ne!(pixel(0.1, 0.1), pixel(1.2, 0.7));
    }
    #[test]
    fn noise_bounded() {
        for i in -20..20 {
            assert!((0.0..=1.0).contains(&noise(i as f64 * 0.23, 0.3)));
        }
    }
}
