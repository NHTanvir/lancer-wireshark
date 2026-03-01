//! `capinfos` — print stats about a capture file.

use anyhow::Result;
use clap::Parser;
use sha2::{Digest, Sha256};

#[derive(Parser, Debug)]
#[command(name = "capinfos", version, about = "capinfos-equivalent")]
struct Args {
    #[arg(short = 'M')]
    machine: bool,
    files: Vec<String>,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    for f in &args.files {
        report_one(f, args.machine)?;
    }
    Ok(())
}

fn report_one(path: &str, machine: bool) -> Result<()> {
    let mut src = lancer_wireshark_capture::open_offline(path)?;
    let mut n = 0u64;
    let mut bytes = 0u64;
    let mut first = None;
    let mut last = (0i64, 0u32);
    let mut hasher = Sha256::new();
    while let Some(f) = src.next()? {
        n += 1;
        bytes += f.captured_len as u64;
        if first.is_none() {
            first = Some((f.ts_secs, f.ts_nanos));
        }
        last = (f.ts_secs, f.ts_nanos);
        hasher.update(&f.data);
    }
    let digest = hex::encode(&hasher.finalize()[..16]);
    let (fs, fn_) = first.unwrap_or((0, 0));
    let (ls, ln) = last;
    let duration = (ls - fs) as f64 + (ln as f64 - fn_ as f64) / 1_000_000_000.0;
    if machine {
        let m = serde_json::json!({
            "file": path,
            "packets": n,
            "bytes": bytes,
            "duration": duration,
            "sha256_first16": digest,
            "link_type": src.link_type(),
        });
        println!("{}", m);
    } else {
        println!("File name:           {path}");
        println!("Number of packets:   {n}");
        println!("File size:           {bytes} bytes");
        println!("Capture duration:    {duration:.3} seconds");
        println!("First packet time:   {fs}.{fn_:09}");
        println!("Last packet time:    {ls}.{ln:09}");
        println!("Link layer type:     {}", src.link_type());
        println!("SHA256 (first 16B):  {digest}");
    }
    Ok(())
}
