//! `rawshark` — read raw frames from stdin (no pcap header) and emit
//! newline-delimited JSON dissection.

use anyhow::Result;
use clap::Parser;
use epan::{Engine, PInfo, ProtoTree, Tvb};
use std::io::{BufRead, Write};

#[derive(Parser, Debug)]
#[command(name = "rawshark", version, about = "rawshark-equivalent — header-less stream dissection")]
struct Args {
    #[arg(short = 'l', default_value_t = 1)]
    link_type: u32,
    #[arg(short = 's', default_value_t = 262_144)]
    snaplen: u32,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let engine = Engine::new();
    let mut stdout = std::io::stdout().lock();
    let stdin = std::io::stdin();
    let mut n = 0u64;
    for line in stdin.lock().lines() {
        let bytes = hex::decode(line?.trim()).unwrap_or_default();
        n += 1;
        let mut pinfo = PInfo::new(n, (0, 0), bytes.len() as u32, bytes.len() as u32);
        let mut tree = ProtoTree::new();
        let _ = pinfo.link_type;
        let tvb = Tvb::new(&bytes);
        if let Some(d) = engine.registry.dissector("frame") {
            d.dissect(&tvb, &mut pinfo, &mut tree);
        }
        if args.link_type == 1 {
            if let Some(d) = engine.registry.dissector("eth") {
                d.dissect(&tvb, &mut pinfo, &mut tree);
            }
        }
        let obj = serde_json::json!({
            "frame": n,
            "len": bytes.len(),
            "proto_stack": tree.proto_stack,
            "info": pinfo.info,
        });
        writeln!(stdout, "{obj}")?;
        let _ = args.snaplen;
    }
    Ok(())
}
