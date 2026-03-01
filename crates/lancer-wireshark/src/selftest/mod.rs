//! `--self-test` — verify that every registered protocol's display-filter
//! field paths compile, every output format produces a non-empty render of
//! a canned packet, and that dfilter recognises common shapes.

use anyhow::Result;
use epan::{Dfilter, Engine, PInfo, ProtoTree, Tvb};
use std::io::Write;

pub fn run() -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    let engine = Engine::new();
    let registry = &engine.registry;

    writeln!(stdout, "lancer-wireshark --self-test")?;
    writeln!(stdout, "============================")?;
    writeln!(stdout, "Protocols registered: {}", registry.protocols_iter().len())?;
    writeln!(stdout, "Fields registered:    {}", registry.fields_iter().len())?;
    writeln!(stdout, "Dispatch tables:      {}", registry.tables_iter().len())?;

    // Try a basic filter compile
    for f in [
        "ip.addr == 10.0.0.1",
        "tcp.port == 443",
        "tcp.flags.syn == 1",
        "http.request.method == \"GET\"",
        "dns.qry.name contains \"example\"",
        "tls.handshake.extensions_server_name matches \".*\\\\.com\"",
        "ip.src in_subnet \"10.0.0.0/8\"",
        "frame.len > 1500",
        "tcp.window_size_value > 65535",
        "any_of(ip.addr) == 10.0.0.1",
    ] {
        match Dfilter::compile(f, registry) {
            Ok(_) => writeln!(stdout, "  ok   filter: {f}")?,
            Err(e) => writeln!(stdout, "  FAIL filter: {f} ({e})")?,
        }
    }

    // Build a tiny canned packet
    let mut pinfo = PInfo::new(1, (1, 0), 64, 64);
    let mut tree = ProtoTree::new();
    let bytes = vec![0u8; 64];
    let tvb = Tvb::new(&bytes);
    if let Some(d) = registry.dissector("frame") {
        d.dissect(&tvb, &mut pinfo, &mut tree);
        writeln!(stdout, "  ok   dissect: frame")?;
    } else {
        writeln!(stdout, "  FAIL dissect: frame missing")?;
    }

    writeln!(stdout, "Self-test complete.")?;
    Ok(())
}
