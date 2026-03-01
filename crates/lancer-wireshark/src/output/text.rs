//! Default text output — single-line summary, optional verbose tree, optional hex.

use super::OutputOptions;
use anyhow::Result;
use epan::register::Registry;
use epan::{PInfo, ProtoTree};
use epan::proto::ProtoItem;
use std::io::Write;

pub fn write<W: Write>(
    w: &mut W,
    opts: &OutputOptions,
    pinfo: &PInfo,
    tree: &ProtoTree,
    reg: &Registry,
    raw: &[u8],
) -> Result<()> {
    let ts = wsutil::format_timestamp(pinfo.timestamp_secs, pinfo.timestamp_nanos, (0, 0), (0, 0), wsutil::time::TimeFmt::Relative);
    let src = pinfo
        .src_addr
        .map(|a| a.to_string())
        .or_else(|| pinfo.src_mac.map(wsutil::mac::format_mac))
        .unwrap_or_else(|| "-".into());
    let dst = pinfo
        .dst_addr
        .map(|a| a.to_string())
        .or_else(|| pinfo.dst_mac.map(wsutil::mac::format_mac))
        .unwrap_or_else(|| "-".into());
    let proto = tree.last_layer().unwrap_or("?");
    writeln!(
        w,
        "{:>5}  {ts}  {:<22} -> {:<22}  {:<8} {:>4}  {}",
        pinfo.frame_number,
        src,
        dst,
        proto,
        pinfo.captured_len,
        pinfo.info,
    )?;

    if opts.verbose {
        for item in &tree.items {
            write_tree(w, item, 0, reg)?;
        }
    }
    if opts.hexdump {
        let opts = opts.hexdump_opts.as_deref().map(wsutil::hexdump::HexdumpOpts::parse).unwrap_or_default();
        write!(w, "{}", wsutil::hexdump::format_hexdump_with(raw, opts))?;
    }
    Ok(())
}

fn write_tree<W: Write>(w: &mut W, item: &ProtoItem, depth: usize, reg: &Registry) -> Result<()> {
    let indent = "    ".repeat(depth);
    let name = item
        .label
        .clone()
        .unwrap_or_else(|| reg.field(item.field).map(|f| f.display_name.to_string()).unwrap_or_default());
    let display = if matches!(item.value, epan::proto::FieldValue::None) {
        name
    } else {
        let display = reg.field(item.field).map(|f| f.display).unwrap_or(epan::proto::FieldDisplay::BaseNone);
        let vals = reg.field(item.field).and_then(|f| f.vals);
        let v = item.value.display(display, vals);
        format!("{name}: {v}")
    };
    writeln!(w, "{indent}{display}")?;
    for c in &item.children {
        write_tree(w, c, depth + 1, reg)?;
    }
    Ok(())
}
