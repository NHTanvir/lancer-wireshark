//! Tab-separated summary output.

use super::OutputOptions;
use anyhow::Result;
use epan::register::Registry;
use epan::{PInfo, ProtoTree};
use std::io::Write;

pub fn write<W: Write>(w: &mut W, _: &OutputOptions, pinfo: &PInfo, tree: &ProtoTree, _: &Registry) -> Result<()> {
    let ts = wsutil::format_timestamp(pinfo.timestamp_secs, pinfo.timestamp_nanos, (0, 0), (0, 0), wsutil::time::TimeFmt::Relative);
    let src = pinfo.src_addr.map(|a| a.to_string()).unwrap_or_else(|| "-".into());
    let dst = pinfo.dst_addr.map(|a| a.to_string()).unwrap_or_else(|| "-".into());
    let proto = tree.last_layer().unwrap_or("?");
    writeln!(w, "{}\t{}\t{}\t{}\t{}\t{}\t{}", pinfo.frame_number, ts, src, dst, proto, pinfo.captured_len, pinfo.info)?;
    Ok(())
}
