//! PSML — Packet Summary Markup Language (XML, summary lines).

use super::OutputOptions;
use anyhow::Result;
use epan::register::Registry;
use epan::{PInfo, ProtoTree};
use std::io::Write;

pub fn write<W: Write>(w: &mut W, _: &OutputOptions, pinfo: &PInfo, tree: &ProtoTree, _: &Registry) -> Result<()> {
    let proto = tree.last_layer().unwrap_or("?");
    writeln!(
        w,
        "  <packet><section>{}</section><section>{}</section><section>{}</section><section>{}</section><section>{}</section></packet>",
        pinfo.frame_number,
        pinfo.timestamp_secs,
        proto,
        pinfo.captured_len,
        escape_xml(&pinfo.info)
    )?;
    Ok(())
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}
