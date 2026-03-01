//! PDML — Packet Details Markup Language (XML).

use super::OutputOptions;
use anyhow::Result;
use epan::proto::ProtoItem;
use epan::register::Registry;
use epan::{PInfo, ProtoTree};
use std::io::Write;

pub fn write<W: Write>(w: &mut W, _: &OutputOptions, pinfo: &PInfo, tree: &ProtoTree, reg: &Registry) -> Result<()> {
    writeln!(
        w,
        "  <packet num=\"{}\" cap_len=\"{}\" len=\"{}\" timestamp=\"{}.{:09}\">",
        pinfo.frame_number, pinfo.captured_len, pinfo.original_len, pinfo.timestamp_secs, pinfo.timestamp_nanos
    )?;
    for item in &tree.items {
        write_item(w, item, 2, reg)?;
    }
    writeln!(w, "  </packet>")?;
    Ok(())
}

fn write_item<W: Write>(w: &mut W, item: &ProtoItem, indent: usize, reg: &Registry) -> Result<()> {
    let pad = " ".repeat(indent);
    let abbr = reg.field(item.field).map(|f| f.abbr.to_string()).unwrap_or_default();
    let show = item.label.clone().unwrap_or_else(|| {
        reg.field(item.field).map(|f| f.display_name.to_string()).unwrap_or_default()
    });
    let value = match &item.value {
        epan::proto::FieldValue::None => String::new(),
        v => {
            let display = reg.field(item.field).map(|f| f.display).unwrap_or(epan::proto::FieldDisplay::BaseNone);
            let vals = reg.field(item.field).and_then(|f| f.vals);
            v.display(display, vals)
        }
    };
    let show = escape_xml(&show);
    let value = escape_xml(&value);
    writeln!(
        w,
        "{pad}<{tag} name=\"{abbr}\" pos=\"{pos}\" size=\"{size}\" show=\"{show}\" value=\"{value}\">",
        tag = if item.is_subtree { "proto" } else { "field" },
        pos = item.abs_offset,
        size = item.length,
    )?;
    for c in &item.children {
        write_item(w, c, indent + 2, reg)?;
    }
    writeln!(
        w,
        "{pad}</{tag}>",
        tag = if item.is_subtree { "proto" } else { "field" }
    )?;
    Ok(())
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
