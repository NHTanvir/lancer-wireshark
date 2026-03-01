//! `-T fields -e <field>` — selected fields, separator-delimited.

use super::OutputOptions;
use anyhow::Result;
use epan::register::Registry;
use epan::{PInfo, ProtoTree};
use std::io::Write;

pub fn write<W: Write>(w: &mut W, opts: &OutputOptions, _: &PInfo, tree: &ProtoTree, reg: &Registry) -> Result<()> {
    let mut row = Vec::new();
    for f in &opts.fields {
        let values: Vec<String> = tree
            .find_all(reg, f)
            .into_iter()
            .map(|it| {
                let display = reg.field(it.field).map(|f| f.display).unwrap_or(epan::proto::FieldDisplay::BaseNone);
                let vals = reg.field(it.field).and_then(|f| f.vals);
                it.value.display(display, vals)
            })
            .collect();
        let joined = values.join(",");
        if opts.field_quote.is_empty() {
            row.push(joined);
        } else {
            row.push(format!("{}{}{}", opts.field_quote, joined, opts.field_quote));
        }
    }
    writeln!(w, "{}", row.join(&opts.field_sep))?;
    Ok(())
}
