//! Output formats: text, tabs, pdml, psml, json, jsonraw, ek, fields.

pub mod text;
pub mod tabs;
pub mod pdml;
pub mod psml;
pub mod json;
pub mod fields;
pub mod ek;

use anyhow::Result;
use epan::register::Registry;
use epan::{PInfo, ProtoTree};
use std::io::Write;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Text,
    Tabs,
    Pdml,
    Psml,
    Json,
    JsonRaw,
    Ek,
    Fields,
}

impl Format {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "text" => Format::Text,
            "tabs" => Format::Tabs,
            "pdml" => Format::Pdml,
            "psml" => Format::Psml,
            "json" => Format::Json,
            "jsonraw" => Format::JsonRaw,
            "ek" => Format::Ek,
            "fields" => Format::Fields,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct OutputOptions {
    pub format: Option<Format>,
    pub verbose: bool,
    pub hexdump: bool,
    pub hexdump_opts: Option<String>,
    pub color: bool,
    pub fields: Vec<String>,
    pub field_sep: String,
    pub field_quote: String,
    pub field_header: bool,
    pub no_duplicate_keys: bool,
    pub only_protos: Vec<String>,
}

pub struct Writer {
    pub opts: OutputOptions,
    pub first: bool,
}

impl Writer {
    pub fn new(opts: OutputOptions) -> Self {
        Self { opts, first: true }
    }

    pub fn header<W: Write>(&mut self, w: &mut W) -> Result<()> {
        match self.opts.format.unwrap_or(Format::Text) {
            Format::Pdml => writeln!(w, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<pdml>")?,
            Format::Psml => writeln!(w, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<psml>")?,
            Format::Json => writeln!(w, "[")?,
            Format::Fields if self.opts.field_header => {
                writeln!(w, "{}", self.opts.fields.join(&self.opts.field_sep))?;
            }
            _ => {}
        }
        Ok(())
    }

    pub fn write_packet<W: Write>(&mut self, w: &mut W, pinfo: &PInfo, tree: &ProtoTree, reg: &Registry, raw: &[u8]) -> Result<()> {
        let fmt = self.opts.format.unwrap_or(Format::Text);
        match fmt {
            Format::Text => text::write(w, &self.opts, pinfo, tree, reg, raw)?,
            Format::Tabs => tabs::write(w, &self.opts, pinfo, tree, reg)?,
            Format::Pdml => pdml::write(w, &self.opts, pinfo, tree, reg)?,
            Format::Psml => psml::write(w, &self.opts, pinfo, tree, reg)?,
            Format::Json | Format::JsonRaw => json::write(w, &self.opts, pinfo, tree, reg, raw, &mut self.first, matches!(fmt, Format::JsonRaw))?,
            Format::Ek => ek::write(w, &self.opts, pinfo, tree, reg)?,
            Format::Fields => fields::write(w, &self.opts, pinfo, tree, reg)?,
        }
        Ok(())
    }

    pub fn footer<W: Write>(&mut self, w: &mut W) -> Result<()> {
        match self.opts.format.unwrap_or(Format::Text) {
            Format::Pdml => writeln!(w, "</pdml>")?,
            Format::Psml => writeln!(w, "</psml>")?,
            Format::Json => writeln!(w, "\n]")?,
            _ => {}
        }
        Ok(())
    }
}
