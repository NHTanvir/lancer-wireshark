//! Natural-language → display-filter generator.
//!
//! Round-trips through the [`epan::Dfilter`] type-checker so we never emit a
//! filter the engine will reject.

use super::{ChatMessage, Provider};
use anyhow::Result;
use epan::Dfilter;

pub fn translate(nl: &str, provider: &dyn Provider, reg: &epan::Registry) -> Result<String> {
    let system = ChatMessage {
        role: "system".into(),
        content: "You are an expert in Wireshark/tshark display filters. \
                  Given a natural-language description, output ONLY a single \
                  display-filter expression. No prose, no markdown.".into(),
    };
    let user = ChatMessage {
        role: "user".into(),
        content: nl.into(),
    };
    let raw = provider.complete(&[system, user])?;
    let candidate = raw.trim().trim_matches('`').to_string();
    // Validate before returning so the GUI / CLI never runs a broken filter.
    Dfilter::compile(&candidate, reg).map_err(|e| anyhow::anyhow!("LLM returned invalid filter: {e}"))?;
    Ok(candidate)
}
