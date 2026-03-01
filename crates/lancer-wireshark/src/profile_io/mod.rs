//! Profile file I/O — preferences, disabled_protos, decode_as_entries,
//! color filters. Mirrors upstream Wireshark's profile layout under
//! `$config/profiles/<name>/`.

use anyhow::Result;
use std::path::PathBuf;

pub fn save_disabled_protos(profile_name: &str, list: &[String]) -> Result<()> {
    let p = wsutil::profile::Profile::user_named(profile_name).ok_or_else(|| anyhow::anyhow!("no user profiles dir"))?;
    p.ensure_dir()?;
    std::fs::write(p.pref_file("disabled_protos"), list.join("\n"))?;
    Ok(())
}

pub fn load_disabled_protos(profile_name: &str) -> Result<Vec<String>> {
    let p = wsutil::profile::Profile::user_named(profile_name).ok_or_else(|| anyhow::anyhow!("no user profiles dir"))?;
    let path: PathBuf = p.pref_file("disabled_protos");
    if !path.exists() {
        return Ok(Vec::new());
    }
    Ok(std::fs::read_to_string(path)?
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect())
}

pub fn save_decode_as(profile_name: &str, entries: &[epan::decode_as::DecodeAsEntry]) -> Result<()> {
    let p = wsutil::profile::Profile::user_named(profile_name).ok_or_else(|| anyhow::anyhow!("no user profiles dir"))?;
    p.ensure_dir()?;
    let body = entries
        .iter()
        .map(|e| match &e.key {
            epan::decode_as::DecodeAsKey::Uint(v) => format!("{}=={},{}", e.table, v, e.dissector_name),
            epan::decode_as::DecodeAsKey::String(s) => format!("{}=={},{}", e.table, s, e.dissector_name),
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(p.pref_file("decode_as_entries"), body)?;
    Ok(())
}
