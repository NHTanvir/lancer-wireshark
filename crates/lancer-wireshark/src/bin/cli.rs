//! `lancer-wireshark-cli` — the CLI-only entry point for headless usage.

use anyhow::Result;

fn main() -> Result<()> {
    wsutil::logging::init(&wsutil::logging::LogConfig::default());
    let raw: Vec<String> = std::env::args().collect();
    lancer_wireshark::cli::run(raw)
}
