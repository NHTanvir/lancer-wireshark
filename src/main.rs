//! lancer-wireshark
//! Rust clone of wireshark. See plan.md (local, gitignored) for the spec.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "lancer-wireshark", version, about = "Rust clone of wireshark")]
struct Cli {}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let _cli = Cli::parse();
    println!("lancer-wireshark - scaffold ready. Implement per plan.md.");
    Ok(())
}
