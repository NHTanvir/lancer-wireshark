//! `lancer-wireshark` — entry point.
//!
//! Default invocation opens the egui GUI. With `--cli` (or invoking the
//! sibling `lancer-wireshark-cli` binary) the upstream tshark surface is
//! exposed unchanged. `--self-test` runs the parity matrix.

use anyhow::Result;
use clap::Parser;

use lancer_wireshark::{cli, gui, selftest};

#[derive(Parser, Debug)]
#[command(
    name = "lancer-wireshark",
    version,
    about = "Rust clone of wireshark — CLI + GUI",
    long_about = "lancer-wireshark — Rust clone of wireshark. \n\
        Default invocation opens the native GUI. \n\
        Pass --cli to invoke the tshark-equivalent command line."
)]
struct LauncherArgs {
    /// Drop into the tshark-equivalent CLI surface.
    #[arg(long)]
    cli: bool,

    /// Run the parity self-test matrix and exit.
    #[arg(long)]
    self_test: bool,

    /// Print version + build info and exit.
    #[arg(long)]
    build_info: bool,

    /// Trailing args forwarded to the CLI surface when `--cli` is set.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    rest: Vec<String>,
}

fn main() -> Result<()> {
    wsutil::logging::init(&wsutil::logging::LogConfig::default());

    // Fast detection: if the user invoked us with any CLI-typical flag, route
    // through the CLI even without explicit `--cli`. This matches upstream tshark.
    let raw: Vec<String> = std::env::args().collect();
    if raw.iter().any(|a| matches!(a.as_str(), "-r" | "-w" | "-i" | "-D" | "-G" | "-z" | "-Y" | "-T" | "-V" | "-x" | "--cli")) {
        return cli::run(raw);
    }

    let args = LauncherArgs::try_parse_from(&raw).unwrap_or(LauncherArgs {
        cli: false,
        self_test: false,
        build_info: false,
        rest: Vec::new(),
    });

    if args.build_info {
        println!("lancer-wireshark {}", env!("CARGO_PKG_VERSION"));
        println!("Lancer toolkit — Rust clone of wireshark");
        println!("Built {} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    if args.self_test {
        return selftest::run();
    }

    if args.cli {
        return cli::run(args.rest);
    }

    // Default: launch the GUI.
    gui::launch()
}
