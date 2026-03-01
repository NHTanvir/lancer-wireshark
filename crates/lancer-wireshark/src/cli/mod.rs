//! `tshark`-equivalent CLI surface. Exposes every documented flag from
//! plan.md "## Granular feature catalog" with the same semantics where
//! possible.

pub mod args;
pub mod runner;
pub mod g_reports;

use anyhow::Result;

pub fn run(argv: Vec<String>) -> Result<()> {
    let args = args::parse(argv)?;
    runner::run(args)
}
