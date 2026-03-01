//! `lancer-wireshark` — library surface so the CLI binary can re-use
//! the same modules as the GUI entry point.

pub mod cli;
pub mod output;
pub mod stats;
pub mod gui;
pub mod ai;
pub mod selftest;
pub mod ipc;
pub mod profile_io;

/// Re-export of the capture crate so old `crate::capture::*` paths
/// continue to resolve.
pub use lancer_wireshark_capture as capture;
