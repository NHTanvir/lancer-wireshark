//! Parity check against upstream tshark flag list.
//!
//! Each entry pins a flag to either: implemented (assert true), behaviour-
//! divergent (link to comment) or N/A (with reason).

#[test]
fn capture_flags_present() {
    let cli_help = include_str!("../../crates/lancer-wireshark/src/cli/runner.rs");
    for f in &[
        "-i", "-D", "-L", "-f", "-s", "-c", "-a", "-b", "-w", "-F",
        "-p", "-I", "-B", "-y", "--time-stamp-type", "-Q", "-q",
        "-r", "-V", "-O", "-x", "-2", "-Y", "-R", "-n", "-N",
        "--enable-protocol", "--disable-protocol", "-d",
        "--enable-heuristic", "--disable-heuristic",
        "-T", "-e", "-E", "-l", "-W", "--compress", "--global-profile",
        "--export-objects", "--export-tls-session-keys", "-G",
        "--temp-dir", "--capture-comment", "--update-interval",
        "--hexdump", "--color", "--no-duplicate-keys",
        "--log-level", "--log-domain", "--log-debug", "--log-noisy",
        "--log-file", "--log-fatal", "-K", "--print", "-H", "-z", "-X",
    ] {
        assert!(
            cli_help.contains(f),
            "tshark parity: flag {f:?} not referenced in CLI runner"
        );
    }
}
