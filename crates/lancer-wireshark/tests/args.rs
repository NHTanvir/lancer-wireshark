//! Smoke tests for the tshark-style argv parser.

use lancer_wireshark::cli::args::parse;

fn parse_args(extra: &[&str]) -> lancer_wireshark::cli::args::Args {
    let mut v = vec!["lancer-wireshark-cli".to_string()];
    v.extend(extra.iter().map(|s| s.to_string()));
    parse(v).expect("parse")
}

#[test]
fn parses_read_file() {
    let a = parse_args(&["-r", "in.pcap"]);
    assert_eq!(a.read.as_deref(), Some("in.pcap"));
}

#[test]
fn parses_display_filter() {
    let a = parse_args(&["-Y", "ip.addr == 10.0.0.1"]);
    assert_eq!(a.display_filter.as_deref(), Some("ip.addr == 10.0.0.1"));
}

#[test]
fn parses_stats_z() {
    let a = parse_args(&["-z", "io,stat,1"]);
    assert_eq!(a.stats, vec!["io,stat,1".to_string()]);
}

#[test]
fn parses_fields_combo() {
    let a = parse_args(&["-T", "fields", "-e", "frame.number", "-e", "http.host"]);
    assert_eq!(a.output_format.as_deref(), Some("fields"));
    assert_eq!(a.fields, vec!["frame.number".to_string(), "http.host".to_string()]);
}

#[test]
fn parses_compress() {
    let a = parse_args(&["--compress", "gzip"]);
    assert_eq!(a.compress.as_deref(), Some("gzip"));
}
