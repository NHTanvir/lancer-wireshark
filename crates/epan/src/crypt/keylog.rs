//! SSLKEYLOGFILE / QUIC key log file parser.
//!
//! Supports the NSS / Mozilla / Chromium format:
//!   `<LABEL> <CLIENT_RANDOM-or-CLIENT_DCID hex> <SECRET hex>`
//!
//! Examples:
//!   CLIENT_RANDOM 0a... b1...
//!   CLIENT_HANDSHAKE_TRAFFIC_SECRET 0a... b1...
//!   SERVER_HANDSHAKE_TRAFFIC_SECRET 0a... b1...
//!   CLIENT_TRAFFIC_SECRET_0 0a... b1...
//!   SERVER_TRAFFIC_SECRET_0 0a... b1...
//!   EXPORTER_SECRET 0a... b1...
//!   EARLY_EXPORTER_SECRET 0a... b1...
//!   CLIENT_EARLY_TRAFFIC_SECRET 0a... b1...
//!   QUIC_CLIENT_TRAFFIC_SECRET_0 0a... b1...
//!   QUIC_SERVER_TRAFFIC_SECRET_0 0a... b1...
//!   QUIC_CLIENT_HANDSHAKE_TRAFFIC_SECRET 0a... b1...
//!   QUIC_SERVER_HANDSHAKE_TRAFFIC_SECRET 0a... b1...

use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyLogSecret {
    Tls12ClientRandom,
    Tls13ClientHandshake,
    Tls13ServerHandshake,
    Tls13ClientTraffic0,
    Tls13ServerTraffic0,
    Tls13Exporter,
    Tls13EarlyExporter,
    Tls13ClientEarly,
    QuicClientTraffic0,
    QuicServerTraffic0,
    QuicClientHandshake,
    QuicServerHandshake,
    QuicClientInitial,
    QuicServerInitial,
    Other(String),
}

impl KeyLogSecret {
    pub fn parse(s: &str) -> Self {
        match s {
            "CLIENT_RANDOM" => KeyLogSecret::Tls12ClientRandom,
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET" => KeyLogSecret::Tls13ClientHandshake,
            "SERVER_HANDSHAKE_TRAFFIC_SECRET" => KeyLogSecret::Tls13ServerHandshake,
            "CLIENT_TRAFFIC_SECRET_0" => KeyLogSecret::Tls13ClientTraffic0,
            "SERVER_TRAFFIC_SECRET_0" => KeyLogSecret::Tls13ServerTraffic0,
            "EXPORTER_SECRET" => KeyLogSecret::Tls13Exporter,
            "EARLY_EXPORTER_SECRET" => KeyLogSecret::Tls13EarlyExporter,
            "CLIENT_EARLY_TRAFFIC_SECRET" => KeyLogSecret::Tls13ClientEarly,
            "QUIC_CLIENT_TRAFFIC_SECRET_0" => KeyLogSecret::QuicClientTraffic0,
            "QUIC_SERVER_TRAFFIC_SECRET_0" => KeyLogSecret::QuicServerTraffic0,
            "QUIC_CLIENT_HANDSHAKE_TRAFFIC_SECRET" => KeyLogSecret::QuicClientHandshake,
            "QUIC_SERVER_HANDSHAKE_TRAFFIC_SECRET" => KeyLogSecret::QuicServerHandshake,
            other => KeyLogSecret::Other(other.into()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct KeyLogEntry {
    pub label: KeyLogSecret,
    pub client_random: Vec<u8>, // or QUIC DCID
    pub secret: Vec<u8>,
}

#[derive(Debug, Default, Clone)]
pub struct KeyLog {
    pub entries: Vec<KeyLogEntry>,
}

impl KeyLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load_path<P: AsRef<Path>>(p: P) -> std::io::Result<Self> {
        let s = std::fs::read_to_string(p)?;
        Ok(Self::parse(&s))
    }

    pub fn parse(s: &str) -> Self {
        let mut out = KeyLog::default();
        for line in s.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            let label = match parts.next() {
                Some(s) => s,
                None => continue,
            };
            let cr = match parts.next() {
                Some(s) => s,
                None => continue,
            };
            let secret = match parts.next() {
                Some(s) => s,
                None => continue,
            };
            let cr = match hex::decode(cr) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let secret = match hex::decode(secret) {
                Ok(v) => v,
                Err(_) => continue,
            };
            out.entries.push(KeyLogEntry {
                label: KeyLogSecret::parse(label),
                client_random: cr,
                secret,
            });
        }
        out
    }

    pub fn find(&self, label: &KeyLogSecret, client_random: &[u8]) -> Option<&KeyLogEntry> {
        self.entries
            .iter()
            .find(|e| &e.label == label && e.client_random == client_random)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_lines() {
        let s = concat!(
            "# comment\n",
            "CLIENT_RANDOM 0a0b0c0d 11223344\n",
            "SERVER_TRAFFIC_SECRET_0 deadbeef cafebabe\n",
        );
        let log = KeyLog::parse(s);
        assert_eq!(log.entries.len(), 2);
        assert_eq!(log.entries[0].label, KeyLogSecret::Tls12ClientRandom);
        assert_eq!(log.entries[1].label, KeyLogSecret::Tls13ServerTraffic0);
    }
}
