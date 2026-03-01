//! Decryption hooks: TLS 1.2 / 1.3 via SSLKEYLOGFILE, WPA, Kerberos, IPsec.
//!
//! The TLS module is the most complete; WPA / Kerberos / IPsec are stubs
//! that surface their key-material formats without performing decryption
//! in this MVP build.

pub mod tls;
pub mod wpa;
pub mod kerberos;
pub mod ipsec;
pub mod keylog;

pub use keylog::{KeyLog, KeyLogEntry, KeyLogSecret};
pub use tls::TlsDecryptor;
