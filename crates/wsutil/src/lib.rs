//! `wsutil` — utility crate for lancer-wireshark.
//!
//! Mirrors upstream Wireshark's `wsutil/` directory: byte/string helpers,
//! time formatting, IP/MAC/OUI lookups, name-resolution caches, CRC tables,
//! interface enumeration, BPF helpers and value-string lookups.

pub mod bytes;
pub mod time;
pub mod oui;
pub mod ports;
pub mod nameres;
pub mod ip;
pub mod mac;
pub mod crc;
pub mod valstr;
pub mod bpf;
pub mod interfaces;
pub mod hexdump;
pub mod compress;
pub mod enterprise;
pub mod ethers;
pub mod hosts;
pub mod vlans;
pub mod profile;
pub mod logging;

pub use bytes::{Endian, BytesExt};
pub use time::{format_timestamp, TimeFmt, parse_duration};
pub use nameres::{NameResolver, NameResolveFlags};
pub use ip::{is_loopback_v4, is_loopback_v6, is_multicast_v4, is_multicast_v6, is_link_local_v4, is_link_local_v6};
pub use valstr::ValStr;
pub use hexdump::format_hexdump;
pub use compress::{Compression, detect_compression, decompress_reader, compress_writer};
