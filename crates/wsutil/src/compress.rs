//! Capture-file compression detection and stream wrappers.
//!
//! Wireshark 4.4+ supports gzip / lz4 / zstd compression on output
//! (`--compress <gzip|lz4|zstd>`), and reads any of these transparently
//! when the file extension or magic bytes indicate it.

use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    None,
    Gzip,
    Lz4,
    Zstd,
}

impl Compression {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "none" | "" => Some(Compression::None),
            "gzip" | "gz" => Some(Compression::Gzip),
            "lz4" => Some(Compression::Lz4),
            "zstd" | "zst" => Some(Compression::Zstd),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Compression::None => "none",
            Compression::Gzip => "gzip",
            Compression::Lz4 => "lz4",
            Compression::Zstd => "zstd",
        }
    }
}

/// Guess compression from a file extension.
pub fn from_path<P: AsRef<Path>>(p: P) -> Compression {
    match p
        .as_ref()
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())
    {
        Some(s) if s == "gz" => Compression::Gzip,
        Some(s) if s == "lz4" => Compression::Lz4,
        Some(s) if s == "zst" || s == "zstd" => Compression::Zstd,
        _ => Compression::None,
    }
}

/// Detect compression from the first few bytes of a file.
pub fn detect_compression(prefix: &[u8]) -> Compression {
    if prefix.len() >= 2 && prefix[0] == 0x1f && prefix[1] == 0x8b {
        return Compression::Gzip;
    }
    if prefix.len() >= 4 && &prefix[..4] == [0x28, 0xB5, 0x2F, 0xFD] {
        return Compression::Zstd;
    }
    if prefix.len() >= 4 && &prefix[..4] == [0x04, 0x22, 0x4D, 0x18] {
        return Compression::Lz4;
    }
    Compression::None
}

/// Wrap a reader in the appropriate decompressor.
pub fn decompress_reader<R: Read + Send + 'static>(r: R, c: Compression) -> io::Result<Box<dyn Read + Send>> {
    Ok(match c {
        Compression::None => Box::new(BufReader::new(r)),
        Compression::Gzip => Box::new(flate2::read::GzDecoder::new(r)),
        Compression::Lz4 => Box::new(lz4_flex::frame::FrameDecoder::new(r)),
        Compression::Zstd => Box::new(zstd::stream::read::Decoder::new(r)?),
    })
}

/// Wrap a writer in the appropriate compressor.
pub fn compress_writer<W: Write + Send + 'static>(w: W, c: Compression) -> io::Result<Box<dyn Write + Send>> {
    Ok(match c {
        Compression::None => Box::new(BufWriter::new(w)),
        Compression::Gzip => Box::new(flate2::write::GzEncoder::new(w, flate2::Compression::default())),
        Compression::Lz4 => Box::new(lz4_flex::frame::FrameEncoder::new(w)),
        Compression::Zstd => Box::new(zstd::stream::write::Encoder::new(w, 3)?.auto_finish()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_names() {
        assert_eq!(Compression::parse("gzip"), Some(Compression::Gzip));
        assert_eq!(Compression::parse("zstd"), Some(Compression::Zstd));
        assert_eq!(Compression::parse("lz4"), Some(Compression::Lz4));
        assert_eq!(Compression::parse("none"), Some(Compression::None));
        assert!(Compression::parse("bzip2").is_none());
    }

    #[test]
    fn detect_gz() {
        assert_eq!(detect_compression(&[0x1f, 0x8b, 0x08]), Compression::Gzip);
    }

    #[test]
    fn detect_zstd() {
        assert_eq!(detect_compression(&[0x28, 0xB5, 0x2F, 0xFD]), Compression::Zstd);
    }

    #[test]
    fn detect_lz4() {
        assert_eq!(detect_compression(&[0x04, 0x22, 0x4D, 0x18]), Compression::Lz4);
    }
}
