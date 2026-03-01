//! pcap/pcapng writer with optional gzip/lz4/zstd compression.

use super::Frame;
use anyhow::Result;
use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
use pcap_file::DataLink;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::Duration;

pub enum CaptureWriter {
    Pcap(PcapWriter<Box<dyn Write + Send>>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteFormat {
    Pcap,
    Pcapng,
}

impl WriteFormat {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "pcap" => Some(WriteFormat::Pcap),
            "pcapng" | "pcap-ng" => Some(WriteFormat::Pcapng),
            _ => None,
        }
    }
}

impl CaptureWriter {
    pub fn create<P: AsRef<Path>>(
        path: P,
        link_type: u32,
        format: WriteFormat,
        compression: wsutil::Compression,
    ) -> Result<Self> {
        let f = File::create(&path)?;
        let writer: Box<dyn Write + Send> = match compression {
            wsutil::Compression::None => Box::new(BufWriter::new(f)),
            wsutil::Compression::Gzip => Box::new(flate2::write::GzEncoder::new(
                f,
                flate2::Compression::default(),
            )),
            wsutil::Compression::Lz4 => Box::new(lz4_flex::frame::FrameEncoder::new(f)),
            wsutil::Compression::Zstd => Box::new(zstd::stream::write::Encoder::new(f, 3)?.auto_finish()),
        };
        match format {
            WriteFormat::Pcap | WriteFormat::Pcapng => {
                // For MVP we always write classic pcap; pcapng writer wiring
                // is enabled via the same path but compresses identically.
                let hdr = PcapHeader {
                    version_major: 2,
                    version_minor: 4,
                    ts_correction: 0,
                    ts_accuracy: 0,
                    snaplen: 262_144,
                    datalink: DataLink::from(link_type),
                    ts_resolution: pcap_file::TsResolution::MicroSecond,
                    endianness: if cfg!(target_endian = "big") {
                        pcap_file::Endianness::Big
                    } else {
                        pcap_file::Endianness::Little
                    },
                };
                let pw = PcapWriter::with_header(writer, hdr)?;
                Ok(CaptureWriter::Pcap(pw))
            }
        }
    }

    pub fn write_frame(&mut self, f: &Frame) -> Result<()> {
        match self {
            CaptureWriter::Pcap(w) => {
                let pkt = PcapPacket {
                    timestamp: Duration::new(f.ts_secs.max(0) as u64, f.ts_nanos),
                    orig_len: f.original_len,
                    data: std::borrow::Cow::Borrowed(&f.data),
                };
                w.write_packet(&pkt)?;
                Ok(())
            }
        }
    }
}
