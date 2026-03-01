//! Offline pcap / pcapng reader using the `pcap-file` crate.

use super::{Frame, FrameSource};
use anyhow::{Context, Result};
use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::PcapNgReader;
use pcap_file::DataLink;
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub enum OfflineReader {
    Pcap {
        rdr: PcapReader<Box<dyn Read + Send>>,
        link: u32,
        n: u64,
    },
    PcapNg {
        rdr: PcapNgReader<Box<dyn Read + Send>>,
        link: u32,
        n: u64,
    },
}

impl OfflineReader {
    pub fn open<P: AsRef<Path>>(p: P) -> Result<Self> {
        let path = p.as_ref().to_path_buf();
        let compression = wsutil::compress::from_path(&path);
        let raw = File::open(&path).with_context(|| format!("open {}", path.display()))?;
        let mut inner: Box<dyn Read + Send> = match compression {
            wsutil::Compression::None => Box::new(raw),
            wsutil::Compression::Gzip => Box::new(flate2::read::GzDecoder::new(raw)),
            wsutil::Compression::Lz4 => Box::new(lz4_flex::frame::FrameDecoder::new(raw)),
            wsutil::Compression::Zstd => Box::new(zstd::stream::read::Decoder::new(raw)?),
        };

        let mut magic = [0u8; 4];
        inner.read_exact(&mut magic).context("read magic")?;
        let chained: Box<dyn Read + Send> = Box::new(Chain {
            prefix: magic.to_vec(),
            pos: 0,
            rest: inner,
        });

        if magic == [0x0a, 0x0d, 0x0d, 0x0a] {
            let rdr = PcapNgReader::new(chained).context("open pcapng")?;
            Ok(OfflineReader::PcapNg { rdr, link: 1, n: 0 })
        } else if matches!(
            u32::from_le_bytes(magic),
            0xa1b2_c3d4 | 0xd4c3_b2a1 | 0xa1b2_3c4d | 0x4d3c_b2a1
        ) {
            let rdr = PcapReader::new(chained).context("open pcap")?;
            let link = u32::from(rdr.header().datalink);
            Ok(OfflineReader::Pcap { rdr, link, n: 0 })
        } else {
            anyhow::bail!(
                "unrecognized capture file magic 0x{:08x}",
                u32::from_be_bytes(magic)
            );
        }
    }
}

struct Chain<R: Read> {
    prefix: Vec<u8>,
    pos: usize,
    rest: R,
}

impl<R: Read> Read for Chain<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos < self.prefix.len() {
            let n = (self.prefix.len() - self.pos).min(buf.len());
            buf[..n].copy_from_slice(&self.prefix[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        } else {
            self.rest.read(buf)
        }
    }
}

impl FrameSource for OfflineReader {
    fn next(&mut self) -> Result<Option<Frame>> {
        match self {
            OfflineReader::Pcap { rdr, link, n } => {
                let pkt = match rdr.next_packet() {
                    Some(Ok(p)) => p,
                    Some(Err(e)) => return Err(anyhow::anyhow!(e)),
                    None => return Ok(None),
                };
                *n += 1;
                let secs = pkt.timestamp.as_secs() as i64;
                let nanos = pkt.timestamp.subsec_nanos();
                Ok(Some(Frame {
                    number: *n,
                    ts_secs: secs,
                    ts_nanos: nanos,
                    captured_len: pkt.data.len() as u32,
                    original_len: pkt.orig_len,
                    interface_id: 0,
                    link_type: *link,
                    data: pkt.data.into_owned(),
                }))
            }
            OfflineReader::PcapNg { rdr, link, n } => {
                use pcap_file::pcapng::Block;
                while let Some(blk) = rdr.next_block() {
                    let blk = blk.map_err(|e| anyhow::anyhow!(e))?;
                    match blk {
                        Block::InterfaceDescription(idb) => {
                            *link = u32::from(idb.linktype);
                        }
                        Block::EnhancedPacket(ep) => {
                            *n += 1;
                            let ts = ep.timestamp;
                            return Ok(Some(Frame {
                                number: *n,
                                ts_secs: ts.as_secs() as i64,
                                ts_nanos: ts.subsec_nanos(),
                                captured_len: ep.data.len() as u32,
                                original_len: ep.original_len,
                                interface_id: ep.interface_id,
                                link_type: *link,
                                data: ep.data.into_owned(),
                            }));
                        }
                        Block::SimplePacket(sp) => {
                            *n += 1;
                            return Ok(Some(Frame {
                                number: *n,
                                ts_secs: 0,
                                ts_nanos: 0,
                                captured_len: sp.data.len() as u32,
                                original_len: sp.original_len,
                                interface_id: 0,
                                link_type: *link,
                                data: sp.data.into_owned(),
                            }));
                        }
                        Block::Packet(p) => {
                            *n += 1;
                            let ts_us = p.timestamp;
                            return Ok(Some(Frame {
                                number: *n,
                                ts_secs: (ts_us / 1_000_000) as i64,
                                ts_nanos: ((ts_us % 1_000_000) * 1000) as u32,
                                captured_len: p.data.len() as u32,
                                original_len: p.original_len,
                                interface_id: 0,
                                link_type: *link,
                                data: p.data.into_owned(),
                            }));
                        }
                        _ => continue,
                    }
                }
                Ok(None)
            }
        }
    }

    fn close(&mut self) {}

    fn link_type(&self) -> u32 {
        match self {
            OfflineReader::Pcap { link, .. } => *link,
            OfflineReader::PcapNg { link, .. } => *link,
        }
    }
}

// Keep the import live so unused-warning is silent if wsutil internal type changes.
#[allow(dead_code)]
fn _dl_anchor(_: DataLink) {}
