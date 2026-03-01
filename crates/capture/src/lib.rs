//! Live capture + offline file reader. Drives dissection by handing
//! parsed `Frame` records to [`epan::Engine`].

pub mod offline;
pub mod live;
pub mod ringbuffer;
pub mod writer;

pub use offline::OfflineReader;
pub use writer::CaptureWriter;

use anyhow::Result;
use std::path::Path;

/// One packet as delivered by the capture layer.
#[derive(Debug, Clone)]
pub struct Frame {
    pub number: u64,
    pub ts_secs: i64,
    pub ts_nanos: u32,
    pub captured_len: u32,
    pub original_len: u32,
    pub interface_id: u32,
    pub link_type: u32,
    pub data: Vec<u8>,
}

pub trait FrameSource: Send {
    fn next(&mut self) -> Result<Option<Frame>>;
    fn close(&mut self);
    fn link_type(&self) -> u32;
}

/// Open whatever the path looks like — `.pcap`, `.pcapng`, `.gz`, etc.
pub fn open_offline<P: AsRef<Path>>(p: P) -> Result<Box<dyn FrameSource>> {
    Ok(Box::new(OfflineReader::open(p)?))
}
