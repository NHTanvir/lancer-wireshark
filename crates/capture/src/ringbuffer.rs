//! Ring-buffer capture (`-b`) — keep N rolling files of M bytes each.

use super::{CaptureWriter, Frame};
use anyhow::Result;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, Default)]
pub struct RingOptions {
    pub max_files: Option<u32>,
    pub max_filesize_bytes: Option<u64>,
    pub max_duration: Option<Duration>,
    pub max_packets: Option<u64>,
    pub interval: Option<Duration>,
}

impl RingOptions {
    pub fn parse(spec: &str) -> Option<Self> {
        let mut o = Self::default();
        for tok in spec.split(',') {
            let (k, v) = tok.split_once(':')?;
            match k {
                "files" => o.max_files = v.parse().ok(),
                "filesize" => o.max_filesize_bytes = v.parse::<u64>().ok().map(|n| n * 1024),
                "duration" => o.max_duration = wsutil::parse_duration(v),
                "packets" => o.max_packets = v.parse().ok(),
                "interval" => o.interval = wsutil::parse_duration(v),
                _ => {}
            }
        }
        Some(o)
    }
}

pub struct RingBuffer {
    base: PathBuf,
    opts: RingOptions,
    link: u32,
    format: super::writer::WriteFormat,
    compression: wsutil::Compression,
    current: CaptureWriter,
    current_path: PathBuf,
    current_bytes: u64,
    current_packets: u64,
    started: Instant,
    files: VecDeque<PathBuf>,
    serial: u32,
}

impl RingBuffer {
    pub fn create<P: AsRef<Path>>(
        path: P,
        link: u32,
        opts: RingOptions,
        format: super::writer::WriteFormat,
        compression: wsutil::Compression,
    ) -> Result<Self> {
        let base = path.as_ref().to_path_buf();
        let mut rb = Self {
            base,
            opts,
            link,
            format,
            compression,
            current: CaptureWriter::create(path.as_ref(), link, format, compression)?,
            current_path: path.as_ref().to_path_buf(),
            current_bytes: 0,
            current_packets: 0,
            started: Instant::now(),
            files: VecDeque::new(),
            serial: 1,
        };
        rb.files.push_back(rb.current_path.clone());
        Ok(rb)
    }

    pub fn write_frame(&mut self, f: &Frame) -> Result<()> {
        self.current.write_frame(f)?;
        self.current_bytes += f.captured_len as u64 + 16;
        self.current_packets += 1;
        self.maybe_rotate()?;
        Ok(())
    }

    fn maybe_rotate(&mut self) -> Result<()> {
        let rotate = self.opts.max_filesize_bytes.map(|m| self.current_bytes >= m).unwrap_or(false)
            || self.opts.max_packets.map(|m| self.current_packets >= m).unwrap_or(false)
            || self.opts.max_duration.map(|d| self.started.elapsed() >= d).unwrap_or(false)
            || self.opts.interval.map(|d| self.started.elapsed() >= d).unwrap_or(false);
        if !rotate { return Ok(()); }
        self.serial += 1;
        let new_path = self.next_path();
        let new_writer = CaptureWriter::create(&new_path, self.link, self.format, self.compression)?;
        self.current = new_writer;
        self.current_path = new_path.clone();
        self.current_bytes = 0;
        self.current_packets = 0;
        self.started = Instant::now();
        self.files.push_back(new_path);
        if let Some(max) = self.opts.max_files {
            while self.files.len() as u32 > max {
                if let Some(old) = self.files.pop_front() {
                    let _ = std::fs::remove_file(old);
                }
            }
        }
        Ok(())
    }

    fn next_path(&self) -> PathBuf {
        let stem = self.base.file_stem().and_then(|s| s.to_str()).unwrap_or("capture");
        let ext = self.base.extension().and_then(|s| s.to_str()).unwrap_or("pcap");
        let dir = self.base.parent().unwrap_or_else(|| Path::new("."));
        dir.join(format!("{stem}_{:05}.{ext}", self.serial))
    }
}
