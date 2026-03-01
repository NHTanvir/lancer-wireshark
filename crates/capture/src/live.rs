//! Live capture via the `pcap` crate (libpcap on Unix, Npcap on Windows).

use super::{Frame, FrameSource};
use anyhow::{Context, Result};
use pcap::{Active, Capture, Device};

pub struct LiveCapture {
    cap: Capture<Active>,
    n: u64,
    link: u32,
}

#[derive(Debug, Clone)]
pub struct CaptureOptions {
    pub interface: String,
    pub bpf: Option<String>,
    pub snaplen: i32,
    pub promiscuous: bool,
    pub timeout_ms: i32,
    pub buffer_mb: Option<i32>,
    pub immediate: bool,
}

impl Default for CaptureOptions {
    fn default() -> Self {
        Self {
            interface: "any".into(),
            bpf: None,
            snaplen: 262_144,
            promiscuous: true,
            timeout_ms: 1000,
            buffer_mb: None,
            immediate: false,
        }
    }
}

impl LiveCapture {
    pub fn open(opts: &CaptureOptions) -> Result<Self> {
        let device = Device::list()?
            .into_iter()
            .find(|d| d.name == opts.interface)
            .with_context(|| format!("interface {} not found", opts.interface))?;
        let mut builder = Capture::from_device(device)?
            .snaplen(opts.snaplen)
            .promisc(opts.promiscuous)
            .timeout(opts.timeout_ms)
            .immediate_mode(opts.immediate);
        if let Some(mb) = opts.buffer_mb {
            builder = builder.buffer_size(mb * 1024 * 1024);
        }
        let mut cap = builder.open()?;
        if let Some(bpf) = &opts.bpf {
            cap.filter(bpf, true)?;
        }
        let link = cap.get_datalink().0 as u32;
        Ok(Self { cap, n: 0, link })
    }

    pub fn list_interfaces() -> Result<Vec<wsutil::interfaces::Interface>> {
        let mut out = Vec::new();
        for (i, d) in Device::list()?.into_iter().enumerate() {
            let addrs = d
                .addresses
                .iter()
                .map(|a| a.addr.to_string())
                .collect();
            out.push(wsutil::interfaces::Interface {
                index: i as u32 + 1,
                name: d.name,
                description: d.desc,
                is_loopback: false,
                is_up: true,
                is_running: true,
                addresses: addrs,
                link_types: vec![wsutil::interfaces::LinkType::Ethernet],
            });
        }
        Ok(out)
    }
}

impl FrameSource for LiveCapture {
    fn next(&mut self) -> Result<Option<Frame>> {
        loop {
            match self.cap.next_packet() {
                Ok(p) => {
                    self.n += 1;
                    return Ok(Some(Frame {
                        number: self.n,
                        ts_secs: p.header.ts.tv_sec as i64,
                        ts_nanos: (p.header.ts.tv_usec as u32) * 1000,
                        captured_len: p.header.caplen,
                        original_len: p.header.len,
                        interface_id: 0,
                        link_type: self.link,
                        data: p.data.to_vec(),
                    }));
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(pcap::Error::NoMorePackets) => return Ok(None),
                Err(e) => return Err(anyhow::anyhow!(e)),
            }
        }
    }
    fn close(&mut self) {}
    fn link_type(&self) -> u32 {
        self.link
    }
}
