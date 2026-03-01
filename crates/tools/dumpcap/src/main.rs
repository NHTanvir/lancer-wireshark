//! `dumpcap` — minimal raw-capture daemon.

use anyhow::Result;
use clap::Parser;
use crossbeam_channel::bounded;

#[derive(Parser, Debug)]
#[command(name = "dumpcap", version, about = "dumpcap-equivalent — raw-socket capture")]
struct Args {
    #[arg(short = 'i')]
    interface: String,
    #[arg(short = 'w')]
    out: String,
    #[arg(short = 'f')]
    bpf: Option<String>,
    #[arg(short = 'c')]
    count: Option<u64>,
    #[arg(short = 's', default_value_t = 262_144)]
    snaplen: i32,
    #[arg(short = 'p')]
    no_promiscuous: bool,
    #[arg(short = 'D')]
    list_devices: bool,
    #[arg(long, default_value_t = 1000)]
    update_interval: i32,
    #[arg(long, default_value = "none")]
    compress: String,
    #[arg(short = 'B')]
    buffer_mb: Option<i32>,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    if args.list_devices {
        for d in pcap::Device::list()? {
            println!("{}\t{}", d.name, d.desc.unwrap_or_default());
        }
        return Ok(());
    }
    let device = pcap::Device::list()?
        .into_iter()
        .find(|d| d.name == args.interface)
        .ok_or_else(|| anyhow::anyhow!("interface {} not found", args.interface))?;
    let mut builder = pcap::Capture::from_device(device)?
        .snaplen(args.snaplen)
        .promisc(!args.no_promiscuous)
        .timeout(args.update_interval);
    if let Some(mb) = args.buffer_mb {
        builder = builder.buffer_size(mb * 1024 * 1024);
    }
    let mut cap = builder.open()?;
    if let Some(bpf) = args.bpf.as_deref() {
        cap.filter(bpf, true)?;
    }
    let link = cap.get_datalink().0 as u32;
    let compression = wsutil::compress::Compression::parse(&args.compress).unwrap_or(wsutil::Compression::None);
    let mut writer = lancer_wireshark_capture::CaptureWriter::create(
        &args.out,
        link,
        lancer_wireshark_capture::writer::WriteFormat::Pcap,
        compression,
    )?;
    let (tx, rx) = bounded::<lancer_wireshark_capture::Frame>(8192);

    std::thread::spawn(move || -> Result<()> {
        while let Ok(f) = rx.recv() {
            writer.write_frame(&f)?;
        }
        Ok(())
    });

    let mut n = 0u64;
    loop {
        match cap.next_packet() {
            Ok(p) => {
                n += 1;
                tx.send(lancer_wireshark_capture::Frame {
                    number: n,
                    ts_secs: p.header.ts.tv_sec as i64,
                    ts_nanos: (p.header.ts.tv_usec as u32) * 1000,
                    captured_len: p.header.caplen,
                    original_len: p.header.len,
                    interface_id: 0,
                    link_type: link,
                    data: p.data.to_vec(),
                })?;
                if let Some(c) = args.count {
                    if n >= c { break; }
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(pcap::Error::NoMorePackets) => break,
            Err(e) => return Err(anyhow::anyhow!(e)),
        }
    }
    Ok(())
}
