//! `randpkt` — synthetic test packet generator.

use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "randpkt", version, about = "randpkt-equivalent — random packet generator")]
struct Args {
    #[arg(short = 'c')]
    count: u32,
    #[arg(short = 't', default_value = "tcp")]
    pkt_type: String,
    #[arg(short = 's', default_value_t = 1500)]
    snaplen: u32,
    out_file: String,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let mut w = lancer_wireshark_capture::CaptureWriter::create(
        &args.out_file,
        1,
        lancer_wireshark_capture::writer::WriteFormat::Pcap,
        wsutil::Compression::None,
    )?;
    for i in 0..args.count {
        let mut data = vec![0u8; args.snaplen as usize];
        for (j, b) in data.iter_mut().enumerate() {
            *b = ((i as usize).wrapping_mul(j).wrapping_add(0x5A)) as u8;
        }
        w.write_frame(&lancer_wireshark_capture::Frame {
            number: (i + 1) as u64,
            ts_secs: chrono::Utc::now().timestamp() + i as i64,
            ts_nanos: 0,
            captured_len: data.len() as u32,
            original_len: data.len() as u32,
            interface_id: 0,
            link_type: 1,
            data,
        })?;
    }
    Ok(())
}
