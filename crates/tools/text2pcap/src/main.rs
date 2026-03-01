//! `text2pcap` — convert hex dumps to pcap.

use anyhow::Result;
use clap::Parser;
use regex::Regex;

#[derive(Parser, Debug)]
#[command(name = "text2pcap", version, about = "text2pcap-equivalent")]
struct Args {
    #[arg(short = 'l')]
    link_type: Option<u32>,
    #[arg(long)]
    compress: Option<String>,
    in_file: String,
    out_file: String,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let text = std::fs::read_to_string(&args.in_file)?;
    let re = Regex::new(r"(?m)^\s*[0-9a-fA-F]{4,8}[: \t]+((?:[0-9a-fA-F]{2}[ \-:]?)+)")?;
    let mut bytes = Vec::new();
    for cap in re.captures_iter(&text) {
        let hex_part = cap.get(1).unwrap().as_str();
        for tok in hex_part.split(|c: char| !c.is_ascii_hexdigit()) {
            if tok.len() == 2 {
                bytes.push(u8::from_str_radix(tok, 16)?);
            }
        }
    }
    let link = args.link_type.unwrap_or(1);
    let compression = args
        .compress
        .as_deref()
        .and_then(wsutil::compress::Compression::parse)
        .unwrap_or(wsutil::compress::from_path(&args.out_file));
    let mut w = lancer_wireshark_capture::CaptureWriter::create(
        &args.out_file,
        link,
        lancer_wireshark_capture::writer::WriteFormat::Pcap,
        compression,
    )?;
    w.write_frame(&lancer_wireshark_capture::Frame {
        number: 1,
        ts_secs: chrono::Utc::now().timestamp(),
        ts_nanos: 0,
        captured_len: bytes.len() as u32,
        original_len: bytes.len() as u32,
        interface_id: 0,
        link_type: link,
        data: bytes,
    })?;
    Ok(())
}
