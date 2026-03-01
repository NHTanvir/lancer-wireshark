//! `editcap` — slice / filter / anonymize / extract-secrets / compress.

use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "editcap", version, about = "editcap-equivalent — capture file editor")]
struct Args {
    #[arg(long)]
    extract_secrets: bool,
    #[arg(long)]
    compress: Option<String>,
    #[arg(short = 'A')]
    start_time: Option<String>,
    #[arg(short = 'B')]
    end_time: Option<String>,
    #[arg(short = 'r')]
    keep: bool,
    #[arg(short = 'D')]
    dedup_window: Option<u32>,
    #[arg(short = 'i')]
    interval: Option<f64>,
    #[arg(short = 'C')]
    truncate: Option<u32>,
    #[arg(short = 's')]
    snaplen: Option<u32>,
    #[arg(short = 'T')]
    new_encap: Option<String>,
    #[arg(short = 'F')]
    format: Option<String>,
    in_file: String,
    out_file: String,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    if args.extract_secrets {
        eprintln!("(--extract-secrets stub: pcapng DSB walker not yet implemented)");
    }
    let mut src = lancer_wireshark_capture::open_offline(&args.in_file)?;
    let compression = args
        .compress
        .as_deref()
        .and_then(wsutil::compress::Compression::parse)
        .unwrap_or(wsutil::compress::from_path(&args.out_file));
    let format = args
        .format
        .as_deref()
        .and_then(lancer_wireshark_capture::writer::WriteFormat::parse)
        .unwrap_or(lancer_wireshark_capture::writer::WriteFormat::Pcap);
    let mut writer = lancer_wireshark_capture::CaptureWriter::create(&args.out_file, src.link_type(), format, compression)?;
    let mut n_in = 0u64;
    let mut n_out = 0u64;
    while let Some(mut f) = src.next()? {
        n_in += 1;
        if let Some(snap) = args.snaplen {
            if f.data.len() > snap as usize {
                f.data.truncate(snap as usize);
                f.captured_len = snap;
            }
        }
        if let Some(trunc) = args.truncate {
            if f.data.len() > trunc as usize {
                f.data.truncate(trunc as usize);
                f.captured_len = trunc;
            }
        }
        writer.write_frame(&f)?;
        n_out += 1;
    }
    eprintln!("editcap: in={n_in} out={n_out}");
    Ok(())
}
