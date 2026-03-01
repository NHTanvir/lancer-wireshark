//! `mergecap` — chrono multi-file merge of capture files.

use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "mergecap", version, about = "mergecap-equivalent")]
struct Args {
    #[arg(short = 'w')]
    out: String,
    #[arg(short = 'F')]
    format: Option<String>,
    #[arg(long)]
    compress: Option<String>,
    in_files: Vec<String>,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let compression = args
        .compress
        .as_deref()
        .and_then(wsutil::compress::Compression::parse)
        .unwrap_or(wsutil::compress::from_path(&args.out));
    let format = args
        .format
        .as_deref()
        .and_then(lancer_wireshark_capture::writer::WriteFormat::parse)
        .unwrap_or(lancer_wireshark_capture::writer::WriteFormat::Pcap);

    let mut sources: Vec<Box<dyn lancer_wireshark_capture::FrameSource>> = Vec::new();
    let mut link = 1u32;
    for f in &args.in_files {
        let s = lancer_wireshark_capture::open_offline(f)?;
        link = s.link_type();
        sources.push(s);
    }

    let mut writer = lancer_wireshark_capture::CaptureWriter::create(&args.out, link, format, compression)?;
    let mut heads: Vec<Option<lancer_wireshark_capture::Frame>> = sources
        .iter_mut()
        .map(|s| s.next().ok().flatten())
        .collect();

    loop {
        // Pick the source whose head is the oldest.
        let mut min_idx: Option<usize> = None;
        for (i, h) in heads.iter().enumerate() {
            if let Some(f) = h {
                if min_idx.is_none()
                    || heads[min_idx.unwrap()]
                        .as_ref()
                        .map(|m| (f.ts_secs, f.ts_nanos) < (m.ts_secs, m.ts_nanos))
                        .unwrap_or(true)
                {
                    min_idx = Some(i);
                }
            }
        }
        let i = match min_idx {
            Some(i) => i,
            None => break,
        };
        if let Some(f) = heads[i].take() {
            writer.write_frame(&f)?;
            heads[i] = sources[i].next().ok().flatten();
        }
    }
    Ok(())
}
