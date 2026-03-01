//! Glue between parsed CLI args and the engine / capture / output layers.

use super::args::Args;
use crate::capture::{open_offline, FrameSource, CaptureWriter};
use crate::output::{Format, OutputOptions, Writer};
use crate::stats;
use anyhow::Result;
use epan::{Dfilter, Engine, PInfo, ProtoTree, Tvb};
use std::io::{self, Write};

pub fn run(args: Args) -> Result<()> {
    if args.help {
        print_help();
        return Ok(());
    }

    let mut logcfg = wsutil::logging::LogConfig::default();
    if let Some(l) = args.log_level.as_ref() {
        logcfg.level = wsutil::logging::LogLevel::parse(l);
    }
    if let Some(file) = args.log_file.as_ref() {
        logcfg.file = Some(file.into());
    }
    wsutil::logging::init(&logcfg);

    let engine = std::sync::Arc::new(Engine::new());
    for p in &args.disable_protos { engine.disable_protocol(p); }
    for p in &args.enable_protos { engine.enable_protocol(p); }
    for h in &args.disable_heur { engine.disable_heuristic(h); }
    for h in &args.enable_heur { engine.enable_heuristic(h); }
    for d in &args.decode_as {
        match epan::decode_as::DecodeAsTable::parse(d) {
            Ok(e) => engine.decode_as.insert(e),
            Err(e) => tracing::warn!("--decode-as parse error: {e}"),
        }
    }

    if args.list_interfaces {
        return list_interfaces();
    }

    if let Some(report) = args.g_report.as_ref() {
        return super::g_reports::print(&engine, report);
    }

    let dfilter = args
        .display_filter
        .as_ref()
        .or(args.read_filter.as_ref())
        .map(|s| Dfilter::compile(s, &engine.registry))
        .transpose()
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    let names = std::sync::Arc::clone(&engine.names);
    if args.disable_name_res {
        names.disable_all();
    } else if let Some(flags) = args.name_res_flags.as_ref() {
        names.set_flags(wsutil::NameResolveFlags::parse(flags));
    }

    let format = args
        .output_format
        .as_deref()
        .and_then(Format::parse)
        .unwrap_or(Format::Text);

    let mut output_opts = OutputOptions::default();
    output_opts.format = Some(format);
    output_opts.verbose = args.verbose;
    output_opts.hexdump = args.hexdump;
    output_opts.hexdump_opts = args.hexdump_opts.clone();
    output_opts.color = args.color;
    output_opts.no_duplicate_keys = args.no_duplicate_keys;
    output_opts.only_protos = args.only_protos.clone();
    output_opts.fields = args.fields.clone();
    output_opts.field_sep = "\t".into();
    for opt in &args.field_opts {
        if let Some(v) = opt.strip_prefix("separator=") { output_opts.field_sep = v.into(); }
        if let Some(v) = opt.strip_prefix("quote=") { output_opts.field_quote = v.into(); }
        if let Some(v) = opt.strip_prefix("header=") { output_opts.field_header = v == "y"; }
    }

    let mut writer = Writer::new(output_opts.clone());
    let mut stdout = io::stdout().lock();
    if !args.quiet && !args.super_quiet {
        writer.header(&mut stdout)?;
    }

    // Build stat commands
    let mut stats_cmds: Vec<std::sync::Arc<dyn stats::StatsCommand>> = Vec::new();
    for s in &args.stats {
        let spec = stats::StatsSpec::parse(s);
        match stats::build(&spec, &engine.tap) {
            Ok(cmd) => stats_cmds.push(cmd),
            Err(e) => tracing::warn!("-z parse error: {e}"),
        }
    }

    let mut cap_writer: Option<CaptureWriter> = None;
    if let Some(path) = &args.write {
        let compression = args
            .compress
            .as_deref()
            .and_then(wsutil::compress::Compression::parse)
            .unwrap_or(wsutil::compress::from_path(path));
        let format = args
            .write_format
            .as_deref()
            .and_then(crate::capture::writer::WriteFormat::parse)
            .unwrap_or(crate::capture::writer::WriteFormat::Pcap);
        cap_writer = Some(CaptureWriter::create(path, 1, format, compression)?);
    }

    if let Some(read) = args.read.as_ref() {
        let mut src = open_offline(read)?;
        let link = src.link_type();
        process_source(
            engine.clone(),
            &mut *src,
            link,
            dfilter.as_ref(),
            &mut writer,
            &mut stdout,
            &mut cap_writer,
            args.count,
            args.line_buffered,
            args.print_packets || args.write.is_none(),
        )?;
    } else if !args.interfaces.is_empty() {
        let opts = crate::capture::live::CaptureOptions {
            interface: args.interfaces[0].clone(),
            bpf: args.bpf.clone(),
            snaplen: args.snaplen.unwrap_or(262_144),
            promiscuous: !args.no_promisc,
            timeout_ms: args.update_interval.map(|m| m as i32).unwrap_or(1000),
            buffer_mb: args.buffer_mb,
            immediate: false,
        };
        let mut src = crate::capture::live::LiveCapture::open(&opts)?;
        let link = <crate::capture::live::LiveCapture as FrameSource>::link_type(&src);
        process_source(
            engine.clone(),
            &mut src,
            link,
            dfilter.as_ref(),
            &mut writer,
            &mut stdout,
            &mut cap_writer,
            args.count,
            args.line_buffered,
            args.print_packets || args.write.is_none(),
        )?;
    } else {
        eprintln!("lancer-wireshark: nothing to do (specify -i <iface> or -r <file>)");
    }

    if !args.quiet && !args.super_quiet {
        writer.footer(&mut stdout)?;
    }
    for cmd in stats_cmds {
        cmd.finalize(&mut stdout)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn process_source<W: Write>(
    engine: std::sync::Arc<Engine>,
    src: &mut dyn FrameSource,
    link_type: u32,
    dfilter: Option<&Dfilter>,
    writer: &mut Writer,
    stdout: &mut W,
    cap_writer: &mut Option<CaptureWriter>,
    count: Option<u64>,
    line_buffered: bool,
    print_to_stdout: bool,
) -> Result<()> {
    let mut emitted = 0u64;
    while let Some(frame) = src.next()? {
        let mut pinfo = PInfo::new(frame.number, (frame.ts_secs, frame.ts_nanos), frame.captured_len, frame.original_len);
        pinfo.interface_id = frame.interface_id;
        pinfo.link_type = link_type;
        let mut tree = ProtoTree::new();

        // Drive dissection by link type (Ethernet = 1 most common).
        let tvb = Tvb::new(&frame.data);
        let _ = engine
            .registry
            .dissector("frame")
            .expect("frame")
            .dissect(&tvb, &mut pinfo, &mut tree);
        let _ = match link_type {
            1 => dispatch_eth(&engine, &mut pinfo, &mut tree, &tvb),
            _ => 0,
        };

        engine.tap.emit(epan::tap::TapEvent::Frame {
            number: pinfo.frame_number,
            ts_secs: pinfo.timestamp_secs,
            ts_nanos: pinfo.timestamp_nanos,
            captured_len: pinfo.captured_len,
            original_len: pinfo.original_len,
        });
        if let (Some(src), Some(dst)) = (pinfo.src_addr, pinfo.dst_addr) {
            engine.tap.emit(epan::tap::TapEvent::Ip {
                src,
                dst,
                len: pinfo.original_len,
                proto: pinfo.l4_proto.unwrap_or(0),
            });
        }

        let pass = match dfilter {
            Some(df) => df.matches(&tree, &engine.registry),
            None => true,
        };
        if pass {
            if print_to_stdout {
                writer.write_packet(stdout, &pinfo, &tree, &engine.registry, &frame.data)?;
                if line_buffered {
                    stdout.flush().ok();
                }
            }
            if let Some(w) = cap_writer {
                w.write_frame(&frame)?;
            }
            emitted += 1;
            if let Some(c) = count {
                if emitted >= c { break; }
            }
        }
    }
    Ok(())
}

fn dispatch_eth(engine: &Engine, pinfo: &mut PInfo, tree: &mut ProtoTree, tvb: &Tvb) -> usize {
    if let Some(eth) = engine.registry.dissector("eth") {
        eth.dissect(tvb, pinfo, tree);
    }
    let etype = match tvb.u16_be(12) {
        Ok(v) => v,
        Err(_) => return 14,
    };
    let inner = tvb.tail(14);
    if let Some(d) = engine.registry.table("ethertype").lookup_uint(etype as u32) {
        match d.dissect(&inner, pinfo, tree) {
            epan::DissectResult::Ok(n) => {
                dispatch_l4(engine, pinfo, tree, &inner.tail(n));
            }
            _ => {}
        }
    }
    14
}

fn dispatch_l4(engine: &Engine, pinfo: &mut PInfo, tree: &mut ProtoTree, tvb: &Tvb) {
    let proto = match pinfo.l4_proto { Some(p) => p, None => return };
    if let Some(d) = engine.registry.table("ip.proto").lookup_uint(proto as u32) {
        match d.dissect(tvb, pinfo, tree) {
            epan::DissectResult::Ok(n) => {
                let payload = tvb.tail(n);
                // Port-based app layer dispatch.
                let table = match proto {
                    6 => Some(engine.registry.table("tcp.port")),
                    17 => Some(engine.registry.table("udp.port")),
                    _ => None,
                };
                if let Some(t) = table {
                    if let Some(port) = pinfo.dst_port.or(pinfo.src_port) {
                        if let Some(app) = t.lookup_uint(port as u32) {
                            app.dissect(&payload, pinfo, tree);
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

fn list_interfaces() -> Result<()> {
    let ifaces = crate::capture::live::LiveCapture::list_interfaces()?;
    println!("{}", wsutil::interfaces::format_d(&ifaces));
    Ok(())
}

fn print_help() {
    println!("lancer-wireshark — Rust clone of tshark/wireshark");
    println!();
    println!("Usage:");
    println!("  lancer-wireshark [GUI launch]");
    println!("  lancer-wireshark --cli -i <iface> [-f <bpf>] [-c <count>] [-Y <dfilter>] [-T <fmt>]");
    println!("  lancer-wireshark --cli -r <file>   [-Y <dfilter>] [-T <fmt>] [-V] [-x]");
    println!();
    println!("Common flags (see plan.md for full list — parity with tshark 4.4+):");
    println!("  -i, -D, -L, -f, -s, -c, -a, -b, -w, -F, -p, -I, -B, -y, --time-stamp-type");
    println!("  -Q, -q, -S, -M, -r, -V, -O, -x, -2, -Y, -R, -n, -N, --enable-protocol, --disable-protocol");
    println!("  -d, --enable-heuristic, --disable-heuristic, -T, -e, -E, -l, -W, --compress");
    println!("  --global-profile, --export-objects, --export-tls-session-keys, -G, --temp-dir");
    println!("  --capture-comment, --update-interval, --hexdump, --color, --no-duplicate-keys");
    println!("  --log-level, --log-domain, --log-debug, --log-noisy, --log-file, --log-fatal");
    println!("  -K, --print, -H, -z, -X");
    println!();
    println!("Default invocation (with no CLI flags) opens the GUI.");
}
