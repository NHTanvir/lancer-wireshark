//! Hand-rolled argv parser for tshark-style flags. We use clap for the
//! high-level launcher and roll our own here because tshark's command line
//! is incompatible with clap's value-of-each-flag conventions.

use anyhow::{Context, Result};

#[derive(Debug, Default, Clone)]
pub struct Args {
    pub interfaces: Vec<String>,
    pub bpf: Option<String>,
    pub snaplen: Option<i32>,
    pub count: Option<u64>,
    pub autostop: Vec<String>,
    pub ringbuffer: Vec<String>,
    pub write: Option<String>,
    pub write_format: Option<String>,
    pub no_promisc: bool,
    pub monitor_mode: bool,
    pub buffer_mb: Option<i32>,
    pub link_type: Option<String>,
    pub time_stamp_type: Option<String>,
    pub list_interfaces: bool,
    pub list_link_types: bool,
    pub list_time_stamp_types: bool,
    pub quiet: bool,
    pub super_quiet: bool,
    pub stats_live: bool,
    pub machine_stats: bool,
    pub read: Option<String>,
    pub verbose: bool,
    pub only_protos: Vec<String>,
    pub hexdump: bool,
    pub hexdump_opts: Option<String>,
    pub two_pass: bool,
    pub display_filter: Option<String>,
    pub read_filter: Option<String>,
    pub disable_name_res: bool,
    pub name_res_flags: Option<String>,
    pub enable_protos: Vec<String>,
    pub disable_protos: Vec<String>,
    pub decode_as: Vec<String>,
    pub enable_heur: Vec<String>,
    pub disable_heur: Vec<String>,
    pub output_format: Option<String>,
    pub fields: Vec<String>,
    pub field_opts: Vec<String>,
    pub line_buffered: bool,
    pub write_per_packet_comments: bool,
    pub compress: Option<String>,
    pub global_profile: Option<String>,
    pub export_objects: Vec<String>,
    pub export_tls_keys: Option<String>,
    pub g_report: Option<String>,
    pub temp_dir: Option<String>,
    pub capture_comment: Option<String>,
    pub update_interval: Option<u32>,
    pub color: bool,
    pub no_duplicate_keys: bool,
    pub elastic_filter: Option<String>,
    pub log_level: Option<String>,
    pub log_domain: Option<String>,
    pub log_debug: Option<String>,
    pub log_noisy: Option<String>,
    pub log_file: Option<String>,
    pub log_fatal: Option<String>,
    pub kerberos_keytab: Option<String>,
    pub print_packets: bool,
    pub flush_every: Option<u64>,
    pub hosts_file: Option<String>,
    pub stats: Vec<String>,
    pub extcap: Vec<String>,
    pub ssl_keylog: Option<String>,
    pub self_test: bool,
    pub help: bool,
}

pub fn parse(argv: Vec<String>) -> Result<Args> {
    let mut a = Args::default();
    let mut it = argv.into_iter().skip(1).peekable();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--cli" => {}
            "-h" | "--help" => a.help = true,
            "--self-test" => a.self_test = true,
            "-i" => a.interfaces.push(it.next().context("-i needs value")?),
            "-f" => a.bpf = Some(it.next().context("-f needs value")?),
            "-s" => a.snaplen = Some(it.next().context("-s")?.parse()?),
            "-c" => a.count = Some(it.next().context("-c")?.parse()?),
            "-a" => a.autostop.push(it.next().context("-a")?),
            "-b" => a.ringbuffer.push(it.next().context("-b")?),
            "-w" => a.write = Some(it.next().context("-w")?),
            "-F" => a.write_format = Some(it.next().context("-F")?),
            "-p" => a.no_promisc = true,
            "-I" => a.monitor_mode = true,
            "-B" => a.buffer_mb = Some(it.next().context("-B")?.parse()?),
            "-y" => a.link_type = Some(it.next().context("-y")?),
            "--time-stamp-type" => a.time_stamp_type = Some(it.next().context("--time-stamp-type")?),
            "-D" => a.list_interfaces = true,
            "-L" => a.list_link_types = true,
            "--list-time-stamp-types" => a.list_time_stamp_types = true,
            "-Q" => a.super_quiet = true,
            "-q" => a.quiet = true,
            "-S" => a.stats_live = true,
            "-M" => a.machine_stats = true,
            "-r" => a.read = Some(it.next().context("-r")?),
            "-V" => a.verbose = true,
            "-O" => a.only_protos.extend(it.next().context("-O")?.split(',').map(|s| s.to_string())),
            "-x" => a.hexdump = true,
            "--hexdump" => a.hexdump_opts = Some(it.next().context("--hexdump")?),
            "-2" => a.two_pass = true,
            "-Y" => a.display_filter = Some(it.next().context("-Y")?),
            "-R" => a.read_filter = Some(it.next().context("-R")?),
            "-n" => a.disable_name_res = true,
            "-N" => a.name_res_flags = Some(it.next().context("-N")?),
            "--enable-protocol" => a.enable_protos.push(it.next().context("--enable-protocol")?),
            "--disable-protocol" => a.disable_protos.push(it.next().context("--disable-protocol")?),
            "-d" => a.decode_as.push(it.next().context("-d")?),
            "--enable-heuristic" => a.enable_heur.push(it.next().context("--enable-heuristic")?),
            "--disable-heuristic" => a.disable_heur.push(it.next().context("--disable-heuristic")?),
            "-T" => a.output_format = Some(it.next().context("-T")?),
            "-e" => a.fields.push(it.next().context("-e")?),
            "-E" => a.field_opts.push(it.next().context("-E")?),
            "-l" => a.line_buffered = true,
            "-W" => a.write_per_packet_comments = true,
            "--compress" | "--compress-type" => a.compress = Some(it.next().context("--compress")?),
            "--global-profile" => a.global_profile = Some(it.next().context("--global-profile")?),
            "--export-objects" => a.export_objects.push(it.next().context("--export-objects")?),
            "--export-tls-session-keys" => a.export_tls_keys = Some(it.next().context("--export-tls-session-keys")?),
            "-G" => a.g_report = Some(it.next().unwrap_or_else(|| "fields".into())),
            "--temp-dir" => a.temp_dir = Some(it.next().context("--temp-dir")?),
            "--capture-comment" => a.capture_comment = Some(it.next().context("--capture-comment")?),
            "--update-interval" => a.update_interval = Some(it.next().context("--update-interval")?.parse()?),
            "--color" => a.color = true,
            "--no-duplicate-keys" => a.no_duplicate_keys = true,
            "--elastic-mapping-filter" => a.elastic_filter = Some(it.next().context("--elastic-mapping-filter")?),
            "--log-level" => a.log_level = Some(it.next().context("--log-level")?),
            "--log-domain" => a.log_domain = Some(it.next().context("--log-domain")?),
            "--log-debug" => a.log_debug = Some(it.next().context("--log-debug")?),
            "--log-noisy" => a.log_noisy = Some(it.next().context("--log-noisy")?),
            "--log-file" => a.log_file = Some(it.next().context("--log-file")?),
            "--log-fatal" => a.log_fatal = Some(it.next().context("--log-fatal")?),
            "-K" => a.kerberos_keytab = Some(it.next().context("-K")?),
            "--print" => a.print_packets = true,
            "-H" => a.hosts_file = Some(it.next().context("-H")?),
            "-z" => a.stats.push(it.next().context("-z")?),
            "-X" => a.extcap.push(it.next().context("-X")?),
            "--ssl-keylog" => a.ssl_keylog = Some(it.next().context("--ssl-keylog")?),
            other if other.starts_with("-M") && other.len() > 2 => {
                a.flush_every = Some(other[2..].parse()?);
            }
            other => {
                if other.starts_with('-') {
                    anyhow::bail!("unknown flag {other}");
                }
                // bare positional treated as -r if no read set
                if a.read.is_none() {
                    a.read = Some(other.to_string());
                } else {
                    anyhow::bail!("unexpected positional {other}");
                }
            }
        }
    }
    Ok(a)
}
