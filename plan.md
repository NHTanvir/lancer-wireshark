# RESEARCH DOSSIER: Wireshark

> Part of the Lancer ecosystem. A Rust clone of Wireshark — the de facto packet capture and protocol analysis tool. Build with Claude Code.
> Upstream: wireshark.org / github.com/wireshark/wireshark (C + Qt + Lua, GPL-2.0, 4.4.x stable, 4.6.x current as of 2026). Ships `wireshark` GUI, `tshark` CLI, `dumpcap`, `editcap`, `mergecap`, `capinfos`, `rawshark`, `randpkt`, `text2pcap`, **`sharkd`** (long-running JSON-RPC daemon, drives the web/etl ecosystem — must port). ~3 million LOC of C; cloning fully is a research-grade decade-long undertaking. Realistic Rust scope is a tshark-equivalent CLI covering the top 50 protocols, plus a Lancer GUI panel.

## Feature Parity Mandate

**`lancer-wireshark` MUST ship with 100% feature parity to the upstream `wireshark` tool — every flag, every subcommand, every output format, every probe / detector / module / payload / mode — plus a native Rust GUI on top.** This is not a "subset clone" — this is a full reimplementation in Rust with a GUI wrapper.

### Parity contract

- **Every CLI flag** documented in upstream `wireshark --help` (and the long-form man page / docs) must work in `lancer-wireshark --cli`.
- **Every output format** the upstream tool emits (text, JSON, XML, CSV, SARIF, custom formats) must round-trip through `lancer-wireshark` byte-equivalent where the format allows.
- **Every probe / detector / module / category / payload class / built-in script** must be ported. None silently dropped.
- **Every supported target type / input format / protocol / file format / language** must work.
- **Every configuration option** (config files, env vars, registry / settings entries) must be honoured.
- **Companion binaries / sub-tools** in the upstream suite (if any) must each get their own binary in this workspace.

### GUI on top

Every feature reachable via CLI is also reachable from the GUI (see `## GUI (Lancer-standard pattern)` below). The GUI is not a subset — it is an alternate frontend over the same `core` library that the CLI uses. The `core` crate is GUI-agnostic.

### Verification

- The `## Granular feature catalog` section below enumerates everything that must be supported.
- Reference: `tests/upstream_parity/` will pin upstream flag combinations + canned outputs as parity tests. CI fails if any flag is unsupported or output diverges.
- A `lancer-wireshark --self-test` flag runs the full parity matrix against a bundled reference target and prints pass/fail per upstream feature group.

### What is allowed to diverge

- **Performance** — Rust-native, async-first; we are allowed to be faster.
- **Memory footprint** — we are allowed to be smaller.
- **GUI** — entirely new (no upstream GUI to copy except where the upstream ships its own GUI like Zenmap / Wireshark UI / Ghidra GUI / jadx-gui — in which case our GUI must cover every panel the upstream GUI has, plus the Lancer-standard layout from `## GUI` below).
- **AI augmentation** — net-new (see `## AI augmentation ideas`).

### What is NOT allowed to diverge

- Any flag silently dropped, renamed, or behavior-changed compared to upstream.
- Any output format / record schema diverging in field names, types, or semantics.
- Any built-in script / detector / module not ported (mark explicitly with `[N/A — see note]` if genuinely impossible in Rust, e.g. NSE Lua scripts requiring features not in `mlua`).

## What it actually does

Wireshark is *the* packet capture and protocol analysis tool. It does five things that together make it irreplaceable:

1. **Captures live traffic** off any network interface (Ethernet, Wi-Fi, loopback, USB, Bluetooth, virtual NICs, TUN/TAP) via `libpcap` (Unix) or `Npcap` (Windows). Supports BPF filters at the kernel level so you only pull packets you care about.
2. **Reads and writes capture files** in `pcap` (classic) and `pcapng` (modern, with interface blocks, comments, name resolution sections, decryption-key sections, secrets blocks) plus dozens of legacy formats (Sun snoop, Microsoft Network Monitor, Cisco NetXRay, Catapult DCT2000, K12 text, HP-UX nettl, Endace ERF, etc.).
3. **Dissects 3000+ protocols** end-to-end from L2 to L7. Each packet's bytes are parsed into a labeled tree (e.g. Ethernet II → IPv4 → TCP → TLS → HTTP/2 → gRPC → protobuf message → individual fields), with every field byte-addressable so clicking a row highlights the exact bytes.
4. **Filters and statistics**: a full display-filter DSL (`http.request.method == "POST" && tcp.flags.syn == 1`), conversation/endpoint tables, IO graphs, flow graphs, TCP stream graphs (Stevens, tcptrace, time-sequence), expert info (warnings/errors per packet), follow-stream (rebuild a TCP/UDP/QUIC/TLS conversation as a single text blob), and ~60 `-z` statistics commands in tshark.
5. **Decrypts and inspects encrypted traffic** when you supply key material: WPA/WPA2/WPA3, IPsec, Kerberos, SNMPv3, SSH, **TLS 1.2 / 1.3 via `SSLKEYLOGFILE`**, QUIC, IEEE 802.11. With keys, you can follow an HTTPS session, see the decoded HTTP/2 frames, see the decoded protobuf, all in real time.

It also has flow analysis (TCP throughput, retransmissions, OOO, dup-acks), VoIP (RTP streams + jitter, call-flow graphs, replayable audio), USB analysis, Bluetooth analysis, ringbuffer captures (`-b filesize:100000 -b files:10` to keep a rolling 1GB buffer for forensics), and a built-in Lua scripting engine for custom dissectors.

## Internal architecture

**Workspace** (Lancer-Rust scope):
```
[workspace]
members = ["lancer-wireshark", "wsutil", "epan", "ui", "tools/*"]
```

- **`lancer-wireshark`** — CLI binary. The `tshark`-equivalent — argument parsing, capture/file orchestration, dissection driver, output formatting. Also the entry point for a TUI "live capture viewer."
- **`wsutil`** — Utilities crate. Bytes/strings helpers, time formatting, IP/MAC/OUI lookups, name resolution caches (`/etc/hosts`, `/etc/ethers`, IANA OUI), CRC tables, value-strings (`val_to_str` equivalents), interface enumeration, BPF compiler glue.
- **`epan`** — Enhanced Packet ANalyzer. The dissection engine. Field registration, dissector table registry, packet tree construction, display-filter DSL parser and evaluator, decryption hooks, expert info, conversation tracking, reassembly (TCP/IP/SCTP), follow-stream extraction.
- **`ui`** — Lancer GUI panel. Svelte components hosted inside the Lancer UI. Live capture view, packet list virtual scroller, packet detail tree, hex view, IO graph (Plotly/Canvas), conversation/endpoint tables, follow-stream window, expert info pane. The full Wireshark Qt UI is wildly out of scope; we stream packets from `lancer-wireshark` over IPC into the Lancer UI.
- **`tools/*`** — `editcap`-equivalent (slice/filter/anonymize captures, **`--extract-secrets`** to pull decryption keys out of pcapng DSB blocks, **`--compress gzip|lz4|zstd`**), `mergecap`-equivalent (chrono multi-file pattern, `--compress`), `capinfos`-equivalent (stats about a capture file), `text2pcap`-equivalent (hex dump → pcap, `--compress`), `randpkt`-equivalent (synthetic test packets), `rawshark`-equivalent (no-pcap-header stream dissection for pipe consumers), **`sharkd`-equivalent** (long-running JSON-RPC server speaking the upstream sharkd protocol — needed for any web/SaaS frontend to reuse `epan`).

**Key modules inside `epan/`:**

- `dissect/` — Per-protocol dissectors. One file per protocol. Each registers fields (each `hf_*` slot describing name, type, display, mask, bitfield) and a dissect function `fn dissect(tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> usize`.
- `dfilter/` — Display-filter DSL. `lalrpop`-generated grammar for the filter language. AST → typed expression tree → evaluator that walks a built proto-tree.
- `reassembly/` — TCP/IPv4/IPv6/SCTP reassembly + IP defragmentation + virtual fragments for stream-based dissection (TLS records, HTTP/1 chunked bodies).
- `crypt/` — Decryption: TLS (RSA key file, DH(E) via PMS/MS, TLS 1.3 SSLKEYLOGFILE), IPsec ESP, WPA/WPA2/WPA3 4-way handshake key derivation, Kerberos keytab, IEEE 802.11.
- `conversation/` — Per-flow state. `Conversation` keyed by (src, sport, dst, dport, proto, vlan, …). Holds per-flow dissection state (TCP segments queue, TLS record reassembly state, HTTP/2 stream table).
- `expert/` — Expert info severity table (chat / note / warn / error) per packet.
- `proto/` — `ProtoTree`, `ProtoItem`, `ProtoField`. The tree of labeled spans + offset-into-tvb back-references. Drives both display and dfilter evaluation.
- `tvb/` — Tvbuff (Testy Virtual Buffer). Zero-copy slice over a captured packet's bytes (or a reassembled buffer). Range-checked reads (`u8`, `u16_be`, `u32_le`, `bytes(off, len)`, `string`).
- `register/` — One-time-init field registry, dissector-table registry, post-dissector list.
- `dissector_table.rs` — Per-port / per-uuid / per-string dispatch (e.g. TCP port 80 → HTTP dissector).

**How dissectors plug in:**
```rust
pub trait Dissector: Send + Sync + 'static {
    fn name(&self) -> &'static str;        // "http", "tls", "tcp"
    fn register_fields(&self, reg: &mut FieldRegistry);
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> usize;
}
```

The `register_protocols!` macro at startup walks every registered dissector, allocates `hf_*` slots and `ett_*` (expansion tree type) slots, and installs them in lookup tables. The TCP dissector for example calls `dissector_table.get("tcp.port", 443)` to fan out to TLS, which calls `dissector_table.get("tls.handshake.extensions_server_name", sni)` to fan out to HTTP/2, and so on.

**Capture pipeline:**
1. **`wsutil`** enumerates interfaces (`pcap_findalldevs` on Unix, `PacketGetAdapterNames` via Npcap on Windows).
2. **`lancer-wireshark capture`** opens a live handle (`pcap_open_live`), applies the BPF filter (`pcap_compile` + `pcap_setfilter`), drops privileges (POSIX: setuid back to a non-root user) if started as root for raw-socket access.
3. Packet callbacks deliver `(ts, caplen, len, bytes)` tuples on a hot loop. Each is written to a ringbuffer pcapng file *and* dispatched to dissection.
4. Dissection runs `Frame` → `Ethernet II` → … by walking the L2/L3/L4 dispatch tables. Each layer produces a `ProtoTree` subtree.
5. The resulting `(packet_index, proto_tree, summary_line, expert_info)` is streamed to the UI over a channel.
6. Display-filter evaluation (if any) prunes packets out of the visible list — the underlying capture is unchanged.

**Offline file pipeline:**
Same as capture, except the source is `pcap_open_offline` (pcap) or our own `pcap-file`-backed pcapng reader. Pcapng's section header / interface description / enhanced packet / name resolution / decryption secrets / interface statistics / packet block types must each be handled.

## Cloning reality check

Wireshark proper is approximately:
- `epan/dissectors/` — **~3000 protocol dissectors**, ~1.5M LOC of C
- `epan/` core — ~250k LOC of C (dissection engine, dfilter, reassembly, tap framework)
- `ui/qt/` — ~300k LOC of C++ Qt
- `wiretap/` — ~50k LOC of C (capture file formats)
- `capinfos`, `editcap`, `mergecap`, `text2pcap`, `randpkt`, `rawshark`, `dumpcap` — ~50k LOC

**Brutal truth**: cloning Wireshark fully is multi-decade for a team. Solo dev in 6-12 months can ship a useful `tshark`-equivalent covering ~50 protocols, plus a Lancer GUI panel. That's still very valuable for bug bounty / pentest workflows where the alternative is "switch to Wireshark, lose context."

| Component | Solo-dev 6-12 month feasibility | Verdict |
|---|---|---|
| pcap/pcapng read | YES | `pcap-file` |
| pcap/pcapng write | YES | `pcap-file` |
| Live capture (libpcap/Npcap) | YES | `pcap` crate |
| BPF filter compile | YES (via libpcap) | Already there |
| Ethernet/IPv4/IPv6/TCP/UDP/ICMP | YES | `etherparse` |
| ARP, DHCP, DNS, HTTP/1, FTP, SSH | YES | hand-rolled |
| TLS dissect (no decrypt) | YES | `tls-parser` |
| TLS 1.2 RSA + 1.3 SSLKEYLOGFILE decrypt | YES (week of work each) | `rustls`/`ring` |
| HTTP/2 dissect | YES | `h2` parser bits |
| QUIC / HTTP/3 dissect | HARD | `quiche` |
| 2950 long-tail protocols | NO (each = days) | Ship 50, doc the rest |
| Display-filter DSL | YES (weeks) | `lalrpop` |
| TCP reassembly + follow-stream | YES (weeks) | hand-rolled |
| IO graph + statistics | YES | trivial after dissect |
| Expert info | YES | trivial trait hook |
| Full Wireshark Qt GUI | NO | Lancer Svelte panel instead |
| VoIP + RTP analyzer | NO v1 | Phase 3 |
| 802.11 monitor mode + WPA decrypt | NO v1 | Phase 3 |
| USB / Bluetooth capture | NO | Skip |
| Lua scripting for custom dissectors | YES | `mlua` |

**Realistic MVP scope (3-4 months)**: capture/read/write/filter, top 50 protocols, basic display-filter DSL, follow-stream, IO graph. Useful for 80% of bug-bounty captures.

## Granular feature catalog

### CLI (tshark-equivalent flags we replicate)

**Capture control:**
- `-i <interface>` / `-i any` — interface selection (multi `-i` allowed)
- `-D` — list interfaces with index, name, description
- `-L` — list link-layer encapsulation types for `-i`
- `-f <BPF>` — kernel-level BPF filter (e.g. `tcp port 443`)
- `-s <snaplen>` — snapshot length per packet (default full = 262144)
- `-c <count>` — stop after N packets
- `-a <autostop>` — `duration:<s>`, `filesize:<KB>`, `files:<n>`, `packets:<n>`
- `-b <ringbuffer>` — `duration:<s>`, `filesize:<KB>`, `files:<n>`, `interval:<s>`, `packets:<n>` (rolling capture)
- `-w <outfile>` — write to file (pcapng by default; `.pcap` extension switches)
- `-F <format>` — output file format (`pcap`, `pcapng`, `pcap-ng`)
- `-p` — non-promiscuous mode
- `-I` — 802.11 monitor mode (where supported)
- `-B <buffer-MB>` — kernel ring buffer size
- `-y <encap>` — link-layer type
- `--time-stamp-type <type>` — `host` / `adapter_unsynced` / etc.

**dumpcap-specific:**
- `-Q` — quieter (errors only) — 4.4+
- `-q` — slightly quieter
- `-S` — print packet statistics live
- `-M` — machine-readable interface stats
- `-N <packets>` — capture-thread queue size
- `-t` — multithreaded write
- `-P` — force legacy pcap (rather than pcapng) output
- `--ifdescr` / `--ifname` — override per-interface pcapng IDB strings
- `--capture-comment` — pcapng SHB comment

**Reading existing capture:**
- `-r <infile>` — read from pcap/pcapng (auto-detects gzip/lz4/zstd)
- `-X <ext>` — pass extension args to plugins/extcap

**Dissection control:**
- `-V` — verbose (full packet tree)
- `-O <protos>` — only show tree for these protos
- `-x` — append hex+ASCII dump per packet
- `-2` — two-pass (needed for reassembly-dependent dfilters)
- `-Y <dfilter>` — display filter applied after dissection
- `-R <dfilter>` — read filter (alias of `-Y` in `-2` mode)
- `-n` — disable all name resolution
- `-N <flags>` — selective name resolution: `m` MAC, `n` network, `t` transport, `N` external network (DNS), `d` use captured DNS
- `--enable-protocol <p>` / `--disable-protocol <p>`
- `-d <decode-as>` — `tcp.port==8443,tls` (force a port through a non-default dissector)
- `--enable-heuristic <h>` / `--disable-heuristic <h>`

**Output:**
- `-T <fmt>` — `pdml` / `psml` / `ek` / `json` / `jsonraw` / `fields` / `text` / `tabs`
- `-e <field>` — repeated; fields to emit in `-T fields` (e.g. `-e frame.number -e http.host`)
- `-E <opt>` — separator/quote/header tweaks for `-T fields`
- `-l` — line-buffered stdout (for `tail -f`-like piping)
- `-q` — quiet (statistics only when combined with `-z`)
- `-W <flags>` — write per-packet file comments through pcapng
- `--compress <gzip|lz4|zstd>` — live capture / file output compression (4.4+; live compress 4.6+)
- `--compress-type <gzip|lz4|zstd>` — alias accepted by editcap/mergecap/text2pcap/tshark
- `--global-profile <name>` — apply a system-wide profile (4.4+)
- `--export-objects <proto>,<dir>` — dump reassembled HTTP / SMB / TFTP / DICOM / IMF / X.509 cert objects to disk (4.6 adds X.509)
- `--export-tls-session-keys <file>` — dump derived TLS session keys (mirror of SSLKEYLOGFILE)
- `-G <report>` — info reports: `fields`, `protocols`, `values`, `decodes`, `defaultprefs`, `currentprefs`, `dissector-tables`, `heuristic-decodes`, `folders`, `ftypes`, `plugins`, `manuf`, `enterprises`, `services`, `elastic-mapping`. **4.6 removes the "must be first arg" constraint.**
- `--temp-dir <dir>` — override capture temp directory
- `--list-time-stamp-types` / `--time-stamp-type` — already covered, but enumerate per interface
- `--capture-comment <text>` — bake a pcapng SHB user comment
- `--update-interval <ms>` — UI/stdout refresh granularity
- `--hexdump <opts>` — granular control over `-x` (`all`/`frames`/`noascii`/`ascii`/`delimit`)
- `--color` — colourize text output by expert/proto rules
- `--no-duplicate-keys` — collapse repeated JSON keys into arrays (`-T json`)
- `--elastic-mapping-filter <protos>` — narrow `-G elastic-mapping` to a subset
- `--log-level <level>` / `--log-domain <domain>` / `--log-debug <domain>` / `--log-noisy <domain>` / `--log-file <path>` / `--log-fatal <level>` — the new wslog logging surface (4.0+; expanded each release)
- `-K <keytab>` — Kerberos keytab for decryption
- `--print` — explicitly request packet print when also writing with `-w` (4.4 made this required)
- `-M <n>` — flush sequence (reinit dissectors after N packets — long-capture leak mitigation)
- `-H <hosts-file>` — `tshark -H` to pin a hosts file for name resolution

**Statistics (`-z`):**

(~60 commands — the long tail makes tshark indispensable for SREs.)

- `-z io,stat,<interval>[,<filter>][,<filter>...]` — IO stats table
- `-z conv,<type>[,<filter>]` — conversations (eth/ip/ipv6/tcp/udp/sctp)
- `-z endpoints,<type>[,<filter>]` — endpoints
- `-z hosts,<filter>` — IP/host list
- `-z http,tree` — HTTP req/res counts
- `-z http_req,tree` — HTTP requests by URL
- `-z http_srv,tree` — HTTP by server
- `-z http_seq` — HTTP request sequence
- `-z http_stat` — HTTP status code distribution
- `-z dns,tree` — DNS queries/responses
- `-z follow,<proto>,<mode>,<filter>` — follow stream (`proto`: tcp/udp/tls/http/http2/dccp/quic; `mode`: ascii/raw/yaml/hex)
- `-z expert[,error|warn|note|chat][,<filter>]` — expert info
- `-z rpc,programs` / `-z rpc,srt,<num>,<ver>` — Sun RPC stats
- `-z smb,srt` / `-z smb2,srt` — SMB / SMB2 service response times
- `-z ldap,srt` / `-z nfs,srt` — etc.
- `-z sip,stat` / `-z mgcp,stat` / `-z megaco,stat` — VoIP
- `-z rtp,streams` — RTP streams (jitter, loss, max-delta)
- `-z voip,calls` — VoIP call list
- `-z mac-lte,stat` / `-z rlc-lte,stat` — LTE stats
- `-z plen,tree` — packet length histogram
- `-z ptype,tree` — IP packet types
- `-z dests,tree` — destination tree
- `-z flow,<filter>` — flow graph
- `-z icmp,srt` / `-z icmpv6,srt`
- `-z bootp,stat` — DHCPv4
- `-z calls,sip` — SIP call list
- `-z follow,quic,<mode>,<filter>` — follow QUIC stream (4.2+)
- `-z follow,http2,<mode>,<filter>` — follow per-HTTP/2 stream id
- `-z follow,http3,<mode>,<filter>` — follow HTTP/3 over QUIC (4.4+)
- `-z follow,mpeg2ts,pid:<pid>` / `follow,pes,<pid>` — extract MPEG-2 TS PID or PES payload for audio/video tooling (4.6+)
- `-z conv,dnp3` / `-z endpoints,dnp3` — DNP3 conversations / endpoints (4.6+)
- `-z hpfeeds,tree` — HPFEEDS
- `-z credentials` — surface decoded credentials (HTTP basic / FTP / IMAP / POP / Telnet)
- `-z dhcp,stat` — DHCP message-type stats
- `-z hosts[,ipv4|ipv6]` — IP host list with optional family filter
- `-z gquic,tree` — GQUIC fallback stats
- `-z wlan,stat` — 802.11 stations
- `-z mac-3gpp,stat`, `-z rlc-3gpp,stat`, `-z pdcp-lte,stat`, `-z f5_tmm_dist,tree` — telco / F5 stats
- `-z ansi_a,bsmap` / `-z ansi_a,dtap` / `-z ansi_map`, `-z gsm_a,bssmap` — cellular
- `-z http2,tree` — HTTP/2 frame/stream counts
- `-z quic,handshake` — QUIC handshake stats
- `-z ja3,tree` / `-z ja4,tree` — TLS fingerprint clustering (4.2+ for JA3, 4.4+ for JA4)
- `-z stat,tree,<filter>` — generic tree builder over any field

### Display-filter DSL

Full operator set: `==` `eq` `!=` `ne` `>` `gt` `<` `lt` `>=` `ge` `<=` `le` `contains` `matches` (regex) `in` (set membership) `~=` (any-byte-match). Logical: `&&` `and` `||` `or` `!` `not`. Slice operator: `tcp.payload[0:4] == 12:ab:cd:ef`. Layer index: `ip.addr[2]` (third IP layer). Function-style: `slice(...)`, `upper(...)`, `lower(...)`, `string(...)`, `len(...)`, `count(...)`, `max(...)`, `min(...)`. Field references like `${tcp.seq}` for inter-packet comparisons (advanced).

Field paths follow protocol hierarchy: `eth.src`, `ip.dst`, `tcp.flags.syn`, `tls.handshake.extensions_server_name`, `http.request.method`, `http2.headers.path`, `dns.qry.name`. Every dissector publishes its field paths during registration.

**dfilter v2 / 4.4-era additions (must support):**
- `any_of` / `all_of` quantifiers over multi-layer fields (`any_of(ip.addr) == 10.0.0.1`).
- Arithmetic on numeric fields (`tcp.window_size_value * tcp.window_size_scalefactor > 65535`).
- **Date/time arithmetic** — `frame.time + 5s`, `frame.time - frame.time_relative`, comparison of duration expressions.
- **Regex on value-string fields** — `tcp.flags matches "S.*"` against the display string, not just raw u8.
- **IP address property tests** — `ip.addr in_subnet 10.0.0.0/8`, `is_multicast(ip.dst)`, `is_link_local(ipv6.addr)`, `is_loopback(...)`, `is_unicast(...)`.
- **Conversion functions** — `string(<int>)`, `int(<string>)`, `dec_to_int(...)`, `hex(...)`, `vals(<field>)` to coerce between value-string label and underlying integer.
- **Function-like macro notation** — `${tcp.window_size}` (cross-packet reference), `@{macro_name}` invocation.
- **Layer slice** — `eth.addr#2` (second occurrence of the field in a tunneled packet), `ip.src#1` vs `ip.src#2` for outer vs inner IP.
- **Raw byte addressing** — `@tcp[0:4]` (raw bytes at TCP header offset 0, length 4) — distinct from `tcp.payload[...]`.
- **Logical test expressions in custom columns** — `if (tcp.flags.syn == 1) then "SYN" else "-"`.
- **Bit-wise** — `&`, `|`, `^`, `~`, `<<`, `>>` over integer fields.
- **`bitand`** keyword (alias for `&`) for protos using glob-mask matching.
- **Set literal** — `tcp.dstport in {80, 443, 8080..8088}` including ranges.
- **Layer protocol modifier** — `tcp.port#udp` to disambiguate stacked encapsulations.

### Output formats

- `text` (default) — `1   0.000000  192.168.1.1 → 1.1.1.1   DNS  64  Standard query A example.com`
- `tabs` — tab-separated text
- `pdml` — Packet Details Markup Language (XML, every field labeled)
- `psml` — Packet Summary Markup Language (XML, summary lines)
- `json` — top-level array of packet objects, every dissector layer as nested object, field values as `_source.layers.<proto>.<field>`
- `jsonraw` — raw bytes per field hex-encoded alongside parsed value
- `ek` — Elastic Common Schema-friendly newline-delimited JSON for Elasticsearch ingest
- `fields` — only the `-e` fields, customizable separators

### Decoding overrides (`Decode As…`)

Tell the dissector to treat traffic on port X as protocol Y. E.g. `--decode-as tcp.port==8443,tls` to force TLS dissection on a non-443 port. Persisted in `decode_as_entries` pref file.

### Enabled-protocol toggle

Each protocol can be disabled (`--disable-protocol kerberos` if you don't care about it polluting the tree). Saved in `disabled_protos` pref file. Heuristic dissectors have a separate `disabled_heuristics` list.

### Name resolution

- MAC OUI → vendor (IEEE OUI registry baked in)
- Ethernet → name via `/etc/ethers`
- IPv4/IPv6 → name via system DNS (optional), `/etc/hosts`, captured DNS A/AAAA
- TCP/UDP port → service via IANA list
- VLAN ID → name via `vlans` file
- SS7 PC → name

All caches are lazy + bounded; DNS lookups optional (`-N N` to enable, `-n` to disable).

### Follow stream / reassembly

For TCP: track per-conversation segment list, reconstruct in-order bytes for both directions, decompress (gzip/deflate) if HTTP marked it, surface to a unified "client → server" / "server → client" interleaved view. Same for UDP (per-flow), QUIC (per stream-id), TLS (per-record). Output as ASCII, hex, raw bytes, or YAML.

### Expert info

Each dissector raises `expert_info!` calls with severity (Comment / Chat / Note / Warn / Error) tied to a specific field. UI surfaces a table; CLI surfaces via `-z expert`. Examples: TCP retransmission, TCP zero window, HTTP 5xx response, malformed TLS record, suspicious DNS reply.

### IO graphs

X = time (configurable interval: 1ms / 10ms / 100ms / 1s / 10s). Y = packets, bytes, bits/s, or a `COUNT(...)` / `SUM(...)` / `AVG(...)` / `MAX(...)` of any numeric dfilter expression (e.g. `AVG(tcp.window_size)`). Multiple Y-series with independent dfilters. Drawn as Canvas/Plotly in our Lancer panel.

### TCP stream graphs

Stevens-style time-sequence, tcptrace time-sequence (with SACK + window), throughput graph, RTT graph, window-scaling graph. Useful for diagnosing race conditions and slow flows.

### RTP analysis / VoIP calls

Identify RTP streams (heuristic on UDP + payload type + SSRC continuity). Per-stream: jitter, max delta, loss %, sequence errors. Replay audio (PCMU/PCMA/G.722/Opus). Pair RTP streams with SIP/SDP to build a call list.

### Dissectors (top 50 we ship in MVP)

L2: Ethernet II, IEEE 802.3, ARP, IEEE 802.1Q (VLAN), LLDP, CDP, STP, PPPoE, LLC, SNAP.

L3: IPv4, IPv6, ICMPv4, ICMPv6, IGMP, MLD, GRE, IPsec ESP (no decrypt), IPsec AH, ICMP-LSP.

L4: TCP (with reassembly + window analysis), UDP, SCTP, DCCP, UDP-Lite.

L4.5/Tunnel: TLS 1.0-1.3 (with SSLKEYLOGFILE decryption), DTLS, QUIC (with key log decryption), WireGuard, GRE, GTP.

L7 application: HTTP/1.0+1.1, HTTP/2, HTTP/3, gRPC (protobuf payload), WebSocket, DNS (incl. DoH/DoT framing), DHCPv4, DHCPv6, FTP, SSH, SMTP, IMAP, POP3, NTP, SNMP v1/v2c/v3, mDNS/DNS-SD, LLMNR, NetBIOS, SMB/SMB2/SMB3 (basic), Kerberos, LDAP, Telnet, RADIUS, syslog, BGP, OSPF, RIP, ISIS, MQTT, AMQP 0-9-1 + 1.0, Kafka wire protocol, Redis RESP, MySQL, PostgreSQL, MongoDB wire, STUN, TURN, SIP, SDP, RTP, RTCP.

Crypto/IDP: TLS handshake (full), TLS application data (decrypted only with keys), Kerberos (decrypted with keytab).

Mobile: GTPv1, GTPv2-C, Diameter, S1AP, X2AP, NAS-EPS, NAS-5GS (basic — handy for telco bug bounty).

Industrial / IoT: MQTT, CoAP, Modbus/TCP, DNP3 (basic) — minimal but valuable.

## Engineering hard parts

1. **libpcap / Npcap binding + privilege drop**. Live capture needs raw socket access. POSIX requires CAP_NET_RAW or root; Windows requires Npcap driver. Best practice (Wireshark's): split `dumpcap` (raw-capable, minimal) from main UI (unprivileged). For us: `lancer-wireshark capture` runs as setuid/admin only, dissection runs as user. Drop privileges via `prctl(PR_SET_KEEPCAPS)` + `setresuid` on Linux; on Windows, run `lancer-wireshark capture` as a service via Npcap, communicate over named pipe.

2. **Zero-copy dissection across 3000 protocols**. The Tvbuff abstraction MUST be zero-copy and range-checked. A naive `Vec<u8>` clone per layer kills performance — captures at 10 Gbps have ~15M packets/s. Wireshark in C uses `tvbuff_t*` with offset arithmetic; we replicate with `Tvb<'a>(&'a [u8], offset, length)` plus typed accessors that bounds-check once and return native types. Reassembled buffers are stored once in the conversation state and re-wrapped as Tvbs.

3. **Display-filter DSL parsing + evaluation**. Wireshark's `dfilter.l` + `dfilter.y` are flex+bison; we do `lalrpop`. Parse to typed expression tree. Evaluate by walking the proto-tree built during dissection. Type-checking happens at compile time (field `tcp.flags.syn` is `u1`, can't compare to a string). Hard parts: layered field references (`ip.addr` matches in src or dst; `eth.addr[2]` is the third Ethernet layer in a tunneled packet), the `in` operator over sets, regex `matches`, slice-equality, range expressions.

4. **Name resolution caching**. DNS lookups are slow; OUI lookups are O(1). All caches must be bounded, async-friendly, with per-cache TTL. Captured-DNS resolution (use the DNS A records *in the capture* to label other packets in the same capture) needs the proto-tree to expose `dns.resp.name` + `dns.a` pairs into the resolver during a two-pass run.

5. **TLS decryption**:
   - **RSA key file**: dissector finds ClientKeyExchange, decrypts pre-master secret with RSA private key, derives master secret + key block per RFC 5246, decrypts application data records.
   - **Diffie-Hellman (ephemeral)**: cannot decrypt with a server private key. Requires `SSLKEYLOGFILE` ("session secret format" lines like `CLIENT_RANDOM <hex> <hex>` or `CLIENT_HANDSHAKE_TRAFFIC_SECRET <hex> <hex>`).
   - **TLS 1.3**: no master secret; secrets are `CLIENT_HANDSHAKE_TRAFFIC_SECRET`, `SERVER_HANDSHAKE_TRAFFIC_SECRET`, `CLIENT_TRAFFIC_SECRET_0`, `SERVER_TRAFFIC_SECRET_0`, `EXPORTER_SECRET`. Parser must derive keys via HKDF-Expand-Label with the right labels.
   - Decryption is per-record and per-direction; we need a TLS state machine per conversation.

6. **pcapng format support**. Multi-section files, per-section interface description blocks (link-layer + tsresol + name), enhanced packet blocks with options (drop count, flags, comments), name resolution blocks, decryption secrets blocks (TLS keys baked into the capture!), interface statistics blocks. The `pcap-file` crate handles most of this; we need writer support for live capture.

7. **Real-time pipeline**. 10 Gbps line rate = 1.25 GB/s of bytes, ~15M packets/s at minimum-size frames. We won't compete with hardware capture rigs, but we should sustain 1 Gbps lossless (1.5M packets/s small frames, 80k large). Single-thread dissection per interface is fine; we let multiple interfaces dissect in parallel. Backpressure: bounded channel from capture → dissect → UI; on full channel, drop packets at the UI side, not the capture side, and increment a "dropped" counter visible in the UI.

8. **TCP reassembly correctness**. SACK, retransmissions, OOO segments, fast-open, partial overlaps. Wireshark's reassembly has decades of edge-case fixes; we'll deliberately ship a simpler model first (in-order only, log a warning on OOO) and iterate.

9. **QUIC**. UDP-based, encrypted from packet number onward. Initial packets use a derived key (per RFC 9001) from version + DCID; handshake packets need the keys negotiated during the handshake. Without SSLKEYLOGFILE entries (`QUIC_TRAFFIC_SECRET_*`), we can only show version negotiation and unencrypted header bits.

10. **3000 dissectors is forever**. The honest plan: hand-write the top 50. For the long tail, ship a Lua scripting bridge (`mlua`) so users can write their own dissectors and we can port Wireshark's Lua dissectors with light edits. Also expose a "raw bytes" fallback that hex-dumps anything unknown.

## Rust library mapping

| Need | Crate | Notes |
|---|---|---|
| Live capture (libpcap/Npcap) | `pcap` | Standard, mature, wraps libpcap/Npcap |
| pcap + pcapng read/write | `pcap-file` | Pure-Rust, supports pcapng blocks |
| L2/L3/L4 packet parse | `etherparse` | Zero-copy Ethernet/IPv4/IPv6/TCP/UDP/ICMP |
| Alternative low-level parse | `pnet`, `pnet_packet` | Older, broader, FFI-heavy |
| TLS handshake dissect | `tls-parser` (rusticata) | Parses ClientHello/ServerHello/Certificate |
| TLS key derivation (decrypt) | `ring` + hand-roll HKDF-Expand-Label | Or `rustls` internals |
| HTTP/1 parse | `httparse` | Streaming, no-alloc |
| HTTP/2 parse | `h2` (frame-level pieces) | Or hand-roll from RFC 7540 |
| HTTP/3 / QUIC dissect | `quiche` | Cloudflare's QUIC; we use parse paths only |
| DNS parse | `trust-dns-proto` / `hickory-proto` | Mature |
| Display-filter parser | `lalrpop` | Wireshark uses bison; lalrpop is the Rust analog |
| Protocol parser DSL | `nom` | Combinator-based, perfect for ad-hoc protocols |
| BPF filter compile | use `pcap` crate's `Capture::filter()` | Lets libpcap handle it |
| Async runtime | `tokio` | Standard |
| TUI | `ratatui` | For a console capture viewer |
| GUI panel | Svelte (Lancer's existing stack) | No standalone GUI |
| Hex view rendering | hand-roll | Trivial |
| OUI / IANA tables | `oui` crate, hand-roll for ports/services | Update at build time |
| MAC / IP parsing | `mac_address`, `ipnetwork` | Trivial helpers |
| Charts (IO graph) | Plotly via Svelte side, or `plotters` for export | Both viable |
| Lua scripting (custom dissectors) | `mlua` | Lua 5.4 |
| Concurrency | `crossbeam-channel`, `parking_lot` | Standard |
| SARIF / JSON output | `serde_json` | Standard |
| Compression (HTTP body decompress) | `flate2`, `brotli`, `zstd` | All exist |
| Protobuf decode (gRPC payloads) | `prost-reflect`, `protobuf-parse` | For reflection-based decode |

## Bug bounty / pentest workflows

- **Capture during a Burp/Lancer session** to recover headers and bytes the proxy doesn't normalize. Frames that get rewritten or dropped by the proxy are visible here.
- **Decrypt TLS with `SSLKEYLOGFILE`** when testing a hybrid mobile/desktop app that won't honor a proxy. Set `SSLKEYLOGFILE=/tmp/keys.log` for Chromium/Firefox/curl; for a mobile app, `frida` script that exports `CLIENT_RANDOM`/traffic-secret lines on every TLS handshake. Plumb the log into our capture.
- **Follow TCP/UDP streams** when you suspect interleaved or chunked weirdness (request smuggling, HTTP/2 stream confusion).
- **IO graph for race conditions** — plot request timing per filter (`http.request.method == "POST" && http.host == "victim.com"`) at 1ms granularity to spot the contention window.
- **Identify out-of-band C2 / exfil** during dynamic mobile / desktop testing — capture all interfaces, post-filter for non-proxy hosts, fingerprint TLS JA3/JA3S to bucket connections.
- **Decode mTLS sessions with bundled client certs** — when the target app pins both server and client certs, only an in-process key log gets you in.
- **Replay capture into Lancer history** — convert pcap HTTP requests into Lancer "Repeater" entries for further fuzzing.
- **WPA/WPA2/WPA3 decrypt** for assessments where you have the PSK and capture the 4-way handshake — see the actual application layer over an unfamiliar Wi-Fi network.
- **DNS exfil hunt** — `-z dns,tree` + `-z conv,udp` to spot a beaconing DNS pattern.
- **Slow-loris and request smuggling** — `tcp.flags.fin == 1 && tcp.len > 0`, `http.next_request_in`, and `tcp.analysis.retransmission` flags to find sneaky requests.
- **Cellular / IoT** — telco bounty programs increasingly accept GTP / Diameter findings; even our basic dissection becomes useful.

## 2024-2026 state

- **Wireshark 4.0** (late 2022): switched default UI from GTK to Qt long-prior, modernized display-filter engine (`dfilter` v2 with proper types).
- **Wireshark 4.2** (Nov 2023): much better HTTP/2 + HTTP/3 dissection, improved Conversation Hash window, JA4/JA4S fingerprinting in TLS dissector.
- **Wireshark 4.4** (2024-2025): current stable branch. PCAPng decryption-secrets block support consolidated (embed TLS keys in the capture itself — game-changer for sharing reproducible captures); custom-column expression improvements; richer Brim/Zeek integration; "Find as You Type" filter bar; redesigned IO graph; better Apple Silicon support.
- **Wireshark 4.6 / 5.0 horizon** (2025-2026): rumored Rust-based dissector pipeline experiments, more dfilter type rigor, expanded QUIC version coverage (v2 RFC 9369), eBPF-based capture in mainline (XDP-AF socket support), TLS 1.3 0-RTT data dissection, post-quantum KEM hybrid handshakes (X25519+Kyber/MLKEM) in TLS dissector.
- **QUIC + HTTP/3** dissector matured significantly; key log format now standardized across browsers (Firefox, Chrome) for QUIC.
- **TLS 1.3 0-RTT** decryption requires `EARLY_EXPORTER_SECRET` and `CLIENT_EARLY_TRAFFIC_SECRET` lines; mainline now supports them.
- **Kernel-bypass capture**: DPDK / XDP / AF_XDP interfaces appearing for line-rate captures; Wireshark added experimental DPDK extcap. We probably skip and document.
- **Encrypted protocol awareness**: TLS Encrypted Client Hello (ECH) means we lose SNI visibility unless we have the ECH config; dissector flags ECH packets.
- **eBPF dissection experiments**: kernel-side first-pass classification before user-space dissection.

## AI augmentation ideas

1. **Auto-narrate a capture**: "Here is a 4-second capture. Identify the login sequence, the OAuth redirect, and the post-login API call." LLM gets summarized packet list + dfilter access; emits a markdown narrative with hyperlinks to packet indices.
2. **Explain protocol violations**: when expert info flags an anomaly, send the surrounding packets + RFC excerpt to LLM, get a plain-English explanation ("the server sent TLS application data before completing the handshake, which violates RFC 8446 §4.1.4").
3. **Natural-language to display filter**: "show me only HTTP POSTs to /login that returned a 5xx" → `http.request.method == "POST" && http.request.uri == "/login" && http.response.code >= 500`. Validated against schema before running.
4. **Anomaly detection over a long capture**: feed conversation-table summaries to LLM, ask "anything weird here?" — useful for blue-team triage of large captures.
5. **Auto-tag interesting streams**: each TCP stream + first 1KB of payload → LLM classifies as "credential exchange" / "C2 beacon" / "telemetry" / "static asset" / etc.
6. **Custom dissector scaffolding**: "write me a Lua dissector for the binary protocol on UDP 9090 — magic byte `0x42`, then a 4-byte length, then an XOR-with-0x55 payload." LLM emits dissector skeleton; user iterates.
7. **JA3/JA4 cluster narration**: given a pile of TLS fingerprints, LLM groups them ("these 7 hashes are all Chromium variants; these 2 are a Go stdlib client; this one is Python `requests`").
8. **Encrypted-payload guess**: when no key log exists but TLS metadata + sizing patterns are visible, LLM estimates application class (file download vs interactive vs streaming).
9. **Replay-attack proposal**: "given this captured session, what part is replayable?" — checks for nonces, timestamps, cookies.

## Implementation phases (20-week roadmap)

Wireshark is large enough that even a tshark-equivalent is multi-month. We sequence: capture/file plumbing → core protocols → display filter → reassembly + follow stream → TLS decrypt → GUI panel → progressive protocol expansion.

**Week 1 — Workspace & build.** Cargo workspace (`lancer-wireshark`, `wsutil`, `epan`, `ui`). Hook into Lancer's existing build pattern. `pcap` crate compiles + links on Windows (Npcap headers) and Linux (libpcap-dev). Smoke test: open default interface, count packets per second, exit.

**Week 2 — pcap/pcapng I/O.** `pcap-file`-backed reader + writer. Round-trip a 10MB pcapng through read-write-read. Support multi-section pcapng with interface description blocks. CLI: `lancer-wireshark -r in.pcapng -w out.pcapng`.

**Week 3 — Tvbuff + Frame + Ethernet/IPv4/IPv6 dissection.** Zero-copy `Tvb<'a>`. `ProtoTree` + `ProtoItem` types. Ethernet → IPv4/IPv6 dispatch. CLI `-V` prints a tree.

**Week 4 — TCP/UDP/ICMP dissection.** TCP header + flags + window scaling + SACK. TCP conversation tracking (per-flow state stash). UDP. ICMPv4 + ICMPv6.

**Week 5 — Display-filter DSL v1.** `lalrpop` grammar covering numeric and string comparisons, logical ops, slice operator. Type-check against field registry. Evaluate against `ProtoTree`. CLI `-Y "ip.addr == 10.0.0.1"`.

**Week 6 — DNS + DHCP + ARP + HTTP/1.** Five high-leverage L7 dissectors. HTTP/1 with `httparse`. Cover ~80% of capture exploration needs.

**Week 7 — TLS handshake dissect (no decrypt).** Parse ClientHello, ServerHello, Certificate, extensions (SNI, ALPN, supported_groups, key_share, signature_algorithms). JA3 + JA4 + JA4S fingerprint computation. Decision: TLS state machine per conversation in `crypt/tls_state.rs`.

**Week 8 — TCP reassembly + follow TCP stream.** In-order segment reassembly per direction. `-z follow,tcp,ascii,<idx>` emits the interleaved client/server payload.

**Week 9 — TLS decryption via SSLKEYLOGFILE.** Parse `keylog.txt`. TLS 1.2 with `CLIENT_RANDOM` master-secret derivation. TLS 1.3 with HKDF-Expand-Label and traffic secrets. Decrypted application data fed into a virtual reassembly buffer for upper-layer dissection.

**Week 10 — HTTP/2 dissect over decrypted TLS.** HPACK header decoding. Stream tracking. Frame types: HEADERS, DATA, SETTINGS, GOAWAY, RST_STREAM, PUSH_PROMISE, CONTINUATION, PING, WINDOW_UPDATE.

**Week 11 — Statistics framework.** `-z conv,*`, `-z endpoints,*`, `-z http,tree`, `-z http_req,tree`, `-z io,stat`. Generic "tap" trait: dissectors emit tap events; stat commands subscribe.

**Week 12 — Expert info + name resolution.** Expert info table per packet. OUI lookup (IEEE OUI registry baked into binary). IPv4/IPv6 DNS resolution (async, cached, optional). Service-port → name table. `-n` and `-N` flags.

**Week 13 — Lancer GUI panel (Svelte).** Live capture window: virtualized packet list, packet detail tree, hex view with synchronized highlight. IPC: `lancer-wireshark capture --json --stdout` streams newline-delimited packet JSON; the Svelte panel renders. Display filter input wired.

**Week 14 — IO graph + conversation tables in GUI.** Plotly time-series. Click a conversation row → filtered packet list updates.

**Week 15 — Decode-as + enable/disable protocol.** Pref file persistence. Heuristic dissectors with explicit enable/disable.

**Week 16 — QUIC dissection (read-only).** Parse version, packet header, retry, initial. Key derivation from version + DCID for Initial packets (RFC 9001). HTTP/3 over QUIC with `quiche` parsing pieces. Without key log, surface headers only.

**Week 17 — Additional protocols batch 1.** SSH (handshake only), FTP, SMTP, IMAP, POP3, NTP, SNMP v1/v2c (no v3 yet), Telnet, LDAP, Kerberos. Mostly straightforward request/response parsers.

**Week 18 — Additional protocols batch 2.** BGP, OSPF, RIP, MQTT, AMQP, Kafka wire, Redis, MySQL, PostgreSQL, MongoDB. Many lifted directly from `nom`-based crates.

**Week 19 — Lua scripting bridge.** `mlua` 5.4. Expose `Tvb`, `ProtoTree`, `ProtoField`, field registration to Lua. Port two Wireshark Lua dissectors as smoke tests. Document the API.

**Week 20 — Polish + AI panel.** Natural-language → display filter via LLM. Auto-narrate capture. Anomaly detection over conversation tables. Final perf pass: 1 Gbps lossless on 16-thread laptop.

**Beyond week 20** (progressive expansion, not blocking initial ship):
- WPA/WPA2/WPA3 decrypt + 802.11 monitor mode
- VoIP + RTP analyzer + audio replay
- USB / Bluetooth capture
- Long-tail dissectors (each = 1-3 days; never done)
- DPDK / AF_XDP capture for line-rate

---

## GUI (Lancer-standard pattern)

`lancer-wireshark` ships as a **native GUI application** by default. The CLI surface listed in `## Granular feature catalog` is still available behind a `--cli` flag (or via the `lancer-wireshark-cli` companion binary), but the **plain `lancer-wireshark` invocation opens a native desktop window**, matching every other tool in the Lancer ecosystem. No terminal-only mode.

### Framework

Pure-Rust GUI stack — no JavaScript, no Node, single static binary:

| Crate | Role |
|-------|------|
| `eframe` | Cross-platform window + event loop wrapper around `egui` |
| `egui` | Immediate-mode UI widgets (panels, tables, forms, menus, drag-and-drop) |
| `egui_extras` | Sortable tables, image loaders, syntax highlighting, date pickers |
| `egui_plot` | Charts, graphs, timelines (histograms, activity meters, progress) |
| `rfd` | Native file/folder pickers (open file, save dialog) |
| `directories` | Per-OS config dir (`~/.config/lancer-wireshark/`, `%APPDATA%\lancer-wireshark\`, etc.) |
| `image` | Screenshot / preview rendering inside egui |
| `arboard` | Clipboard read/write for "copy result" actions |
| `muda` | Native menu bar (Linux / macOS / Windows) |
| `egui-notify` | Toast notifications |

Optional dark/light theme persisted to `lancer-wireshark-config.json` via `serde_json`.

### Window layout

Three-pane layout matching the Lancer mothership GUI:

```
┌─────────────────────────────────────────────────────────────────────┐
│  File   Tools   Settings   Help                              [≡]    │
├──────────┬────────────────────────────────────────┬─────────────────┤
│          │                                        │                 │
│  Inputs  │           Main view                    │  Detail pane    │
│  / jobs  │  (table of results / source tree /     │  (full record / │
│  / scope │   findings list / packet list / etc.)  │   bytes / src / │
│          │                                        │   remediation)  │
│          │                                        │                 │
├──────────┴────────────────────────────────────────┴─────────────────┤
│  Status: idle           Items: 0          [Open]  [Run]  [Export]   │
└─────────────────────────────────────────────────────────────────────┘
```

- **Left sidebar (200-300px)** — inputs / queued jobs / scope / target list. Drag-and-drop accepted.
- **Center pane (flexible)** — primary result view appropriate to the tool (table for findings, tree for hierarchical data, code editor for source).
- **Right pane (300-400px, collapsible)** — full detail of the currently-selected item.
- **Top menu bar** — File (Open / Save / Export / Recent / Quit), Tools (per-tool actions), Settings (theme, fonts, integrations), Help (About / Docs).
- **Bottom status bar** — current activity, item counts, primary action buttons.

### Cross-tool integration with Lancer + the other 29 clones

Every Lancer-clone GUI exposes a small local HTTP server on a port auto-allocated at launch (`127.0.0.1:<port>`, written to `%TEMP%/lancer-wireshark.port`):

- The main Lancer GUI discovers running tools by scanning `%TEMP%/lancer-*.port` and lists them in its sidebar.
- Right-clicking any item in any tool can "Send to <other Lancer tool>" — the receiving tool fetches the payload via its own HTTP endpoint.
- A future "Lancer Hub" tray shell can launch / focus any of the 30 GUIs from one menu.
- HTTP endpoints exposed:
  - `GET  /v1/state` — current jobs / progress
  - `POST /v1/import` — accept a target / file / record from another Lancer tool
  - `GET  /v1/export?format=json|csv|sarif|markdown` — pull the current result set in a portable format

### Async work + responsiveness

- Long-running scans run on a Tokio task pool; the GUI thread only renders.
- Progress propagates via `crossbeam::channel` from worker → UI.
- A `Stop` button cancels in-flight work via a `CancellationToken`.
- All file I/O / network I/O / subprocess work goes through async channels — the egui thread never blocks.

### Build output

The existing `build.bat` / `build-windows.bat` / `build-linux.sh` already produce a single binary. With `eframe` linked, the same binary is the GUI app.

- Windows: `build\lancer-wireshark.exe` (double-click opens the GUI window).
- Linux: `build/lancer-wireshark` (also installable as a `.desktop` entry via `build-linux.sh --install`).
- macOS: `build/lancer-wireshark` (bundled into `lancer-wireshark.app` via `cargo-bundle` in the `build-mac.sh` companion).

For CI / headless / scripting, pass `--cli` to fall through to the CLI surface from `## Granular feature catalog`.

## Build Setup (Lancer-standard pattern)

This clone follows the same build pattern as the main Lancer project — single `.exe` output via `build.bat` on Windows, `.so/elf` via `build-linux.sh` on Linux.

### Project layout

```
lancer-wireshark/
├── Cargo.toml              # single-crate Rust project
├── Cargo.lock              # committed (binary, not library)
├── src/
│   └── main.rs             # entry point (scaffold)
├── build.bat               # Windows build → build/lancer-wireshark.exe
├── build-windows.bat       # Windows packaged dist build → dist/lancer-wireshark-windows-x86_64/
├── build-linux.sh          # Linux build → build/lancer-wireshark
├── .gitignore              # plan.md (local-only) + target/ + build/ + dist/
├── README.md               # public-facing (pushed to GitHub)
└── plan.md                 # this file (gitignored — local blueprint, never pushed)
```

### Build commands

**Windows (double-click `build.bat`):**
```
build.bat
```
Produces `build\lancer-wireshark.exe`. Pauses at end so the window stays open.

**Windows (packaged dist):**
```
build-windows.bat
```
Produces `dist\lancer-wireshark-windows-x86_64\bin\lancer-wireshark.exe` plus LICENSE/README — ready to zip.

**Linux / macOS:**
```bash
./build-linux.sh
```
Produces `build/lancer-wireshark`.

### Requirements
- Rust toolchain (https://rustup.rs)
- Windows: Visual C++ Build Tools 2019/2022 (needed by some crates); **Npcap SDK** installed and `LIB`/`INCLUDE` env vars pointed at it for the `pcap` crate to link; runtime users need the Npcap driver installed.
- Linux: `libpcap-dev` (Debian/Ubuntu) or `libpcap-devel` (Fedora). CAP_NET_RAW required for live capture (`setcap cap_net_raw,cap_net_admin=eip build/lancer-wireshark` after build, or run via sudo for testing).
- macOS: `libpcap` ships with the OS; ChmodBPF helper from the Wireshark installer recommended for unprivileged capture.

### CI

The build pattern is intentionally identical across Lancer and all 19 clones, so a single Jenkins/GitHub Actions matrix can build everything by calling `build-windows.bat` or `build-linux.sh` per repo. The matrix entry for `lancer-wireshark` adds an extra step to install the Npcap SDK on Windows runners and `libpcap-dev` on Linux runners before invoking the build script.
