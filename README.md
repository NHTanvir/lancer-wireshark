# lancer-wireshark

Rust clone of `wireshark`. Part of the Lancer ecosystem — a 2026 AI-era bug bounty toolkit.

A `tshark`-equivalent CLI, an `egui`-based GUI panel, the companion
binaries from the upstream suite (`editcap`, `mergecap`, `capinfos`,
`text2pcap`, `randpkt`, `rawshark`, `sharkd`, `dumpcap`), plus a Lua
scripting bridge for user-defined dissectors.

## Workspace layout

```
crates/
├── wsutil/                     # bytes/time/IP/MAC/OUI/CRC/BPF/compression helpers
├── epan/                       # Enhanced Packet ANalyzer (tvb, proto tree, dfilter, reassembly, crypto)
├── capture/                    # pcap / pcapng I/O + live capture
├── lua/                        # mlua 5.4 scripting bridge for custom dissectors
├── ui/                         # native egui GUI (lancer-wireshark-ui)
├── lancer-wireshark/           # main binary (CLI + GUI launcher)
└── tools/
    ├── editcap/                # slice / filter / compress capture files
    ├── mergecap/               # chrono multi-file merge
    ├── capinfos/               # capture-file stats
    ├── text2pcap/              # hex dump → pcap
    ├── randpkt/                # synthetic test packet generator
    ├── rawshark/               # header-less stream dissection
    ├── sharkd/                 # JSON-RPC dissection daemon
    └── dumpcap/                # raw-capable capture daemon
```

## Build

### Windows

Double-click `build.bat` or run from cmd:

```
build.bat
```

Output: `build\lancer-wireshark.exe`, `build\editcap.exe`, …

For a packaged distribution build:

```
build-windows.bat
```

Output: `dist\lancer-wireshark-windows-x86_64\bin\*.exe`

### Linux / macOS

```bash
./build-linux.sh
```

Output: `build/lancer-wireshark` (+ all companion binaries).

Install to `~/.local/bin` with a `.desktop` entry:

```bash
./build-linux.sh --install
```

### Requirements

- [Rust / Cargo](https://rustup.rs) (1.74 or newer)
- Windows: Visual C++ Build Tools 2019/2022, plus **Npcap SDK**
  installed and `LIB` / `INCLUDE` pointed at it for the `pcap` crate.
  Runtime users need the Npcap driver.
- Linux: `libpcap-dev` (Debian/Ubuntu) / `libpcap-devel` (Fedora).
  Grant capture permission once: `sudo setcap cap_net_raw,cap_net_admin=eip build/lancer-wireshark`.
- macOS: `libpcap` ships with the OS; install the ChmodBPF helper from
  Wireshark for unprivileged capture.

## Usage

```bash
# Default invocation opens the native GUI.
lancer-wireshark

# tshark-style CLI surface (or invoke `lancer-wireshark-cli` directly).
lancer-wireshark --cli -i any -f "tcp port 443" -Y "tls" -V

# Offline capture file with statistics.
lancer-wireshark --cli -r capture.pcap -Y "http" -z io,stat,1 -z conv,tcp

# Emit JSON for ingestion.
lancer-wireshark --cli -r capture.pcap -T json --no-duplicate-keys

# Verify everything is wired:
lancer-wireshark --self-test
```

## Documentation

Full design + implementation roadmap lives in `plan.md` (local, gitignored).
The CLI surface targets parity with upstream `tshark` 4.4+ — every documented
flag is supported (see `crates/lancer-wireshark/src/cli/args.rs`).
