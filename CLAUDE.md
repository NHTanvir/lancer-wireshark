# CLAUDE.md

Project-level instructions for Claude Code when working in this repo.

## What this project is

`lancer-wireshark` is the Rust clone of Wireshark in the Lancer ecosystem
(part of a 19-tool suite of 2026 bug-bounty tooling). The implementation
blueprint lives in `plan.md`, which is **gitignored on purpose** — it must
never be committed or pushed.

## Repo layout (Cargo workspace)

```
crates/
├── wsutil/                 # byte/time/IP/MAC/OUI helpers
├── epan/                   # dissection engine, dfilter DSL, reassembly, crypto
├── capture/                # pcap/pcapng I/O + live capture (lancer-wireshark-capture)
├── lua/                    # mlua 5.4 scripting bridge (lancer-wireshark-lua)
├── ui/                     # native egui GUI (lancer-wireshark-ui)
├── lancer-wireshark/       # CLI + GUI launcher (main binary)
└── tools/
    ├── editcap/            # slice / filter / compress
    ├── mergecap/           # chrono multi-file merge
    ├── capinfos/           # capture-file stats
    ├── text2pcap/          # hex dump → pcap
    ├── randpkt/            # synthetic test packets
    ├── rawshark/           # header-less stream dissection
    ├── sharkd/             # JSON-RPC dissection daemon
    └── dumpcap/            # raw-capable capture daemon
```

## Hard rules

1. **Never commit or push `plan.md`.** It is the local design blueprint
   and must remain in `.gitignore`. If you see it staged, unstage it.
2. **Never add a `Co-Authored-By: Claude` trailer or any AI footer to
   commits.** Commit messages must contain only what was asked for.
3. **Always install / write under `D:\`.** This repo lives on `D:\19\wireshark`;
   `C:\` is full and must never be touched for new files or installs.
4. **Workspace-aware commands only.** Use `cargo check --workspace` /
   `cargo build --workspace`. Single-crate builds skip linked binaries.
5. **Verify with `cargo check`, not `cargo build`** unless explicitly
   asked. `cargo check` is the faster signal; release builds take a
   long time because of `lto = "fat"`.

## Build

| Platform | Command | Output |
|---|---|---|
| Windows | `build.bat` | `build\*.exe` (10 binaries) |
| Windows packaged | `build-windows.bat` | `dist\lancer-wireshark-windows-x86_64\bin\` |
| Linux / macOS | `./build-linux.sh` | `build/*` |
| Linux install | `./build-linux.sh --install` | `~/.local/bin/` + `.desktop` |

Build requirements:
- Rust 1.74+ (workspace uses edition 2021)
- Windows: Visual C++ Build Tools 2019/2022 + Npcap SDK (`LIB`/`INCLUDE`
  must point at it for the `pcap` crate to link `wpcap.lib`)
- Linux: `libpcap-dev` (Debian) / `libpcap-devel` (Fedora);
  `setcap cap_net_raw,cap_net_admin=eip build/lancer-wireshark` after build

## How dissectors are organized

Each protocol lives in its own file under `crates/epan/src/dissect/<proto>.rs`
and implements the `Dissector` trait:

```rust
pub trait Dissector: Send + Sync {
    fn name(&self) -> &'static str;
    fn register(&self, reg: &mut Registry);
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult;
}
```

Adding a new protocol:
1. Create `crates/epan/src/dissect/<name>.rs` following the pattern in
   any of the existing 70+ dissectors (e.g. `dns.rs`, `tls.rs`, `http.rs`).
2. Add `pub mod <name>;` to `crates/epan/src/dissect/mod.rs`.
3. Add `Arc::new(<name>::<Type>::default())` to the `register_builtin`
   `dissectors` Vec in the same file.
4. If it dispatches through a port/ethertype/IP-proto table, add it to
   `wire_tables()` in `dissect/mod.rs`.

## How display-filter (`-Y`) works

`Dfilter::compile(src, &registry)` runs the hand-rolled
lexer → parser → AST → typed evaluator pipeline in `crates/epan/src/dfilter/`.
The evaluator walks the `ProtoTree` and looks up field values by abbr.

## How statistics (`-z`) work

Each `-z` command is a `StatsCommand` (extends the `Tap` trait). The
engine's `TapBus` fans out `TapEvent`s to all subscribed taps. Add a new
`-z foo,bar` entry by:
1. Implementing a struct in `crates/lancer-wireshark/src/stats/<area>.rs`.
2. Adding a match arm in `crates/lancer-wireshark/src/stats/mod.rs::build`.

## How the GUI works

`lancer_wireshark_ui::launch()` runs an `eframe::App` rendered with `egui`.
Three-pane layout: left sidebar (inputs / jobs), centre (virtualized
packet list), right (packet detail tree + hex). Dialogs (Conversations,
IO Graph, Follow Stream) live in `crates/ui/src/dialogs.rs`.

The local HTTP server (`crates/ui/src/ipc.rs`) binds on a random
127.0.0.1 port and writes the port to `%TEMP%/lancer-wireshark.port`
so other Lancer tools can discover us.

## Cross-tool integration endpoints

- `GET  /v1/state`             — current job/progress JSON
- `POST /v1/import`            — accept a target / file / record
- `GET  /v1/export?format=...` — pull current result set

## Tests

- `cargo test -p lancer-wireshark`   — arg parser + engine wiring
- `cargo test -p epan`               — tvb, dfilter, reassembly, crypto
- `cargo test -p wsutil`             — bytes, time, OUI, IP, MAC, hexdump
- `cargo test --workspace`           — everything

`lancer-wireshark --self-test` runs the parity matrix at runtime.

## Common pitfalls

- `pcap-file` 2.x uses `Duration` for `EnhancedPacketBlock.timestamp` but
  raw `u64` (microseconds) for the obsolete `PacketBlock.timestamp`.
- `DataLink` is an enum in pcap-file 2.x; use `DataLink::from(u32)` /
  `u32::from(dl)` for round-trips, **not** tuple field access.
- mlua 0.10 removed the `'lua` lifetime parameter; user data methods are
  `fn add_methods<M: LuaUserDataMethods<Self>>(methods: &mut M)`.
- The capture pipeline crate is named `lancer-wireshark-capture` but is
  re-exported as `lancer_wireshark::capture` from the main crate so old
  paths keep resolving.
