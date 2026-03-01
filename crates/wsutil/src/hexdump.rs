//! Canonical hex+ASCII dump matching upstream `tshark -x` output.

#[derive(Debug, Clone, Copy)]
pub struct HexdumpOpts {
    pub all: bool,
    pub frames: bool,
    pub noascii: bool,
    pub ascii: bool,
    pub delimit: bool,
}

impl Default for HexdumpOpts {
    fn default() -> Self {
        Self {
            all: false,
            frames: true,
            noascii: false,
            ascii: false,
            delimit: false,
        }
    }
}

impl HexdumpOpts {
    pub fn parse(s: &str) -> Self {
        let mut o = HexdumpOpts::default();
        for tok in s.split(',') {
            match tok.trim() {
                "all" => o.all = true,
                "frames" => o.frames = true,
                "noascii" => o.noascii = true,
                "ascii" => o.ascii = true,
                "delimit" => o.delimit = true,
                _ => {}
            }
        }
        o
    }
}

/// Produce a hex+ascii dump like:
///   `0000  45 00 00 73 00 00 40 00 40 11 b8 61 c0 a8 00 01  E..s..@.@..a....`
pub fn format_hexdump(bytes: &[u8]) -> String {
    format_hexdump_with(bytes, HexdumpOpts::default())
}

pub fn format_hexdump_with(bytes: &[u8], opts: HexdumpOpts) -> String {
    let mut out = String::with_capacity(bytes.len() / 16 * 80);
    if opts.delimit {
        out.push_str("=== begin hexdump ===\n");
    }
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let off = i * 16;
        out.push_str(&format!("{off:04x}  "));
        for (j, b) in chunk.iter().enumerate() {
            out.push_str(&format!("{b:02x}"));
            out.push(if j == 7 { ' ' } else { ' ' });
        }
        for _ in chunk.len()..16 {
            out.push_str("   ");
        }
        if !opts.noascii {
            out.push(' ');
            for b in chunk {
                let c = *b as char;
                out.push(if (32u8..127).contains(b) { c } else { '.' });
            }
        }
        out.push('\n');
    }
    if opts.delimit {
        out.push_str("=== end hexdump ===\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_dump() {
        let s = format_hexdump(b"Hello, world!");
        assert!(s.contains("48 65 6c 6c 6f"));
        assert!(s.contains("Hello, world!"));
    }
}
