//! BPF helpers — we delegate compilation to the `pcap` crate inside `lancer-wireshark`;
//! here we expose a basic source-string validator and a stub for offline
//! one-packet evaluation of a precompiled program.

#[derive(Debug, Clone)]
pub struct BpfSource(pub String);

impl BpfSource {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Lightweight syntax sanity check — rejects empty filters and balances parens/quotes.
    /// Real compilation happens via `pcap::Capture::filter()` once a handle is open.
    pub fn validate(&self) -> Result<(), String> {
        let s = self.0.trim();
        if s.is_empty() {
            return Err("empty BPF expression".into());
        }
        let mut paren = 0i32;
        let mut in_str = false;
        for c in s.chars() {
            match c {
                '"' => in_str = !in_str,
                '(' if !in_str => paren += 1,
                ')' if !in_str => {
                    paren -= 1;
                    if paren < 0 {
                        return Err("unbalanced parens".into());
                    }
                }
                _ => {}
            }
        }
        if paren != 0 {
            return Err("unbalanced parens".into());
        }
        if in_str {
            return Err("unterminated string".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_simple() {
        BpfSource::new("tcp port 443").validate().unwrap();
    }

    #[test]
    fn rejects_empty() {
        assert!(BpfSource::new("").validate().is_err());
    }

    #[test]
    fn detects_unbalanced() {
        assert!(BpfSource::new("(tcp port 443").validate().is_err());
    }
}
