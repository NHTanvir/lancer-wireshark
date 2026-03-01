//! Capture timestamp formatting and duration parsing.

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeFmt {
    Relative,
    Absolute,
    AbsoluteWithDate,
    DeltaToPrev,
    DeltaToFirst,
    Epoch,
    Utc,
}

/// Format a timestamp (seconds + nanos since epoch) in the requested style.
///
/// `first` is the capture's first packet (for relative/delta-first modes),
/// `prev` is the previous packet (for delta-to-prev). Both may equal `(s, n)`
/// for the first packet of a capture.
pub fn format_timestamp(s: i64, n: u32, first: (i64, u32), prev: (i64, u32), fmt: TimeFmt) -> String {
    match fmt {
        TimeFmt::Relative => {
            let (ds, dn) = sub_ts((s, n), first);
            format!("{ds:>4}.{:09}", dn)
        }
        TimeFmt::Absolute => {
            let dt = ts_to_naive(s, n);
            dt.format("%H:%M:%S%.6f").to_string()
        }
        TimeFmt::AbsoluteWithDate => {
            let dt = ts_to_naive(s, n);
            dt.format("%Y-%m-%d %H:%M:%S%.6f").to_string()
        }
        TimeFmt::DeltaToPrev => {
            let (ds, dn) = sub_ts((s, n), prev);
            format!("{ds:>4}.{:09}", dn)
        }
        TimeFmt::DeltaToFirst => {
            let (ds, dn) = sub_ts((s, n), first);
            format!("{ds:>4}.{:09}", dn)
        }
        TimeFmt::Epoch => format!("{s}.{:09}", n),
        TimeFmt::Utc => {
            let dt = Utc.timestamp_opt(s, n).single().unwrap_or_else(Utc::now);
            dt.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
        }
    }
}

fn ts_to_naive(s: i64, n: u32) -> NaiveDateTime {
    DateTime::<Utc>::from_timestamp(s, n)
        .unwrap_or_else(Utc::now)
        .naive_utc()
}

fn sub_ts(a: (i64, u32), b: (i64, u32)) -> (i64, u32) {
    let mut ds = a.0 - b.0;
    let mut dn = a.1 as i64 - b.1 as i64;
    if dn < 0 {
        ds -= 1;
        dn += 1_000_000_000;
    }
    (ds, dn as u32)
}

/// Parse autostop / ringbuffer durations like `30s`, `2m`, `1h`, `500ms`.
pub fn parse_duration(s: &str) -> Option<std::time::Duration> {
    let s = s.trim();
    let (num_end, unit_start) = s
        .char_indices()
        .find(|(_, c)| !c.is_ascii_digit())
        .map(|(i, _)| (i, i))
        .unwrap_or((s.len(), s.len()));
    let num: u64 = s[..num_end].parse().ok()?;
    let unit = &s[unit_start..];
    Some(match unit {
        "" | "s" => std::time::Duration::from_secs(num),
        "ms" => std::time::Duration::from_millis(num),
        "us" => std::time::Duration::from_micros(num),
        "ns" => std::time::Duration::from_nanos(num),
        "m" => std::time::Duration::from_secs(num * 60),
        "h" => std::time::Duration::from_secs(num * 3600),
        "d" => std::time::Duration::from_secs(num * 86_400),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_seconds() {
        assert_eq!(parse_duration("30").unwrap(), std::time::Duration::from_secs(30));
        assert_eq!(parse_duration("30s").unwrap(), std::time::Duration::from_secs(30));
    }

    #[test]
    fn parses_units() {
        assert_eq!(parse_duration("500ms").unwrap(), std::time::Duration::from_millis(500));
        assert_eq!(parse_duration("2m").unwrap(), std::time::Duration::from_secs(120));
        assert_eq!(parse_duration("1h").unwrap(), std::time::Duration::from_secs(3600));
    }

    #[test]
    fn relative_format() {
        let s = format_timestamp(2, 500_000_000, (0, 0), (0, 0), TimeFmt::Relative);
        assert!(s.contains("2"));
        assert!(s.contains("500000000"));
    }
}
