//! `val_to_str` equivalents — integer → human-readable label tables.
//!
//! Mirrors upstream Wireshark's `value_string` and `range_string` constructs.

#[derive(Debug, Clone, Copy)]
pub struct ValStr {
    pub value: u32,
    pub label: &'static str,
}

pub fn val_to_str(value: u32, table: &[ValStr]) -> Option<&'static str> {
    table.iter().find(|e| e.value == value).map(|e| e.label)
}

pub fn val_to_str_or(value: u32, table: &[ValStr], default: &'static str) -> &'static str {
    val_to_str(value, table).unwrap_or(default)
}

/// Format an integer as `Label (0x...)` for dissection display.
pub fn val_to_display(value: u32, table: &[ValStr]) -> String {
    match val_to_str(value, table) {
        Some(s) => format!("{s} (0x{value:x})"),
        None => format!("Unknown (0x{value:x})"),
    }
}

#[macro_export]
macro_rules! vs {
    ($( ($v:expr, $l:expr) ),* $(,)?) => {
        &[$( $crate::valstr::ValStr { value: $v, label: $l } ),*][..]
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    static SAMPLE: &[ValStr] = &[
        ValStr { value: 0, label: "Reserved" },
        ValStr { value: 1, label: "Request" },
        ValStr { value: 2, label: "Reply" },
    ];

    #[test]
    fn lookups() {
        assert_eq!(val_to_str(1, SAMPLE), Some("Request"));
        assert!(val_to_str(99, SAMPLE).is_none());
        assert_eq!(val_to_str_or(99, SAMPLE, "Unknown"), "Unknown");
    }

    #[test]
    fn display_form() {
        assert_eq!(val_to_display(2, SAMPLE), "Reply (0x2)");
    }
}
