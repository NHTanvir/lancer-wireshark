//! Expert info — per-packet severity/notice collector consumed by
//! `-z expert` and surfaced in the GUI panel.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExpertSeverity {
    Comment,
    Chat,
    Note,
    Warn,
    Error,
}

impl ExpertSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            ExpertSeverity::Comment => "Comment",
            ExpertSeverity::Chat => "Chat",
            ExpertSeverity::Note => "Note",
            ExpertSeverity::Warn => "Warning",
            ExpertSeverity::Error => "Error",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "comment" => ExpertSeverity::Comment,
            "chat" => ExpertSeverity::Chat,
            "note" => ExpertSeverity::Note,
            "warn" | "warning" => ExpertSeverity::Warn,
            "error" => ExpertSeverity::Error,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExpertGroup {
    Checksum,
    Sequence,
    Response,
    Request,
    Undecoded,
    Reassemble,
    Malformed,
    Debug,
    Security,
    Comments,
    Decryption,
    Assumption,
    Deprecated,
    Receive,
    Interface,
    Dissector,
    Protocol,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpertInfo {
    pub frame: u64,
    pub severity: ExpertSeverity,
    pub group: ExpertGroup,
    pub proto: String,
    pub field: Option<String>,
    pub message: String,
}

#[derive(Debug, Default)]
pub struct Expert {
    pub items: parking_lot::RwLock<Vec<ExpertInfo>>,
}

impl Expert {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&self, info: ExpertInfo) {
        self.items.write().push(info);
    }

    pub fn add_simple(
        &self,
        frame: u64,
        sev: ExpertSeverity,
        group: ExpertGroup,
        proto: impl Into<String>,
        message: impl Into<String>,
    ) {
        self.add(ExpertInfo {
            frame,
            severity: sev,
            group,
            proto: proto.into(),
            field: None,
            message: message.into(),
        });
    }

    pub fn items(&self) -> Vec<ExpertInfo> {
        self.items.read().clone()
    }
}

#[macro_export]
macro_rules! expert_info {
    ($expert:expr, $pinfo:expr, $sev:ident, $group:ident, $proto:expr, $msg:expr) => {
        $expert.add($crate::expert::ExpertInfo {
            frame: $pinfo.frame_number,
            severity: $crate::expert::ExpertSeverity::$sev,
            group: $crate::expert::ExpertGroup::$group,
            proto: ($proto).to_string(),
            field: None,
            message: ($msg).to_string(),
        })
    };
}
