//! Anomaly detection over conversation-table summaries.

use super::{ChatMessage, Provider};
use anyhow::Result;

pub fn detect(provider: &dyn Provider, conv_summary: &str) -> Result<String> {
    let system = ChatMessage {
        role: "system".into(),
        content: "You are a senior network analyst. Given a conversation table \
                  summary, identify anything suspicious (beaconing, exfil sizes, \
                  asymmetric byte ratios, rare ports). Reply with a bullet list.".into(),
    };
    let user = ChatMessage { role: "user".into(), content: conv_summary.into() };
    provider.complete(&[system, user])
}
