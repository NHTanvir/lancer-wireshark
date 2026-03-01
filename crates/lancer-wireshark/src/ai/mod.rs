//! AI augmentation helpers.
//!
//! Provider-agnostic surface: `complete(messages) -> String`. The default
//! implementation returns canned responses so the rest of the codebase
//! is testable; production users wire in their own provider.

pub mod nl_filter;
pub mod narrate;
pub mod anomaly;
pub mod ja_cluster;
pub mod dissector_scaffold;

#[derive(Debug, Clone)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

pub trait Provider: Send + Sync {
    fn complete(&self, messages: &[ChatMessage]) -> anyhow::Result<String>;
}

pub struct CannedProvider;

impl Provider for CannedProvider {
    fn complete(&self, messages: &[ChatMessage]) -> anyhow::Result<String> {
        let last = messages.last().map(|m| m.content.as_str()).unwrap_or("");
        Ok(format!("(canned AI response to: {})", last.chars().take(80).collect::<String>()))
    }
}
