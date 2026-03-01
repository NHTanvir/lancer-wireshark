//! JA3 / JA4 cluster narration.

use super::{ChatMessage, Provider};
use anyhow::Result;

pub fn narrate(provider: &dyn Provider, hashes: &[String]) -> Result<String> {
    let body = hashes.join("\n");
    let system = ChatMessage {
        role: "system".into(),
        content: "Given this list of JA3/JA4 hashes, cluster them into likely client families (Chromium variants, Go stdlib, curl, Firefox, mobile SDKs, etc.) and return a short Markdown table.".into(),
    };
    let user = ChatMessage { role: "user".into(), content: body };
    provider.complete(&[system, user])
}
