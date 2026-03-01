//! Auto-narrate a capture — feeds a summarized packet list to an LLM and
//! returns a Markdown story with packet-index hyperlinks.

use super::{ChatMessage, Provider};
use anyhow::Result;
use epan::PInfo;

#[derive(Debug, Clone)]
pub struct Summary {
    pub number: u64,
    pub ts_secs: i64,
    pub src: String,
    pub dst: String,
    pub proto: String,
    pub info: String,
}

pub fn summarize(p: &PInfo, last_proto: &str) -> Summary {
    Summary {
        number: p.frame_number,
        ts_secs: p.timestamp_secs,
        src: p.src_addr.map(|a| a.to_string()).unwrap_or_else(|| "-".into()),
        dst: p.dst_addr.map(|a| a.to_string()).unwrap_or_else(|| "-".into()),
        proto: last_proto.to_string(),
        info: p.info.clone(),
    }
}

pub fn narrate(provider: &dyn Provider, summaries: &[Summary]) -> Result<String> {
    let table = summaries
        .iter()
        .take(200)
        .map(|s| format!("{}\t{}\t{} -> {}\t{}\t{}", s.number, s.ts_secs, s.src, s.dst, s.proto, s.info))
        .collect::<Vec<_>>()
        .join("\n");
    let system = ChatMessage {
        role: "system".into(),
        content: "Summarise this packet capture in 6-12 sentences of Markdown. \
                  Identify request/response flows, surprising behaviour, and \
                  link interesting packets as [frame N].".into(),
    };
    let user = ChatMessage { role: "user".into(), content: table };
    provider.complete(&[system, user])
}
