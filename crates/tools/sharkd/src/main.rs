//! `sharkd` — long-running JSON-RPC dissection daemon.
//!
//! Speaks a subset of the upstream sharkd JSON-RPC protocol over stdio:
//! `{"jsonrpc":"2.0","id":1,"method":"status","params":{}}`.

use anyhow::Result;
use epan::Engine;
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::sync::Arc;

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let engine = Arc::new(Engine::new());
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line?;
        let req: Value = serde_json::from_str(&line).unwrap_or_else(|_| json!({}));
        let id = req.get("id").cloned().unwrap_or(json!(null));
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let resp = match method {
            "status" => json!({"jsonrpc":"2.0","id":id,"result":{"status":"ok"}}),
            "list_protocols" => {
                let v: Vec<_> = engine.registry.protocols_iter().into_iter().map(|(_, s, n)| json!({"short":s,"name":n})).collect();
                json!({"jsonrpc":"2.0","id":id,"result":v})
            }
            "list_fields" => {
                let v: Vec<_> = engine.registry.field_paths();
                json!({"jsonrpc":"2.0","id":id,"result":v})
            }
            "load" => {
                let path = req.get("params").and_then(|p| p.get("file")).and_then(|v| v.as_str()).unwrap_or("");
                json!({"jsonrpc":"2.0","id":id,"result":{"loaded":path}})
            }
            other => json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":format!("method not found: {other}")}}),
        };
        writeln!(stdout, "{}", serde_json::to_string(&resp)?)?;
        stdout.flush().ok();
    }
    Ok(())
}
