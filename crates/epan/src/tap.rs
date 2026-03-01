//! Tap framework — dissectors emit events; `-z` statistics commands and
//! GUI panels subscribe.

use parking_lot::RwLock;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub enum TapEvent {
    Frame {
        number: u64,
        ts_secs: i64,
        ts_nanos: u32,
        captured_len: u32,
        original_len: u32,
    },
    Ip {
        src: std::net::IpAddr,
        dst: std::net::IpAddr,
        len: u32,
        proto: u8,
    },
    Tcp {
        src_port: u16,
        dst_port: u16,
        len: u32,
        flags: u8,
    },
    Udp {
        src_port: u16,
        dst_port: u16,
        len: u32,
    },
    Http {
        method: Option<String>,
        host: Option<String>,
        path: Option<String>,
        status: Option<u16>,
    },
    Dns {
        query: Option<String>,
        qtype: Option<u16>,
        response_code: Option<u8>,
    },
    Tls {
        is_handshake: bool,
        version: Option<u16>,
        sni: Option<String>,
        ja3: Option<String>,
        ja4: Option<String>,
    },
    Custom {
        kind: &'static str,
        payload: serde_json::Value,
    },
}

pub trait Tap: Send + Sync {
    fn name(&self) -> &'static str;
    fn on_event(&self, ev: &TapEvent);
}

pub struct TapBus {
    listeners: RwLock<Vec<Arc<dyn Tap>>>,
}

impl TapBus {
    pub fn new() -> Self {
        Self {
            listeners: RwLock::new(Vec::new()),
        }
    }

    pub fn subscribe(&self, tap: Arc<dyn Tap>) {
        self.listeners.write().push(tap);
    }

    pub fn unsubscribe(&self, name: &str) {
        self.listeners.write().retain(|t| t.name() != name);
    }

    pub fn emit(&self, ev: TapEvent) {
        for t in self.listeners.read().iter() {
            t.on_event(&ev);
        }
    }

    pub fn listener_names(&self) -> Vec<&'static str> {
        self.listeners.read().iter().map(|t| t.name()).collect()
    }
}

impl Default for TapBus {
    fn default() -> Self {
        Self::new()
    }
}
