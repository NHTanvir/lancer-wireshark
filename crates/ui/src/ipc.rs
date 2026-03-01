//! Local HTTP server for cross-tool integration with other Lancer tools.

use anyhow::Result;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::thread;
use tiny_http::{Method, Response, Server};

pub struct CrossToolServer {
    pub port: u16,
}

impl CrossToolServer {
    pub fn start() -> Result<Self> {
        let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0).to_string();
        let server = Server::http(addr).map_err(|e| anyhow::anyhow!("local http: {e}"))?;
        let port = server
            .server_addr()
            .to_ip()
            .map(|a| a.port())
            .unwrap_or(0);
        let server = Arc::new(server);
        write_port_file(port)?;

        let s = server.clone();
        thread::spawn(move || {
            for req in s.incoming_requests() {
                let _ = serve(req);
            }
        });

        Ok(CrossToolServer { port })
    }
}

fn serve(req: tiny_http::Request) -> Result<()> {
    let url = req.url().to_string();
    let resp = match (req.method(), url.as_str()) {
        (&Method::Get, "/v1/state") => Response::from_string(r#"{"status":"ok"}"#).with_header(json_header()),
        (&Method::Post, "/v1/import") => Response::from_string(r#"{"imported":true}"#).with_header(json_header()),
        (&Method::Get, p) if p.starts_with("/v1/export") => Response::from_string(r#"[]"#).with_header(json_header()),
        _ => Response::from_string("Not Found").with_status_code(404),
    };
    req.respond(resp).ok();
    Ok(())
}

fn json_header() -> tiny_http::Header {
    "Content-Type: application/json".parse().unwrap()
}

fn write_port_file(port: u16) -> Result<()> {
    let dir = std::env::temp_dir();
    let path = dir.join("lancer-wireshark.port");
    std::fs::write(path, format!("{port}\n"))?;
    Ok(())
}
