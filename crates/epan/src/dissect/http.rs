//! HTTP/1.x dissector — request and response with header parsing.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tap::TapEvent;
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();

#[derive(Debug, Clone, Copy)]
struct Fields {
    method: FieldId,
    uri: FieldId,
    version: FieldId,
    host: FieldId,
    user_agent: FieldId,
    referer: FieldId,
    response_code: FieldId,
    response_phrase: FieldId,
    request: FieldId,
    response: FieldId,
    header_name: FieldId,
    header_value: FieldId,
}

#[derive(Default)]
pub struct HttpDissector;

impl Dissector for HttpDissector {
    fn name(&self) -> &'static str { "http" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Hypertext Transfer Protocol", "http", "http");
        let f = Fields {
            method: reg.register_field(ProtoField::simple("http.request.method", "Request Method", FieldType::String, FieldDisplay::StrAscii)),
            uri: reg.register_field(ProtoField::simple("http.request.uri", "Request URI", FieldType::String, FieldDisplay::StrAscii)),
            version: reg.register_field(ProtoField::simple("http.request.version", "Request Version", FieldType::String, FieldDisplay::StrAscii)),
            host: reg.register_field(ProtoField::simple("http.host", "Host", FieldType::String, FieldDisplay::StrAscii)),
            user_agent: reg.register_field(ProtoField::simple("http.user_agent", "User-Agent", FieldType::String, FieldDisplay::StrAscii)),
            referer: reg.register_field(ProtoField::simple("http.referer", "Referer", FieldType::String, FieldDisplay::StrAscii)),
            response_code: reg.register_field(ProtoField::simple("http.response.code", "Status Code", FieldType::U16, FieldDisplay::BaseDec)),
            response_phrase: reg.register_field(ProtoField::simple("http.response.phrase", "Status Phrase", FieldType::String, FieldDisplay::StrAscii)),
            request: reg.register_field(ProtoField::simple("http.request", "Request", FieldType::Boolean, FieldDisplay::BaseNone)),
            response: reg.register_field(ProtoField::simple("http.response", "Response", FieldType::Boolean, FieldDisplay::BaseNone)),
            header_name: reg.register_field(ProtoField::simple("http.header.name", "Header Name", FieldType::String, FieldDisplay::StrAscii)),
            header_value: reg.register_field(ProtoField::simple("http.header.value", "Header Value", FieldType::String, FieldDisplay::StrAscii)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        let bytes = tvb.as_slice();
        if !looks_like_http(bytes) {
            return DissectResult::NotForUs;
        }
        let f = F.get().unwrap();
        pinfo.current_proto = "http".into();
        tree.append_proto("http");

        let (start_line_end, headers_end) = match find_header_break(bytes) {
            Some(p) => p,
            None => return DissectResult::NeedMoreData,
        };
        let start_line = std::str::from_utf8(&bytes[..start_line_end]).unwrap_or("");
        let mut root = ProtoItem::subtree(f.method, format!("Hypertext Transfer Protocol — {start_line}"), 0, headers_end);

        let mut host = None;
        let mut method = None;
        let mut status = None;
        let mut path = None;

        if let Some((m, u, v)) = parse_request_line(start_line) {
            method = Some(m.to_string());
            path = Some(u.to_string());
            root.push(ProtoItem::new(f.method, FieldValue::Str(m.to_string()), 0, m.len()));
            root.push(ProtoItem::new(f.uri, FieldValue::Str(u.to_string()), 0, u.len()));
            root.push(ProtoItem::new(f.version, FieldValue::Str(v.to_string()), 0, v.len()));
            root.push(ProtoItem::new(f.request, FieldValue::Bool(true), 0, 0));
            pinfo.set_info(format!("{m} {u} {v}"));
        } else if let Some((v, c, p)) = parse_status_line(start_line) {
            status = Some(c);
            root.push(ProtoItem::new(f.version, FieldValue::Str(v.to_string()), 0, v.len()));
            root.push(ProtoItem::new(f.response_code, FieldValue::U64(c as u64), 0, 3));
            root.push(ProtoItem::new(f.response_phrase, FieldValue::Str(p.to_string()), 0, p.len()));
            root.push(ProtoItem::new(f.response, FieldValue::Bool(true), 0, 0));
            pinfo.set_info(format!("{v} {c} {p}"));
        } else {
            return DissectResult::NotForUs;
        }

        // headers
        let headers = std::str::from_utf8(&bytes[start_line_end + 2..headers_end]).unwrap_or("");
        for line in headers.split("\r\n") {
            if line.is_empty() {
                continue;
            }
            if let Some((name, value)) = line.split_once(':') {
                let name = name.trim();
                let value = value.trim();
                let mut h = ProtoItem::subtree(f.header_name, format!("{name}: {value}"), 0, line.len());
                h.push(ProtoItem::new(f.header_name, FieldValue::Str(name.to_string()), 0, name.len()));
                h.push(ProtoItem::new(f.header_value, FieldValue::Str(value.to_string()), 0, value.len()));
                if name.eq_ignore_ascii_case("Host") {
                    host = Some(value.to_string());
                    h.push(ProtoItem::new(f.host, FieldValue::Str(value.to_string()), 0, value.len()));
                }
                if name.eq_ignore_ascii_case("User-Agent") {
                    h.push(ProtoItem::new(f.user_agent, FieldValue::Str(value.to_string()), 0, value.len()));
                }
                if name.eq_ignore_ascii_case("Referer") {
                    h.push(ProtoItem::new(f.referer, FieldValue::Str(value.to_string()), 0, value.len()));
                }
                root.push(h);
            }
        }
        tree.push(root);

        let _ = TapEvent::Http {
            method,
            host,
            path,
            status,
        };
        DissectResult::Ok(headers_end)
    }
}

fn looks_like_http(b: &[u8]) -> bool {
    b.starts_with(b"GET ")
        || b.starts_with(b"POST ")
        || b.starts_with(b"HEAD ")
        || b.starts_with(b"PUT ")
        || b.starts_with(b"DELETE ")
        || b.starts_with(b"OPTIONS ")
        || b.starts_with(b"PATCH ")
        || b.starts_with(b"CONNECT ")
        || b.starts_with(b"TRACE ")
        || b.starts_with(b"HTTP/")
}

fn find_header_break(b: &[u8]) -> Option<(usize, usize)> {
    let end = b.windows(4).position(|w| w == b"\r\n\r\n")?;
    let sl = b[..end].windows(2).position(|w| w == b"\r\n")?;
    Some((sl, end))
}

fn parse_request_line(s: &str) -> Option<(&str, &str, &str)> {
    let mut it = s.split_whitespace();
    let m = it.next()?;
    let u = it.next()?;
    let v = it.next()?;
    if !v.starts_with("HTTP/") { return None; }
    Some((m, u, v))
}

fn parse_status_line(s: &str) -> Option<(&str, u16, &str)> {
    let mut it = s.splitn(3, ' ');
    let v = it.next()?;
    if !v.starts_with("HTTP/") { return None; }
    let c: u16 = it.next()?.parse().ok()?;
    let phrase = it.next().unwrap_or("");
    Some((v, c, phrase))
}
