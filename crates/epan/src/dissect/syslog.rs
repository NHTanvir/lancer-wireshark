//! Syslog (RFC 5424 / 3164) — printable line.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<FieldId> = OnceCell::new();

#[derive(Default)] pub struct SyslogDissector;
impl Dissector for SyslogDissector {
    fn name(&self) -> &'static str { "syslog" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Syslog message", "syslog", "syslog");
        let _ = F.set(reg.register_field(ProtoField::simple("syslog.msg", "Message", FieldType::String, FieldDisplay::StrAscii)));
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        let s = String::from_utf8_lossy(tvb.as_slice()).into_owned();
        pinfo.current_proto = "syslog".into();
        tree.append_proto("syslog");
        pinfo.set_info(s.clone());
        let fid = *F.get().unwrap();
        let mut root = ProtoItem::subtree(fid, format!("Syslog: {s}"), 0, tvb.len());
        root.push(ProtoItem::new(fid, FieldValue::Str(s), 0, tvb.len()));
        tree.push(root);
        DissectResult::Ok(tvb.len())
    }
}
