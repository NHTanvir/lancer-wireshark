//! POP3 — text-line dissector.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<FieldId> = OnceCell::new();

#[derive(Default)] pub struct Pop3Dissector;
impl Dissector for Pop3Dissector {
    fn name(&self) -> &'static str { "pop3" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Post Office Protocol", "pop", "pop");
        let _ = F.set(reg.register_field(ProtoField::simple("pop.line", "Line", FieldType::String, FieldDisplay::StrAscii)));
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        let line = std::str::from_utf8(tvb.as_slice()).unwrap_or("").lines().next().unwrap_or("").trim_end();
        pinfo.current_proto = "pop3".into();
        tree.append_proto("pop");
        pinfo.set_info(line.into());
        let fid = *F.get().unwrap();
        let mut root = ProtoItem::subtree(fid, format!("POP3: {line}"), 0, line.len());
        root.push(ProtoItem::new(fid, FieldValue::Str(line.into()), 0, line.len()));
        tree.push(root);
        DissectResult::Ok(tvb.len())
    }
}
