//! Telnet — surface IAC commands and a printable payload field.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { data: FieldId, cmd: FieldId }

#[derive(Default)] pub struct TelnetDissector;
impl Dissector for TelnetDissector {
    fn name(&self) -> &'static str { "telnet" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Telnet", "telnet", "telnet");
        let f = Fields {
            data: reg.register_field(ProtoField::simple("telnet.data", "Data", FieldType::String, FieldDisplay::StrAscii)),
            cmd: reg.register_field(ProtoField::simple("telnet.cmd", "Command", FieldType::U8, FieldDisplay::BaseDec)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        let f = F.get().unwrap();
        pinfo.current_proto = "telnet".into();
        tree.append_proto("telnet");
        let mut root = ProtoItem::subtree(f.data, "Telnet".into(), 0, tvb.len());
        let mut data = Vec::with_capacity(tvb.len());
        let mut i = 0;
        while i < tvb.len() {
            let b = tvb.u8(i).unwrap_or(0);
            if b == 0xFF && i + 1 < tvb.len() {
                let cmd = tvb.u8(i + 1).unwrap_or(0);
                root.push(ProtoItem::new(f.cmd, FieldValue::U64(cmd as u64), i + 1, 1));
                i += 2;
                continue;
            }
            data.push(b);
            i += 1;
        }
        if !data.is_empty() {
            let s = String::from_utf8_lossy(&data).into_owned();
            root.push(ProtoItem::new(f.data, FieldValue::Str(s), 0, data.len()));
        }
        tree.push(root);
        DissectResult::Ok(tvb.len())
    }
}
