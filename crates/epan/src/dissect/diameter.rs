//! Diameter — surface command-code + application-id.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { version: FieldId, length: FieldId, flags: FieldId, cmd_code: FieldId, app_id: FieldId }

#[derive(Default)] pub struct DiameterDissector;
impl Dissector for DiameterDissector {
    fn name(&self) -> &'static str { "diameter" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Diameter Protocol", "diameter", "diameter");
        let f = Fields {
            version: reg.register_field(ProtoField::simple("diameter.version", "Version", FieldType::U8, FieldDisplay::BaseDec)),
            length: reg.register_field(ProtoField::simple("diameter.length", "Length", FieldType::U32, FieldDisplay::BaseDec)),
            flags: reg.register_field(ProtoField::simple("diameter.flags", "Flags", FieldType::U8, FieldDisplay::BaseHex)),
            cmd_code: reg.register_field(ProtoField::simple("diameter.cmd.code", "Command Code", FieldType::U32, FieldDisplay::BaseDec)),
            app_id: reg.register_field(ProtoField::simple("diameter.applicationId", "ApplicationId", FieldType::U32, FieldDisplay::BaseDec)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 20 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "diameter".into();
        tree.append_proto("diameter");
        let mut root = ProtoItem::subtree(f.version, "Diameter".into(), 0, 20);
        root.push(ProtoItem::new(f.version, FieldValue::U64(tvb.u8(0).unwrap_or(0) as u64), 0, 1));
        root.push(ProtoItem::new(f.length, FieldValue::U64(tvb.u24_be(1).unwrap_or(0) as u64), 1, 3));
        root.push(ProtoItem::new(f.flags, FieldValue::U64(tvb.u8(4).unwrap_or(0) as u64), 4, 1));
        root.push(ProtoItem::new(f.cmd_code, FieldValue::U64(tvb.u24_be(5).unwrap_or(0) as u64), 5, 3));
        root.push(ProtoItem::new(f.app_id, FieldValue::U64(tvb.u32_be(8).unwrap_or(0) as u64), 8, 4));
        tree.push(root);
        DissectResult::Ok(20)
    }
}
