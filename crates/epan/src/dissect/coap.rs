//! CoAP — RFC 7252 fixed header.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { ver: FieldId, ty: FieldId, code: FieldId, mid: FieldId }

#[derive(Default)] pub struct CoapDissector;
impl Dissector for CoapDissector {
    fn name(&self) -> &'static str { "coap" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Constrained Application Protocol", "coap", "coap");
        let f = Fields {
            ver: reg.register_field(ProtoField::simple("coap.version", "Version", FieldType::U8, FieldDisplay::BaseDec)),
            ty: reg.register_field(ProtoField::simple("coap.type", "Type", FieldType::U8, FieldDisplay::BaseDec)),
            code: reg.register_field(ProtoField::simple("coap.code", "Code", FieldType::U8, FieldDisplay::BaseHex)),
            mid: reg.register_field(ProtoField::simple("coap.mid", "Message ID", FieldType::U16, FieldDisplay::BaseDec)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 4 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "coap".into();
        tree.append_proto("coap");
        let first = tvb.u8(0).unwrap_or(0);
        let mut root = ProtoItem::subtree(f.ver, "CoAP".into(), 0, 4);
        root.push(ProtoItem::new(f.ver, FieldValue::U64((first >> 6) as u64), 0, 1));
        root.push(ProtoItem::new(f.ty, FieldValue::U64(((first >> 4) & 0x03) as u64), 0, 1));
        root.push(ProtoItem::new(f.code, FieldValue::U64(tvb.u8(1).unwrap_or(0) as u64), 1, 1));
        root.push(ProtoItem::new(f.mid, FieldValue::U64(tvb.u16_be(2).unwrap_or(0) as u64), 2, 2));
        tree.push(root);
        DissectResult::Ok(4)
    }
}
