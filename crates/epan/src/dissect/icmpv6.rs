//! ICMPv6.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { ty: FieldId, code: FieldId, csum: FieldId }

#[derive(Default)] pub struct Icmpv6Dissector;
impl Dissector for Icmpv6Dissector {
    fn name(&self) -> &'static str { "icmpv6" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Internet Control Message Protocol v6", "icmpv6", "icmpv6");
        let f = Fields {
            ty: reg.register_field(ProtoField::simple("icmpv6.type", "Type", FieldType::U8, FieldDisplay::BaseDec)),
            code: reg.register_field(ProtoField::simple("icmpv6.code", "Code", FieldType::U8, FieldDisplay::BaseDec)),
            csum: reg.register_field(ProtoField::simple("icmpv6.checksum", "Checksum", FieldType::U16, FieldDisplay::BaseHex)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 4 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "icmpv6".into();
        tree.append_proto("icmpv6");
        let mut root = ProtoItem::subtree(f.ty, "ICMPv6".into(), 0, tvb.len());
        root.push(ProtoItem::new(f.ty, FieldValue::U64(tvb.u8(0).unwrap_or(0) as u64), 0, 1));
        root.push(ProtoItem::new(f.code, FieldValue::U64(tvb.u8(1).unwrap_or(0) as u64), 1, 1));
        root.push(ProtoItem::new(f.csum, FieldValue::U64(tvb.u16_be(2).unwrap_or(0) as u64), 2, 2));
        tree.push(root);
        DissectResult::Ok(tvb.len())
    }
}
