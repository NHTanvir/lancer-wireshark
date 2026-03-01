//! Cisco CDP — minimal TLV walker.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { version: FieldId, ttl: FieldId, csum: FieldId }

#[derive(Default)] pub struct CdpDissector;
impl Dissector for CdpDissector {
    fn name(&self) -> &'static str { "cdp" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Cisco Discovery Protocol", "cdp", "cdp");
        let f = Fields {
            version: reg.register_field(ProtoField::simple("cdp.version", "Version", FieldType::U8, FieldDisplay::BaseDec)),
            ttl: reg.register_field(ProtoField::simple("cdp.ttl", "TTL", FieldType::U8, FieldDisplay::BaseDec)),
            csum: reg.register_field(ProtoField::simple("cdp.checksum", "Checksum", FieldType::U16, FieldDisplay::BaseHex)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 4 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "cdp".into();
        tree.append_proto("cdp");
        let mut root = ProtoItem::subtree(f.version, "Cisco Discovery Protocol".into(), 0, tvb.len());
        root.push(ProtoItem::new(f.version, FieldValue::U64(tvb.u8(0).unwrap_or(0) as u64), 0, 1));
        root.push(ProtoItem::new(f.ttl, FieldValue::U64(tvb.u8(1).unwrap_or(0) as u64), 1, 1));
        root.push(ProtoItem::new(f.csum, FieldValue::U64(tvb.u16_be(2).unwrap_or(0) as u64), 2, 2));
        tree.push(root);
        DissectResult::Ok(tvb.len())
    }
}
