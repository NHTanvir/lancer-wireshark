//! IPsec — AH (proto 51) and ESP (proto 50). Decryption not in v1.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { spi: FieldId, seq: FieldId }

#[derive(Default)] pub struct IpsecDissector;
impl Dissector for IpsecDissector {
    fn name(&self) -> &'static str { "ipsec.esp" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("IPsec ESP", "esp", "esp");
        let f = Fields {
            spi: reg.register_field(ProtoField::simple("esp.spi", "SPI", FieldType::U32, FieldDisplay::BaseHex)),
            seq: reg.register_field(ProtoField::simple("esp.seq", "Sequence Number", FieldType::U32, FieldDisplay::BaseDec)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 8 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "esp".into();
        tree.append_proto("esp");
        let mut root = ProtoItem::subtree(f.spi, "Encapsulating Security Payload".into(), 0, tvb.len());
        root.push(ProtoItem::new(f.spi, FieldValue::U64(tvb.u32_be(0).unwrap_or(0) as u64), 0, 4));
        root.push(ProtoItem::new(f.seq, FieldValue::U64(tvb.u32_be(4).unwrap_or(0) as u64), 4, 4));
        tree.push(root);
        DissectResult::Ok(tvb.len())
    }
}
