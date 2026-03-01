//! AMQP 0-9-1 frame header.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { ty: FieldId, channel: FieldId, length: FieldId }

#[derive(Default)] pub struct AmqpDissector;
impl Dissector for AmqpDissector {
    fn name(&self) -> &'static str { "amqp" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Advanced Message Queueing Protocol", "amqp", "amqp");
        let f = Fields {
            ty: reg.register_field(ProtoField::simple("amqp.type", "Frame Type", FieldType::U8, FieldDisplay::BaseDec)),
            channel: reg.register_field(ProtoField::simple("amqp.channel", "Channel", FieldType::U16, FieldDisplay::BaseDec)),
            length: reg.register_field(ProtoField::simple("amqp.length", "Length", FieldType::U32, FieldDisplay::BaseDec)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 7 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "amqp".into();
        tree.append_proto("amqp");
        let mut root = ProtoItem::subtree(f.ty, "AMQP".into(), 0, 7);
        root.push(ProtoItem::new(f.ty, FieldValue::U64(tvb.u8(0).unwrap_or(0) as u64), 0, 1));
        root.push(ProtoItem::new(f.channel, FieldValue::U64(tvb.u16_be(1).unwrap_or(0) as u64), 1, 2));
        root.push(ProtoItem::new(f.length, FieldValue::U64(tvb.u32_be(3).unwrap_or(0) as u64), 3, 4));
        tree.push(root);
        DissectResult::Ok(7)
    }
}
