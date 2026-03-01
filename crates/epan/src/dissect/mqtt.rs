//! MQTT — fixed header parse.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { ty: FieldId, flags: FieldId, length: FieldId }

#[derive(Default)] pub struct MqttDissector;
impl Dissector for MqttDissector {
    fn name(&self) -> &'static str { "mqtt" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("MQ Telemetry Transport", "mqtt", "mqtt");
        let f = Fields {
            ty: reg.register_field(ProtoField::simple("mqtt.msgtype", "Message Type", FieldType::U8, FieldDisplay::BaseDec)),
            flags: reg.register_field(ProtoField::simple("mqtt.flags", "Flags", FieldType::U8, FieldDisplay::BaseHex)),
            length: reg.register_field(ProtoField::simple("mqtt.len", "Remaining Length", FieldType::U32, FieldDisplay::BaseDec)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 2 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "mqtt".into();
        tree.append_proto("mqtt");
        let first = tvb.u8(0).unwrap_or(0);
        let ty = first >> 4;
        let flags = first & 0x0F;
        let mut rem_len = 0u32;
        let mut mul = 1u32;
        let mut p = 1usize;
        while p < tvb.len() {
            let b = tvb.u8(p).unwrap_or(0);
            rem_len += (b as u32 & 0x7F) * mul;
            mul *= 128;
            p += 1;
            if b & 0x80 == 0 { break; }
            if mul > 128 * 128 * 128 { break; }
        }
        let mut root = ProtoItem::subtree(f.ty, format!("MQTT Type {ty}"), 0, p);
        root.push(ProtoItem::new(f.ty, FieldValue::U64(ty as u64), 0, 1));
        root.push(ProtoItem::new(f.flags, FieldValue::U64(flags as u64), 0, 1));
        root.push(ProtoItem::new(f.length, FieldValue::U64(rem_len as u64), 1, p - 1));
        tree.push(root);
        DissectResult::Ok(p)
    }
}
