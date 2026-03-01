//! WebSocket — RFC 6455 frame header.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { fin: FieldId, opcode: FieldId, masked: FieldId, length: FieldId, mask_key: FieldId, payload: FieldId }

#[derive(Default)] pub struct WebsocketDissector;
impl Dissector for WebsocketDissector {
    fn name(&self) -> &'static str { "websocket" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("WebSocket", "websocket", "websocket");
        let f = Fields {
            fin: reg.register_field(ProtoField::simple("websocket.fin", "Fin", FieldType::Boolean, FieldDisplay::BaseNone)),
            opcode: reg.register_field(ProtoField::simple("websocket.opcode", "Opcode", FieldType::U8, FieldDisplay::BaseHex)),
            masked: reg.register_field(ProtoField::simple("websocket.mask", "Mask", FieldType::Boolean, FieldDisplay::BaseNone)),
            length: reg.register_field(ProtoField::simple("websocket.payload_length", "Payload Length", FieldType::U64, FieldDisplay::BaseDec)),
            mask_key: reg.register_field(ProtoField::simple("websocket.masking_key", "Masking Key", FieldType::U32, FieldDisplay::BaseHex)),
            payload: reg.register_field(ProtoField::simple("websocket.payload", "Payload", FieldType::Bytes, FieldDisplay::BaseNone)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 2 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "websocket".into();
        tree.append_proto("websocket");
        let b0 = tvb.u8(0).unwrap_or(0);
        let b1 = tvb.u8(1).unwrap_or(0);
        let fin = (b0 & 0x80) != 0;
        let op = b0 & 0x0F;
        let masked = (b1 & 0x80) != 0;
        let len_short = (b1 & 0x7F) as u64;
        let (length, header_extra) = if len_short == 126 {
            (tvb.u16_be(2).unwrap_or(0) as u64, 2)
        } else if len_short == 127 {
            (tvb.u64_be(2).unwrap_or(0), 8)
        } else {
            (len_short, 0)
        };
        let mut hdr_end = 2 + header_extra;
        let mask_key = if masked {
            let v = tvb.u32_be(hdr_end).unwrap_or(0);
            hdr_end += 4;
            Some(v)
        } else {
            None
        };
        let mut root = ProtoItem::subtree(f.opcode, format!("WebSocket frame op=0x{op:x}"), 0, hdr_end);
        root.push(ProtoItem::new(f.fin, FieldValue::Bool(fin), 0, 1));
        root.push(ProtoItem::new(f.opcode, FieldValue::U64(op as u64), 0, 1));
        root.push(ProtoItem::new(f.masked, FieldValue::Bool(masked), 1, 1));
        root.push(ProtoItem::new(f.length, FieldValue::U64(length), 1, 1 + header_extra));
        if let Some(k) = mask_key {
            root.push(ProtoItem::new(f.mask_key, FieldValue::U64(k as u64), hdr_end - 4, 4));
        }
        if length > 0 && hdr_end + length as usize <= tvb.len() {
            let payload = tvb.bytes(hdr_end, length as usize).unwrap_or(&[]);
            root.push(ProtoItem::new(f.payload, FieldValue::Bytes(payload.to_vec()), hdr_end, length as usize));
        }
        tree.push(root);
        DissectResult::Ok((hdr_end + length as usize).min(tvb.len()))
    }
}
