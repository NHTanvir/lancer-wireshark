//! NTPv4 short-header dissector.

use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::{FieldDisplay, FieldType, FieldValue, ProtoField, ProtoItem, ProtoTree};
use crate::register::{FieldId, Registry};
use crate::tvb::Tvb;
use once_cell::sync::OnceCell;

static F: OnceCell<Fields> = OnceCell::new();
#[derive(Debug, Clone, Copy)] struct Fields { li_vn_mode: FieldId, stratum: FieldId, poll: FieldId, precision: FieldId, ref_id: FieldId }

#[derive(Default)] pub struct NtpDissector;
impl Dissector for NtpDissector {
    fn name(&self) -> &'static str { "ntp" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Network Time Protocol", "ntp", "ntp");
        let f = Fields {
            li_vn_mode: reg.register_field(ProtoField::simple("ntp.flags", "Flags", FieldType::U8, FieldDisplay::BaseHex)),
            stratum: reg.register_field(ProtoField::simple("ntp.stratum", "Stratum", FieldType::U8, FieldDisplay::BaseDec)),
            poll: reg.register_field(ProtoField::simple("ntp.ppoll", "Poll", FieldType::U8, FieldDisplay::BaseDec)),
            precision: reg.register_field(ProtoField::simple("ntp.precision", "Precision", FieldType::I8, FieldDisplay::BaseDec)),
            ref_id: reg.register_field(ProtoField::simple("ntp.refid", "Reference ID", FieldType::U32, FieldDisplay::BaseHex)),
        };
        let _ = F.set(f);
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        if tvb.len() < 48 { return DissectResult::NeedMoreData; }
        let f = F.get().unwrap();
        pinfo.current_proto = "ntp".into();
        tree.append_proto("ntp");
        let mut root = ProtoItem::subtree(f.li_vn_mode, "NTP".into(), 0, 48);
        root.push(ProtoItem::new(f.li_vn_mode, FieldValue::U64(tvb.u8(0).unwrap_or(0) as u64), 0, 1));
        root.push(ProtoItem::new(f.stratum, FieldValue::U64(tvb.u8(1).unwrap_or(0) as u64), 1, 1));
        root.push(ProtoItem::new(f.poll, FieldValue::U64(tvb.u8(2).unwrap_or(0) as u64), 2, 1));
        root.push(ProtoItem::new(f.precision, FieldValue::I64(tvb.u8(3).unwrap_or(0) as i8 as i64), 3, 1));
        root.push(ProtoItem::new(f.ref_id, FieldValue::U64(tvb.u32_be(12).unwrap_or(0) as u64), 12, 4));
        tree.push(root);
        DissectResult::Ok(48)
    }
}
