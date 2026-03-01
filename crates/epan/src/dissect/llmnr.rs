//! LLMNR — RFC 4795, same wire format as DNS.

use crate::dissect::dns::DnsDissector;
use crate::dissector::{DissectResult, Dissector};
use crate::pinfo::PInfo;
use crate::proto::ProtoTree;
use crate::register::Registry;
use crate::tvb::Tvb;

#[derive(Default)] pub struct LlmnrDissector;
impl Dissector for LlmnrDissector {
    fn name(&self) -> &'static str { "llmnr" }
    fn register(&self, reg: &mut Registry) {
        reg.register_protocol("Link-Local Multicast Name Resolution", "llmnr", "llmnr");
    }
    fn dissect(&self, tvb: &Tvb, pinfo: &mut PInfo, tree: &mut ProtoTree) -> DissectResult {
        pinfo.current_proto = "llmnr".into();
        tree.append_proto("llmnr");
        DnsDissector::default().dissect(tvb, pinfo, tree)
    }
}
