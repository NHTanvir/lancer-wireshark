//! Heuristic dissector trait — a dissector that decides via shallow
//! inspection whether the payload is "for it".
//!
//! `tcp.heur`, `udp.heur`, etc. registries are stored on [`crate::Registry`].

use crate::dissector::{DissectResult, Dissector};

pub trait HeuristicDissector: Dissector {
    /// Cheap test before performing full dissection. Default just delegates
    /// to `dissect` — implementors typically override with a magic-bytes check.
    fn heuristic_check(
        &self,
        tvb: &crate::Tvb,
        pinfo: &crate::PInfo,
    ) -> bool {
        let mut throwaway = crate::ProtoTree::new();
        let _ = pinfo; // unused in default
        matches!(
            self.dissect(tvb, &mut crate::PInfo::new(pinfo.frame_number, (pinfo.timestamp_secs, pinfo.timestamp_nanos), pinfo.captured_len, pinfo.original_len), &mut throwaway),
            DissectResult::Ok(_)
        )
    }
}
