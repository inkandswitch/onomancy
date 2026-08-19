//! The zone-state key: one lexicographic sort key per record.
//!
//! `(window_end, serial, issued_at)` — one key per record rather than
//! pairwise comparators, deliberately: mixed pairwise rules (windows
//! for disjoint pairs, serials for overlapping ones) are non-transitive
//! and can cycle on honest inputs after a serial reset. A single key
//! makes the order total and "the maximal record" well-defined.
//!
//! `window_end` leads because it is DNSSEC-vouched where serials are
//! publisher-chosen; serials break exact window ties; `issued_at` is
//! signer-claimed and breaks ties only **within a single document** —
//! cross-document equality at `(window_end, serial)` is zone
//! equivocation, which a signer-claimed field must never resolve. That
//! scoping rule lives in the comparison ladder (`onomancy_proto`); this
//! type is just the key.

use crate::{time::UnixSeconds, txt::serial::Serial};

/// A record's zone-state sort key, ordered lexicographically.
///
/// The derived [`Ord`] relies on field declaration order:
/// `window_end`, then `serial`, then `issued_at`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ZoneStateKey {
    /// The end of the record's chain ∩-window: DNSSEC-vouched.
    pub window_end: UnixSeconds,

    /// The TXT serial `n=`: zone-vouched.
    pub serial: Serial,

    /// The certificate's claimed issuance time: signer-claimed. A bare
    /// chain refresh ingested without its certificate carries zero
    /// here, sorting below an equal-window, equal-serial certificate
    /// item.
    pub issued_at: UnixSeconds,
}

impl ZoneStateKey {
    /// The key with `issued_at` zeroed: the spelling for a bare chain
    /// refresh, and the projection under which cross-document
    /// equivocation is judged.
    #[must_use]
    pub const fn zone_vouched(&self) -> (UnixSeconds, Serial) {
        (self.window_end, self.serial)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(window_end: u64, serial: u64, issued_at: u64) -> ZoneStateKey {
        ZoneStateKey {
            window_end: UnixSeconds::from(window_end),
            serial: Serial::from(serial),
            issued_at: UnixSeconds::from(issued_at),
        }
    }

    #[test]
    fn window_end_dominates_serial_dominates_issued_at() {
        // DNSSEC-vouched beats zone-vouched beats signer-claimed.
        assert!(key(2, 0, 0) > key(1, 99, 99));
        assert!(key(1, 2, 0) > key(1, 1, 99));
        assert!(key(1, 1, 2) > key(1, 1, 1));
    }

    mod props {
        use super::*;

        /// The derived order is total and agrees with tuple order —
        /// the well-defined-maximum property the spec buys with one
        /// key instead of pairwise comparators.
        #[test]
        fn order_is_lexicographic() {
            bolero::check!()
                .with_type::<((u64, u64, u64), (u64, u64, u64))>()
                .for_each(|((w1, s1, i1), (w2, s2, i2))| {
                    let left = key(*w1, *s1, *i1);
                    let right = key(*w2, *s2, *i2);

                    assert_eq!(
                        left.cmp(&right),
                        (*w1, *s1, *i1).cmp(&(*w2, *s2, *i2)),
                        "zone-state key order must be tuple order"
                    );
                });
        }
    }
}
