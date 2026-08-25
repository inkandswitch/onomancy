//! `Head` ⇄ `ChangeHash` conversions.
//!
//! Both sides are 32 raw bytes: Onomancy's [`Head`] is the wire/name
//! vocabulary (bs58check in names, raw bytes in certificates), and
//! Automerge's [`ChangeHash`] is the substrate's own change identity.
//! Orphan rules keep these as free functions — neither type is ours.

use automerge::ChangeHash;
use onomancy_core::anchor::doc::Head;

/// The Automerge change hash a head pins.
#[must_use]
pub const fn to_change_hash(head: &Head) -> ChangeHash {
    ChangeHash(*head.as_bytes())
}

/// The head form of an Automerge change hash — e.g. for stamping a
/// certificate's advisory `heads` field from `Automerge::get_heads`.
#[must_use]
pub fn from_change_hash(hash: &ChangeHash) -> Head {
    Head::from(hash.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversions_roundtrip() {
        let head = Head::from([7u8; 32]);
        assert_eq!(from_change_hash(&to_change_hash(&head)), head);

        let hash = ChangeHash([9u8; 32]);
        assert_eq!(to_change_hash(&from_change_hash(&hash)), hash);
    }
}
