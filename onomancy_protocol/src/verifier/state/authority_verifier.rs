//! The Keyhive authority-verification seam.
//!
//! `derive` is pure over its inputs; authority verification is a seam
//! so `onomancy_keyhive` (delegation-graph verification) can plug in —
//! and so conformance tests can fake it without mocking IO. The chain
//! seam (`ChainValidator`) lives in `onomancy_dnssec`.

use ed25519_dalek::VerifyingKey;
use onomancy_core::{anchor::doc::DocAnchor, delegation_chain::DelegationChain};
use onomancy_dnssec::txt::generation_key::GenerationKey;

/// Verifies Keyhive delegation proofs — `onomancy_keyhive`'s seam.
pub trait AuthorityVerifier {
    /// Whether `carriage` is a valid delegation chain rooting at
    /// `root`, terminating at `signer`, with the delegating hop held
    /// at admin access.
    fn authorizes(
        &self,
        root: &DocAnchor,
        signer: &VerifyingKey,
        carriage: &DelegationChain,
    ) -> bool;

    /// Whether `generation` lies on the delegation path in `carriage`,
    /// at any depth — the path-membership check behind the TXT `g=` rules.
    fn on_path(&self, carriage: &DelegationChain, generation: &GenerationKey) -> bool;
}
