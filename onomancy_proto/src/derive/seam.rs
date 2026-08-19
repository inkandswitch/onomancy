//! The derivation's trait seams: chain validation and Keyhive
//! authority verification.
//!
//! `derive` is pure over its inputs; the two cryptographic oracles it
//! consults are seams so that `onomancy_dnssec` (RFC 4034/4035 over
//! supplied bytes) and `onomancy_keyhive` (delegation-graph
//! verification) can plug in — and so conformance tests can fake them
//! without mocking IO, because there is no IO to mock.

use alloc::vec::Vec;
use ed25519_dalek::VerifyingKey;
use onomancy_core::{
    cert::chain::DnssecChain,
    delegation::DelegationBytes,
    freshness::ChainWindow,
    name::{dns::DnsName, doc::DocAnchor},
    time::UnixSeconds,
    txt::{generation_key::GenerationKey, record::TxtRecord},
};

/// What a DNSSEC chain, once validated from the verifier's own trust
/// anchor, proves about a hostname's `_onomancy` owner name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainProof {
    /// NSEC/NSEC3 proven absence of the binding record.
    Absence {
        /// The chain's ∩-window.
        window: ChainWindow,
        /// Inception of the denial records' own RRSIG — the absence
        /// comparator (the chain ∩-window start moves with unrelated
        /// parent re-signing).
        leaf_inception: UnixSeconds,
    },

    /// A proven TXT `RRset` carrying binding records.
    Binding {
        /// Inception of the TXT `RRset`'s own RRSIG.
        leaf_inception: UnixSeconds,
        /// Every parseable `ONO0` record in the proven `RRset`, in
        /// `RRset` order. Several is normal during migration
        /// dual-publish; SELECTION is the derivation's job (zone-state
        /// key), not the validator's — the validator only proves what
        /// the zone said. Unknown-version and unknown-record strings
        /// are already dispositioned out; per-record grammar
        /// rejections (D5) drop only the offending record.
        records: Vec<TxtRecord>,
        /// The chain's ∩-window.
        window: ChainWindow,
    },
}

/// Validates DNSSEC chains against the baked-in trust anchor.
/// Sans-IO: bytes in, proof out — `onomancy_dnssec`'s seam.
pub trait ChainValidator {
    /// Validate `chain` for `hostname`'s `_onomancy` owner name.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidChain`] when the chain never verifies from the
    /// trust anchor (including empty ∩-windows and unsupported
    /// algorithms, which MUST be invalid ✗, never insecure-but-ok).
    fn validate(&self, hostname: &DnsName, chain: &DnssecChain)
    -> Result<ChainProof, InvalidChain>;
}

/// Verifies Keyhive delegation proofs — `onomancy_keyhive`'s seam.
pub trait AuthorityVerifier {
    /// Whether `carriage` is a valid delegation chain rooting at
    /// `root`, terminating at `signer`, with the delegating hop held
    /// at admin access.
    fn authorizes(
        &self,
        root: &DocAnchor,
        signer: &VerifyingKey,
        carriage: &[DelegationBytes],
    ) -> bool;

    /// Whether `carriage` threads `generation` at any depth — the
    /// path-membership check behind the TXT `g=` rules.
    fn threads(&self, carriage: &[DelegationBytes], generation: &GenerationKey) -> bool;
}

/// The chain never verified from the trust anchor: invalid ✗, not
/// stale — discarded entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("chain does not verify from the trust anchor")]
pub struct InvalidChain;
