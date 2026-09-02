//! The chain-validation seam: what a validated chain proves.
//!
//! The verifier derivation in `onomancy_protocol` is pure over its
//! inputs; chain validation is a seam so this crate (RFC 4034/4035
//! over supplied bytes) can plug in — and so conformance tests can
//! fake it without mocking IO, because there is no IO to mock.

use alloc::vec::Vec;

use crate::{
    chain::DnssecChain, dns_name::DnsName, freshness::ValidityWindow, txt::record::TxtRecord,
};

/// What a DNSSEC chain, once validated from the verifier's own trust
/// anchor, proves about a hostname's `_onomancy` owner name: a TXT
/// `RRset` carrying binding records.
///
/// Deliberately no absence variant: negative proofs are out of the
/// protocol at v0 — a chain without a provable TXT leaf is
/// simply invalid, and unbinding awaits the future owner-signed
/// unbind statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainProof {
    /// Every parseable `ONO0` record in the proven `RRset`, in
    /// `RRset` order. Several is normal during migration
    /// dual-publish; SELECTION is the derivation's job (zone-state
    /// key), not the validator's — the validator only proves what
    /// the zone said. Unknown-version and unknown-record strings
    /// are already dispositioned out; per-record grammar rejections
    /// drop only the offending record.
    pub records: Vec<TxtRecord>,

    /// The chain's ∩-window.
    pub window: ValidityWindow,
}

/// Validates DNSSEC chains against the baked-in trust anchor.
/// Sans-IO: bytes in, proof out.
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

/// The chain never verified from the trust anchor: invalid ✗, not
/// stale — discarded entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("chain does not verify from the trust anchor")]
pub struct InvalidChain;
