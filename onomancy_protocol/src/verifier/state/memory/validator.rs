//! A table-driven fake for the chain-validation oracle.
//!
//! The seam is sans-IO, so faking it is a lookup table, not a mock:
//! the validator maps (hostname, chain) to the proof a real DNSSEC
//! walk would produce. Unregistered chains are invalid ✗.

use alloc::vec::Vec;

use onomancy_core::{
    collections::Map,
    digest::{Blake3, Digest},
};
use onomancy_dnssec::{
    chain::DnssecChain,
    chain_proof::{ChainProof, ChainValidator, InvalidChain},
    dns_name::DnsName,
};

/// A [`ChainValidator`] backed by a proof table.
#[derive(Debug, Clone, Default)]
pub struct MemoryValidator {
    proofs: Map<(DnsName, Digest<Blake3, [u8]>), ChainProof>,
}

impl MemoryValidator {
    /// Register the proof that validating `chain` for `hostname`
    /// yields. Unregistered chains are invalid ✗.
    #[must_use]
    pub fn with(mut self, hostname: DnsName, chain: &DnssecChain, proof: ChainProof) -> Self {
        self.proofs.insert((hostname, chain_key(chain)), proof);
        self
    }
}

impl ChainValidator for MemoryValidator {
    fn validate(
        &self,
        hostname: &DnsName,
        chain: &DnssecChain,
    ) -> Result<ChainProof, InvalidChain> {
        self.proofs
            .get(&(hostname.clone(), chain_key(chain)))
            .cloned()
            .ok_or(InvalidChain)
    }
}

/// Content-address a chain's framing, the fake's lookup key.
fn chain_key(chain: &DnssecChain) -> Digest<Blake3, [u8]> {
    let mut framed = Vec::new();
    chain.write_framed(&mut framed);
    Digest::hash(&framed)
}
