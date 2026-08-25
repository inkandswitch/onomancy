//! Table-driven fakes for the derivation's oracles.
//!
//! The seams are sans-IO, so faking them is a lookup table, not a
//! mock: a [`MemoryValidator`] maps (hostname, chain) to the proof a
//! real DNSSEC walk would produce, and a [`MemoryAuthority`] answers
//! delegation questions from configured deny-lists (permissive by
//! default — carriage semantics are `onomancy_keyhive`'s job, and
//! tests usually care about everything *around* them).

use alloc::vec::Vec;
use ed25519_dalek::VerifyingKey;

use onomancy_core::{
    certificate::chain::DnssecChain,
    collections::{Map, Set},
    delegation::DelegationBytes,
    digest::{Blake3, Digest},
    name::{dns::DnsName, doc::DocAnchor},
    txt::generation_key::GenerationKey,
};

use super::seam::{AuthorityVerifier, ChainProof, ChainValidator, InvalidChain};

/// Content-address a chain's framing, the lookup key both fakes use.
fn chain_key(chain: &DnssecChain) -> Digest<Blake3, [u8]> {
    let mut framed = Vec::new();
    chain.write_framed(&mut framed);
    Digest::hash(&framed)
}

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

/// An [`AuthorityVerifier`] with configurable deny-lists, permissive
/// by default.
#[derive(Debug, Clone, Default)]
pub struct MemoryAuthority {
    denied_signers: Set<(DocAnchor, [u8; 32])>,
    off_paths: Set<[u8; 32]>,
}

impl MemoryAuthority {
    /// Deny authorization for `signer` acting for `root`.
    #[must_use]
    pub fn deny(mut self, root: DocAnchor, signer: &VerifyingKey) -> Self {
        self.denied_signers.insert((root, *signer.as_bytes()));
        self
    }

    /// Report `generation` as on NO delegation path (for D10
    /// scenarios).
    #[must_use]
    pub fn off_path(mut self, generation: &GenerationKey) -> Self {
        self.off_paths
            .insert(*generation.verifying_key().as_bytes());
        self
    }
}

impl AuthorityVerifier for MemoryAuthority {
    fn authorizes(
        &self,
        root: &DocAnchor,
        signer: &VerifyingKey,
        _carriage: &[DelegationBytes],
    ) -> bool {
        !self.denied_signers.contains(&(*root, *signer.as_bytes()))
    }

    fn on_path(&self, _carriage: &[DelegationBytes], generation: &GenerationKey) -> bool {
        !self
            .off_paths
            .contains(generation.verifying_key().as_bytes())
    }
}
