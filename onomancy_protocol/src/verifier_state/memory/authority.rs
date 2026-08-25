//! A configurable fake for the authority-verification oracle.
//!
//! Permissive by default with deny-lists — carriage semantics are
//! `onomancy_keyhive`'s job, and tests usually care about everything
//! *around* them.

use ed25519_dalek::VerifyingKey;

use onomancy_core::{anchor::doc::DocAnchor, collections::Set, delegation::DelegationChain};
use onomancy_dnssec::txt::generation_key::GenerationKey;

use crate::verifier_state::authority_verifier::AuthorityVerifier;

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
        _carriage: &DelegationChain,
    ) -> bool {
        !self.denied_signers.contains(&(*root, *signer.as_bytes()))
    }

    fn on_path(&self, _carriage: &DelegationChain, generation: &GenerationKey) -> bool {
        !self
            .off_paths
            .contains(generation.verifying_key().as_bytes())
    }
}
