//! Minting carriages: the owner-side counterpart of verification.
//!
//! The verifier demands proof that a TXT `g=` generation key lies on
//! the document's delegation path (D10). This module lets ceremonies
//! produce that proof from the keys they already hold: a two-event
//! carriage introducing the generation key (proof of possession,
//! signed by the generation key itself) and delegating to it from the
//! document root (signed by the document key).
//!
//! Access is [`Access::Relay`] (the floor): the generation key holds
//! no document access. It still clears the SIGNING bar — the
//! delegating hop is the root itself (dns-anchor §Who Signs) — which
//! is deliberate: successor generation keys must sign rotation
//! statements. A leaked generation key can pollute cert evidence
//! until rotation; rotation heals it fully (D10 rejects fresh records
//! whose zone generation is off the leaked carriage's path). Analysis
//! in design/security.md.

use keyhive_core::{
    access::Access,
    event::static_event::StaticEvent,
    principal::{group::delegation::StaticDelegation, individual::op::add_key::AddKeyOp},
};
use keyhive_crypto::{share_key::ShareKey, signer::memory::MemorySigner};
use onomancy_core::delegation::DelegationChain;
use rand::rngs::OsRng;

use crate::carriage::{Carriage, EncodeCarriageError};

/// Delegate `generation_key` from `doc_key`'s document, producing the
/// carriage entries a certificate attaches to prove D10 path
/// membership for its TXT `g=`.
///
/// Both signing keys are borrowed only for signing; nothing is stored.
///
/// # Errors
///
/// Returns [`MintError`] if Keyhive's encoding refuses an event —
/// structurally impossible for well-formed keys, but the APIs are
/// fallible.
pub fn generation_carriage(
    doc_key: &ed25519_dalek::SigningKey,
    generation_key: &ed25519_dalek::SigningKey,
) -> Result<DelegationChain, MintError> {
    relay_carriage(doc_key, generation_key)
}

/// A document carriage: proof that a delegation graph roots at
/// `doc_key`'s document, for vouching dev-bridge replicas
/// (`KeyhiveAuthority::vouches_document`). Delegates to an ephemeral
/// witness key at the floor access level; the witness's signing half
/// is dropped before returning — its only job was to give the graph
/// an edge to exist through.
///
/// # Errors
///
/// Returns [`MintError`] if the host provides no entropy or Keyhive's
/// encoding refuses an event.
pub fn document_carriage(
    doc_key: &ed25519_dalek::SigningKey,
) -> Result<DelegationChain, MintError> {
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut OsRng, &mut seed);
    let witness = ed25519_dalek::SigningKey::from_bytes(&seed);

    relay_carriage(doc_key, &witness)
}

/// The shared two-event shape: introduce `delegate` (proof of
/// possession) and delegate to it from `doc_key`'s document at
/// [`Access::Relay`].
fn relay_carriage(
    doc_key: &ed25519_dalek::SigningKey,
    generation_key: &ed25519_dalek::SigningKey,
) -> Result<DelegationChain, MintError> {
    // Introduction: the generation key vouches for itself (proof of
    // possession); the share key is ceremonial — generation keys
    // never decrypt.
    let introduction = MemorySigner(generation_key.clone()).try_sign_sync(AddKeyOp {
        share_key: ShareKey::generate(&mut OsRng),
    })?;

    // Root delegation: subject = issuer (the document), delegate =
    // the generation key, at the floor access level.
    let delegation = MemorySigner(doc_key.clone()).try_sign_sync(StaticDelegation::<[u8; 32]> {
        can: Access::Relay,
        proof: None,
        delegate: generation_key.verifying_key().into(),
        after_revocations: Vec::new(),
        after_content: std::collections::BTreeMap::new(),
    })?;

    let carriage = Carriage::new(vec![
        StaticEvent::PrekeysExpanded(Box::new(introduction)),
        StaticEvent::Delegated(delegation),
    ]);

    Ok(carriage.to_delegation_bytes()?)
}

/// Carriage minting failed.
#[derive(Debug, thiserror::Error)]
pub enum MintError {
    /// An event refused bincode serialization.
    #[error(transparent)]
    Encode(#[from] EncodeCarriageError),

    /// Keyhive's signer refused the payload.
    #[error("unsignable Keyhive event: {0}")]
    Sign(#[from] keyhive_crypto::signed::SigningError),
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use onomancy_core::anchor::doc::DocAnchor;
    use onomancy_dnssec::txt::generation_key::GenerationKey;
    use onomancy_protocol::verifier_state::authority_verifier::AuthorityVerifier;
    use testresult::TestResult;

    use super::*;
    use crate::authority::KeyhiveAuthority;

    #[test]
    fn minted_carriages_prove_path_membership() -> TestResult {
        let doc_key = SigningKey::from_bytes(&[1; 32]);
        let generation_key = SigningKey::from_bytes(&[2; 32]);

        let carriage = generation_carriage(&doc_key, &generation_key)?;
        let generation = GenerationKey::from(generation_key.verifying_key());
        let other = GenerationKey::from(SigningKey::from_bytes(&[3; 32]).verifying_key());

        assert!(
            KeyhiveAuthority.on_path(&carriage, &generation),
            "the minted delegation puts the generation key on the path"
        );
        assert!(
            !KeyhiveAuthority.on_path(&carriage, &other),
            "and nothing else"
        );
        Ok(())
    }

    #[test]
    fn root_granted_generation_keys_clear_the_signing_bar() -> TestResult {
        // Deliberate (dns-anchor §Who Signs): the bar is the
        // DELEGATING hop, and a root grant is the highest hop there
        // is. Leak analysis: design/security.md.
        let doc_key = SigningKey::from_bytes(&[1; 32]);
        let generation_key = SigningKey::from_bytes(&[2; 32]);

        let carriage = generation_carriage(&doc_key, &generation_key)?;
        let anchor = DocAnchor::from(doc_key.verifying_key());

        assert!(
            KeyhiveAuthority.authorizes(&anchor, &generation_key.verifying_key(), &carriage),
            "a root-granted key clears the signing bar"
        );
        Ok(())
    }
}
