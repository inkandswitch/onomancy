//! [`KeyhiveAuthority`]: the real [`AuthorityVerifier`].
//!
//! Verification is a replay: a throwaway Keyhive instance ingests the
//! carriage's events (each signature-checked by Keyhive on receipt),
//! materializes the delegation graph they describe, and answers
//! membership questions against it. Nothing is trusted from the
//! carriage that the graph does not prove; every failure mode —
//! unreadable entry, missing dependency, absent membership,
//! insufficient access — degrades to a refusal, never an acceptance.
//!
//! Two rules beyond the graph itself:
//!
//! - **Identity**: the document root key speaks for its own document
//!   with an empty chain. A signer IS the root — nothing to delegate.
//! - **The signing bar** (dns-anchor §Who Signs, one bar for
//!   certificates and statements alike): the chain terminates at the
//!   signer with the DELEGATING hop held at [`Access::Admin`] — the
//!   signer's own access rank is irrelevant, which is exactly why
//!   successor generation keys can sign rotation statements without
//!   holding any document authority. Path membership
//!   ([`on_path`](AuthorityVerifier::on_path)) accepts any access —
//!   a generation key is *on* the path by being delegated to at all.

use ed25519_dalek::VerifyingKey;
use future_form::Sendable;
use futures::executor::block_on;
use keyhive_core::{
    access::Access, keyhive::Keyhive, listener::no_listener::NoListener,
    principal::identifier::Identifier, store::ciphertext::memory::MemoryCiphertextStore,
};
use keyhive_crypto::signer::memory::MemorySigner;
use onomancy_core::{anchor::doc::DocAnchor, delegation_chain::DelegationChain};
use onomancy_dnssec::txt::generation_key::GenerationKey;
use onomancy_protocol::verifier::state::authority_verifier::AuthorityVerifier;
use rand::rngs::OsRng;

use crate::carriage::Carriage;

type Instance = Keyhive<
    Sendable,
    MemorySigner,
    [u8; 32],
    Vec<u8>,
    MemoryCiphertextStore<[u8; 32], Vec<u8>>,
    NoListener,
    OsRng,
>;

/// Authority verification over real Keyhive delegation graphs.
///
/// Stateless between calls: each question replays its carriage into a
/// fresh instance, so verdicts depend only on the presented evidence
/// — same input, same answer, no cross-certificate contamination.
#[derive(Debug, Clone, Copy, Default)]
pub struct KeyhiveAuthority;

impl KeyhiveAuthority {
    /// Replay `carriage` into a fresh instance.
    ///
    /// Events are retried to a fixpoint so entry order only has to be
    /// dependency-*compatible*, not perfectly sorted. Returns `None`
    /// when any entry fails to parse or never ingests — an authority
    /// proof with unreadable or dangling pieces proves nothing.
    async fn replay(carriage: &DelegationChain) -> Option<Instance> {
        let events = Carriage::parse(carriage).ok()?.events().to_vec();

        let instance = Instance::generate(
            MemorySigner::generate(&mut OsRng),
            MemoryCiphertextStore::new(),
            NoListener,
            OsRng,
        )
        .await
        .ok()?;

        let mut remaining = events;
        loop {
            let mut deferred = Vec::with_capacity(remaining.len());

            for event in remaining.drain(..) {
                if instance.receive_static_event(event.clone()).await.is_err() {
                    deferred.push(event);
                }
            }

            match (deferred.is_empty(), deferred.len() == deferred.capacity()) {
                (true, _) => return Some(instance),
                // No progress this round: something is invalid or
                // depends on evidence the carriage never supplies.
                (false, true) => return None,
                (false, false) => remaining = deferred,
            }
        }
    }

    /// The spec's signing bar (dns-anchor §Statement validity, §Who
    /// Signs): the chain terminates at `signer` and the DELEGATING
    /// hop held admin access — a root-issued delegation counts (the
    /// root key is the document's own authority), and Keyhive already
    /// refused any chain whose links escalate or dangle at ingest.
    ///
    /// Whether `carriage` is a genuine delegation graph rooted at
    /// `anchor`: every event signature-checks, the set ingests to a
    /// fixpoint, and the materialized graph contains the anchor as a
    /// group or document. Empty or unreadable carriages vouch nothing.
    ///
    /// This vouches the CARRIAGE, not the document's content —
    /// content authorship is not checkable until signed operations
    /// land upstream. Callers grade such documents
    /// `Authority::CarriageVerified`, never higher.
    #[must_use]
    pub fn vouches_document(&self, anchor: &DocAnchor, carriage: &DelegationChain) -> bool {
        block_on(async {
            let Some(instance) = Self::replay(carriage).await else {
                return false;
            };

            let id = Identifier(*anchor.verifying_key());
            instance.get_group(id.into()).await.is_some()
                || instance.get_document(id.into()).await.is_some()
        })
    }

    /// Direct membership only for now: naming chains through nested
    /// group intermediaries are future work.
    async fn sanctioned(instance: &Instance, root: &DocAnchor, signer: &VerifyingKey) -> bool {
        let root_id = Identifier(*root.verifying_key());
        let signer_id = Identifier(*signer);

        let delegations = if let Some(group) = instance.get_group(root_id.into()).await {
            group.lock().await.members().get(&signer_id).cloned()
        } else if let Some(doc) = instance.get_document(root_id.into()).await {
            doc.lock().await.members().get(&signer_id).cloned()
        } else {
            None
        };

        let Some(delegations) = delegations else {
            return false;
        };

        delegations.iter().any(|granting| {
            match granting.payload().proof() {
                // Keyhive enforces issuer == subject for rootless
                // delegations: this grant came from the root key.
                None => true,
                Some(proof) => proof.payload().can() == Access::Admin,
            }
        })
    }
}

impl AuthorityVerifier for KeyhiveAuthority {
    fn authorizes(
        &self,
        root: &DocAnchor,
        signer: &VerifyingKey,
        carriage: &DelegationChain,
    ) -> bool {
        if signer == root.verifying_key() {
            return true;
        }

        block_on(async {
            let Some(instance) = Self::replay(carriage).await else {
                return false;
            };

            Self::sanctioned(&instance, root, signer).await
        })
    }

    fn on_path(&self, carriage: &DelegationChain, generation: &GenerationKey) -> bool {
        block_on(async {
            let Some(instance) = Self::replay(carriage).await else {
                return false;
            };

            let generation_id = Identifier(*generation.verifying_key());

            // The carriage names no root; the generation key is on
            // the path if any graph the carriage proves delegates to
            // it, at any depth.
            let groups: Vec<_> = { instance.groups().lock().await.values().cloned().collect() };
            for group in groups {
                let members = group.lock().await.transitive_members().await;
                if members.contains_key(&generation_id) {
                    return true;
                }
            }

            let docs: Vec<_> = {
                instance
                    .documents()
                    .lock()
                    .await
                    .values()
                    .cloned()
                    .collect()
            };
            for doc in docs {
                let members = doc.lock().await.transitive_members().await;
                if members.contains_key(&generation_id) {
                    return true;
                }
            }

            false
        })
    }
}
