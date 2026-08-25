//! Signed statement units: rotation (`ONR\x00`) and successor
//! (`ONS\x00`).
//!
//! Statements are signed artifacts in their own right, held to exactly
//! the certificate's standard: strict deterministic decoding,
//! roundtrip, format-tag domain separation, injectivity. They are the
//! inputs to the lineage ratchet and the succession check — a statement
//! whose bytes are ambiguous is a statement whose signature is
//! ambiguous.
//!
//! Each statement travels as one self-contained unit: signed fields,
//! signature, then its **authority carriage** — the delegation-chain
//! proof that its signer speaks for the document it makes claims about.
//! Unlike the certificate's attached region, the carriage rides
//! *inside* the unit: it is frozen ceremony-time history and never
//! needs the keyless-refresh lifecycle.
//!
//! | Region           | Type            | Width       | Notes                            | Signed |
//! |------------------|-----------------|-------------|----------------------------------|--------|
//! | tag              | magic bytes     | 4B          | 3-ASCII schema + version byte    | yes    |
//! | key fields       | ed25519 vks     | 32B each    | the statement's document/key set | yes    |
//! | hostname         | len + ASCII     | varies      | successor statements only        | yes    |
//! | signature        | ed25519         | 64B         |                                  | —      |
//! | carriage         | entry list      | varies      | count + len-prefixed entries     | no     |
//!
//! # Module Organization
//!
//! - [`rotation`] — [`RotationStatement`](rotation::RotationStatement):
//!   generation key Gₙ → Gₙ₊₁, per document, hostname-free
//! - [`successor`] —
//!   [`SuccessorStatement`](successor::SuccessorStatement): document
//!   migration under one hostname
//!
//! The carriage framing itself is [`crate::delegation`]'s entry-list
//! encoding; carriage *semantics* (roots at the statement's document,
//! terminates at its signer, admin-held delegating hop) are checked by
//! Keyhive verification behind the `AuthorityVerifier` seam, not here.

pub mod rotation;
pub mod successor;
