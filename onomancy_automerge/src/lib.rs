//! Automerge substrate adapter: the sans-IO bridge between Onomancy's
//! pure machines and [Automerge] documents.
//!
//! This crate implements the seams the protocol crates define, over
//! documents the caller already holds — replication, persistence, and
//! networking belong to the substrate and the agent, never here
//! (substrate adapters are sans-IO; they differ from
//! `onomancy_dnssec` only in depending on foreign library types).
//!
//! ```text
//!            onomancy_protocol seams          this crate
//!            ───────────────────────          ─────────────────────
//!            resolve::Namestore          ←    DocumentNamestore
//!            resolve::Replicas           ←    HeldDocuments
//!            verifier_state::Decisions    ←    decisions::read
//!            stage-8 pins                ←    petname::pins
//! ```
//!
//! What this crate deliberately does NOT do:
//!
//! - **No Keyhive.** Authority verification (`AuthorityVerifier`) is
//!   `onomancy_keyhive`'s single job — resolver-only
//!   consumers skip the CGKA crypto entirely.
//! - **No fetching.** Every reader answers from documents already in
//!   hand; `None` means "not replicated here", the designed outcome
//!   under partition.
//!
//! [Automerge]: https://automerge.org

#![forbid(unsafe_code)]

pub mod change_hash;
pub mod decisions;
pub mod namestore;
pub mod petname;

/// The reserved top-level key Onomancy data lives under, in every
/// document role: the flat namestore map in namestore documents
/// (path-resolution spec, Namestore Layout), the decisions schema in
/// decision documents (binding-cache spec, Schema).
///
/// The namestore location is a coordination point with upstream
/// automerge-repo (design/names.md, open tension) — treat it as
/// provisional until that lands.
pub const RESERVED_KEY: &str = "onomancy";
