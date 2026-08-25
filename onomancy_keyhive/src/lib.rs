//! Keyhive-backed authority verification for Onomancy.
//!
//! The protocol layer asks two questions through its
//! `AuthorityVerifier` seam: does a delegation chain authorize a
//! signer to speak for a document, and does a generation key lie on
//! the document's delegation path? This crate answers both with a
//! REAL delegation graph — [`keyhive_core`] — instead of the
//! permissive memory fake.
//!
//! ```text
//!  Certificate / Statement            KeyhiveAuthority
//!  ┌─────────────────────┐   replay   ┌──────────────────────┐
//!  │ carriage:           │──────────▶│ throwaway Keyhive     │
//!  │  [kh0‖StaticEvent]… │            │ instance: verify ops, │
//!  │ (UNSIGNED attached  │            │ materialize groups,   │
//!  │  region — churn =   │            │ query membership      │
//!  │  re-attach)         │◀──────────│ → authorized? on path?│
//!  └─────────────────────┘   verdict  └──────────────────────┘
//! ```
//!
//! Keyhive 0.5 is pre-alpha: its event encoding may churn.
//! That is absorbed by design — carriage bytes ride the certificate's
//! unsigned attached region, so a re-encode means re-attaching
//! evidence, never re-signing the unit. The [`carriage`] envelope
//! tags every entry with an encoding version so drift is detected,
//! not misread.
//!
//! Host-only: verification drives Keyhive's async API to completion
//! on the current thread. No IO occurs — the futures are
//! state-machine-only and resolve immediately.

#![forbid(unsafe_code)]

pub mod authority;
pub mod carriage;
pub mod mint;
