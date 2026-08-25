//! The verifier: one subsystem, two entries.
//!
//! [`state`] is the flagship — `derive(store, now, decisions)`, the
//! binding-cache derivation over the whole evidence set. [`verdict`]
//! is the one-shot: one certificate against one clock reading,
//! sharing the derivation's stage machinery so the two paths cannot
//! drift. Use `verdict` for "is this unit well-formed and
//! zone-rooted?", `state` for "what do I believe about this name?".

pub mod state;
pub mod verdict;
