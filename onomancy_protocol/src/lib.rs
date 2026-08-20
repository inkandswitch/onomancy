//! The sans-IO protocol machines for Onomancy.
//!
//! Where [`onomancy_core`] is the vocabulary — types and codecs for
//! every protocol artifact — this crate is the grammar: the pure
//! functions that turn evidence into verdicts. Nothing here performs
//! IO. Networks, clocks, and storage enter only as values and trait
//! seams, so every machine is deterministic, testable without mocks,
//! and shared verbatim between native and Wasm builds.
//!
//! # Crate Organization
//!
//! - [`verifier_state`] — the binding-cache derivation: all verifier state as
//!   a pure function of `(store, now, decisions)`
//! - [`ladder`] — the comparison ladder: freshness, then succession/
//!   lineage, then the zone-state key (the offline-comparison rules)
//! - [`resolve`] — the namestore walk: greedy longest-key matching
//!   over local replicas (the path-resolution specification)
//! - [`verify`] — one-shot certificate verification: graded verdicts
//!   for a single unit at a single clock reading
//! - [`chain_provider`] — the fetch seam: the one place IO enters.
//!   Providers are byte couriers in backend crates (`onomancy_hickory`
//!   natively, `DoH` on Wasm); everything downstream is pure.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod chain_provider;
pub mod ladder;
pub mod resolve;
pub mod verifier_state;
pub mod verify;

#[cfg(feature = "test_utils")]
pub mod test_utils;
