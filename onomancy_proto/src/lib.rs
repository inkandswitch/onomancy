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
//! - [`derive`] — the binding-cache derivation: all verifier state as
//!   a pure function of `(store, now, judgment)`
//! - [`ladder`] — the comparison ladder: freshness, then succession/
//!   lineage, then the zone-state key (the offline-comparison rules)
//! - [`resolve`] — the namestore walk: greedy longest-key matching
//!   over local replicas (the path-resolution specification)
//!
//! Planned: the full certificate verification pipeline and the
//! `ChainProvider` fetch seam.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod derive;
pub mod ladder;
pub mod resolve;

#[cfg(feature = "test_utils")]
pub mod test_utils;
