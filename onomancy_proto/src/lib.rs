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
//! - [`resolve`] — the namestore walk: greedy longest-key matching
//!   over local replicas (the path-resolution specification)
//!
//! Planned alongside the remaining `onomancy_core` codecs: the
//! comparison ladder (zone-state key), the binding-cache derivation
//! (`derive(store, now, judgment)`), and the certificate verification
//! pipeline with its `AuthorityVerifier` / `ChainValidator` /
//! `ChainProvider` seams.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod resolve;
