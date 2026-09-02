//! The substrate-neutral vocabulary kernel of Onomancy: names,
//! digests, signed units, and wire primitives that mean the same
//! thing under every anchor substrate. Anchor-specific machinery
//! lives with its substrate (e.g. `onomancy_dnssec`).
//!
//! This crate is `no_std` by default; enable the `std` feature for
//! `std::error::Error` integration and friends.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod anchor;
pub mod collections;
pub mod delegation_chain;
pub mod digest;
pub mod key;
pub mod name;
pub mod signed;
pub mod time;
pub mod wire;
