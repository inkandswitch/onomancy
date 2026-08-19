//! Core logic for Onomancer, the reference implementation of the
//! Onomancy protocol.
//!
//! This crate is `no_std` by default; enable the `std` feature for
//! `std::error::Error` integration and friends.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod cert;
pub mod collections;
pub mod content_hash;
pub mod delegation;
pub mod digest;
pub mod freshness;
pub mod name;
pub mod signed;
pub mod statement;
pub mod time;
pub mod txt;
pub mod wire;
pub mod zone_state;
