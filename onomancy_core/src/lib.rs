//! Core logic for Onomancer, the reference implementation of the
//! Onomancy protocol.
//!
//! This crate is `no_std` by default; enable the `std` feature for
//! `std::error::Error` integration and friends.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod name;
pub mod txt;
