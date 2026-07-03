//! Core logic for Onomancer.
//!
//! This crate is `no_std` by default; enable the `std` feature for
//! `std::error::Error` integration and friends.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod name;
