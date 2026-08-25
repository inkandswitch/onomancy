//! Table-driven fakes for the derivation's oracles.
//!
//! The seams are sans-IO, so faking them is a lookup table, not a
//! mock: [`validator::MemoryValidator`] maps (hostname, chain) to the
//! proof a real DNSSEC walk would produce, and
//! [`authority::MemoryAuthority`] answers delegation questions from
//! configured deny-lists.

pub mod authority;
pub mod validator;
