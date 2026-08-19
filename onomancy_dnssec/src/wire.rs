//! The minimal DNS wire vocabulary: exactly what validation touches.
//!
//! Chain links carry the RFC 4034 §6 **canonical wire form** — the
//! byte form DNSSEC signatures are computed over: owner names
//! uncompressed and lowercase, fixed big-endian integers, no
//! normalization left to do. This module parses that form strictly:
//! a compression pointer, an uppercase owner byte, or an overlong
//! label is a reject, never a repair — parser leniency here would let
//! two implementations disagree about what bytes were signed, which is
//! the exact differential class the strict codecs exist to kill.
//!
//! This is deliberately not a general DNS library. Seven RR types, one
//! class, no compression, no EDNS, no message envelopes.
//!
//! # Module Organization
//!
//! - [`name`] — [`Name`](name::Name): canonical owner names, with the
//!   RFC 4034 §6.1 canonical ordering
//! - [`record`] — [`Record`](record::Record) framing and
//!   [`RrType`](record::RrType)
//! - [`algorithm`] — [`Algorithm`](algorithm::Algorithm) codes and the
//!   D13 supported-set
//! - RDATA views: [`rrsig`], [`dnskey`], [`ds`], [`txt`], [`denial`]
//!   (NSEC/NSEC3 + type bitmaps), [`cname`]

pub mod algorithm;
pub mod cname;
pub mod denial;
pub mod dnskey;
pub mod ds;
pub mod name;
pub mod record;
pub mod rrsig;
pub mod txt;
