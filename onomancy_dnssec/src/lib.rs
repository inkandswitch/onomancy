//! Sans-IO DNSSEC chain validation for Onomancy.
//!
//! Implements `onomancy_protocol`'s `ChainValidator` seam: framed chain
//! bytes in, [`ChainProof`](onomancy_protocol::verifier_state::seam::ChainProof)
//! out, verified from a caller-supplied trust-anchor set. No sockets,
//! no resolver, no clock access — verification time enters as a value.
//!
//! ```text
//!       fetch (IO, elsewhere)              validate (pure, here)
//! ┌───────────────────────────┐      ┌────────────────────────────┐
//! │ onomancy_hickory / DoH    │ bytes│ trust anchors → DNSKEY/DS  │
//! │ gossip / courier / cache  ├─────►│ → RRSIG walk → TXT RRset   │
//! └───────────────────────────┘      │   or NSEC/NSEC3 absence    │
//!      untrusted couriers            └────────────────────────────┘
//! ```
//!
//! Chain links are the RFC 4034 **canonical wire form** of one `RRset`
//! plus its RRSIG(s) — uncompressed, lowercase owner names — which is
//! also the form signatures are computed over, so this crate parses
//! strictly and never re-encodes DNS data.
//!
//! # Crate Organization
//!
//! - [`wire`] — the minimal DNS wire vocabulary: owner names, RR
//!   types, record framing, RDATA views (strict,
//!   reject-never-normalize)
//! - [`link`] — one chain link as (`RRset`, covering RRSIGs)
//! - [`crypto`] — canonical signed-data construction, per-algorithm
//!   signature verification (8/13/15), the DS digest check
//! - [`anchor`] — DS-form trust anchors + the baked-in IANA root KSKs
//! - [`validator`] — the walk: [`Validator`](validator::Validator)
//!   implements `ChainValidator`

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod anchor;
pub mod crypto;
pub mod link;
pub mod validator;

#[cfg(feature = "test_utils")]
pub mod test_utils;
pub mod wire;
