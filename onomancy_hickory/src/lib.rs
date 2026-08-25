//! The host DNSSEC chain courier: `ChainProvider` over real DNS.
//!
//! This crate is a byte courier and nothing more (ADR-006/ADR-040):
//! it drives the sans-IO assembly machine (`onomancy_chain`) over
//! OS sockets, answering its questions — root DNSKEY, then DS +
//! DNSKEY per signed zone cut, then the TXT leaf at
//! `_onomancy.<hostname>` — so the machine can frame the link format
//! the sans-IO validator (`onomancy_dnssec`) walks. Nothing here is
//! trusted: transport spoofing, a lying resolver, or a broken cache
//! can only produce a chain that fails validation — never a false
//! bind. That is why the stub keeps no DNSSEC state, sets `CD`
//! (checking disabled) to see even what the resolver considers
//! bogus, and leaves every verdict to the verifier's own trust
//! anchor.
//!
//! ```text
//! HickoryProvider::chain(hostname)
//!   │  DNSKEY(.)                      → link 0
//!   │  per suffix with a DS RRset:
//!   │    DS(zone), DNSKEY(zone)       → links 2k+1, 2k+2
//!   │  TXT(_onomancy.hostname)        → CNAME links…, TXT link
//!   ▼
//! DnssecChain ──► onomancy_dnssec::validator::Validator (sans-IO)
//! ```

#![forbid(unsafe_code)]

pub mod provider;
pub mod stub;
