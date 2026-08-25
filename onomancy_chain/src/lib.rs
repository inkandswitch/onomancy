//! Sans-IO DNSSEC chain assembly: questions out, records in, framed
//! links.
//!
//! [`assembly::Assembly`] mirrors the validator's expected grammar
//! (root DNSKEY; DS + child DNSKEY per signed cut; CNAME hops; TXT
//! leaf) but PROVES nothing — it selects and frames bytes; the
//! sans-IO validator (`onomancy_dnssec`) renders every verdict.
//! Suffixes without a DS `RRset` are simply not cuts (or not signed
//! ones); either way no link is emitted and the validator renders
//! the verdict.
//!
//! The machine performs no IO: each step yields the next
//! [`question::Question`], the driver answers it however it likes —
//! OS sockets in `onomancy_hickory`, `fetch()` `DoH` in
//! `onomancy_wasm` — and transport failure stays the driver's error,
//! never this crate's.
//!
//! ```text
//! Assembly::start(hostname) ──► Question ──► driver (any IO)
//!        ▲                                       │
//!        └───────── answer(records) ◄────────────┘
//!                        │
//!                        ├─► Step::Ask(machine, question)   (loop)
//!                        └─► Step::Done(DnssecChain)
//! ```

#![forbid(unsafe_code)]

pub mod answer;
pub mod assembly;
pub mod question;
