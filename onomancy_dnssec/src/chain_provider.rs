//! The chain-fetching seam: the ONE place IO enters the system.
//!
//! Everything downstream of this trait is pure — the fetched bytes go
//! to `ChainValidator` (sans-IO validation against the caller's own
//! trust anchor) and then into the store as evidence. Backends:
//! `onomancy_hickory` on hosts, a `DoH` `fetch()` provider on Wasm.
//!
//! The future is deliberately not `Send`-bound: Wasm fetch futures
//! are `!Send`, and host callers that need `Send` can require it at
//! their own usage sites.

use core::future::Future;

use crate::{chain::DnssecChain, dns_name::DnsName};

/// Fetches the DNSSEC chain for a hostname's `_onomancy` TXT record.
///
/// A provider is a byte courier, nothing more: it MUST NOT be trusted
/// to validate — the returned chain is unverified input, and the
/// verifier's own [`ChainValidator`](crate::chain_proof::ChainValidator)
/// is the only judge. A malicious or broken provider can cause
/// staleness or rejection, never a false bind.
pub trait ChainProvider {
    /// Transport-level failure: network, timeout, malformed response.
    /// Never a validity verdict — those belong to the validator.
    type Error: core::error::Error;

    /// Fetch the full chain — root DNSKEY down to the TXT leaf at
    /// `_onomancy.<hostname>` — as framed links.
    fn chain(&self, hostname: &DnsName) -> impl Future<Output = Result<DnssecChain, Self::Error>>;
}
