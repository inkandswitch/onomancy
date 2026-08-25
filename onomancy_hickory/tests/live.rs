//! Manual network smoke tests — ignored by default, run explicitly:
//!
//! ```sh
//! cargo test -p onomancy_hickory --test live -- --ignored
//! ```

#![allow(clippy::expect_used, clippy::panic)]

use onomancy_chain::assembly::AssembleError;
use onomancy_core::name::dns::DnsName;
use onomancy_hickory::provider::{FetchChainError, HickoryProvider};
use onomancy_protocol::chain_provider::ChainProvider;

/// Transport and zone-cut walking against a public recursive
/// resolver. `cloudflare.com` publishes no `_onomancy` TXT record, so
/// the expected outcome is a clean `MissingRrset` — which exercises
/// the root DNSKEY fetch, the DS probe walk, and the leaf query.
#[tokio::test(flavor = "current_thread")]
#[ignore = "network: queries a public recursive resolver"]
async fn walks_a_real_signed_zone_to_a_missing_leaf() {
    let provider = HickoryProvider::new("1.1.1.1:53".parse().expect("socket addr"));
    let hostname = DnsName::parse("cloudflare.com").expect("valid hostname");

    match provider.chain(&hostname).await {
        Err(FetchChainError::Assemble(AssembleError::MissingRrset { owner, .. })) => {
            assert!(
                owner.starts_with("_onomancy."),
                "failed at the leaf: {owner}"
            );
        }
        Ok(chain) => panic!(
            "unexpected _onomancy record published ({} links)?",
            chain.links().len()
        ),
        Err(other) => panic!("transport or framing failure: {other}"),
    }
}
