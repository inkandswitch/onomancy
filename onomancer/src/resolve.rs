//! `onomancer resolve`: live chain fetch → DNSSEC walk → verdict.

use std::{
    net::SocketAddr,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::say;
use clap::Args;
use onomancy_core::{freshness::Freshness, name::dns::DnsName, time::UnixSeconds};
use onomancy_dnssec::validator::{Validator, WalkError};
use onomancy_hickory::provider::{FetchChainError, HickoryProvider};
use onomancy_protocol::{
    verifier_state::memory::MemoryAuthority,
    verify::{self, Rejection},
};

/// Fetch, validate, and grade a hostname's binding.
#[derive(Debug, Args)]
pub(crate) struct Resolve {
    /// The hostname to resolve (display form accepted).
    #[arg(long)]
    hostname: String,

    /// Recursive resolver to fetch through.
    #[arg(long, default_value = "1.1.1.1:53")]
    resolver: SocketAddr,

    /// A gossiped/fetched ONC certificate to verify fully (its own
    /// attached chain is what gets validated).
    #[arg(long)]
    cert: Option<PathBuf>,

    /// Write the fetched chain (framed links) here — e.g. to capture
    /// a fixture.
    #[arg(long)]
    chain_out: Option<PathBuf>,
}

impl Resolve {
    /// Run the pipeline and print what the evidence supports.
    ///
    /// # Errors
    ///
    /// Returns [`ResolveError`] for transport failures, invalid
    /// chains, and rejected certificates.
    pub(crate) fn run(&self) -> Result<(), ResolveError> {
        let hostname = DnsName::parse_display(&self.hostname)?;
        let now = UnixSeconds::from(now_seconds());
        let validator = Validator::iana();

        // The live zone: fetch → walk from the baked-in IANA anchors.
        let provider = HickoryProvider::new(self.resolver);
        let chain = crate::block_on(provider.assemble(&hostname))??;

        say(&format!("chain: {} links fetched", chain.links().len()));

        if let Some(chain_out) = &self.chain_out {
            let mut framed = Vec::new();
            chain.write_framed(&mut framed);
            std::fs::write(chain_out, framed)?;
            say(&format!("chain written: {}", chain_out.display()));
        }

        let proof = validator.validate_detailed(&hostname, &chain)?;
        let grade = match proof.window.grade(now) {
            onomancy_core::freshness::Grade::Fresh => "fresh \u{2713}",
            onomancy_core::freshness::Grade::Stale => "stale \u{26a0}",
            onomancy_core::freshness::Grade::NotYetBegun => "not yet begun (deferred)",
        };
        say(&format!("DNSSEC: valid, window {grade}"));

        for record in &proof.records {
            say(&format!("zone says: {record}"));
        }

        // A certificate makes it a full graded verdict.
        let Some(cert_path) = &self.cert else {
            return Ok(());
        };
        let bytes = std::fs::read(cert_path)?;

        // KEYHIVE PENDING: delegation carriages are not yet verified —
        // MemoryAuthority is permissive by default, so D10 path-membership
        // and carriage checks pass vacuously until onomancy_keyhive
        // lands. The DNSSEC walk above is fully real.
        let authority = MemoryAuthority::default();

        let verdict = verify::verify(&bytes, &hostname, now, &validator, &authority)?;

        let freshness = match verdict.freshness {
            Freshness::Fresh => "fresh \u{2713}",
            Freshness::Stale => "stale \u{26a0}",
        };
        let generation = match verdict.generation_check {
            verify::GenerationCheck::OnPath => {
                "on delegation path — VACUOUSLY: delegation checks are permissive until onomancy_keyhive"
            }
            verify::GenerationCheck::Provisional => {
                "provisional ⚠ (stale evidence; re-checked when fresher evidence arrives)"
            }
        };

        say(&format!("verdict: {freshness}"));
        say(&format!("  document:   {}", verdict.document));
        say(&format!("  serial:     {}", verdict.serial));
        say(&format!("  generation: {generation}"));
        Ok(())
    }
}

/// Seconds since the Unix epoch.
fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Resolution failed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ResolveError {
    /// The chain could not be assembled from live DNS.
    #[error(transparent)]
    Fetch(#[from] FetchChainError),

    /// The hostname did not parse.
    #[error("hostname: {0}")]
    Hostname(#[from] onomancy_core::name::dns::ParseDnsNameError),

    /// File or runtime IO failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// The certificate was rejected.
    #[error("certificate rejected: {0}")]
    Rejected(#[from] Rejection),

    /// The chain failed DNSSEC validation.
    #[error("chain invalid: {0}")]
    Walk(#[from] WalkError),
}
