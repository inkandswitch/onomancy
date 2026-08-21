//! `onomancer migrate`: the document-migration ceremony as a Plan.
//!
//! The currently published record is fetched live (it becomes the
//! dual-publish `RetainTxt` op), so the plan reflects the zone as it
//! actually is.

use std::{net::SocketAddr, path::PathBuf};

use clap::Args;
use onomancy_core::{
    name::{dns::DnsName, doc::DocAnchor},
    txt::record::TxtRecord,
};
use onomancy_dnssec::validator::{Validator, WalkError};
use onomancy_hickory::provider::{FetchChainError, HickoryProvider};
use onomancy_publish::{ceremony::migrate::Migrate as MigrateCeremony, signer::Signer};

use crate::{
    now_ms, plan_io,
    rotate::{parse_generation, NotAGenerationKey},
    seed::{self, SeedError},
};

/// Plan a migration: move the hostname to a successor document,
/// dual-publishing through the window and proving continuity.
#[derive(Debug, Args)]
pub(crate) struct Migrate {
    /// The hostname migrating.
    #[arg(long)]
    hostname: String,

    /// Key file holding the PREDECESSOR document's seed (signs the
    /// succession proof).
    #[arg(long)]
    predecessor_key: Option<PathBuf>,

    /// Inline predecessor seed (prefer --predecessor-key).
    #[arg(long, conflicts_with = "predecessor_key")]
    predecessor_seed: Option<String>,

    /// Key file holding the SUCCESSOR document's seed (signs the new
    /// certificate).
    #[arg(long)]
    successor_key: Option<PathBuf>,

    /// Inline successor seed (prefer --successor-key).
    #[arg(long, conflicts_with = "successor_key")]
    successor_seed: Option<String>,

    /// The successor document's generation key, in its TXT `g=`
    /// spelling (base64).
    #[arg(long)]
    successor_generation: String,

    /// Recursive resolver for fetching the currently published record.
    #[arg(long, default_value = "1.1.1.1:53")]
    resolver: SocketAddr,

    /// Where artifacts land.
    #[arg(long, default_value = ".")]
    out_dir: PathBuf,
}

impl Migrate {
    /// Fetch the live record, run the ceremony, print/write the Plan.
    ///
    /// # Errors
    ///
    /// Returns [`MigrateError`] for malformed inputs, missing or
    /// invalid live records, refused ceremonies, and IO failures.
    pub(crate) fn run(&self) -> Result<(), MigrateError> {
        let hostname = DnsName::parse_display(&self.hostname)?;
        let predecessor_key = seed::load(
            self.predecessor_seed.as_deref(),
            self.predecessor_key.as_deref(),
        )?;
        let successor_key = seed::load(
            self.successor_seed.as_deref(),
            self.successor_key.as_deref(),
        )?;
        let successor_generation = parse_generation(&self.successor_generation)?;

        let predecessor = DocAnchor::from(predecessor_key.verifying_key());

        // The record being left behind, live from the zone.
        let retained = self.fetch_current(&hostname, &predecessor)?;

        let plan = MigrateCeremony {
            hostname,
            predecessor,
            successor: DocAnchor::from(successor_key.verifying_key()),
            retained,
            successor_generation,
            lineage: vec![],
        }
        .plan(
            now_ms(),
            &Signer::new(predecessor_key),
            &Signer::new(successor_key),
        )?;

        crate::block_on(plan_io::execute(&plan, &self.out_dir))??;
        Ok(())
    }

    /// The zone's current record for the predecessor document.
    fn fetch_current(
        &self,
        hostname: &DnsName,
        predecessor: &DocAnchor,
    ) -> Result<TxtRecord, MigrateError> {
        let provider = HickoryProvider::new(self.resolver);
        let chain = crate::block_on(provider.assemble(hostname))??;
        let proof = Validator::iana().validate_detailed(hostname, &chain)?;

        proof
            .records
            .iter()
            .filter(|record| record.document() == predecessor)
            .max_by_key(|record| record.serial())
            .copied()
            .ok_or(MigrateError::NoCurrentRecord)
    }
}

/// The migrate verb failed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum MigrateError {
    /// The ceremony refused to emit a Plan.
    #[error(transparent)]
    Ceremony(#[from] onomancy_publish::ceremony::CeremonyError),

    /// The live chain could not be assembled.
    #[error(transparent)]
    Fetch(#[from] FetchChainError),

    /// A generation-key argument was malformed.
    #[error(transparent)]
    Generation(#[from] NotAGenerationKey),

    /// The hostname did not parse.
    #[error("hostname: {0}")]
    Hostname(#[from] onomancy_core::name::dns::ParseDnsNameError),

    /// Artifact or runtime IO failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// The zone publishes no record for the predecessor document.
    #[error("no live record attests the predecessor document — nothing to migrate from")]
    NoCurrentRecord,

    /// A seed argument was malformed.
    #[error(transparent)]
    Seed(#[from] SeedError),

    /// The live chain failed DNSSEC validation.
    #[error("live chain invalid: {0}")]
    Walk(#[from] WalkError),
}
