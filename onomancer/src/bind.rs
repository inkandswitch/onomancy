//! `onomancer bind`: the first-binding ceremony, as a verified Plan.

use std::path::PathBuf;

use clap::Args;
use onomancy_core::anchor::doc::DocAnchor;
use onomancy_dnssec::{dns_name::DnsName, txt::generation_key::GenerationKey};
use onomancy_keyhive::{authority::KeyhiveAuthority, mint};
use onomancy_publish::{ceremony::bind::Bind as BindCeremony, signer::Signer};

use crate::{
    now_ms, plan_io,
    seed::{self, SeedError},
};

/// Plan a first binding: TXT record + certificate, verified by
/// construction before anything prints.
#[derive(Debug, Args)]
pub(crate) struct Bind {
    /// The hostname to bind (display form accepted).
    #[arg(long)]
    hostname: String,

    /// Key file holding the root document seed (also signs the
    /// certificate until Keyhive delegation lands).
    #[arg(long)]
    doc_key: Option<PathBuf>,

    /// Inline document seed (prefer --doc-key).
    #[arg(long, conflicts_with = "doc_key")]
    doc_seed: Option<String>,

    /// Key file holding the generation seed.
    #[arg(long)]
    generation_key: Option<PathBuf>,

    /// Inline generation seed (prefer --generation-key).
    #[arg(long, conflicts_with = "generation_key")]
    generation_seed: Option<String>,

    /// Where artifacts land.
    #[arg(long, default_value = ".")]
    out_dir: PathBuf,
}

impl Bind {
    /// Run the ceremony and print/write the Plan.
    ///
    /// # Errors
    ///
    /// Returns [`BindError`] for malformed inputs, refused ceremonies,
    /// and IO failures.
    pub(crate) fn run(&self) -> Result<(), BindError> {
        let hostname = DnsName::parse_display(&self.hostname)?;
        let doc_key = seed::load(self.doc_seed.as_deref(), self.doc_key.as_deref())?;
        let generation_key = seed::load(
            self.generation_seed.as_deref(),
            self.generation_key.as_deref(),
        )?;

        // The path proof: the document delegates the generation key.
        let carriage = mint::generation_carriage(&doc_key, &generation_key)?;

        let plan = BindCeremony {
            hostname,
            document: DocAnchor::from(doc_key.verifying_key()),
            generation: GenerationKey::from(generation_key.verifying_key()),
            heads: vec![],
            lineage: vec![],
            carriage,
        }
        .plan(now_ms(), &Signer::new(doc_key), &KeyhiveAuthority)?;

        crate::block_on(plan_io::execute(&plan, &self.out_dir))??;
        Ok(())
    }
}

/// The bind verb failed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum BindError {
    /// The ceremony refused to emit a Plan.
    #[error(transparent)]
    Ceremony(#[from] onomancy_publish::ceremony::CeremonyError),

    /// The authority carriage could not be minted.
    #[error(transparent)]
    Mint(#[from] onomancy_keyhive::mint::MintError),

    /// The hostname did not parse.
    #[error("hostname: {0}")]
    Hostname(#[from] onomancy_dnssec::dns_name::ParseDnsNameError),

    /// Artifact or runtime IO failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// A seed argument was malformed.
    #[error(transparent)]
    Seed(#[from] SeedError),
}
