//! `onomancer rotate`: the generation-rotation ceremony as a Plan.

use std::path::PathBuf;

use clap::Args;
use ed25519_dalek::VerifyingKey;
use onomancy_core::anchor::doc::DocAnchor;
use onomancy_dnssec::{
    certificate::Certificate, dns_name::DnsName, txt::generation_key::GenerationKey,
};
use onomancy_keyhive::{authority::KeyhiveAuthority, mint};
use onomancy_publish::{ceremony::rotate::Rotate as RotateCeremony, signer::Signer};

use crate::{
    now_ms, plan_io,
    seed::{self, SeedError},
};

/// Plan a generation rotation: retire the attested `g=` in favor of
/// the successor key. One ceremony heals every name bound to the
/// document; run once per name only for the per-name TXT ops.
#[derive(Debug, Args)]
pub(crate) struct Rotate {
    /// The hostname whose TXT op this plan carries.
    #[arg(long)]
    hostname: String,

    /// Key file holding the root document seed (signs the refreshed
    /// certificate until Keyhive delegation lands).
    #[arg(long)]
    doc_key: Option<PathBuf>,

    /// Inline document seed (prefer --doc-key).
    #[arg(long, conflicts_with = "doc_key")]
    doc_seed: Option<String>,

    /// The generation being retired, in its TXT `g=` spelling
    /// (base64).
    #[arg(long)]
    replaced: String,

    /// Key file holding the SUCCESSOR generation's seed — rotation
    /// statements are signed by the incoming generation.
    #[arg(long)]
    successor_key: Option<PathBuf>,

    /// Inline successor seed (prefer --successor-key).
    #[arg(long, conflicts_with = "successor_key")]
    successor_seed: Option<String>,

    /// A prior certificate whose lineage this rotation extends.
    #[arg(long)]
    prior_cert: Option<PathBuf>,

    /// Where artifacts land.
    #[arg(long, default_value = ".")]
    out_dir: PathBuf,
}

impl Rotate {
    /// Run the ceremony and print/write the Plan.
    ///
    /// # Errors
    ///
    /// Returns [`RotateError`] for malformed inputs, refused
    /// ceremonies (generation reuse, self-forks), and IO failures.
    pub(crate) fn run(&self) -> Result<(), RotateError> {
        let hostname = DnsName::parse_display(&self.hostname)?;
        let doc_key = seed::load(self.doc_seed.as_deref(), self.doc_key.as_deref())?;
        let successor = seed::load(
            self.successor_seed.as_deref(),
            self.successor_key.as_deref(),
        )?;

        let replaced = parse_generation(&self.replaced)?;

        let prior_lineage = match &self.prior_cert {
            Some(path) => Certificate::decode(&std::fs::read(path)?)?
                .lineage()
                .to_vec(),
            None => vec![],
        };

        // One carriage serves both: the statement's signing authority
        // (terminates at Gₙ₊₁) and the certificate's generation-path proof.
        let carriage = mint::generation_carriage(&doc_key, &successor)?;

        let plan = RotateCeremony {
            hostname,
            document: DocAnchor::from(doc_key.verifying_key()),
            replaced,
            prior_lineage,
            carriage,
        }
        .plan(
            now_ms(),
            &Signer::new(successor),
            &Signer::new(doc_key),
            &KeyhiveAuthority,
        )?;

        crate::block_on(plan_io::execute(&plan, &self.out_dir))??;
        Ok(())
    }
}

/// Parse a TXT `g=`-spelled (base64) generation key.
pub(crate) fn parse_generation(text: &str) -> Result<GenerationKey, NotAGenerationKey> {
    let bytes = plan_io::parse_base64_key(text).ok_or(NotAGenerationKey)?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| NotAGenerationKey)?;
    Ok(GenerationKey::from(key))
}

/// The `--replaced`/`--generation` argument was not a base64 ed25519
/// key.
#[derive(Debug, thiserror::Error)]
#[error("expected a generation key in its TXT g= spelling (base64 ed25519 point)")]
pub(crate) struct NotAGenerationKey;

/// The rotate verb failed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RotateError {
    /// The ceremony refused to emit a Plan.
    #[error(transparent)]
    Ceremony(#[from] onomancy_publish::ceremony::CeremonyError),

    /// The authority carriage could not be minted.
    #[error(transparent)]
    Mint(#[from] onomancy_keyhive::mint::MintError),

    /// The prior certificate did not decode.
    #[error("prior certificate: {0}")]
    Certificate(#[from] onomancy_dnssec::certificate::DecodeCertificateError),

    /// A generation-key argument was malformed.
    #[error(transparent)]
    Generation(#[from] NotAGenerationKey),

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
