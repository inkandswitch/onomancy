//! `onomancer record`: the DNS-publishable TXT record,
//! and optionally a signed ONC certificate.

use std::{net::SocketAddr, path::PathBuf};

use clap::Args;
use onomancy_core::{anchor::doc::DocAnchor, time::UnixSeconds, wire::OversizeUnit};
use onomancy_dnssec::{
    certificate::{Certificate, CertificateParams},
    chain::DnssecChain,
    dns_name::DnsName,
    txt::{generation_key::GenerationKey, record::TxtRecord, serial::Serial},
};
use onomancy_hickory::provider::FetchChainError;
use onomancy_keyhive::mint;

use crate::{
    say,
    seed::{self, SeedError},
};

/// Emit the TXT record (and optionally a certificate) for a binding.
#[derive(Debug, Args)]
pub(crate) struct Record {
    /// The hostname being bound (display form accepted; stored as
    /// A-labels).
    #[arg(long)]
    hostname: String,

    /// Seed of the root document key (hex, 32 bytes). Prefer
    /// --doc-key: inline seeds land in shell history.
    #[arg(long, conflicts_with = "doc_key")]
    doc_seed: Option<String>,

    /// Key file holding the root document seed (from `keygen --out`).
    #[arg(long)]
    doc_key: Option<PathBuf>,

    /// Seed of the current generation key (hex, 32 bytes). Prefer
    /// --generation-key.
    #[arg(long, conflicts_with = "generation_key")]
    generation_seed: Option<String>,

    /// Key file holding the generation seed.
    #[arg(long)]
    generation_key: Option<PathBuf>,

    /// Record serial; defaults to the current time in milliseconds
    /// (the serial-as-timestamp convention).
    #[arg(long)]
    serial: Option<u64>,

    /// Also sign an ONC certificate and write it here.
    #[arg(long)]
    cert_out: Option<PathBuf>,

    /// Seed of the certificate signer (defaults to the doc key —
    /// self-signed until Keyhive delegation lands). Prefer
    /// --signer-key.
    #[arg(long, conflicts_with = "signer_key")]
    signer_seed: Option<String>,

    /// Key file holding the signer seed.
    #[arg(long)]
    signer_key: Option<PathBuf>,

    /// Fetch the live DNSSEC chain and attach it to the certificate
    /// (requires the TXT record to already be published).
    #[arg(long)]
    fetch_chain: bool,

    /// Recursive resolver for --fetch-chain (default: system, then 1.1.1.1).
    #[arg(long)]
    resolver: Option<SocketAddr>,
}

impl Record {
    /// Build and print (and optionally sign + write).
    ///
    /// # Errors
    ///
    /// Returns [`RecordError`] for malformed inputs, failed chain
    /// fetches, oversize units, and IO failures.
    pub(crate) fn run(&self) -> Result<(), RecordError> {
        let hostname = DnsName::parse_display(&self.hostname)?;
        let doc_key = seed::load(self.doc_seed.as_deref(), self.doc_key.as_deref())?;
        let generation_key = seed::load(
            self.generation_seed.as_deref(),
            self.generation_key.as_deref(),
        )?;

        let document = DocAnchor::from(doc_key.verifying_key());
        let generation = GenerationKey::from(generation_key.verifying_key());
        let serial = Serial::from(self.serial.unwrap_or_else(crate::now_ms));

        let record = TxtRecord::new(serial, generation, document);
        say("; publish this record (then re-sign the zone):");
        say(&format!("_onomancy.{hostname}. IN TXT \"{record}\""));

        let Some(cert_out) = &self.cert_out else {
            return Ok(());
        };

        let chain = if self.fetch_chain {
            fetch_chain(self.resolver, &hostname)?
        } else {
            DnssecChain::default()
        };

        let signer = if self.signer_seed.is_some() || self.signer_key.is_some() {
            let signer = seed::load(self.signer_seed.as_deref(), self.signer_key.as_deref())?;

            // A carriage minted here proves the document delegates
            // the GENERATION key; it says nothing about some third
            // signer. Minting anyway would emit a certificate that
            // fails for a reason its holder cannot see.
            if signer.verifying_key() != doc_key.verifying_key() {
                return Err(RecordError::UnprovableSigner);
            }

            signer
        } else {
            doc_key.clone()
        };

        // The generation-path proof, as `bind` mints it: without it the attested
        // generation key lies on no path, so the certificate is
        // REJECTED while its own chain is fresh and only graded
        // provisional once stale — exactly backwards.
        let carriage = mint::generation_carriage(&doc_key, &generation_key)?;

        let certificate = Certificate::sign(
            CertificateParams {
                root_doc: document,
                issued_at: UnixSeconds::from(crate::now_ms() / 1000),
                hostname: hostname.clone(),
                heads: vec![],
                predecessor: None,
                delegation_chain: carriage,
                lineage: vec![],
                chain,
            },
            &signer,
        )?;

        std::fs::write(cert_out, certificate.encode())?;
        say(&format!("; wrote certificate: {}", cert_out.display()));
        Ok(())
    }
}

/// Fetch the live chain on a scratch runtime.
fn fetch_chain(
    resolver: Option<SocketAddr>,
    hostname: &DnsName,
) -> Result<DnssecChain, RecordError> {
    let provider = crate::provider(resolver);
    Ok(crate::block_on(provider.fetch_chain(hostname))??)
}

/// Record generation failed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RecordError {
    /// The live chain could not be fetched.
    #[error(transparent)]
    Fetch(#[from] FetchChainError),

    /// The hostname did not parse.
    #[error("hostname: {0}")]
    Hostname(#[from] onomancy_dnssec::dns_name::ParseDnsNameError),

    /// File or runtime IO failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// The carriage could not be minted.
    #[error(transparent)]
    Mint(#[from] onomancy_keyhive::mint::MintError),

    /// The certificate would exceed the unit cap.
    #[error(transparent)]
    Oversize(#[from] OversizeUnit),

    /// A seed argument was malformed.
    #[error(transparent)]
    Seed(#[from] SeedError),

    /// A signer was supplied whose authority this verb cannot prove.
    ///
    /// `record` mints the one carriage it can derive from its own
    /// arguments: the document delegating the generation key. A third
    /// signer needs a delegation path from the document, which lives
    /// in the Keyhive graph rather than in a seed file.
    #[error(
        "refusing to mint a certificate for a signer this verb cannot prove: \
         --signer-key is not the document key, and the carriage minted here \
         proves only that the document delegates the generation key. Such a \
         certificate would be dropped by verifiers without a visible reason. \
         Use the document key, or run the full `bind` ceremony."
    )]
    UnprovableSigner,
}
