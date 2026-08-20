//! `onomancer record`: the DNS-publishable TXT record, and optionally
//! a signed ONC certificate.

use std::{
    net::SocketAddr,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use clap::Args;
use onomancy_core::{
    cert::{Certificate, CertificateParams, chain::DnssecChain},
    name::{dns::DnsName, doc::DocAnchor},
    time::UnixSeconds,
    txt::{generation_key::GenerationKey, record::TxtRecord, serial::Serial},
    wire::OversizeUnit,
};
use onomancy_hickory::provider::{FetchChainError, HickoryProvider};

use crate::seed::{self, SeedError};

/// Emit the TXT record (and optionally a certificate) for a binding.
#[derive(Debug, Args)]
pub(crate) struct Record {
    /// The hostname being bound (display form accepted; stored as
    /// A-labels).
    #[arg(long)]
    hostname: String,

    /// Seed of the root document key (hex, 32 bytes).
    #[arg(long)]
    doc_seed: String,

    /// Seed of the current generation key (hex, 32 bytes).
    #[arg(long)]
    generation_seed: String,

    /// Record serial; defaults to the current time in milliseconds
    /// (the serial-as-timestamp convention).
    #[arg(long)]
    serial: Option<u64>,

    /// Also sign an ONC certificate and write it here.
    #[arg(long)]
    cert_out: Option<PathBuf>,

    /// Seed of the certificate signer (defaults to the doc seed —
    /// self-signed until Keyhive delegation lands).
    #[arg(long)]
    signer_seed: Option<String>,

    /// Fetch the live DNSSEC chain and attach it to the certificate
    /// (requires the TXT record to already be published).
    #[arg(long)]
    fetch_chain: bool,

    /// Recursive resolver for --fetch-chain.
    #[arg(long, default_value = "1.1.1.1:53")]
    resolver: SocketAddr,
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
        let doc_key = seed::signing_key(&self.doc_seed)?;
        let generation_key = seed::signing_key(&self.generation_seed)?;

        let document = DocAnchor::from(doc_key.verifying_key());
        let generation = GenerationKey::from(generation_key.verifying_key());
        let serial = Serial::from(self.serial.unwrap_or_else(now_ms));

        let record = TxtRecord::new(serial, generation, document);
        println!("; publish this record (then re-sign the zone):");
        println!("_onomancy.{hostname}. IN TXT \"{record}\"");

        let Some(cert_out) = &self.cert_out else {
            return Ok(());
        };

        let chain = if self.fetch_chain {
            fetch_chain(self.resolver, &hostname)?
        } else {
            DnssecChain::default()
        };

        let signer = match &self.signer_seed {
            Some(hex) => seed::signing_key(hex)?,
            None => doc_key,
        };

        let certificate = Certificate::sign(
            CertificateParams {
                root_doc: document,
                issued_at: UnixSeconds::from(now_ms() / 1000),
                hostname: hostname.clone(),
                heads: vec![],
                predecessor: None,
                // Empty until Keyhive delegation lands: verification
                // of the carriage is the AuthorityVerifier seam's job.
                delegation_chain: vec![],
                lineage: vec![],
                chain,
            },
            &signer,
        )?;

        std::fs::write(cert_out, certificate.encode())?;
        println!("; wrote certificate: {}", cert_out.display());
        Ok(())
    }
}

/// Fetch the live chain on a scratch runtime.
fn fetch_chain(resolver: SocketAddr, hostname: &DnsName) -> Result<DnssecChain, RecordError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let provider = HickoryProvider::new(resolver);

    Ok(runtime.block_on(provider.assemble(hostname))?)
}

/// Milliseconds since the Unix epoch.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Record generation failed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RecordError {
    /// The live chain could not be assembled.
    #[error(transparent)]
    Fetch(#[from] FetchChainError),

    /// The hostname did not parse.
    #[error("hostname: {0}")]
    Hostname(#[from] onomancy_core::name::dns::ParseDnsNameError),

    /// File or runtime IO failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// The certificate would exceed the unit cap.
    #[error(transparent)]
    Oversize(#[from] OversizeUnit),

    /// A seed argument was malformed.
    #[error(transparent)]
    Seed(#[from] SeedError),
}
