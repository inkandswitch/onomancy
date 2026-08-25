//! `onomancer refresh`: keyless chain re-attachment from live DNS.

use std::{net::SocketAddr, path::PathBuf};

use clap::Args;
use onomancy_core::{certificate::Certificate, time::UnixSeconds};
use onomancy_dnssec::validator::{Validator, WalkError};
use onomancy_hickory::provider::FetchChainError;
use onomancy_publish::ceremony::refresh::Refresh as RefreshCeremony;

use crate::{now_ms, plan_io};

/// Refresh a certificate's attached chain — no key required.
#[derive(Debug, Args)]
pub(crate) struct Refresh {
    /// The certificate to refresh.
    #[arg(long)]
    cert: PathBuf,

    /// Recursive resolver (default: system resolvers, then 1.1.1.1).
    #[arg(long)]
    resolver: Option<SocketAddr>,

    /// Where the refreshed artifact lands.
    #[arg(long, default_value = ".")]
    out_dir: PathBuf,
}

impl Refresh {
    /// Fetch, re-attach, print/write the Plan.
    ///
    /// # Errors
    ///
    /// Returns [`RefreshError`] for undecodable certificates, fetch
    /// and validation failures, refused ceremonies, and IO failures.
    pub(crate) fn run(&self) -> Result<(), RefreshError> {
        let certificate = Certificate::decode(&std::fs::read(&self.cert)?)?;

        let provider = crate::provider(self.resolver);
        let chain = crate::block_on(provider.fetch_chain(certificate.hostname()))??;
        let proof = Validator::iana().validate_detailed(certificate.hostname(), &chain)?;

        let plan = RefreshCeremony {
            certificate,
            chain,
            records: proof.records,
        }
        .plan(UnixSeconds::from(now_ms() / 1000))?;

        crate::block_on(plan_io::execute(&plan, &self.out_dir))??;
        Ok(())
    }
}

/// The refresh verb failed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RefreshError {
    /// The ceremony refused to emit a Plan.
    #[error(transparent)]
    Ceremony(#[from] onomancy_publish::ceremony::CeremonyError),

    /// The certificate did not decode.
    #[error("certificate: {0}")]
    Certificate(#[from] onomancy_core::certificate::DecodeCertificateError),

    /// The live chain could not be fetched.
    #[error(transparent)]
    Fetch(#[from] FetchChainError),

    /// Artifact or runtime IO failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// The live chain failed DNSSEC validation.
    #[error("live chain invalid: {0}")]
    Walk(#[from] WalkError),
}
