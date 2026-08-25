//! `onomancer vouch`: mint a document carriage file for the dev
//! bridge — proof that a delegation graph roots at the document key,
//! written as `<anchor>.carriage` beside the document's
//! `<anchor>.automerge`.
//!
//! > [!WARNING]
//! > A carriage vouches the DELEGATION GRAPH, not the document's
//! > content: content authorship is not checkable until signed
//! > operations land upstream. Walks over carriage-vouched documents
//! > grade `carriage-verified`, never higher.

use std::path::PathBuf;

use clap::Args;
use onomancy_core::anchor::doc::DocAnchor;
use onomancy_keyhive::mint::{MintError, document_carriage};

use crate::{say, seed::SeedError};

/// Mint a `<anchor>.carriage` file from a document signing key.
#[derive(Debug, Args)]
pub(crate) struct Vouch {
    /// The document seed, inline (prefer --doc-key).
    #[arg(long, conflicts_with = "doc_key")]
    doc_seed: Option<String>,

    /// File holding the document seed (what `keygen --out` writes).
    #[arg(long)]
    doc_key: Option<PathBuf>,

    /// Directory to write `<anchor>.carriage` into (default: `.`).
    #[arg(long, default_value = ".")]
    out: PathBuf,
}

impl Vouch {
    /// Mint and write the carriage.
    ///
    /// # Errors
    ///
    /// Returns [`VouchError`] for missing/malformed seeds, minting
    /// refusals, and IO failures.
    pub(crate) fn run(&self) -> Result<(), VouchError> {
        let doc_key = crate::seed::load(self.doc_seed.as_deref(), self.doc_key.as_deref())
            .map_err(|source| VouchError::Seed {
                which: "doc key",
                source,
            })?;
        let anchor = DocAnchor::from(doc_key.verifying_key());

        let carriage = document_carriage(&doc_key)?;
        let mut framed = Vec::new();
        carriage.write_framed(&mut framed);

        let path = self.out.join(format!("{anchor}.carriage"));
        std::fs::write(&path, framed)?;

        say(&format!("wrote {}", path.display()));
        say(&format!(
            "vouches automerge:{anchor} (carriage only — content authorship is not yet checkable)"
        ));
        Ok(())
    }
}

/// The vouch verb failed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum VouchError {
    /// Artifact or runtime IO failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// The carriage could not be minted.
    #[error(transparent)]
    Mint(#[from] MintError),

    /// A seed argument was malformed.
    #[error("{which}: {source}")]
    Seed {
        /// Which key was being loaded.
        which: &'static str,
        /// Why it failed.
        source: SeedError,
    },
}
