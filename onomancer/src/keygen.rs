//! `onomancer keygen`: mint an ed25519 signing key.

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
use std::{io::Write as _, path::PathBuf};

use clap::Args;
use ed25519_dalek::SigningKey;
use onomancy_core::anchor::doc::DocAnchor;

use crate::{say, seed};

/// Mint a signing key and print its forms.
#[derive(Debug, Args)]
pub(crate) struct Keygen {
    /// Write the seed to a key file (owner-only permissions) instead
    /// of printing it — keeps secrets out of terminals and pipes.
    #[arg(long)]
    out: Option<PathBuf>,
}

impl Keygen {
    /// Generate; print the public forms, and either print or file the
    /// seed.
    ///
    /// # Errors
    ///
    /// Returns [`KeygenError`] when the OS randomness source fails or
    /// the key file cannot be written.
    pub(crate) fn run(&self) -> Result<(), KeygenError> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| KeygenError::NoEntropy)?;

        let key = SigningKey::from_bytes(&bytes);
        let anchor = DocAnchor::from(key.verifying_key());

        match &self.out {
            Some(path) => {
                write_key_file(path, &seed::to_hex(&bytes))?;
                eprintln!("key file (SECRET):   {}", path.display());
            }
            // Bare seed on stdout, commentary on stderr: redirecting
            // (`keygen > doc.key`) produces a valid key file.
            None => say(&seed::to_hex(&bytes)),
        }
        eprintln!("verifying key:       {anchor}");
        eprintln!("as automerge URL:    automerge:{anchor}");
        Ok(())
    }
}

/// Write the seed with owner-only permissions (on Unix).
fn write_key_file(path: &std::path::Path, hex: &str) -> Result<(), KeygenError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        options.mode(0o600);
    }

    let mut file = options.open(path).map_err(|source| KeygenError::Write {
        path: path.to_path_buf(),
        source,
    })?;
    writeln!(file, "{hex}").map_err(|source| KeygenError::Write {
        path: path.to_path_buf(),
        source,
    })
}

/// Key generation failed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum KeygenError {
    /// The OS randomness source failed.
    #[error("no entropy available from the OS")]
    NoEntropy,

    /// The key file could not be created (existing files are never
    /// overwritten).
    #[error("key file {path}: {source}")]
    Write {
        /// The offending path.
        path: PathBuf,
        /// The IO failure.
        source: std::io::Error,
    },
}
