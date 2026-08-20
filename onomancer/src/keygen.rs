//! `onomancer keygen`: mint an ed25519 signing key.

use clap::Args;
use ed25519_dalek::SigningKey;
use onomancy_core::name::doc::DocAnchor;

use crate::seed;

/// Mint a signing key and print its forms.
#[derive(Debug, Args)]
pub(crate) struct Keygen;

impl Keygen {
    /// Generate and print.
    ///
    /// # Errors
    ///
    /// Returns [`KeygenError`] when the OS randomness source fails.
    #[allow(clippy::unused_self)] // uniform command shape
    pub(crate) fn run(&self) -> Result<(), KeygenError> {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|_| KeygenError::NoEntropy)?;

        let key = SigningKey::from_bytes(&bytes);
        let anchor = DocAnchor::from(key.verifying_key());

        println!("seed (hex, SECRET):  {}", seed::to_hex(&bytes));
        println!("verifying key:       {anchor}");
        println!("as automerge URL:    automerge:{anchor}");
        Ok(())
    }
}

/// Key generation failed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum KeygenError {
    /// The OS randomness source failed.
    #[error("no entropy available from the OS")]
    NoEntropy,
}
