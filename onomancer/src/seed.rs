//! Seed handling: 32 hex-encoded bytes in, signing keys out.

use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
};

use ed25519_dalek::SigningKey;

/// Load a signing key from either an inline hex seed or a key file
/// (a file containing the hex seed — what `keygen --out` writes).
/// Exactly one source must be given; files keep seeds out of shell
/// history.
///
/// # Errors
///
/// Returns [`SeedError`] when neither or both sources are given, the
/// file is unreadable, or the seed is malformed.
pub(crate) fn load(inline: Option<&str>, file: Option<&Path>) -> Result<SigningKey, SeedError> {
    match (inline, file) {
        (Some(hex), None) => signing_key(hex),
        (None, Some(path)) => {
            let contents =
                std::fs::read_to_string(path).map_err(|source| SeedError::Unreadable {
                    path: path.to_path_buf(),
                    source,
                })?;
            signing_key(&contents)
        }
        (None, None) => Err(SeedError::Missing),
        (Some(_), Some(_)) => Err(SeedError::Ambiguous),
    }
}

/// Parse a 64-hex-character seed into a signing key.
///
/// # Errors
///
/// Returns [`SeedError`] for non-hex input or the wrong length.
pub(crate) fn signing_key(hex: &str) -> Result<SigningKey, SeedError> {
    let raw = hex.trim();
    if raw.len() != 64 {
        return Err(SeedError::WrongLength { chars: raw.len() });
    }

    let mut seed = [0u8; 32];
    for (index, byte) in seed.iter_mut().enumerate() {
        let pair = raw.get(index * 2..index * 2 + 2).ok_or(SeedError::NotHex)?;
        *byte = u8::from_str_radix(pair, 16).map_err(|_| SeedError::NotHex)?;
    }

    Ok(SigningKey::from_bytes(&seed))
}

/// Lowercase-hex encode a seed for display.
#[must_use]
pub(crate) fn to_hex(seed: &[u8; 32]) -> String {
    seed.iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            // Writing to a String cannot fail; ignore the Infallible-ish Ok.
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

/// A seed could not be loaded.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SeedError {
    /// Both an inline seed and a key file were given.
    #[error("give either an inline seed or a key file, not both")]
    Ambiguous,

    /// Neither an inline seed nor a key file was given.
    #[error("a seed is required: inline hex or a key file")]
    Missing,

    /// Non-hex characters in the seed.
    #[error("seed must be lowercase hex")]
    NotHex,

    /// The key file could not be read.
    #[error("key file {path}: {source}")]
    Unreadable {
        /// The offending path.
        path: PathBuf,
        /// The IO failure.
        source: std::io::Error,
    },

    /// The seed was not exactly 64 hex characters.
    #[error("seed must be 64 hex characters (32 bytes), got {chars}")]
    WrongLength {
        /// The offending length.
        chars: usize,
    },
}
