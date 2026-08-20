//! Seed handling: 32 hex-encoded bytes in, signing keys out.

use ed25519_dalek::SigningKey;

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
            use std::fmt::Write as _;

            // Writing to a String cannot fail; ignore the Infallible-ish Ok.
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

/// A seed argument was not 32 hex-encoded bytes.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SeedError {
    /// Non-hex characters in the seed.
    #[error("seed must be lowercase hex")]
    NotHex,

    /// The seed was not exactly 64 hex characters.
    #[error("seed must be 64 hex characters (32 bytes), got {chars}")]
    WrongLength {
        /// The offending length.
        chars: usize,
    },
}
