//! The attested generation key (`g=`).

use core::{cmp::Ordering, fmt};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::VerifyingKey;
use onomancy_core::key;

/// The current generation key: the attested chokepoint that certificate
/// delegation chains must thread as an authority-carrying hop.
///
/// A distinct newtype from [`DocAnchor`](onomancy_core::anchor::doc::DocAnchor)
/// on purpose — generation keys and document IDs are both ed25519
/// keys, and confusing them is exactly the kind of bug newtypes exist
/// to make unrepresentable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GenerationKey(VerifyingKey);

impl GenerationKey {
    /// Parse the wire spelling: canonical padded base64 of the
    /// canonical compression of an ed25519 point, exactly as the `g=`
    /// field carries it and as [`fmt::Display`] prints it.
    ///
    /// # Errors
    ///
    /// Returns [`ParseGenerationKeyError`] when the text is not
    /// canonical base64, decodes to other than 32 bytes, or is not
    /// the canonical spelling of a curve point.
    pub fn parse(text: &str) -> Result<Self, ParseGenerationKeyError> {
        let bytes = BASE64
            .decode(text)
            .map_err(|_| ParseGenerationKeyError::MalformedBase64)?;

        let key_bytes: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| ParseGenerationKeyError::WrongLength { got: bytes.len() })?;

        let key = key::decode(&key_bytes)?;
        Ok(Self(key))
    }

    /// The underlying verifying key.
    #[must_use]
    pub const fn verifying_key(&self) -> &VerifyingKey {
        &self.0
    }
}

impl From<VerifyingKey> for GenerationKey {
    fn from(key: VerifyingKey) -> Self {
        Self(key)
    }
}

/// The wire spelling: canonical padded base64 of the key bytes, as
/// the `g=` field carries it.
impl fmt::Display for GenerationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&BASE64.encode(self.0.as_bytes()))
    }
}

impl PartialOrd for GenerationKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for GenerationKey {
    /// By key bytes, matching `DocAnchor`'s convention.
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.as_bytes().cmp(other.0.as_bytes())
    }
}

/// Why a `g=` spelling failed to parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseGenerationKeyError {
    /// Not canonical padded base64.
    #[error("not canonical padded base64")]
    MalformedBase64,

    /// Decoded to other than 32 bytes.
    #[error("a generation key is exactly 32 bytes, got {got}")]
    WrongLength {
        /// The decoded byte count.
        got: usize,
    },

    /// The bytes are not the canonical encoding of a curve point.
    #[error(transparent)]
    NotCanonicalKey(#[from] key::NotCanonicalKey),
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;

    /// `parse` and `Display` are the two halves of one spelling.
    #[test]
    fn the_wire_spelling_roundtrips() {
        let generation = GenerationKey::from(SigningKey::from_bytes(&[9; 32]).verifying_key());

        assert_eq!(
            GenerationKey::parse(&generation.to_string()).expect("own spelling parses"),
            generation,
        );
    }

    #[test]
    fn non_canonical_spellings_are_refused() {
        // Unpadded base64 of a valid key.
        let generation = GenerationKey::from(SigningKey::from_bytes(&[9; 32]).verifying_key());
        let unpadded = generation.to_string().replace('=', "");
        assert_eq!(
            GenerationKey::parse(&unpadded),
            Err(ParseGenerationKeyError::MalformedBase64),
        );

        // Canonical base64 of a non-canonical key spelling.
        assert_eq!(
            GenerationKey::parse(&BASE64.encode([0xff; 32])),
            Err(ParseGenerationKeyError::NotCanonicalKey(
                key::NotCanonicalKey
            )),
        );

        // Wrong width.
        assert_eq!(
            GenerationKey::parse(&BASE64.encode([9; 16])),
            Err(ParseGenerationKeyError::WrongLength { got: 16 }),
        );
    }
}
