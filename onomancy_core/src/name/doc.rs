//! Doc anchors: Automerge URLs whose document ID is an ed25519 verifying
//! key.
//!
//! doc anchors adopt automerge-repo's URL format wholesale:
//! the `automerge:` scheme, a bs58check-encoded document ID, and optional
//! `#`-suffixed heads. With Keyhive, the document ID IS an ed25519
//! verifying key, so the anchor is self-certifying.
//!
//! Onomancy does not define its own payload encoding — it tracks
//! upstream. bs58check's 4-byte checksum means transcription typos fail
//! loudly instead of silently denoting a different (valid) key.

use alloc::vec::Vec;
use core::fmt;
use ed25519_dalek::VerifyingKey;

/// The URI scheme for doc anchors, including the `:` separator.
pub const SCHEME_PREFIX: &str = "automerge:";

/// A doc anchor: an Automerge document ID that is an ed25519 verifying
/// key (the Keyhive root document ID). Self-certifying — no external
/// authority required.
///
/// The textual form is the bs58check-encoded key, exactly as it appears
/// after `automerge:` in an Automerge URL.
///
/// # Examples
///
/// ```
/// use onomancy_core::name::doc::DocAnchor;
///
/// let raw = "2nBeEMDjAzFa9Ev2pxwejYrgCRmSLx96SbA24uhdMMTUktJWvK";
/// let anchor = DocAnchor::parse(raw).expect("valid key-based doc ID");
/// assert_eq!(anchor.to_string(), raw);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DocAnchor(VerifyingKey);

/// Byte length of a legacy (pre-Keyhive) Automerge document ID.
const LEGACY_DOC_ID_LEN: usize = 16;

/// Byte length of an ed25519 verifying key.
const KEY_LEN: usize = 32;

impl DocAnchor {
    /// Parse a bs58check-encoded document ID (the payload after the
    /// `automerge:` scheme, before any `/` or `#`).
    ///
    /// # Errors
    ///
    /// Returns [`ParseDocAnchorError`] when the payload is not valid
    /// bs58check (including checksum failures — likely transcription
    /// typos), decodes to a legacy 16-byte document ID (a valid Automerge
    /// URL, but not self-certifying and therefore not a name anchor),
    /// has the wrong length, or is not a valid curve point.
    pub fn parse(raw: &str) -> Result<Self, ParseDocAnchorError> {
        let bytes: Vec<u8> = bs58::decode(raw)
            .with_check(None)
            .into_vec()
            .map_err(|_| ParseDocAnchorError::MalformedBase58Check)?;

        if bytes.len() == LEGACY_DOC_ID_LEN {
            return Err(ParseDocAnchorError::LegacyDocumentId);
        }

        let key_bytes: [u8; KEY_LEN] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| ParseDocAnchorError::WrongLength)?;

        let key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| ParseDocAnchorError::NotACurvePoint)?;

        Ok(Self(key))
    }

    /// The underlying verifying key (= Keyhive root document ID).
    #[must_use]
    pub const fn verifying_key(&self) -> &VerifyingKey {
        &self.0
    }
}

impl fmt::Display for DocAnchor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&bs58::encode(self.0.as_bytes()).with_check().into_string())
    }
}

impl From<VerifyingKey> for DocAnchor {
    fn from(key: VerifyingKey) -> Self {
        Self(key)
    }
}

impl PartialOrd for DocAnchor {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DocAnchor {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.as_bytes().cmp(other.0.as_bytes())
    }
}

/// A single pinned head: a bs58check-encoded Automerge change hash.
///
/// Heads appear after `#` in a doc-anchored name (`|`-joined, matching
/// automerge-repo) and pin the *anchor document* to a point in time.
/// Pinned names are stale-by-construction; freshness policy is a
/// resolution-layer concern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Head([u8; KEY_LEN]);

impl Head {
    /// Parse a bs58check-encoded 32-byte change hash.
    ///
    /// # Errors
    ///
    /// Returns [`ParseHeadError`] when the payload is not valid bs58check
    /// or does not decode to exactly 32 bytes.
    pub fn parse(raw: &str) -> Result<Self, ParseHeadError> {
        let bytes: Vec<u8> = bs58::decode(raw)
            .with_check(None)
            .into_vec()
            .map_err(|_| ParseHeadError::MalformedBase58Check)?;

        let hash: [u8; KEY_LEN] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| ParseHeadError::WrongLength)?;

        Ok(Self(hash))
    }

    /// The raw change-hash bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl fmt::Display for Head {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&bs58::encode(&self.0).with_check().into_string())
    }
}

/// The input was not a valid bs58check-encoded key-based document ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseDocAnchorError {
    /// The payload decoded to a legacy 16-byte Automerge document ID —
    /// a valid Automerge URL, but not self-certifying, so it cannot
    /// anchor a name.
    #[error("legacy Automerge document ID — not self-certifying")]
    LegacyDocumentId,

    /// The payload was not valid bs58check (bad characters or checksum
    /// failure — likely a transcription typo).
    #[error("malformed bs58check payload")]
    MalformedBase58Check,

    /// The bytes decoded but were not a valid ed25519 curve point.
    #[error("not a valid ed25519 verifying key")]
    NotACurvePoint,

    /// The decoded payload was neither a legacy ID nor a 32-byte key.
    #[error("key-based document IDs are exactly 32 bytes")]
    WrongLength,
}

/// The input was not a valid bs58check-encoded change hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseHeadError {
    /// The payload was not valid bs58check (bad characters or checksum
    /// failure — likely a transcription typo).
    #[error("malformed bs58check head")]
    MalformedBase58Check,

    /// Automerge change hashes are exactly 32 bytes.
    #[error("heads are exactly 32 bytes")]
    WrongLength,
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use ed25519_dalek::SigningKey;

    fn vector_key() -> VerifyingKey {
        SigningKey::from_bytes(&[7u8; 32]).verifying_key()
    }

    #[test]
    fn roundtrips_from_key() {
        let anchor = DocAnchor::from(vector_key());
        let reparsed = DocAnchor::parse(&anchor.to_string()).expect("printed anchors reparse");
        assert_eq!(anchor, reparsed);
    }

    #[test]
    fn legacy_doc_ids_are_rejected_distinctly() {
        let legacy = bs58::encode(&[9u8; 16]).with_check().into_string();
        assert_eq!(
            DocAnchor::parse(&legacy),
            Err(ParseDocAnchorError::LegacyDocumentId)
        );
    }

    #[test]
    fn typos_fail_the_checksum() {
        let mut s = DocAnchor::from(vector_key()).to_string();
        let last = s.pop().expect("non-empty");
        s.push(if last == '1' { '2' } else { '1' });
        assert_eq!(
            DocAnchor::parse(&s),
            Err(ParseDocAnchorError::MalformedBase58Check)
        );
    }

    #[test]
    fn petname_like_strings_are_rejected() {
        assert_eq!(
            DocAnchor::parse("bob"),
            Err(ParseDocAnchorError::MalformedBase58Check)
        );
    }

    #[test]
    fn encode_decode_roundtrip_from_raw_bytes() {
        bolero::check!().with_type::<[u8; 32]>().for_each(|bytes| {
            if let Ok(key) = VerifyingKey::from_bytes(bytes) {
                let anchor = DocAnchor::from(key);
                let reparsed = DocAnchor::parse(&anchor.to_string()).expect("printed keys reparse");
                assert_eq!(anchor, reparsed);
            }
        });
    }

    #[test]
    fn head_roundtrip_from_raw_bytes() {
        bolero::check!().with_type::<[u8; 32]>().for_each(|bytes| {
            let head = Head(*bytes);
            let reparsed = Head::parse(&head.to_string()).expect("printed heads reparse");
            assert_eq!(head, reparsed);
        });
    }
}
