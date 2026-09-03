//! Doc anchors: Automerge URLs whose document ID is an ed25519 verifying
//! key.
//!
//! Doc anchors adopt automerge-repo's payload format: the
//! `automerge:` scheme and a bs58check-encoded document ID. With
//! Keyhive, the document ID IS an ed25519 verifying key, so the
//! anchor is self-certifying. Upstream's optional `#`-suffixed heads
//! are NOT part of the name grammar — names carry no version pins
//! (pinning is edge data), and `#` is reserved.
//!
//! Onomancy does not define its own payload encoding — it tracks
//! upstream. bs58check's 4-byte checksum means transcription typos fail
//! loudly instead of silently denoting a different (valid) key.

use alloc::vec::Vec;
use core::{cmp::Ordering, fmt};
use ed25519_dalek::VerifyingKey;

use crate::{
    anchor::Anchor,
    key,
    name::{Name, ParseSegmentsError, parse_segments, split_anchor},
};

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
/// use onomancy_core::anchor::doc::DocAnchor;
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

        let key = key::decode(&key_bytes).map_err(|_| ParseDocAnchorError::NotACurvePoint)?;

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
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DocAnchor {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.as_bytes().cmp(other.0.as_bytes())
    }
}

/// One Automerge change hash, bs58check-encoded in text form.
///
/// Names carry no version pins, so heads never appear in the name
/// grammar; the type exists for signed units that attest document
/// state (e.g. a certificate's advisory heads).
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

impl From<[u8; KEY_LEN]> for Head {
    fn from(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
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

    /// The bytes were not the canonical encoding of an ed25519 curve
    /// point.
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

impl Anchor for DocAnchor {
    type ParseError = ParseDocNameError;

    fn parse_name(raw: &str) -> Result<Name<Self>, ParseDocNameError> {
        let rest = raw
            .strip_prefix(SCHEME_PREFIX)
            .ok_or(ParseDocNameError::MissingScheme)?;

        if rest.contains('#') {
            // Names carry no version pins: pinning is edge data, not
            // grammar. `#` stays reserved so every extension option
            // remains open.
            return Err(ParseDocNameError::ReservedFragment);
        }

        let (anchor_raw, segments_raw) = split_anchor(rest);

        Ok(Name::from_parts(
            Self::parse(anchor_raw)?,
            parse_segments(segments_raw)?,
        ))
    }

    fn fmt_anchor(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{SCHEME_PREFIX}{self}")
    }
}

/// The input could not be parsed as a doc-anchored (`automerge:`) name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseDocNameError {
    /// The doc anchor payload was malformed.
    #[error(transparent)]
    Anchor(#[from] ParseDocAnchorError),

    /// Doc-anchored names start with `automerge:`.
    #[error("doc-anchored names start with `automerge:`")]
    MissingScheme,

    /// `#` is reserved: names carry no version pins (pinning is edge
    /// data, not grammar).
    #[error("`#` is reserved: names carry no version pins")]
    ReservedFragment,

    /// The path after the anchor was malformed.
    #[error(transparent)]
    Segments(#[from] ParseSegmentsError),
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
    fn off_length_payloads_are_rejected_distinctly_from_legacy_ids() {
        // Neither a legacy 16-byte ID nor a 32-byte key.
        let odd = bs58::encode(&[9u8; 20]).with_check().into_string();
        assert_eq!(
            DocAnchor::parse(&odd),
            Err(ParseDocAnchorError::WrongLength)
        );
    }

    /// 32 bytes that pass the checksum but decompress to no curve
    /// point are their own failure, not a length or checksum error.
    #[test]
    fn non_curve_points_are_rejected_as_such() {
        let non_point = non_curve_point_bytes();
        let encoded = bs58::encode(&non_point).with_check().into_string();
        assert_eq!(
            DocAnchor::parse(&encoded),
            Err(ParseDocAnchorError::NotACurvePoint)
        );
    }

    #[test]
    fn head_errors_distinguish_checksum_from_length() {
        assert_eq!(
            Head::parse("not-base58-0OIl"),
            Err(ParseHeadError::MalformedBase58Check)
        );

        let short = bs58::encode(&[7u8; 16]).with_check().into_string();
        assert_eq!(Head::parse(&short), Err(ParseHeadError::WrongLength));
    }

    /// The manual `Ord` is byte order — a reversed or constant `cmp`
    /// mutation dies here.
    #[test]
    fn anchors_order_by_key_bytes() {
        let low = DocAnchor::from(vector_key());
        let high = DocAnchor::from(SigningKey::from_bytes(&[8u8; 32]).verifying_key());

        assert_eq!(
            low.cmp(&high),
            low.verifying_key()
                .as_bytes()
                .cmp(high.verifying_key().as_bytes())
        );
        assert_eq!(low.cmp(&low), core::cmp::Ordering::Equal);
        assert_eq!(low.cmp(&high), high.cmp(&low).reverse());
    }

    /// The first constant-fill 32-byte array that fails ed25519 point
    /// decompression (about half the byte space does): a deterministic
    /// non-point without hardcoding curve internals.
    fn non_curve_point_bytes() -> [u8; 32] {
        (0u8..=255)
            .map(|b| [b; 32])
            .find(|bytes| VerifyingKey::from_bytes(bytes).is_err())
            .expect("some constant fill fails decompression")
    }

    mod props {
        use super::*;

        #[test]
        fn encode_decode_roundtrip_from_raw_bytes() {
            bolero::check!().with_type::<[u8; 32]>().for_each(|bytes| {
                let encoded = bs58::encode(bytes).with_check().into_string();

                match VerifyingKey::from_bytes(bytes) {
                    Ok(key) => {
                        let anchor = DocAnchor::from(key);
                        let reparsed =
                            DocAnchor::parse(&anchor.to_string()).expect("printed keys reparse");
                        assert_eq!(anchor, reparsed);
                        assert_eq!(anchor.to_string(), encoded);
                    }
                    // The negative arm: non-points fail as exactly
                    // NotACurvePoint, never some other shape.
                    Err(_) => assert_eq!(
                        DocAnchor::parse(&encoded),
                        Err(ParseDocAnchorError::NotACurvePoint)
                    ),
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
}
