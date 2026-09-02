//! The TXT binding record itself, and its `RRset` dispositions.
//!
//! Deliberately NO expiration field: freshness is graded from the
//! chain's RRSIG windows, and revocation lives in the document's
//! delegation graph
//! (`g=` rotation) — a record-level expiry would fight local-first
//! offline semantics (dns-anchor spec, "Why no expiration on the
//! binding record?").

use alloc::{boxed::Box, string::String};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use core::{fmt, str};
use ed25519_dalek::VerifyingKey;

use super::{
    generation_key::GenerationKey,
    serial::{ParseSerialError, Serial},
};
use onomancy_core::anchor::doc::DocAnchor;

/// The format tag this module implements, as it appears on the wire.
pub const FORMAT_TAG: &str = "v=ONO0";

/// The only key algorithm at `ONO0`.
pub const KEY_ALGORITHM: &str = "k=ed25519";

/// Maximum octets of a conforming `ONO0` record
/// (`6 + 1 + 9 + 1 + 22 + 1 + 46 + 1 + 46`).
pub const MAX_RECORD_LEN: usize = 133;

/// Length of the standard padded base64 encoding of 32 bytes.
const KEY_BASE64_LEN: usize = 44;

/// Byte length of an ed25519 verifying key.
const KEY_LEN: usize = 32;

/// A parsed, canonical TXT binding record.
///
/// Parse-don't-validate: a value of this type *is* the proof that the
/// record was strictly conforming `ONO0`. [`fmt::Display`] renders the
/// unique canonical spelling, so `parse ∘ to_string` is the identity.
///
/// # Examples
///
/// ```
/// use ed25519_dalek::SigningKey;
/// use onomancy_dnssec::txt::record::TxtRecord;
///
/// let key = SigningKey::from_bytes(&[7; 32]).verifying_key();
/// let record = TxtRecord::new(1.into(), key.into(), key.into());
///
/// let rendered = record.to_string();
/// assert!(rendered.starts_with("v=ONO0;k=ed25519;n=1;g="));
/// assert_eq!(TxtRecord::parse(&rendered)?, record);
/// # Ok::<_, onomancy_dnssec::txt::record::ParseTxtRecordError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TxtRecord {
    serial: Serial,
    generation: GenerationKey,
    document: DocAnchor,
}

impl TxtRecord {
    /// Build a record from parts (the publisher path).
    #[must_use]
    pub const fn new(serial: Serial, generation: GenerationKey, document: DocAnchor) -> Self {
        Self {
            serial,
            generation,
            document,
        }
    }

    /// Classify one TXT string per the `RRset` rules: a strict `ONO0`
    /// parse, a future `ONO` tag to skip, or an unknown (non-Onomancy)
    /// record to ignore.
    ///
    /// The input is the *concatenation* of the TXT RDATA's character
    /// strings (standard TXT semantics); concatenation is the caller's
    /// job.
    ///
    /// # Errors
    ///
    /// Returns [`ParseTxtRecordError`] only for a record that *is*
    /// `ONO0` but violates its grammar — the reject-and-surface
    /// disposition. Unknown and future records are `Ok`
    /// classifications, never errors.
    pub fn classify(raw: &str) -> Result<Classified, ParseTxtRecordError> {
        let Some(version_onward) = raw.strip_prefix("v=ONO") else {
            return Ok(Classified::UnknownRecord);
        };

        let version_digits = version_onward.split(';').next().unwrap_or(version_onward);

        if version_digits.is_empty() || !version_digits.bytes().all(|b| b.is_ascii_digit()) {
            // `v=ONO` followed by non-digits is not an ONO tag at all.
            return Ok(Classified::UnknownRecord);
        }

        if version_digits != "0" {
            // Any other digit string — including "00" and digit runs too
            // large for u64 — is a tag this software does not implement.
            return Ok(Classified::UnknownVersion);
        }

        Self::parse_ono0(raw).map(Box::new).map(Classified::Binding)
    }

    /// Parse a string that is expected to be a conforming `ONO0` record.
    ///
    /// Prefer [`classify`](Self::classify) when processing an `RRset`;
    /// this is for contexts where anything but a binding is an error.
    ///
    /// # Errors
    ///
    /// Returns [`ParseTxtRecordError`], including the
    /// [`UnknownRecord`](ParseTxtRecordError::UnknownRecord) and
    /// [`UnknownVersion`](ParseTxtRecordError::UnknownVersion)
    /// variants for inputs `classify` would have dispositioned instead.
    pub fn parse(raw: &str) -> Result<Self, ParseTxtRecordError> {
        match Self::classify(raw)? {
            Classified::Binding(record) => Ok(*record),
            Classified::UnknownRecord => Err(ParseTxtRecordError::UnknownRecord),
            Classified::UnknownVersion => Err(ParseTxtRecordError::UnknownVersion),
        }
    }

    /// Strict `ONO0` field parse. The caller has already matched the tag.
    fn parse_ono0(raw: &str) -> Result<Self, ParseTxtRecordError> {
        if raw.len() > MAX_RECORD_LEN {
            return Err(ParseTxtRecordError::RecordTooLong {
                len: raw.len(),
                max: MAX_RECORD_LEN,
            });
        }

        let mut fields = raw.split(';');

        // Field 0 (`v=ONO0`) was matched by `classify`, but re-checking
        // costs nothing and keeps this function total on its own.
        let field_count = raw.split(';').count();
        if field_count != 5 {
            return Err(ParseTxtRecordError::WrongFieldCount { got: field_count });
        }

        let (Some(_tag), Some(key_algorithm), Some(serial), Some(generation), Some(document)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            return Err(ParseTxtRecordError::WrongFieldCount { got: field_count });
        };

        if key_algorithm != KEY_ALGORITHM {
            return match key_algorithm.strip_prefix("k=") {
                Some(algorithm) => Err(ParseTxtRecordError::UnknownKeyAlgorithm {
                    got: String::from(algorithm),
                }),
                None => Err(ParseTxtRecordError::WrongFieldPrefix {
                    field: FieldName::KeyAlgorithm,
                }),
            };
        }

        let serial = serial
            .strip_prefix("n=")
            .ok_or(ParseTxtRecordError::WrongFieldPrefix {
                field: FieldName::Serial,
            })
            .and_then(|digits| Serial::parse(digits).map_err(Into::into))?;

        let generation = decode_key_field(generation, "g=", FieldName::GenerationKey)
            .map(GenerationKey::from)?;

        let document =
            decode_key_field(document, "p=", FieldName::DocumentId).map(DocAnchor::from)?;

        Ok(Self {
            serial,
            generation,
            document,
        })
    }

    /// The anti-replay serial (`n=`).
    #[must_use]
    pub const fn serial(&self) -> Serial {
        self.serial
    }

    /// The attested generation key (`g=`): the delegation-chain
    /// chokepoint certificate chains must thread.
    #[must_use]
    pub const fn generation(&self) -> &GenerationKey {
        &self.generation
    }

    /// The root document ID (`p=`) — the same identity a doc anchor
    /// names, so divergence joins compare [`DocAnchor`]s directly.
    #[must_use]
    pub const fn document(&self) -> &DocAnchor {
        &self.document
    }
}

impl fmt::Display for TxtRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{FORMAT_TAG};{KEY_ALGORITHM};n={};g={};p={}",
            self.serial,
            BASE64.encode(self.generation.verifying_key().as_bytes()),
            BASE64.encode(self.document.verifying_key().as_bytes()),
        )
    }
}

/// The disposition of one TXT string under the `RRset` rules.
///
/// See the [module docs](crate::txt) for the mapping. `Binding` boxes
/// its record: dispositions are transient classification results, and
/// the two key-bearing fields make the record large relative to the
/// unit variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classified {
    /// A strictly conforming `ONO0` binding record.
    Binding(Box<TxtRecord>),
    /// Not an onomancy record at all (SPF, DKIM, some other
    /// protocol's TXT — the spec's "foreign" disposition) — MUST be
    /// ignored entirely.
    UnknownRecord,
    /// An `ONO`-tagged record with a version this software does not
    /// implement (the spec's "future tag" disposition) — MUST be
    /// skipped, MUST NOT poison the `RRset` (a message to newer
    /// software, not junk).
    UnknownVersion,
}

/// Decode a `<prefix><44 chars of canonical padded base64>` key field.
fn decode_key_field(
    field: &str,
    prefix: &'static str,
    name: FieldName,
) -> Result<VerifyingKey, ParseTxtRecordError> {
    let encoded = field
        .strip_prefix(prefix)
        .ok_or(ParseTxtRecordError::WrongFieldPrefix { field: name })?;

    if encoded.len() != KEY_BASE64_LEN {
        return Err(ParseTxtRecordError::WrongBase64Length {
            field: name,
            got: encoded.len(),
        });
    }

    // `STANDARD` requires canonical padding and rejects set trailing
    // bits, so decoding success implies `encoded` is the unique
    // canonical spelling of `bytes` — injectivity holds with no
    // re-encode check (pinned by `non_canonical_base64_is_malformed`).
    let bytes = BASE64
        .decode(encoded)
        .map_err(|_| ParseTxtRecordError::MalformedBase64 { field: name })?;

    let key_bytes: [u8; KEY_LEN] =
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| ParseTxtRecordError::WrongKeyLength {
                field: name,
                got: bytes.len(),
            })?;

    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| ParseTxtRecordError::NotACurvePoint { field: name })
}

/// Which field of the record an error is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldName {
    /// `k=` — the key algorithm.
    KeyAlgorithm,
    /// `n=` — the serial.
    Serial,
    /// `g=` — the generation key.
    GenerationKey,
    /// `p=` — the root document ID.
    DocumentId,
}

impl fmt::Display for FieldName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::KeyAlgorithm => "k",
            Self::Serial => "n",
            Self::GenerationKey => "g",
            Self::DocumentId => "p",
        })
    }
}

/// A record that is `ONO0` (or was required to be) but violates the
/// grammar. Reject-and-surface disposition; never applies to unknown
/// or future records under [`TxtRecord::classify`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseTxtRecordError {
    /// Not an onomancy record at all (only from [`TxtRecord::parse`];
    /// [`TxtRecord::classify`] dispositions this instead).
    #[error("not an onomancy TXT record")]
    UnknownRecord,

    /// An `ONO` tag this software does not implement (only from
    /// [`TxtRecord::parse`]; `classify` dispositions this instead).
    #[error("ONO format tag newer than this implementation")]
    UnknownVersion,

    /// A conforming record is at most [`MAX_RECORD_LEN`] octets.
    #[error("record is {len} octets; ONO0 records are at most {max}")]
    RecordTooLong {
        /// Actual length in octets.
        len: usize,
        /// The grammar's maximum.
        max: usize,
    },

    /// `ONO0` has exactly five `;`-separated fields.
    #[error("expected exactly 5 fields, got {got}")]
    WrongFieldCount {
        /// How many `;`-separated fields were present.
        got: usize,
    },

    /// A field did not start with its required `<letter>=` prefix
    /// (fixed field order — reordering is malformed).
    #[error("field in position of `{field}=` is missing its prefix")]
    WrongFieldPrefix {
        /// The field expected at this position.
        field: FieldName,
    },

    /// `k=` named an algorithm other than `ed25519`. Per-record
    /// rejection: siblings in the `RRset` are still processed, but this
    /// SHOULD be surfaced as a possible downgrade signal.
    #[error("unknown key algorithm `{got}` (ONO0 is ed25519-only)")]
    UnknownKeyAlgorithm {
        /// The algorithm name presented.
        got: String,
    },

    /// The serial violated its canonical-decimal grammar.
    #[error("serial: {0}")]
    Serial(#[from] ParseSerialError),

    /// A key field's encoded length was not the 44 characters that
    /// standard padded base64 of 32 bytes always produces.
    #[error("`{field}=` is {got} base64 characters; 32-byte keys encode to exactly 44")]
    WrongBase64Length {
        /// The offending field.
        field: FieldName,
        /// Encoded length found.
        got: usize,
    },

    /// A key field was not decodable as *canonical* standard padded
    /// base64 — bad alphabet, bad padding, or non-zero trailing bits
    /// (the engine enforces one-spelling-per-value).
    #[error("`{field}=` is not canonical standard padded base64")]
    MalformedBase64 {
        /// The offending field.
        field: FieldName,
    },

    /// A key field's bytes were not exactly 32.
    #[error("`{field}=` decoded to {got} bytes; keys are exactly 32")]
    WrongKeyLength {
        /// The offending field.
        field: FieldName,
        /// Decoded byte count.
        got: usize,
    },

    /// A key field's 32 bytes were not a valid ed25519 curve point.
    #[error("`{field}=` is not a valid ed25519 verifying key")]
    NotACurvePoint {
        /// The offending field.
        field: FieldName,
    },
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use ed25519_dalek::SigningKey;
    use testresult::TestResult;

    fn key(seed: u8) -> VerifyingKey {
        SigningKey::from_bytes(&[seed; 32]).verifying_key()
    }

    fn vector(serial: u64, g: u8, p: u8) -> TxtRecord {
        TxtRecord::new(
            Serial::from(serial),
            GenerationKey::from(key(g)),
            DocAnchor::from(key(p)),
        )
    }

    mod props {
        use super::*;

        /// parse ∘ render = id, for every reachable record.
        #[test]
        fn parse_render_roundtrip() {
            bolero::check!()
                .with_type::<(u64, [u8; 32], [u8; 32])>()
                .for_each(|(serial, g_seed, p_seed)| {
                    let record = TxtRecord::new(
                        Serial::from(*serial),
                        GenerationKey::from(SigningKey::from_bytes(g_seed).verifying_key()),
                        DocAnchor::from(SigningKey::from_bytes(p_seed).verifying_key()),
                    );
                    let rendered = record.to_string();
                    assert!(
                        rendered.len() <= MAX_RECORD_LEN,
                        "canonical rendering must fit the grammar's bound"
                    );
                    let reparsed = TxtRecord::parse(&rendered).expect("rendered records reparse");
                    assert_eq!(record, reparsed);
                });
        }

        /// classify is total: arbitrary bytes never panic, and only
        /// `ONO0` inputs can produce errors.
        #[test]
        fn classify_is_total_and_errors_only_on_ono0() {
            bolero::check!().for_each(|bytes: &[u8]| {
                let Ok(raw) = str::from_utf8(bytes) else {
                    return;
                };
                match TxtRecord::classify(raw) {
                    Ok(_) => {}
                    Err(err) => {
                        assert!(
                            raw.starts_with("v=ONO0"),
                            "only ONO0 records may be rejected (got {err:?} for {raw:?})"
                        );
                    }
                }
            });
        }

        /// Canonicality: any string that parses re-renders to itself.
        #[test]
        fn accepted_strings_are_canonical() {
            bolero::check!().for_each(|bytes: &[u8]| {
                let Ok(raw) = str::from_utf8(bytes) else {
                    return;
                };
                if let Ok(Classified::Binding(record)) = TxtRecord::classify(raw) {
                    assert_eq!(
                        record.to_string(),
                        raw,
                        "one record, one spelling: parse must only accept the canonical form"
                    );
                }
            });
        }
    }

    /// Pinned regressions: shapes that once mis-parsed stay parsed.
    mod regressions {
        use super::*;

        #[test]
        fn spec_shaped_record_roundtrips() -> TestResult {
            let record = vector(1, 7, 9);
            let rendered = record.to_string();
            assert!(rendered.starts_with("v=ONO0;k=ed25519;n=1;g="));
            assert_eq!(TxtRecord::parse(&rendered)?, record);
            Ok(())
        }

        #[test]
        fn max_serial_stays_within_length_bound() -> TestResult {
            let record = vector(u64::MAX, 7, 9);
            let rendered = record.to_string();
            assert_eq!(rendered.len(), MAX_RECORD_LEN);
            assert_eq!(TxtRecord::parse(&rendered)?, record);
            Ok(())
        }

        #[test]
        fn foreign_records_are_dispositioned_not_rejected() -> TestResult {
            for foreign in [
                "v=spf1 include:_spf.example.com ~all",
                "v=DKIM1; k=rsa; p=MIGf...",
                "",
                "v=ONO", // no version digits at all
                "v=ONOx;k=ed25519;n=1;g=a;p=b",
            ] {
                assert_eq!(TxtRecord::classify(foreign)?, Classified::UnknownRecord);
            }
            Ok(())
        }

        #[test]
        fn future_tags_are_skipped_not_rejected() -> TestResult {
            for future in [
                "v=ONO1;k=ed25519;n=1;g=x;p=y",
                "v=ONO00;utter=junk",
                "v=ONO18446744073709551616", // > u64::MAX is still an ONO tag
            ] {
                assert_eq!(TxtRecord::classify(future)?, Classified::UnknownVersion);
            }
            Ok(())
        }

        #[test]
        fn ono0_junk_is_rejected_with_field_precision() {
            let good = vector(3, 7, 9).to_string();

            // Reordered fields: the field in `k`'s position lacks its prefix.
            let reordered = good.replace("k=ed25519;n=3", "n=3;k=ed25519");
            assert_eq!(
                TxtRecord::parse(&reordered),
                Err(ParseTxtRecordError::WrongFieldPrefix {
                    field: FieldName::KeyAlgorithm
                })
            );

            // Unknown algorithm is its own (surfaceable) case.
            let rsa = good.replace("k=ed25519", "k=rsa");
            assert_eq!(
                TxtRecord::parse(&rsa),
                Err(ParseTxtRecordError::UnknownKeyAlgorithm {
                    got: String::from("rsa")
                })
            );

            // Extra field.
            let extended = alloc::format!("{good};x=1");
            assert_eq!(
                TxtRecord::parse(&extended),
                Err(ParseTxtRecordError::WrongFieldCount { got: 6 })
            );
        }

        #[test]
        fn base64_failures_name_their_field() {
            let good = vector(3, 7, 9).to_string();
            let g_value = good
                .split(';')
                .nth(3)
                .and_then(|f| f.strip_prefix("g="))
                .expect("well-formed vector")
                .to_string();

            // Wrong length.
            let short = good.replace(&g_value, &g_value[..40]);
            assert_eq!(
                TxtRecord::parse(&short),
                Err(ParseTxtRecordError::WrongBase64Length {
                    field: FieldName::GenerationKey,
                    got: 40
                })
            );

            // Invalid alphabet, same length.
            let junk = good.replace(&g_value, &"!".repeat(44));
            assert_eq!(
                TxtRecord::parse(&junk),
                Err(ParseTxtRecordError::MalformedBase64 {
                    field: FieldName::GenerationKey
                })
            );
        }

        /// The decode engine must reject non-canonical trailing-bit
        /// spellings — the injectivity guarantee `decode_key_field` leans
        /// on. 32-byte payloads carry 4 data bits + 2 spare bits in their
        /// 43rd character; flipping the sextet's lowest bit changes only a
        /// spare bit, producing an alternate spelling of the same bytes.
        #[test]
        fn non_canonical_base64_is_malformed() -> TestResult {
            const ALPHABET: &[u8] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

            let good = vector(3, 7, 9).to_string();
            let (prefix, _) = good.split_once(";g=").expect("well-formed vector");
            let g_value = good
                .split(';')
                .nth(3)
                .and_then(|f| f.strip_prefix("g="))
                .expect("well-formed vector");
            let p_field = good.split(';').nth(4).expect("well-formed vector");

            let mut spelled: alloc::vec::Vec<u8> = g_value.bytes().collect();
            let final_data_char = spelled.get_mut(42).expect("44-char field");
            let pos = ALPHABET
                .iter()
                .position(|c| c == final_data_char)
                .expect("alphabet character");
            *final_data_char = *ALPHABET.get(pos ^ 1).expect("in range");

            let noncanonical = String::from_utf8(spelled)?;
            assert_ne!(noncanonical, g_value, "must be an alternate spelling");

            let candidate = alloc::format!("{prefix};g={noncanonical};{p_field}");
            assert_eq!(
                TxtRecord::parse(&candidate),
                Err(ParseTxtRecordError::MalformedBase64 {
                    field: FieldName::GenerationKey
                })
            );
            Ok(())
        }

        #[test]
        fn oversized_records_are_rejected_before_field_work() {
            let long = alloc::format!("v=ONO0;{}", "a".repeat(MAX_RECORD_LEN));
            assert_eq!(
                TxtRecord::parse(&long),
                Err(ParseTxtRecordError::RecordTooLong {
                    len: long.len(),
                    max: MAX_RECORD_LEN
                })
            );
        }
    }
}
