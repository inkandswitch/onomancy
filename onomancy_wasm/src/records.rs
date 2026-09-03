//! The TXT record rules, exported so they live in one place.
//!
//! `resolveHostname` returns the zone's proven records as strings and
//! applies the `RRset` rules internally. A consumer that needs the
//! same answers — which record is the zone's word, whether the zone
//! is equivocating, what to mint next — would otherwise re-implement
//! the grammar and the selection rule, and two implementations of a
//! trust root's parser drift. These exports are the reference rules,
//! verbatim from the crates the verifier runs.
//!
//! What is here is the **`RRset` rule**: one set of records, one
//! instant. It is not the ratchet, the generation lineage, or the
//! decisions logic of the full verifier, all of which need remembered
//! state. A caller persisting state must not read `selected` as "the
//! binding" — it is the zone's current word, before any of that.

use js_sys::{Array, Date, Object, Reflect};
use onomancy_core::{
    anchor::doc::{DocAnchor, ParseDocAnchorError, SCHEME_PREFIX},
    time::UnixSeconds,
};
use onomancy_dnssec::txt::{
    generation_key::{GenerationKey, ParseGenerationKeyError},
    record::{Classified, TxtRecord},
    serial::{Serial, SerialExhausted},
};
use onomancy_protocol::verifier::state::SKEW_MS;
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};

use crate::{
    clock, refusal, shapes,
    text::{self, Text},
};

/// The publisher's serial rule: `max(nowMs, last + 1)`, as a decimal
/// string.
///
/// `last` is the highest serial already published for this record
/// body (same `g=` and `p=`), or omitted on a first binding. `nowMs`
/// is milliseconds since the epoch — `Date.now()` — defaulting to the
/// host clock.
///
/// The `max` is load-bearing: a bare clock read ties with itself
/// across two devices (a top-serial tie derives *contested*), and a
/// clock that steps back mints a record that loses to the one it
/// supersedes. Both are silent at both ends of the wire.
///
/// # Errors
///
/// Rejects a `last` that is not a canonical decimal serial, a `nowMs`
/// that is not a non-negative integer, and a `last` of `u64::MAX`
/// (nothing follows it — refused rather than saturated or wrapped,
/// since either mints a well-formed record with a broken ordering).
#[wasm_bindgen(js_name = nextSerial)]
pub fn next_serial(last: Option<Text>, now_ms: Option<f64>) -> Result<String, JsValue> {
    let last = last
        .map(|raw| -> Result<Serial, JsValue> {
            let raw = text::read(&raw, "a serial").map_err(JsValue::from)?;

            Serial::parse(&raw).map_err(|error| JsValue::from(RecordsError::Serial(error)))
        })
        .transpose()?;

    let now_ms = match now_ms {
        Some(supplied) => milliseconds(supplied).map_err(JsValue::from)?,
        None => host_now_ms(),
    };

    Serial::next(last, now_ms)
        .map(|serial| serial.to_string())
        .map_err(|error| JsValue::from(RecordsError::Exhausted(error)))
}

/// Encode the TXT binding record a zone publishes, from the same
/// spellings `classifyRecords` reports: a canonical decimal serial, a
/// generation key in its canonical base64, and the document as an
/// `automerge:` anchor (the bare bs58check payload is also accepted).
///
/// The output and the parser are two spellings of one definition, so
/// this cannot mint a record `classifyRecords` refuses. Mint the
/// serial with `nextSerial` rather than a bare clock read, and
/// republish an *unchanged* binding under its existing serial — a
/// serial orders records, and only a changed `g=` or `p=` is a new
/// record.
///
/// # Errors
///
/// Rejects a serial that is not a canonical decimal u64, a generation
/// key that is not the canonical base64 spelling of a curve point,
/// and a document that is not a key-based Automerge URL.
#[wasm_bindgen(js_name = encodeRecord)]
pub fn encode_record(serial: &Text, generation: &Text, document: &Text) -> Result<String, JsValue> {
    let serial = text::read(serial, "a serial").map_err(JsValue::from)?;
    let serial =
        Serial::parse(&serial).map_err(|error| JsValue::from(RecordsError::Serial(error)))?;

    let generation = text::read(generation, "a generation key").map_err(JsValue::from)?;
    let generation = GenerationKey::parse(&generation)
        .map_err(|error| JsValue::from(RecordsError::Generation(error)))?;

    let document = text::read(document, "a document anchor").map_err(JsValue::from)?;
    let document = DocAnchor::parse(document.strip_prefix(SCHEME_PREFIX).unwrap_or(&document))
        .map_err(|error| JsValue::from(RecordsError::Document(error)))?;

    Ok(TxtRecord::new(serial, generation, document).to_string())
}

/// Apply the `RRset` rules to one zone's TXT strings.
///
/// Each string is classified — a strict `ONO0` parse, a future `ONO`
/// tag to skip, a non-Onomancy record to ignore, or an `ONO0` record
/// that fails its grammar — then the bindings are judged at
/// `nowSeconds` (default: the host clock):
///
/// 1. **Deferral precedes everything.** A serial more than five
///    minutes ahead of the clock (read as milliseconds) is set aside,
///    never malformed and never able to affect the others.
/// 2. **Highest serial wins.** The remaining bindings' top serial is
///    the zone's word.
/// 3. **Ties are contested, never picked.** Distinct `(document,
///    generation)` pairs at the top serial are equivocation — the zone
///    says two things at once — and are all reported, none selected.
///
/// Contest is keyed on the generation key as well as the document.
/// Two records for one document attesting different `g=` at one
/// serial disagree about which key is current, which the verifier
/// treats as a contest; a rule keyed on the document alone reads them
/// as agreeing duplicates and selects one. A zone mid-rotation can
/// therefore read *contested* here where a document-keyed rule read
/// *verified*.
///
/// This is the one-shot rule over one `RRset`. It is not the ratchet
/// (which remembers), not lineage (which reads statements), and not
/// the decisions logic. See the module docs.
///
/// # Errors
///
/// Rejects a `records` element that is not a string, and a
/// `nowSeconds` that cannot be epoch seconds.
#[wasm_bindgen(js_name = classifyRecords)]
// `Vec<Text>` rather than a slice: the owned form is what publishes
// as `string[]`, matching `Resolution.records`.
#[allow(clippy::needless_pass_by_value)]
pub fn classify_records(
    records: Vec<Text>,
    now_seconds: Option<f64>,
) -> Result<shapes::JsRecordClassification, JsValue> {
    let now = clock::resolve(now_seconds).map_err(|error| {
        refusal::error(&error.to_string(), refusal::RefusalReason::InvalidTimestamp)
    })?;

    let raw = records
        .iter()
        .map(|record| text::read(record, "a TXT record string"))
        .collect::<Result<Vec<_>, _>>()
        .map_err(JsValue::from)?;

    Ok(classification_object(&classify(
        raw.iter().map(String::as_str),
        now,
    )))
}

/// The `RRset` rules over parsed strings — the host-testable half.
pub fn classify<'a, I: IntoIterator<Item = &'a str>>(
    records: I,
    now: UnixSeconds,
) -> Classification {
    let mut tally = Classification::default();
    let mut considered: Vec<TxtRecord> = Vec::new();

    for raw in records {
        match TxtRecord::classify(raw) {
            Ok(Classified::Binding(record)) => {
                if is_deferred(&record, now) {
                    tally.deferred += 1;
                } else {
                    considered.push(*record);
                }
            }
            Ok(Classified::UnknownVersion) => tally.unknown_version += 1,
            Ok(Classified::UnknownRecord) => tally.foreign += 1,
            Err(_) => tally.malformed += 1,
        }
    }

    let Some(top) = considered.iter().map(TxtRecord::serial).max() else {
        return tally;
    };

    let mut at_top: Vec<Candidate> = considered
        .iter()
        .filter(|record| record.serial() == top)
        .map(Candidate::from)
        .collect();

    // Identical (document, generation) pairs at one serial are one
    // statement spelled twice — a DNS RRset is a set, so this needs
    // two inputs to be the same string, but the rule holds either way.
    at_top.sort();
    at_top.dedup();

    match at_top.as_slice() {
        [only] => tally.selected = Some(only.clone()),
        several => tally.contested = several.to_vec(),
        // `considered` was non-empty, so `at_top` is too.
    }

    tally
}

/// Deferral, verbatim from the verifier: a serial more than the skew
/// bound ahead of the clock, read as milliseconds.
const fn is_deferred(record: &TxtRecord, now: UnixSeconds) -> bool {
    let now_ms = now.value().saturating_mul(1000);

    record.serial().value() > now_ms.saturating_add(SKEW_MS)
}

/// One `RRset`'s dispositions and its selection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Classification {
    /// The zone's word: the unique record at the top serial, if any.
    pub selected: Option<Candidate>,
    /// Distinct claims tied at the top serial. Non-empty exactly when
    /// `selected` is `None` and at least one binding was considered.
    pub contested: Vec<Candidate>,
    /// Bindings set aside past the skew bound.
    pub deferred: usize,
    /// Records that are not `v=ONO` at all.
    pub foreign: usize,
    /// `v=ONO` records with a tag this software does not implement.
    pub unknown_version: usize,
    /// `v=ONO0` records that failed the strict grammar.
    pub malformed: usize,
}

/// A binding as the zone states it, at the top serial.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Candidate {
    /// The document, as an `automerge:` anchor.
    pub document: String,
    /// The attested generation key, canonical base64.
    pub generation: String,
    /// The serial, canonical decimal.
    pub serial: String,
}

impl From<&TxtRecord> for Candidate {
    fn from(record: &TxtRecord) -> Self {
        Self {
            document: format!("{SCHEME_PREFIX}{}", record.document()),
            generation: record.generation().to_string(),
            serial: record.serial().to_string(),
        }
    }
}

/// Publish a classification as the declared `RecordClassification`.
fn classification_object(classification: &Classification) -> shapes::JsRecordClassification {
    let object = Object::new();
    let set = |target: &Object, key: &str, value: &JsValue| {
        // Reflect::set on a fresh plain object cannot fail.
        drop(Reflect::set(target, &JsValue::from_str(key), value));
    };
    let candidate = |candidate: &Candidate| {
        let object = Object::new();
        set(&object, "document", &JsValue::from_str(&candidate.document));
        set(
            &object,
            "generation",
            &JsValue::from_str(&candidate.generation),
        );
        set(&object, "serial", &JsValue::from_str(&candidate.serial));
        JsValue::from(object)
    };
    // Counts are small integers, exact in an f64.
    #[allow(clippy::cast_precision_loss)]
    let count = |value: usize| JsValue::from_f64(value as f64);

    if let Some(selected) = &classification.selected {
        set(&object, "selected", &candidate(selected));
    }

    if !classification.contested.is_empty() {
        let contested = classification
            .contested
            .iter()
            .map(candidate)
            .collect::<Array>();
        set(&object, "contested", &contested.into());
    }

    set(&object, "deferred", &count(classification.deferred));
    set(&object, "foreign", &count(classification.foreign));
    set(
        &object,
        "unknownVersion",
        &count(classification.unknown_version),
    );
    set(&object, "malformed", &count(classification.malformed));

    JsValue::from(object).into()
}

/// Read a millisecond clock argument: a non-negative integer that
/// fits a `u64`.
fn milliseconds(value: f64) -> Result<u64, RecordsError> {
    // Exactly the f64 values that are non-negative integers below 2^64.
    #[allow(clippy::cast_precision_loss)]
    const LIMIT: f64 = u64::MAX as f64;

    if !value.is_finite() || value < 0.0 || value.fract() != 0.0 || value >= LIMIT {
        return Err(RecordsError::NotMilliseconds);
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // checked above
    Ok(value as u64)
}

/// The host clock in milliseconds.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // host clock fits
fn host_now_ms() -> u64 {
    Date::now() as u64
}

/// Why a records call refused its inputs.
#[derive(Debug, thiserror::Error)]
enum RecordsError {
    /// A serial argument is not a canonical decimal u64.
    #[error("serial: {0}")]
    Serial(onomancy_dnssec::txt::serial::ParseSerialError),

    /// `nowMs` is not a non-negative integer.
    #[error("nowMs must be a non-negative integer number of milliseconds since the epoch")]
    NotMilliseconds,

    /// No serial follows `last`.
    #[error(transparent)]
    Exhausted(#[from] SerialExhausted),

    /// A generation key argument is not the `g=` wire spelling.
    #[error("generation key: {0}")]
    Generation(ParseGenerationKeyError),

    /// A document argument is not a key-based Automerge URL.
    #[error("document: {0}")]
    Document(ParseDocAnchorError),
}

impl From<RecordsError> for JsValue {
    fn from(error: RecordsError) -> Self {
        // Developer wiring, not a finding about a name: one code, with
        // the message naming the argument.
        refusal::error(&error.to_string(), refusal::RefusalReason::InvalidArgument)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use onomancy_core::anchor::doc::DocAnchor;
    use onomancy_dnssec::txt::generation_key::GenerationKey;

    use super::*;

    const NOW_SECS: u64 = 1_787_266_968;

    fn key(seed: u8) -> VerifyingKey {
        SigningKey::from_bytes(&[seed; 32]).verifying_key()
    }

    /// A conforming record, spelled by the encoder itself.
    fn record(serial: u64, generation: u8, document: u8) -> String {
        TxtRecord::new(
            Serial::from(serial),
            GenerationKey::from(key(generation)),
            DocAnchor::from(key(document)),
        )
        .to_string()
    }

    fn classify_all(records: &[String], now: UnixSeconds) -> Classification {
        classify(records.iter().map(String::as_str), now)
    }

    fn now() -> UnixSeconds {
        UnixSeconds::from(NOW_SECS)
    }

    #[test]
    fn dispositions_are_tallied_separately() {
        let outcome = classify_all(
            &[
                String::from("v=spf1 -all"),
                String::from("v=ONO1;whatever"),
                String::from("v=ONO0;k=ed25519;n=01;g=x;p=y"),
                record(5, 1, 1),
            ],
            now(),
        );

        assert_eq!(outcome.foreign, 1);
        assert_eq!(outcome.unknown_version, 1);
        assert_eq!(outcome.malformed, 1);
        assert_eq!(outcome.deferred, 0);
        assert_eq!(outcome.selected.expect("one binding").serial, "5");
    }

    #[test]
    fn highest_serial_wins_and_lower_ones_are_inert() {
        let outcome = classify_all(&[record(5, 1, 1), record(9, 1, 2), record(7, 2, 1)], now());

        let selected = outcome.selected.expect("unique top");
        assert_eq!(selected.serial, "9");
        assert_eq!(
            selected.document,
            format!("{SCHEME_PREFIX}{}", DocAnchor::from(key(2)))
        );
        assert_eq!(selected.generation, GenerationKey::from(key(1)).to_string());
        assert!(outcome.contested.is_empty());
    }

    #[test]
    fn a_top_serial_tie_across_documents_is_contested() {
        let outcome = classify_all(&[record(9, 1, 1), record(9, 1, 2), record(3, 1, 1)], now());

        assert!(outcome.selected.is_none());
        assert_eq!(outcome.contested.len(), 2);
    }

    /// Same document, two generation keys, one serial: a disagreement
    /// about which key is current, not two spellings of one claim.
    #[test]
    fn a_top_serial_tie_across_generations_of_one_document_is_contested() {
        let outcome = classify_all(&[record(9, 1, 1), record(9, 2, 1)], now());

        assert!(outcome.selected.is_none());
        let [first, second] = outcome.contested.as_slice() else {
            panic!("two contestants, got {:?}", outcome.contested);
        };
        assert_eq!(first.document, second.document);
        assert_ne!(first.generation, second.generation);
    }

    #[test]
    fn an_identical_record_twice_is_one_claim() {
        let outcome = classify_all(&[record(9, 1, 1), record(9, 1, 1)], now());

        assert!(outcome.selected.is_some());
    }

    /// Deferral precedes selection: a far-future serial neither wins
    /// nor contests, and the next-highest record is the zone's word.
    #[test]
    fn far_future_serials_defer_before_selection() {
        let now_ms = NOW_SECS * 1000;
        let outcome = classify_all(
            &[
                record(now_ms + SKEW_MS + 1, 1, 2),
                record(now_ms + SKEW_MS, 1, 1),
            ],
            now(),
        );

        assert_eq!(outcome.deferred, 1);
        assert_eq!(
            outcome.selected.expect("the in-bound record").serial,
            (now_ms + SKEW_MS).to_string()
        );
    }

    #[test]
    fn nothing_considered_selects_nothing_and_contests_nothing() {
        let outcome = classify(["v=spf1 -all"], now());

        assert!(outcome.selected.is_none());
        assert!(outcome.contested.is_empty());
    }

    #[test]
    fn millisecond_arguments_must_be_non_negative_integers() {
        assert_eq!(milliseconds(1.0e12).ok(), Some(1_000_000_000_000));
        assert_eq!(milliseconds(0.0).ok(), Some(0));
        assert!(milliseconds(1.5).is_err());
        assert!(milliseconds(-1.0).is_err());
        assert!(milliseconds(f64::NAN).is_err());
        assert!(milliseconds(f64::INFINITY).is_err());
        assert!(milliseconds(2.0f64.powi(64)).is_err());
    }

    /// The declared shape names every key this module emits.
    #[test]
    fn the_classification_shape_is_declared() {
        for declaration in [
            "export interface RecordClassification {",
            "export interface RecordCandidate {",
            "selected?: RecordCandidate;",
            "contested?: RecordCandidate[];",
            "deferred: number;",
            "foreign: number;",
            "unknownVersion: number;",
            "malformed: number;",
        ] {
            assert!(
                shapes::TYPES.contains(declaration),
                "`{declaration}` is missing from shapes.d.ts"
            );
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    mod props {
        use super::*;

        /// The laws of the one-shot rule over arbitrary `RRset`s:
        /// order-insensitive; `selected` and `contested` exclusive;
        /// the selection, when there is one, carries the top
        /// non-deferred serial; and every contestant shares it.
        #[test]
        fn selection_laws() {
            bolero::check!()
                .with_type::<Vec<(u8, u8, u8, u64)>>()
                .for_each(|inputs| {
                    let records: Vec<String> = inputs
                        .iter()
                        .map(|&(kind, g, p, serial)| match kind % 5 {
                            0 | 1 => record(serial, g % 3, p % 3),
                            2 => String::from("v=spf1 -all"),
                            3 => String::from("v=ONO3;n=1"),
                            _ => format!("v=ONO0;k=ed25519;n={serial}"),
                        })
                        .collect();
                    let reversed: Vec<String> = records.iter().rev().cloned().collect();

                    let forward = classify_all(&records, now());
                    assert_eq!(forward, classify_all(&reversed, now()), "order-insensitive");
                    assert!(
                        forward.selected.is_none() || forward.contested.is_empty(),
                        "selected and contested are exclusive"
                    );

                    let top = inputs
                        .iter()
                        .filter(|&&(kind, _, _, serial)| {
                            kind % 5 < 2 && serial <= NOW_SECS * 1000 + SKEW_MS
                        })
                        .map(|&(_, _, _, serial)| serial)
                        .max()
                        .map(|serial| serial.to_string());

                    match (&forward.selected, forward.contested.as_slice()) {
                        (Some(selected), []) => assert_eq!(Some(&selected.serial), top.as_ref()),
                        (None, [first, rest @ ..]) => {
                            assert_eq!(Some(&first.serial), top.as_ref());
                            assert!(rest.iter().all(|c| c.serial == first.serial));
                            assert!(!rest.is_empty(), "a contest needs two");
                        }
                        (None, []) => assert!(top.is_none()),
                        (Some(_), [_, ..]) => unreachable!("exclusive, asserted above"),
                    }
                });
        }
    }
}
