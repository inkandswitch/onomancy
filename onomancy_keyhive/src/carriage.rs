//! The versioned envelope between Onomancy carriage bytes and Keyhive
//! events.
//!
//! A certificate or statement carries its authority proof as opaque
//! [`SignedDelegationBytes`] entries. This module fixes what those bytes
//! are when Keyhive is the authority: each entry is a 3-byte version
//! tag (`kh0`) followed by one bincode-encoded
//! [`StaticEvent`] — a delegation, revocation, or prekey operation.
//! Prekey events ride along because Keyhive resolves a delegation's
//! delegate against known individuals; a chain that names an unknown
//! key must introduce it.
//!
//! Strict both ways: parsing rejects unknown tags and undecodable
//! events rather than skipping them — an unreadable authority proof
//! proves nothing.

use keyhive_core::event::static_event::StaticEvent;
use onomancy_core::delegation_chain::{DelegationChain, SignedDelegationBytes};

/// The envelope version tag for Keyhive 0.5 bincode encoding.
///
/// Keyhive is pre-alpha; when its event encoding changes, this tag
/// bumps (`kh1`, …) and old entries fail loudly instead of misparsing.
/// Carriages ride the unsigned attached region, so re-encoding a
/// chain re-attaches evidence without touching any signature.
pub const ENVELOPE_TAG: [u8; 3] = *b"kh0";

/// A parsed authority carriage: Keyhive events in ingest order.
#[derive(Debug, Clone, PartialEq)]
pub struct Carriage(Vec<StaticEvent<[u8; 32]>>);

impl Carriage {
    /// Wrap events already in dependency order (prekeys before the
    /// delegations that name them, proofs before their extensions).
    #[must_use]
    pub const fn new(events: Vec<StaticEvent<[u8; 32]>>) -> Self {
        Self(events)
    }

    /// Decode every entry of an attached carriage.
    ///
    /// # Errors
    ///
    /// Returns [`ParseCarriageError`] on an unknown version tag or an
    /// undecodable event; entry order is preserved.
    pub fn parse(entries: &DelegationChain) -> Result<Self, ParseCarriageError> {
        let mut events = Vec::with_capacity(entries.len());

        for (index, entry) in entries.entries().iter().enumerate() {
            let bytes = entry.as_bytes();
            let Some(payload) = bytes.strip_prefix(&ENVELOPE_TAG[..]) else {
                return Err(ParseCarriageError::UnknownEnvelope {
                    index,
                    got: bytes.get(..3).map(<[u8]>::to_vec).unwrap_or_default(),
                });
            };

            let event = bincode::deserialize(payload)
                .map_err(|source| ParseCarriageError::UndecodableEvent { index, source })?;
            events.push(event);
        }

        Ok(Self(events))
    }

    /// Encode into attachable [`SignedDelegationBytes`] entries.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeCarriageError`] if bincode cannot serialize an
    /// event (structurally impossible for well-formed events, but
    /// bincode's API is fallible).
    pub fn to_delegation_bytes(&self) -> Result<DelegationChain, EncodeCarriageError> {
        self.0
            .iter()
            .map(|event| {
                let payload = bincode::serialize(event)?;
                let mut bytes = Vec::with_capacity(ENVELOPE_TAG.len() + payload.len());
                bytes.extend_from_slice(&ENVELOPE_TAG);
                bytes.extend_from_slice(&payload);
                Ok(SignedDelegationBytes::from(bytes))
            })
            .collect::<Result<Vec<_>, EncodeCarriageError>>()
            .map(DelegationChain::from)
    }

    /// The events, in ingest order.
    #[must_use]
    pub fn events(&self) -> &[StaticEvent<[u8; 32]>] {
        &self.0
    }
}

/// An attached carriage entry could not be read as a Keyhive event.
#[derive(Debug, thiserror::Error)]
pub enum ParseCarriageError {
    /// An entry decoded its envelope but not its event.
    #[error("carriage entry {index}: undecodable Keyhive event: {source}")]
    UndecodableEvent {
        /// Position of the entry in the carriage.
        index: usize,
        /// The bincode failure.
        source: bincode::Error,
    },

    /// An entry does not start with a known version tag.
    #[error("carriage entry {index}: unknown envelope tag {got:?} (expected {ENVELOPE_TAG:?})")]
    UnknownEnvelope {
        /// Position of the entry in the carriage.
        index: usize,
        /// The first bytes actually present.
        got: Vec<u8>,
    },
}

/// A Keyhive event refused bincode serialization.
#[derive(Debug, thiserror::Error)]
#[error("unencodable Keyhive event: {0}")]
pub struct EncodeCarriageError(#[from] bincode::Error);

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn unknown_envelope_is_rejected() {
        let entry = SignedDelegationBytes::from(b"zz9garbage".to_vec());

        assert!(matches!(
            Carriage::parse(&DelegationChain::from(vec![entry])),
            Err(ParseCarriageError::UnknownEnvelope { index: 0, .. })
        ));
    }

    /// The reported index is the ENTRY's position, not always zero:
    /// a valid first entry followed by a bad second names index 1.
    #[test]
    fn rejection_indices_name_the_offending_entry() -> testresult::TestResult {
        let minted = crate::mint::generation_carriage(
            &ed25519_dalek::SigningKey::from_bytes(&[1; 32]),
            &ed25519_dalek::SigningKey::from_bytes(&[2; 32]),
        )?;
        let mut entries = minted.entries().to_vec();
        entries.truncate(1); // one valid entry
        entries.push(SignedDelegationBytes::from(b"zz9garbage".to_vec()));

        assert!(matches!(
            Carriage::parse(&DelegationChain::from(entries)),
            Err(ParseCarriageError::UnknownEnvelope { index: 1, .. })
        ));
        Ok(())
    }

    #[test]
    fn tagged_garbage_is_rejected_not_skipped() {
        let entry = SignedDelegationBytes::from(b"kh0garbage".to_vec());

        assert!(matches!(
            Carriage::parse(&DelegationChain::from(vec![entry])),
            Err(ParseCarriageError::UndecodableEvent { index: 0, .. })
        ));
    }

    /// The envelope roundtrips through REAL events — tag prepended
    /// and stripped, bincode both ways — not just the empty vector.
    #[test]
    fn minted_carriages_roundtrip() -> testresult::TestResult {
        let minted = crate::mint::generation_carriage(
            &ed25519_dalek::SigningKey::from_bytes(&[1; 32]),
            &ed25519_dalek::SigningKey::from_bytes(&[2; 32]),
        )?;

        let parsed = Carriage::parse(&minted)?;
        assert_eq!(parsed.events().len(), 2, "introduction + delegation");
        assert_eq!(
            parsed.to_delegation_bytes()?,
            minted,
            "re-encoding reproduces the attached bytes verbatim"
        );

        // The empty carriage is the degenerate case of the same law.
        let empty = Carriage::new(Vec::new());
        assert_eq!(Carriage::parse(&empty.to_delegation_bytes()?)?, empty);
        Ok(())
    }

    mod props {
        use super::*;

        /// `parse ∘ to_delegation_bytes = id` over minted carriages
        /// for arbitrary key pairs — and byte-noise entries never
        /// panic the parser, erring with the offending index instead.
        #[test]
        fn envelope_roundtrip_and_total_parse() {
            bolero::check!()
                .with_type::<([u8; 32], [u8; 32], Vec<u8>)>()
                .for_each(|(doc_seed, generation_seed, noise)| {
                    if doc_seed == generation_seed {
                        return; // a document cannot delegate to itself
                    }

                    let minted = crate::mint::generation_carriage(
                        &ed25519_dalek::SigningKey::from_bytes(doc_seed),
                        &ed25519_dalek::SigningKey::from_bytes(generation_seed),
                    )
                    .expect("mintable");

                    let parsed = Carriage::parse(&minted).expect("own bytes parse");
                    assert_eq!(parsed.to_delegation_bytes().expect("encodable"), minted);

                    // Noise appended after valid entries: total, and
                    // the error names the noise entry's index.
                    let mut entries = minted.entries().to_vec();
                    entries.push(SignedDelegationBytes::from(noise.clone()));
                    match Carriage::parse(&DelegationChain::from(entries)) {
                        Err(
                            ParseCarriageError::UnknownEnvelope { index, .. }
                            | ParseCarriageError::UndecodableEvent { index, .. },
                        ) => assert_eq!(index, 2, "the error names the noise entry"),
                        Ok(_) => {
                            // Vanishingly unlikely (noise must spell
                            // `kh0` + a valid bincode event), but not
                            // impossible — and not a parser defect.
                        }
                    }
                });
        }
    }
}
