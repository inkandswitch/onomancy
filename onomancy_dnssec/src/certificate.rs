//! The Onomancy certificate (`ONC\x00`): the signed binding of a
//! hostname to a root document.
//!
//! # Wire Format
//!
//! Fields in exactly this order, no padding. Fixed-width fields lead
//! the signed region, so a parser reads the tag and keys at constant
//! offsets without decoding a single varint:
//!
//! | #  | Field              | Type            | Width        | Notes                        | Signed |
//! |----|--------------------|-----------------|--------------|------------------------------|--------|
//! | 0  | tag                | magic bytes     | 4B           | `ONC\x00`                    | yes    |
//! | 1  | `root_doc`         | ed25519 vk      | 32B          | the document ID              | yes    |
//! | 2  | `signer`           | ed25519 vk      | 32B          |                              | yes    |
//! | 3  | `issued_at`        | bijou64         | varies       | seconds since epoch (UTC)    | yes    |
//! | 4  | `hostname_len`     | bijou64         | varies       |                              | yes    |
//! | 5  | `hostname`         | ASCII           | `hostname_len` | A-labels, lowercase        | yes    |
//! | 6  | `heads_count`      | bijou64         | varies       | 0 = live (unpinned)          | yes    |
//! | 7  | `heads`            | change hashes   | count × 32B  | sorted ascending, deduped    | yes    |
//! | 8  | `predecessor_len`  | bijou64         | varies       | 0 = none                     | yes    |
//! | 9  | `predecessor`      | `ONS\x00` unit  | len          |                              | yes    |
//! | 10 | `signature`        | ed25519         | 64B          | by `signer` over fields 0–9  | —      |
//! | 11 | `delegation_count` | bijou64         | varies       |                              | no     |
//! | 12 | `delegation_chain` | entry list      | varies       | len-prefixed Keyhive bytes   | no     |
//! | 13 | `lineage_count`    | bijou64         | varies       | 0 = never rotated            | no     |
//! | 14 | `lineage`          | entry list      | varies       | len-prefixed `ONR\x00` units | no     |
//! | 15 | `chain_count`      | bijou64         | varies       |                              | no     |
//! | 16 | `chain`            | entry list      | varies       | DNSSEC chain framing         | no     |
//!
//! The unit is [`Signed<Binding>`](onomancy_core::signed::Signed) plus the
//! attached region. Decoded units rederive their canonical bytes
//! ([`encode`](Certificate::encode)) rather than retaining them: the
//! encoding is canonical and injective, `encode(decode(b)) = b`, the
//! signature is verified against the received bytes at decode, and the
//! digest is computed then.
//!
//! # The Attached Region
//!
//! Fields after the signature are **attached evidence**: independently
//! verifiable, deliberately outside the signature because each item has
//! its own lifecycle and can be replaced by a keyless machine without
//! invalidating the certificate — a chain refresh or a
//! generation-rotation repair is [`Certificate::with_attachments`],
//! never a re-sign. Two certificates differing only in attached fields
//! are the *same certificate* ([`Certificate::same_certificate`])
//! carrying different evidence — but different store items with
//! different [digests](Certificate::digest).

pub mod binding;

use alloc::vec::Vec;
use core::hash::{Hash, Hasher};
use ed25519_dalek::{SigningKey, VerifyingKey};

use self::binding::Binding;
use crate::chain::DnssecChain;
use onomancy_core::{
    anchor::doc::{DocAnchor, Head},
    delegation_chain::DelegationChain,
    digest::{Blake3, Digest},
    signed::{Signed, payload::Malformed},
    time::UnixSeconds,
    wire::{self, OversizeUnit, Reader, WireError},
};

use crate::{
    dns_name::{CanonicalDnsNameError, DnsName},
    statement::{
        rotation::{DecodeRotationError, RotationStatement},
        successor::{DecodeSuccessorError, SuccessorStatement},
    },
};

/// A decoded, signature-checked certificate unit:
/// [`Signed<Binding>`] plus the attached region.
///
/// Attached evidence (DNSSEC chain, delegations, lineage) remains
/// independently *unverified* here: those checks belong to chain
/// validation and Keyhive verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    digest: Digest<Blake3, Certificate>,
    signed: Signed<Binding>,
    delegation_chain: DelegationChain,
    lineage: Vec<RotationStatement>,
    chain: DnssecChain,
}

impl Certificate {
    /// Strictly decode one self-contained unit, verifying its
    /// signature against the received bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeCertificateError`] on a foreign or future format
    /// tag, key bytes that are not curve points, a non-canonical
    /// hostname, unsorted or duplicated heads, a malformed nested
    /// statement, any framing violation, trailing bytes, or a
    /// signature that does not validate.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeCertificateError> {
        let mut reader = Reader::new(bytes)?;
        let signed = Signed::decode_from(bytes, &mut reader)?;

        let delegation_chain = DelegationChain::decode(&mut reader)?;
        let lineage = read_lineage(&mut reader)?;
        let chain = DnssecChain::read(&mut reader)?;

        reader.finish()?;

        Ok(Self {
            digest: Digest::hash(bytes),
            signed,
            delegation_chain,
            lineage,
            chain,
        })
    }

    /// Construct and sign a certificate.
    ///
    /// `heads` are canonicalized (sorted, deduplicated) before
    /// encoding: signers may hold them in any order, but the wire has
    /// exactly one spelling.
    ///
    /// # Errors
    ///
    /// Returns [`OversizeUnit`] when the unit would exceed the 1 MiB
    /// cap — encoders MUST NOT build units their own decoders reject.
    pub fn sign(params: CertificateParams, signer: &SigningKey) -> Result<Self, OversizeUnit> {
        let CertificateParams {
            root_doc,
            issued_at,
            hostname,
            mut heads,
            predecessor,
            delegation_chain,
            lineage,
            chain,
        } = params;

        heads.sort_unstable();
        heads.dedup();

        let signed_unit = Signed::sign(
            Binding::new(
                root_doc,
                signer.verifying_key(),
                issued_at,
                hostname,
                heads,
                predecessor,
            ),
            signer,
        );

        let mut bytes = Vec::new();
        signed_unit.encode_into(&mut bytes);
        encode_attached(&mut bytes, &delegation_chain, &lineage, &chain);
        wire::check_unit_len(bytes.len())?;

        Ok(Self {
            digest: Digest::hash(&bytes),
            signed: signed_unit,
            delegation_chain,
            lineage,
            chain,
        })
    }

    /// Rederive the canonical wire bytes: `encode(decode(b)) = b`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.signed.encode_into(&mut bytes);
        encode_attached(
            &mut bytes,
            &self.delegation_chain,
            &self.lineage,
            &self.chain,
        );

        bytes
    }

    /// Rederive the signed region (fields 0–9): the signature target.
    #[must_use]
    pub fn signed_bytes(&self) -> Vec<u8> {
        self.signed.signed_region()
    }

    /// Replace the attached region without touching the signature: the
    /// keyless refresh/repair operation.
    ///
    /// The result is the [same certificate](Self::same_certificate)
    /// carrying different evidence — and a different store item with a
    /// different [digest](Self::digest).
    ///
    /// # Errors
    ///
    /// Returns [`OversizeUnit`] when the refreshed unit would exceed
    /// the 1 MiB cap.
    pub fn with_attachments(
        &self,
        delegation_chain: DelegationChain,
        lineage: Vec<RotationStatement>,
        chain: DnssecChain,
    ) -> Result<Self, OversizeUnit> {
        let mut refreshed = Self {
            delegation_chain,
            lineage,
            chain,
            ..self.clone()
        };
        let bytes = refreshed.encode();
        wire::check_unit_len(bytes.len())?;
        refreshed.digest = Digest::hash(&bytes);

        Ok(refreshed)
    }

    /// The typed digest of the unit's canonical bytes — the store-item
    /// identity, which changes when attachments change. Computed over
    /// the received bytes at decode (or the built bytes at signing)
    /// and cached; [`erase`](Digest::erase) for the store-level form.
    #[must_use]
    pub const fn digest(&self) -> Digest<Blake3, Certificate> {
        self.digest
    }

    /// Whether `other` is the same certificate — identical signed
    /// fields and signature — regardless of attached evidence.
    #[must_use]
    pub fn same_certificate(&self, other: &Self) -> bool {
        self.signed == other.signed
    }

    /// The signing key.
    #[must_use]
    pub const fn signer(&self) -> &VerifyingKey {
        self.signed.payload().signer()
    }

    /// The bound root document.
    #[must_use]
    pub const fn root_doc(&self) -> &DocAnchor {
        self.signed.payload().root_doc()
    }

    /// Signer-claimed issuance time — the weakest comparison-ladder
    /// rung, never load-bearing.
    #[must_use]
    pub const fn issued_at(&self) -> UnixSeconds {
        self.signed.payload().issued_at()
    }

    /// The bound hostname (full DNS name from the `@` anchor).
    #[must_use]
    pub const fn hostname(&self) -> &DnsName {
        self.signed.payload().hostname()
    }

    /// Advisory heads: known-good state at issuance. MUST NOT pin
    /// resolution. Empty = live (unpinned) name.
    #[must_use]
    pub fn heads(&self) -> &[Head] {
        self.signed.payload().heads()
    }

    /// The succession proof, if any: an independently signed unit,
    /// already signature-checked by its own decode.
    #[must_use]
    pub fn predecessor(&self) -> Option<&SuccessorStatement> {
        self.signed.payload().predecessor()
    }

    /// Attached: verbatim `Signed<Delegation>` entries, doc root →
    /// signer, awaiting Keyhive verification.
    #[must_use]
    pub const fn delegation_chain(&self) -> &DelegationChain {
        &self.delegation_chain
    }

    /// Attached: generation-rotation statements, oldest first, each an
    /// independently signed unit. Empty = never rotated.
    #[must_use]
    pub fn lineage(&self) -> &[RotationStatement] {
        &self.lineage
    }

    /// Attached: the DNSSEC chain, awaiting validation against the
    /// verifier's own trust anchor.
    #[must_use]
    pub const fn dnssec_chain(&self) -> &DnssecChain {
        &self.chain
    }
}

impl Hash for Certificate {
    /// By digest, which the canonical bytes determine.
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.digest.hash(state);
    }
}

/// The signable content of a certificate: everything but the signer
/// (who is a parameter of [`Certificate::sign`]) and the wire form
/// (which encoding derives).
#[derive(Debug, Clone)]
pub struct CertificateParams {
    /// The root document being bound.
    pub root_doc: DocAnchor,
    /// Claimed issuance time, seconds since the Unix epoch.
    pub issued_at: UnixSeconds,
    /// The full DNS name being bound.
    pub hostname: DnsName,
    /// Advisory heads; canonicalized at signing.
    pub heads: Vec<Head>,
    /// Succession proof from the predecessor document, if migrating.
    pub predecessor: Option<SuccessorStatement>,
    /// Verbatim `Signed<Delegation>` chain, doc root → signer.
    pub delegation_chain: DelegationChain,
    /// Rotation statements, oldest first.
    pub lineage: Vec<RotationStatement>,
    /// The DNSSEC chain for the hostname's TXT record.
    pub chain: DnssecChain,
}

/// Encode the attached region (fields 11–16).
fn encode_attached(
    bytes: &mut Vec<u8>,
    delegation_chain: &DelegationChain,
    lineage: &[RotationStatement],
    chain: &DnssecChain,
) {
    delegation_chain.encode_into(bytes);

    wire::put_varint(bytes, lineage.len() as u64);
    for statement in lineage {
        let unit = statement.encode();
        wire::put_varint(bytes, unit.len() as u64);
        bytes.extend_from_slice(&unit);
    }

    chain.write_framed(bytes);
}

/// Read one 32-byte field as an ed25519 verifying key.
fn read_key(
    reader: &mut Reader<'_>,
    field: FieldName,
) -> Result<VerifyingKey, DecodeCertificateError> {
    let bytes: [u8; 32] = reader.take_array()?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| DecodeCertificateError::NotACurvePoint { field })
}

/// Read the heads list, enforcing sortedness and uniqueness.
fn read_heads(reader: &mut Reader<'_>) -> Result<Vec<Head>, DecodeCertificateError> {
    let count = reader.bounded_len(32)?;
    let mut heads: Vec<Head> = Vec::with_capacity(count);

    for _ in 0..count {
        let head = Head::from(reader.take_array::<32>()?);

        match heads.last() {
            Some(previous) if *previous >= head => {
                return Err(DecodeCertificateError::HeadsNotCanonical);
            }
            _ => heads.push(head),
        }
    }

    Ok(heads)
}

/// Minimum wire size of one lineage entry: a 1-byte `entry_len`
/// prefix plus the smallest `ONR\x00` unit (tag 4 + three keys 96 +
/// signature 64 + empty-carriage count 1).
const MIN_LINEAGE_ENTRY: usize = 1 + (4 + 96 + 64 + 1);

/// Read the lineage: count-prefixed, length-prefixed `ONR\x00` units.
///
/// The count is bounds-checked at the TRUE minimum entry width, and
/// entries are collected without a count-sized pre-allocation: decoded
/// statements are far larger in memory than on the wire, so a declared
/// count must never reserve memory the input cannot back.
fn read_lineage(reader: &mut Reader<'_>) -> Result<Vec<RotationStatement>, DecodeCertificateError> {
    let count = reader.bounded_len(MIN_LINEAGE_ENTRY)?;
    let mut lineage = Vec::new();

    for index in 0..count {
        let len = reader.bounded_len(1)?;
        let unit = reader.take(len)?;
        let statement = RotationStatement::decode(unit)
            .map_err(|source| DecodeCertificateError::Lineage { index, source })?;
        lineage.push(statement);
    }

    Ok(lineage)
}

/// Which fixed-width key field a decode error pinpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldName {
    /// Field 1: the bound document.
    RootDoc,
    /// Field 2: the signing key.
    Signer,
}

/// The bytes were not a canonical, validly signed `ONC\x00` unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecodeCertificateError {
    /// Heads were unsorted or duplicated: not the canonical encoding.
    #[error("heads must be sorted ascending with no duplicates")]
    HeadsNotCanonical,

    /// The hostname bytes were not the canonical spelling of a DNS
    /// name. Decoders reject rather than normalize.
    #[error("hostname: {0}")]
    Hostname(#[from] CanonicalDnsNameError),

    /// A lineage entry was not a valid rotation statement unit.
    #[error("lineage entry {index}: {source}")]
    Lineage {
        /// Zero-based entry position.
        index: usize,
        /// The nested decode failure.
        source: DecodeRotationError,
    },

    /// The signed skeleton failed: wrong tag (cross-tag confusion) or
    /// an invalid signature.
    #[error(transparent)]
    Malformed(#[from] Malformed),

    /// A key field was not a valid curve point.
    #[error("certificate field {field:?} is not an ed25519 key")]
    NotACurvePoint {
        /// The offending field.
        field: FieldName,
    },

    /// The predecessor field was not a valid successor statement unit.
    #[error("predecessor: {0}")]
    Predecessor(#[from] DecodeSuccessorError),

    /// A framing violation: truncation, length overrun, trailing
    /// bytes, size cap, or a bad varint.
    #[error(transparent)]
    Wire(#[from] WireError),
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::txt::generation_key::GenerationKey;
    use alloc::vec;
    use onomancy_core::delegation_chain::SignedDelegationBytes;

    fn doc(seed: u8) -> DocAnchor {
        DocAnchor::from(SigningKey::from_bytes(&[seed; 32]).verifying_key())
    }

    fn host() -> DnsName {
        DnsName::parse("expede.wtf").expect("valid")
    }

    fn sample_params() -> CertificateParams {
        CertificateParams {
            root_doc: doc(1),
            issued_at: UnixSeconds::from(1_755_500_000),
            hostname: host(),
            heads: vec![Head::from([9u8; 32]), Head::from([3u8; 32])],
            predecessor: Some(
                SuccessorStatement::sign(
                    &doc(4),
                    &doc(1),
                    &host(),
                    &SigningKey::from_bytes(&[5; 32]),
                    DelegationChain::from(vec![SignedDelegationBytes::from(vec![1, 2, 3])]),
                )
                .expect("under the unit cap"),
            ),
            delegation_chain: DelegationChain::from(vec![SignedDelegationBytes::from(vec![
                0xAA;
                9
            ])]),
            lineage: vec![
                RotationStatement::sign(
                    &doc(1),
                    &GenerationKey::from(SigningKey::from_bytes(&[6; 32]).verifying_key()),
                    &SigningKey::from_bytes(&[7; 32]),
                    DelegationChain::default(),
                )
                .expect("under the unit cap"),
            ],
            chain: DnssecChain::from(vec![vec![0xBB; 17].into()]),
        }
    }

    fn sample() -> Certificate {
        Certificate::sign(sample_params(), &SigningKey::from_bytes(&[2; 32]))
            .expect("under the unit cap")
    }

    #[test]
    fn sign_encode_decode_roundtrips_to_identical_bytes() {
        let cert = sample();
        let bytes = cert.encode();

        let decoded = Certificate::decode(&bytes).expect("own encoding decodes");
        assert_eq!(cert, decoded);
        assert_eq!(bytes, decoded.encode(), "encode ∘ decode = identity");
        assert_eq!(cert.digest(), decoded.digest());

        assert_eq!(decoded.root_doc(), &doc(1));
        assert_eq!(decoded.hostname(), &host());
        assert_eq!(decoded.heads().len(), 2);
        assert!(decoded.predecessor().is_some());
        assert_eq!(decoded.lineage().len(), 1);
    }

    #[test]
    fn heads_are_canonicalized_at_signing_and_enforced_at_decode() {
        let cert = sample();
        assert!(cert.heads().windows(2).all(|w| w[0] < w[1]));

        // Swapping the two heads on the wire breaks canonicality.
        let mut bytes = cert.encode();
        let heads_at = bytes
            .windows(32)
            .position(|w| w == [3u8; 32])
            .expect("first head present");
        let (a, b) = (heads_at, heads_at + 32);
        let first: [u8; 32] = bytes[a..a + 32].try_into().expect("32 bytes");
        let second: [u8; 32] = bytes[b..b + 32].try_into().expect("32 bytes");
        bytes[a..a + 32].copy_from_slice(&second);
        bytes[b..b + 32].copy_from_slice(&first);

        assert!(matches!(
            Certificate::decode(&bytes),
            Err(DecodeCertificateError::HeadsNotCanonical)
        ));
    }

    #[test]
    fn absent_predecessor_is_length_zero_not_a_flag() {
        let mut params = sample_params();
        params.predecessor = None;
        let cert = Certificate::sign(params, &SigningKey::from_bytes(&[2; 32]))
            .expect("under the unit cap");

        let decoded = Certificate::decode(&cert.encode()).expect("decodes");
        assert!(decoded.predecessor().is_none());
    }

    #[test]
    fn reattach_is_the_same_certificate_but_a_different_item() {
        let cert = sample();
        let refreshed = cert
            .with_attachments(
                DelegationChain::from(vec![SignedDelegationBytes::from(vec![0xCC; 4])]),
                vec![],
                DnssecChain::from(vec![vec![0xDD; 5].into()]),
            )
            .expect("under the unit cap");

        assert!(cert.same_certificate(&refreshed));
        assert_ne!(cert.digest(), refreshed.digest());

        // The signature survives re-attach: the unit still decodes.
        let decoded = Certificate::decode(&refreshed.encode()).expect("reattached unit decodes");
        assert_eq!(decoded.digest(), refreshed.digest());
    }

    #[test]
    fn invalid_signatures_are_undecodable() {
        // Flip one signature bit: framing is untouched, so the
        // failure is precisely the signature check.
        let cert = sample();
        let mut bytes = cert.encode();
        let signature_at = cert.signed_bytes().len();
        bytes[signature_at] ^= 0x01;

        assert!(matches!(
            Certificate::decode(&bytes),
            Err(DecodeCertificateError::Malformed(
                Malformed::InvalidSignature
            ))
        ));
    }

    #[test]
    fn cross_tag_confusion_fails_at_decode() {
        let statement_bytes = SuccessorStatement::sign(
            &doc(1),
            &doc(2),
            &host(),
            &SigningKey::from_bytes(&[3; 32]),
            DelegationChain::default(),
        )
        .expect("under the unit cap")
        .encode();

        assert!(matches!(
            Certificate::decode(&statement_bytes),
            Err(DecodeCertificateError::Malformed(Malformed::WrongTag { got, .. }))
                if got == *b"ONS\x00"
        ));
    }

    #[test]
    fn oversized_units_are_refused_at_signing() {
        // A delegation blob past the cap: the encoder must refuse to
        // build what its own decoder would reject.
        let mut params = sample_params();
        params.delegation_chain = DelegationChain::from(vec![SignedDelegationBytes::from(vec![
            0u8;
            wire::MAX_UNIT_BYTES + 1
        ])]);

        assert!(matches!(
            Certificate::sign(params, &SigningKey::from_bytes(&[2; 32])),
            Err(OversizeUnit { .. })
        ));

        // Same rule on the keyless re-attach path.
        assert!(matches!(
            sample().with_attachments(
                DelegationChain::from(vec![SignedDelegationBytes::from(vec![
                    0u8;
                    wire::MAX_UNIT_BYTES
                        + 1
                ])]),
                vec![],
                DnssecChain::default(),
            ),
            Err(OversizeUnit { .. })
        ));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut bytes = sample().encode();
        bytes.push(0);
        assert!(matches!(
            Certificate::decode(&bytes),
            Err(DecodeCertificateError::Wire(WireError::TrailingBytes {
                extra: 1
            }))
        ));
    }

    mod props {
        use super::*;

        /// The canonical-re-derivation contract: sign → encode →
        /// decode → encode yields identical bytes and identical
        /// digests, for arbitrary heads, attachments, and key seeds.
        #[test]
        fn encode_decode_byte_identity() {
            bolero::check!()
                .with_type::<(u8, u8, Vec<[u8; 32]>, Vec<Vec<u8>>, u64)>()
                .for_each(|(root, signer, raw_heads, blobs, issued)| {
                    let params = CertificateParams {
                        root_doc: doc(*root),
                        issued_at: UnixSeconds::from(*issued),
                        hostname: host(),
                        heads: raw_heads.iter().copied().map(Head::from).collect(),
                        predecessor: None,
                        delegation_chain: blobs
                            .iter()
                            .cloned()
                            .map(SignedDelegationBytes::from)
                            .collect(),
                        lineage: vec![],
                        chain: DnssecChain::default(),
                    };

                    let cert = Certificate::sign(params, &SigningKey::from_bytes(&[*signer; 32]))
                        .expect("under the unit cap");
                    let bytes = cert.encode();

                    let decoded = Certificate::decode(&bytes).expect("own encoding decodes");
                    assert_eq!(cert, decoded);
                    assert_eq!(bytes, decoded.encode(), "byte identity");
                    assert_eq!(cert.digest(), decoded.digest());
                });
        }

        /// Any bit flip inside the signed region kills the unit at
        /// decode: strictness catches it, or the signature does.
        #[test]
        fn signed_region_is_tamper_evident() {
            bolero::check!()
                .with_type::<(usize, u8)>()
                .for_each(|(at, mask)| {
                    let cert = sample();
                    let signed_len = cert.signed_bytes().len();
                    let mut bytes = cert.encode();
                    let at = at % signed_len;
                    let mask = if *mask == 0 { 1 } else { *mask };

                    bytes[at] ^= mask;

                    assert!(
                        Certificate::decode(&bytes).is_err(),
                        "tampered signed region must not decode"
                    );
                });
        }
    }
}
