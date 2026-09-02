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
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

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
        // Routed through the same builder as `signable_bytes`, so the
        // two signing paths cannot disagree about what gets signed.
        let binding = Self::binding(&params, signer.verifying_key());

        let CertificateParams {
            delegation_chain,
            lineage,
            chain,
            ..
        } = params;

        let signed_unit = Signed::sign(binding, signer)
            .unwrap_or_else(|_| unreachable!("the binding names this signer's verifying key"));

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

    /// The bytes a signature must cover, for a certificate not yet
    /// signed.
    ///
    /// The counterpart to [`Self::from_parts`], and the pair exists so
    /// a signer that is not this process can mint a certificate: the
    /// Keyhive document root key is destroyed at creation, so the only
    /// admin key able to sign lives wherever that document's runtime
    /// keeps it. Handing that key to a serializer to avoid a two-step
    /// API would trade the property worth having for a convenience.
    ///
    /// `signer` is supplied rather than derived because there is no
    /// signing key here to derive it from — that is the point.
    ///
    /// Guaranteed equal to the signed region of the certificate that
    /// [`Self::sign`] would have produced from the same parameters:
    /// both route through [`Signed::signable_region`].
    #[must_use]
    pub fn signable_bytes(params: &CertificateParams, signer: VerifyingKey) -> Vec<u8> {
        Signed::<Binding>::signable_region(&Self::binding(params, signer))
    }

    /// Assemble from parameters and a signature produced elsewhere.
    ///
    /// The attached region — carriage, lineage, DNSSEC chain — is
    /// **not** validated here. Attachments are unsigned evidence and
    /// the verifier judges them; a second judge at assembly time could
    /// only disagree with the first, and a certificate refused at
    /// birth for a reason the verifier would have accepted is worse
    /// than one that fails loudly where the judging happens.
    ///
    /// # Errors
    ///
    /// Returns [`AssembleError::InvalidSignature`] when the signature
    /// does not cover [`Self::signable_bytes`] under `signer`, and
    /// [`AssembleError::Oversize`] when the assembled unit exceeds the
    /// cap.
    pub fn from_parts(
        params: CertificateParams,
        signer: VerifyingKey,
        signature: Signature,
    ) -> Result<Self, AssembleError> {
        let binding = Self::binding(&params, signer);

        let CertificateParams {
            delegation_chain,
            lineage,
            chain,
            ..
        } = params;

        let signed_unit = Signed::try_from_parts(binding, signature)
            .map_err(|_| AssembleError::InvalidSignature)?;

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

    /// The signed payload, built identically for both signing routes.
    fn binding(params: &CertificateParams, signer: VerifyingKey) -> Binding {
        let mut heads = params.heads.clone();
        heads.sort_unstable();
        heads.dedup();

        Binding::new(
            params.root_doc,
            signer,
            params.issued_at,
            params.hostname.clone(),
            heads,
            params.predecessor.clone(),
        )
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

/// Assembling a certificate from an externally-produced signature
/// failed.
#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum AssembleError {
    /// The signature does not cover
    /// [`Certificate::signable_bytes`] under the supplied signer.
    ///
    /// The likely causes are signing the wrong bytes, or a signer that
    /// is not the one named in the parameters — the two are worth
    /// distinguishing in a caller's own diagnostics, because the first
    /// is a wiring bug and the second is an authority one.
    #[error("signature does not cover the certificate's signed region under the given signer")]
    InvalidSignature,

    /// The assembled unit would exceed the cap.
    #[error(transparent)]
    Oversize(#[from] OversizeUnit),
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::txt::generation_key::GenerationKey;
    use alloc::vec;
    use ed25519_dalek::Signer as _;
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

    /// The pin an external signer depends on: what `signable_bytes`
    /// hands out must be exactly what `sign` actually signed.
    ///
    /// Checked through the **signature**, not by comparing two byte
    /// strings: both byte strings route through
    /// `Signed::signable_region`, so comparing them is `f(x) == f(x)`
    /// and never reaches `sign`. Verifying the real signature over
    /// the offered bytes is the only form that does.
    #[test]
    fn signable_bytes_are_what_sign_signs() {
        let key = SigningKey::from_bytes(&[2; 32]);
        let signed = sample();
        let offered = Certificate::signable_bytes(&sample_params(), key.verifying_key());

        assert!(
            key.verifying_key()
                .verify_strict(&offered, signed.signed.signature())
                .is_ok(),
            "a signature made by `sign` must verify over what `signable_bytes` offers"
        );
    }

    /// A certificate assembled from an outside signature is
    /// byte-identical to one signed in process.
    #[test]
    fn external_signing_reaches_the_same_certificate() {
        let key = SigningKey::from_bytes(&[2; 32]);
        let signature = key.sign(&Certificate::signable_bytes(
            &sample_params(),
            key.verifying_key(),
        ));

        let assembled = Certificate::from_parts(sample_params(), key.verifying_key(), signature)
            .expect("a valid signature assembles");

        assert_eq!(assembled.encode(), sample().encode());
    }

    /// And the invariant holds: a `Signed` never carries a signature
    /// that does not verify, whoever produced it.
    #[test]
    fn a_wrong_signature_is_refused_at_assembly() {
        let key = SigningKey::from_bytes(&[2; 32]);
        let wrong = SigningKey::from_bytes(&[8; 32]).sign(&Certificate::signable_bytes(
            &sample_params(),
            key.verifying_key(),
        ));

        assert!(matches!(
            Certificate::from_parts(sample_params(), key.verifying_key(), wrong),
            Err(AssembleError::InvalidSignature)
        ));
    }

    /// The same invariant on the in-process route: `Signed::sign`
    /// with a key that is not the payload's named signer is refused,
    /// in release builds too — no constructor may ship a `Signed`
    /// that no decoder would accept.
    #[test]
    fn signing_with_a_key_the_payload_does_not_name_is_refused() {
        let named = SigningKey::from_bytes(&[2; 32]);
        let other = SigningKey::from_bytes(&[8; 32]);
        let binding = Certificate::decode(&sample().encode())
            .expect("own encoding decodes")
            .signed
            .payload()
            .clone();

        assert_eq!(binding.signer(), &named.verifying_key(), "fixture sanity");
        assert!(
            matches!(
                onomancy_core::signed::Signed::sign(binding, &other),
                Err(onomancy_core::signed::payload::Malformed::InvalidSignature)
            ),
            "a payload must be signed by the key it names as its signer — \
             refused as the documented `InvalidSignature`, not some other shape"
        );
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

    /// The lineage count is bounds-checked at the TRUE minimum entry
    /// width (166 bytes), not at one byte: a declared count the input
    /// cannot back at that width dies as `LengthOverrun` BEFORE any
    /// entry decode runs. A weakened `MIN_LINEAGE_ENTRY` (say 1)
    /// would wander into entry parsing and fail differently.
    #[test]
    fn lineage_counts_are_bounded_at_the_true_entry_width() {
        let mut params = sample_params();
        params.lineage = vec![];
        params.chain = DnssecChain::default();
        params.delegation_chain = DelegationChain::default();
        let mut bytes = Certificate::sign(params, &SigningKey::from_bytes(&[2; 32]))
            .expect("under the unit cap")
            .encode();

        // The attached region of this certificate is three zero
        // varints: delegation count, lineage count, chain count.
        let mut zero = Vec::new();
        wire::put_varint(&mut zero, 0);
        assert_eq!(
            bytes[bytes.len() - 3 * zero.len()..],
            [zero.clone(), zero.clone(), zero.clone()].concat(),
            "fixture sanity: empty attached region"
        );

        // Declare 2 lineage entries backed by 200 junk bytes: enough
        // for 2 one-byte entries, nowhere near 2 × 166.
        bytes.truncate(bytes.len() - 2 * zero.len());
        wire::put_varint(&mut bytes, 2);
        bytes.extend_from_slice(&[0u8; 200]);

        assert!(matches!(
            Certificate::decode(&bytes),
            Err(DecodeCertificateError::Wire(WireError::LengthOverrun {
                declared: 2,
                have: 200
            }))
        ));
    }

    /// A non-point in the root-doc field is named as such — and the
    /// grammar check fires before the signature check.
    #[test]
    fn non_curve_points_name_their_field() {
        let non_point: [u8; 32] = (0u8..=255)
            .map(|b| [b; 32])
            .find(|bytes| VerifyingKey::from_bytes(bytes).is_err())
            .expect("some constant fill fails decompression");

        for (position, field) in [(0, FieldName::RootDoc), (1, FieldName::Signer)] {
            let mut bytes = sample().encode();
            let at = 4 + position * 32;
            bytes[at..at + 32].copy_from_slice(&non_point);

            assert!(
                matches!(
                    Certificate::decode(&bytes),
                    Err(DecodeCertificateError::NotACurvePoint { field: got }) if got == field
                ),
                "field {field:?}"
            );
        }
    }

    /// A corrupt lineage entry surfaces with its zero-based index.
    #[test]
    fn corrupt_lineage_entries_carry_their_index() {
        let cert = sample();
        let mut bytes = cert.encode();

        // The one lineage entry is an embedded ONR unit in the
        // attached region; break its tag.
        let onr_at = bytes
            .windows(4)
            .rposition(|w| w == b"ONR\x00")
            .expect("lineage unit present");
        bytes[onr_at..onr_at + 4].copy_from_slice(b"JUNK");

        assert!(matches!(
            Certificate::decode(&bytes),
            Err(DecodeCertificateError::Lineage { index: 0, .. })
        ));
    }

    /// Equal adjacent heads are as non-canonical as unsorted ones —
    /// the `>=` in `read_heads`, both halves.
    #[test]
    fn duplicate_heads_are_not_canonical() {
        let cert = sample();
        let mut bytes = cert.encode();

        // Overwrite the second head with the first: equal adjacent.
        let heads_at = bytes
            .windows(32)
            .position(|w| w == [3u8; 32])
            .expect("first head present");
        let first: [u8; 32] = bytes[heads_at..heads_at + 32].try_into().expect("32 bytes");
        bytes[heads_at + 32..heads_at + 64].copy_from_slice(&first);

        assert!(matches!(
            Certificate::decode(&bytes),
            Err(DecodeCertificateError::HeadsNotCanonical)
        ));
    }

    /// A non-canonical hostname on the wire is the certificate's own
    /// `Hostname` error, before the signature check.
    #[test]
    fn non_canonical_hostnames_are_rejected_not_normalized() {
        let mut bytes = sample().encode();

        // The hostname appears twice (the embedded predecessor
        // statement carries its own copy, later in the wire); the
        // certificate's field 5 is the FIRST occurrence.
        let needle = b"expede.wtf";
        let at = bytes
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("hostname present");
        bytes[at] = b'E';

        assert!(matches!(
            Certificate::decode(&bytes),
            Err(DecodeCertificateError::Hostname(
                CanonicalDnsNameError::NotCanonical
            ))
        ));
    }

    /// A corrupt embedded predecessor unit is the certificate's own
    /// `Predecessor` error, carrying the nested failure.
    #[test]
    fn corrupt_predecessors_surface_as_their_own_error() {
        let mut bytes = sample().encode();

        let ons_at = bytes
            .windows(4)
            .position(|w| w == b"ONS\x00")
            .expect("predecessor unit present");
        bytes[ons_at..ons_at + 4].copy_from_slice(b"JUNK");

        assert!(matches!(
            Certificate::decode(&bytes),
            Err(DecodeCertificateError::Predecessor(_))
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

        /// The attached region's counterpart: a flip after the
        /// signature either breaks framing (an error) or yields the
        /// SAME certificate as a DIFFERENT store item — never a
        /// different certificate.
        #[test]
        fn attached_region_tampering_never_changes_the_certificate() {
            bolero::check!()
                .with_type::<(usize, u8)>()
                .for_each(|(at, mask)| {
                    let cert = sample();
                    let mut bytes = cert.encode();
                    let attached_start = cert.signed_bytes().len() + 64;
                    let attached_len = bytes.len() - attached_start;
                    let at = attached_start + (at % attached_len);
                    let mask = if *mask == 0 { 1 } else { *mask };

                    bytes[at] ^= mask;

                    if let Ok(reread) = Certificate::decode(&bytes) {
                        assert!(
                            cert.same_certificate(&reread),
                            "attached flips never alter the signed unit"
                        );
                        assert_ne!(cert.digest(), reread.digest(), "but the item changed");
                    }
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
