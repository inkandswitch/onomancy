//! The RRSIG RDATA view: the signature record.
//!
//! The layout is DNS's, not ours: RFC 4034 §3.1.
//!
//! The preamble is every RDATA field before the signature. The
//! signature is computed over `preamble ‖ canonical RRset`, so the
//! view retains the preamble **verbatim** — re-encoding it for
//! verification would reintroduce the re-encode-mismatch bug class.

use alloc::{vec, vec::Vec};
use core::cmp::Ordering;

use onomancy_core::{
    time::UnixSeconds,
    wire::{Reader, WireError},
};

use crate::freshness::{EmptyWindow, ValidityWindow};

use super::{
    algorithm::Algorithm,
    dnskey::Dnskey,
    name::{Name, ParseNameError},
    record::CLASS_IN,
    rr_type::RrType,
};
use crate::{
    crypto::{self, VerifyError},
    link::Link,
};

/// A parsed RRSIG RDATA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rrsig {
    algorithm: Algorithm,
    expiration: u32,
    inception: u32,
    key_tag: u16,
    labels: u8,
    original_ttl: u32,
    preamble: Vec<u8>,
    signature: Vec<u8>,
    signer_name: Name,
    type_covered: RrType,
}

impl Rrsig {
    /// Strictly parse one RRSIG RDATA (full consumption).
    ///
    /// # Errors
    ///
    /// Returns [`ParseRrsigError`] on truncation or a non-canonical
    /// signer name.
    pub fn parse(rdata: &[u8]) -> Result<Self, ParseRrsigError> {
        let mut reader = Reader::new(rdata)?;

        let type_covered = RrType::new(read_u16(&mut reader)?);
        let [algorithm] = reader.take_array::<1>()?;
        let [labels] = reader.take_array::<1>()?;
        let original_ttl = read_u32(&mut reader)?;
        let expiration = read_u32(&mut reader)?;
        let inception = read_u32(&mut reader)?;
        let key_tag = read_u16(&mut reader)?;
        let signer_name = Name::read(&mut reader)?;

        let preamble_len = rdata.len() - reader.remaining();
        let preamble = rdata.get(..preamble_len).unwrap_or_default().to_vec();
        let signature = reader.take(reader.remaining())?.to_vec();

        Ok(Self {
            algorithm: Algorithm::new(algorithm),
            expiration,
            inception,
            key_tag,
            labels,
            original_ttl,
            preamble,
            signature,
            signer_name,
            type_covered,
        })
    }

    /// The RR type this signature covers.
    #[must_use]
    pub const fn type_covered(&self) -> RrType {
        self.type_covered
    }

    /// The signing algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// The owner-name label count (the wildcard-synthesis detector:
    /// fewer labels than the owner name means the answer was expanded
    /// from a wildcard — D14 requires a no-closer-match proof).
    #[must_use]
    pub const fn labels(&self) -> u8 {
        self.labels
    }

    /// The original TTL, substituted for the received TTL when
    /// rebuilding the canonical `RRset`.
    #[must_use]
    pub const fn original_ttl(&self) -> u32 {
        self.original_ttl
    }

    /// The validity window, seconds since the Unix epoch.
    ///
    /// RFC 4034 times are `u32` in RFC 1982 serial arithmetic; this
    /// view reads them as plain epoch seconds, which is exact until
    /// 2106 — revisit alongside the Y2106 rollover, not before.
    ///
    /// # Errors
    ///
    /// Returns [`EmptyWindow`] when expiration precedes inception:
    /// such a signature never had joint validity (invalid ✗).
    pub fn window(&self) -> Result<ValidityWindow, EmptyWindow> {
        ValidityWindow::new(
            UnixSeconds::from(u64::from(self.inception)),
            UnixSeconds::from(u64::from(self.expiration)),
        )
    }

    /// The inception instant — the leaf-RRSIG comparator absence
    /// proofs and tenure read.
    #[must_use]
    pub fn inception(&self) -> UnixSeconds {
        UnixSeconds::from(u64::from(self.inception))
    }

    /// The key tag of the DNSKEY this signature claims (a hint, never
    /// a security check).
    #[must_use]
    pub const fn key_tag(&self) -> u16 {
        self.key_tag
    }

    /// The zone that signed.
    #[must_use]
    pub const fn signer_name(&self) -> &Name {
        &self.signer_name
    }

    /// The verbatim signed preamble (RDATA before the signature): the
    /// first half of the signature input.
    #[must_use]
    pub fn preamble(&self) -> &[u8] {
        &self.preamble
    }

    /// The signature bytes.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

/// Read one big-endian `u16`.
fn read_u16(reader: &mut Reader<'_>) -> Result<u16, WireError> {
    Ok(u16::from_be_bytes(reader.take_array::<2>()?))
}

/// Read one big-endian `u32`.
fn read_u32(reader: &mut Reader<'_>) -> Result<u32, WireError> {
    Ok(u32::from_be_bytes(reader.take_array::<4>()?))
}

/// The bytes were not a canonical RRSIG RDATA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseRrsigError {
    /// The signer name was malformed or non-canonical.
    #[error("signer name: {0}")]
    SignerName(#[from] ParseNameError),

    /// The fixed fields were truncated.
    #[error(transparent)]
    Truncated(#[from] WireError),
}

impl Rrsig {
    /// Verify one RRSIG over a link's `RRset` with one DNSKEY.
    ///
    /// Pure: bytes and parsed views in, verdict out. Key selection
    /// (matching key tags, trying rollover siblings) is the walk's job;
    /// this function answers for exactly one (signature, key) pair.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError`] when the algorithm is unsupported or
    /// mismatched, the key is not a zone key, the signed-owner
    /// reconstruction is impossible, the key bytes are malformed, or the
    /// signature simply does not verify.
    pub fn verify(&self, link: &Link, key: &Dnskey) -> Result<(), VerifyError> {
        if !key.is_zone_key() {
            // RFC 4034 §2.1.1: a cleared ZONE bit MUST NOT verify RRsets.
            return Err(VerifyError::NotAZoneKey);
        }

        if key.algorithm() != self.algorithm() {
            return Err(VerifyError::AlgorithmMismatch {
                key: key.algorithm(),
                signature: self.algorithm(),
            });
        }

        let message = signed_data(link, self)?;
        crypto::verify_signature(
            self.algorithm(),
            key.public_key(),
            &message,
            self.signature(),
        )
    }
}

/// Construct the RFC 4035 §5.3.2 signed data for one (link, RRSIG)
/// pair.
///
/// # Errors
///
/// Returns [`VerifyError::LabelCount`] when the RRSIG label count
/// exceeds the owner's (no valid reconstruction exists).
fn signed_data(link: &Link, rrsig: &Rrsig) -> Result<Vec<u8>, VerifyError> {
    let signed_owner = signed_owner(link.owner(), rrsig)?;

    let mut owner_wire = Vec::new();
    signed_owner.write(&mut owner_wire);

    // Canonical RRset order: RDATA as left-justified octet strings,
    // ascending, duplicates dropped (RFC 4034 §6.3).
    let mut rdatas: Vec<&[u8]> = link.rrset().iter().map(|r| r.rdata.as_slice()).collect();
    rdatas.sort_unstable();
    rdatas.dedup();

    let mut message = rrsig.preamble().to_vec();

    for rdata in rdatas {
        message.extend_from_slice(&owner_wire);
        message.extend_from_slice(&link.rtype().code().to_be_bytes());
        message.extend_from_slice(&CLASS_IN.to_be_bytes());
        message.extend_from_slice(&rrsig.original_ttl().to_be_bytes());
        // RDATA length fits u16: it was framed from a u16 RDLENGTH.
        message.extend_from_slice(&u16::try_from(rdata.len()).unwrap_or(u16::MAX).to_be_bytes());
        message.extend_from_slice(rdata);
    }

    Ok(message)
}

/// Reconstruct the signed owner name: the owner itself, or its
/// wildcard source when the RRSIG label count says the answer was
/// expanded (`labels < owner labels` ⇒ `*.<rightmost labels>`).
fn signed_owner(owner: &Name, rrsig: &Rrsig) -> Result<Name, VerifyError> {
    let owner_labels = owner.labels().len();
    let signed_labels = usize::from(rrsig.labels());

    match signed_labels.cmp(&owner_labels) {
        Ordering::Equal => Ok(owner.clone()),
        Ordering::Less => {
            let mut labels: Vec<Vec<u8>> = vec![b"*".to_vec()];
            labels.extend(
                owner
                    .labels()
                    .iter()
                    .skip(owner_labels - signed_labels)
                    .cloned(),
            );
            Ok(Name::from_labels(labels))
        }
        Ordering::Greater => Err(VerifyError::LabelCount {
            owner: owner_labels,
            signature: signed_labels,
        }),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use alloc::format;

    use crate::chain::ChainLink;
    use ed25519_dalek::Signer as _;

    use super::*;
    use crate::wire::record::Record;

    /// Hand-built RRSIG RDATA covering TXT, signed by `expede.wtf`.
    fn sample_rdata() -> Vec<u8> {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&RrType::TXT.code().to_be_bytes()); // covered
        rdata.push(15); // algorithm: ED25519
        rdata.push(3); // labels
        rdata.extend_from_slice(&900u32.to_be_bytes()); // original TTL
        rdata.extend_from_slice(&1_755_600_000u32.to_be_bytes()); // expiration
        rdata.extend_from_slice(&1_754_000_000u32.to_be_bytes()); // inception
        rdata.extend_from_slice(&12345u16.to_be_bytes()); // key tag
        rdata.extend_from_slice(b"\x06expede\x03wtf\x00"); // signer
        rdata.extend_from_slice(&[0xEE; 64]); // signature
        rdata
    }

    #[test]
    fn parses_and_projects_the_fields() {
        let rdata = sample_rdata();
        let rrsig = Rrsig::parse(&rdata).expect("parses");

        assert_eq!(rrsig.type_covered(), RrType::TXT);
        assert_eq!(rrsig.algorithm(), Algorithm::ED25519);
        assert_eq!(rrsig.labels(), 3);
        assert_eq!(rrsig.key_tag(), 12345);
        assert_eq!(alloc::format!("{}", rrsig.signer_name()), "expede.wtf");
        assert_eq!(rrsig.signature(), &[0xEE; 64]);

        let window = rrsig.window().expect("non-empty");
        assert_eq!(window.inception(), UnixSeconds::from(1_754_000_000));
        assert_eq!(window.expiration(), UnixSeconds::from(1_755_600_000));
    }

    #[test]
    fn preamble_is_verbatim_rdata_before_the_signature() {
        let rdata = sample_rdata();
        let rrsig = Rrsig::parse(&rdata).expect("parses");

        assert_eq!(rrsig.preamble(), &rdata[..rdata.len() - 64]);
    }

    #[test]
    fn inverted_windows_are_empty_not_stale() {
        let mut rdata = sample_rdata();
        // Swap expiration below inception.
        rdata[8..12].copy_from_slice(&1u32.to_be_bytes());

        let rrsig = Rrsig::parse(&rdata).expect("frame still parses");
        assert!(rrsig.window().is_err(), "never had joint validity");
    }

    #[test]
    fn truncation_is_rejected() {
        let rdata = sample_rdata();
        assert!(Rrsig::parse(&rdata[..10]).is_err());
    }

    mod props {
        use super::*;

        /// The preamble/signature split is exact: they partition the
        /// RDATA for every parseable input.
        #[test]
        fn preamble_and_signature_partition_the_rdata() {
            bolero::check!().with_type::<Vec<u8>>().for_each(|rdata| {
                if let Ok(rrsig) = Rrsig::parse(rdata) {
                    let mut rebuilt = rrsig.preamble().to_vec();
                    rebuilt.extend_from_slice(rrsig.signature());
                    assert_eq!(&rebuilt, rdata);
                }
            });
        }
    }

    /// Build a TXT link signed for real with a test Ed25519 zone key.
    fn signed_link(rdatas: &[&[u8]], owner: &str, labels: u8) -> (Link, Dnskey) {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);

        // DNSKEY: ZONE flag, protocol 3, ED25519.
        let mut key_rdata = Vec::new();
        key_rdata.extend_from_slice(&0x0100u16.to_be_bytes());
        key_rdata.push(3);
        key_rdata.push(Algorithm::ED25519.code());
        key_rdata.extend_from_slice(signing.verifying_key().as_bytes());
        let dnskey = Dnskey::parse(&key_rdata).expect("valid DNSKEY");

        let owner_name: Name = owner.parse().expect("parses");

        // RRSIG preamble (unsigned yet): covered/alg/labels/ttl/
        // windows/tag/signer.
        let mut preamble = Vec::new();
        preamble.extend_from_slice(&RrType::TXT.code().to_be_bytes());
        preamble.push(Algorithm::ED25519.code());
        preamble.push(labels);
        preamble.extend_from_slice(&900u32.to_be_bytes());
        preamble.extend_from_slice(&1_755_600_000u32.to_be_bytes());
        preamble.extend_from_slice(&1_754_000_000u32.to_be_bytes());
        preamble.extend_from_slice(&dnskey.key_tag().to_be_bytes());
        preamble.extend_from_slice(b"\x06expede\x03wtf\x00");

        // Construct the signed data by the same rules and sign it.
        let mut sorted: Vec<&[u8]> = rdatas.to_vec();
        sorted.sort_unstable();
        sorted.dedup();

        let mut message = preamble.clone();
        let signed_name: Name = if usize::from(labels) < owner_name.labels().len() {
            format!(
                "*.{}",
                owner
                    .split('.')
                    .skip(owner_name.labels().len() - usize::from(labels))
                    .collect::<Vec<_>>()
                    .join(".")
            )
            .parse()
            .expect("wildcard form parses")
        } else {
            owner_name.clone()
        };
        let mut owner_wire = Vec::new();
        signed_name.write(&mut owner_wire);

        for rdata in &sorted {
            message.extend_from_slice(&owner_wire);
            message.extend_from_slice(&RrType::TXT.code().to_be_bytes());
            message.extend_from_slice(&CLASS_IN.to_be_bytes());
            message.extend_from_slice(&900u32.to_be_bytes());
            message.extend_from_slice(&u16::try_from(rdata.len()).expect("small").to_be_bytes());
            message.extend_from_slice(rdata);
        }

        let signature = signing.sign(&message);

        let mut rrsig_rdata = preamble;
        rrsig_rdata.extend_from_slice(&signature.to_bytes());

        // Frame the link: data records (received TTL differs from the
        // original on purpose) + the RRSIG.
        let mut bytes = Vec::new();
        for rdata in rdatas {
            Record {
                owner: owner_name.clone(),
                rtype: RrType::TXT,
                class: CLASS_IN,
                ttl: 42, // received TTL ≠ original: must not matter
                rdata: rdata.to_vec(),
            }
            .write(&mut bytes);
        }
        Record {
            owner: owner_name,
            rtype: RrType::RRSIG,
            class: CLASS_IN,
            ttl: 42,
            rdata: rrsig_rdata,
        }
        .write(&mut bytes);

        let link = Link::parse(&ChainLink::from(bytes)).expect("link parses");
        (link, dnskey)
    }

    #[test]
    fn ed25519_rrsig_verifies_end_to_end() {
        let (link, key) = signed_link(&[b"\x04test"], "_onomancy.expede.wtf", 3);
        let rrsig = &link.signatures()[0];

        rrsig
            .verify(&link, &key)
            .expect("genuine signature verifies");
    }

    #[test]
    fn rrset_order_does_not_matter_but_content_does() {
        // Two records, framed in the order NOT matching canonical
        // RDATA order: canonical sorting must fix it.
        let (link, key) = signed_link(&[b"\x02zz", b"\x02aa"], "_onomancy.expede.wtf", 3);
        link.signatures()[0]
            .verify(&link, &key)
            .expect("order-insensitive");

        // A different RRset under the same signature must fail.
        let (tampered, _) = signed_link(&[b"\x02zz", b"\x02ab"], "_onomancy.expede.wtf", 3);
        assert_eq!(
            link.signatures()[0].verify(&tampered, &key),
            Err(VerifyError::BadSignature)
        );
    }

    #[test]
    fn wildcard_expansion_reconstructs_the_signed_owner() {
        // Signed as *.expede.wtf (labels=2), answered at the full
        // owner name.
        let (link, key) = signed_link(&[b"\x04test"], "_onomancy.expede.wtf", 2);
        link.signatures()[0]
            .verify(&link, &key)
            .expect("wildcard reconstruction");
    }

    #[test]
    fn excess_label_counts_are_rejected() {
        let (link, key) = signed_link(&[b"\x04test"], "_onomancy.expede.wtf", 3);
        let mut preamble = link.signatures()[0].preamble().to_vec();
        preamble[3] = 9; // labels byte
        preamble.extend_from_slice(link.signatures()[0].signature());
        let forged = Rrsig::parse(&preamble).expect("frame parses");

        assert!(matches!(
            forged.verify(&link, &key),
            Err(VerifyError::LabelCount { .. })
        ));
    }

    #[test]
    fn non_zone_keys_never_verify() {
        let (link, key) = signed_link(&[b"\x04test"], "_onomancy.expede.wtf", 3);
        let mut rdata = key.rdata().to_vec();
        rdata[0] = 0;
        rdata[1] = 0; // clear ZONE
        let revoked = Dnskey::parse(&rdata).expect("parses");

        assert_eq!(
            link.signatures()[0].verify(&link, &revoked),
            Err(VerifyError::NotAZoneKey)
        );
    }
}
