//! The RRSIG RDATA view: the signature record.
//!
//! The layout is DNS's, not ours: RFC 4034 §3.1.
//!
//! The preamble is every RDATA field before the signature. The
//! signature is computed over `preamble ‖ canonical RRset`, so the
//! view retains the preamble **verbatim** — re-encoding it for
//! verification would reintroduce the re-encode-mismatch bug class.

use alloc::vec::Vec;

use onomancy_core::{
    freshness::{ChainWindow, EmptyWindow},
    time::UnixSeconds,
    wire::{Reader, WireError},
};

use super::{
    algorithm::Algorithm,
    name::{Name, ParseNameError},
    rr_type::RrType,
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

        let type_covered = RrType(read_u16(&mut reader)?);
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
            algorithm: Algorithm(algorithm),
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
    pub fn window(&self) -> Result<ChainWindow, EmptyWindow> {
        ChainWindow::new(
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Hand-built RRSIG RDATA covering TXT, signed by `expede.wtf`.
    fn sample_rdata() -> Vec<u8> {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&RrType::TXT.0.to_be_bytes()); // covered
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
}
