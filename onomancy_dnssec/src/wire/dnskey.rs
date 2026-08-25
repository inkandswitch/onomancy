//! The DNSKEY RDATA view: zone keys.
//!
//! The layout is DNS's, not ours: RFC 4034 §2.1.
//!
//! The verbatim RDATA is retained: both the key tag (RFC 4034
//! Appendix B) and the DS digest (`owner ‖ RDATA`) are computed over
//! these exact bytes.

use alloc::vec::Vec;

use onomancy_core::wire::{Reader, WireError};

use super::algorithm::Algorithm;

/// The ZONE flag bit: set on keys that sign zone data.
const FLAG_ZONE: u16 = 0x0100;

/// The SEP flag bit: secure entry point (KSK convention; a hint,
/// never a security boundary).
const FLAG_SEP: u16 = 0x0001;

/// The only defined protocol value (RFC 4034 §2.1.2).
const PROTOCOL_DNSSEC: u8 = 3;

/// A parsed DNSKEY RDATA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dnskey {
    algorithm: Algorithm,
    flags: u16,
    public_key: Vec<u8>,
    rdata: Vec<u8>,
}

impl Dnskey {
    /// Strictly parse one DNSKEY RDATA (full consumption).
    ///
    /// # Errors
    ///
    /// Returns [`ParseDnskeyError`] on truncation or a protocol value
    /// other than 3 (RFC 4034: MUST be treated as invalid).
    pub fn parse(rdata: &[u8]) -> Result<Self, ParseDnskeyError> {
        let mut reader = Reader::new(rdata)?;

        let flags = u16::from_be_bytes(reader.take_array::<2>()?);
        let [protocol] = reader.take_array::<1>()?;
        let [algorithm] = reader.take_array::<1>()?;
        let public_key = reader.take(reader.remaining())?.to_vec();

        if protocol != PROTOCOL_DNSSEC {
            return Err(ParseDnskeyError::WrongProtocol { got: protocol });
        }

        Ok(Self {
            algorithm: Algorithm(algorithm),
            flags,
            public_key,
            rdata: rdata.to_vec(),
        })
    }

    /// The signing algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Whether the ZONE flag is set: only zone keys sign `RRsets`
    /// (RFC 4034 §2.1.1 — a cleared bit means the key MUST NOT verify
    /// zone data).
    #[must_use]
    pub const fn is_zone_key(&self) -> bool {
        self.flags & FLAG_ZONE != 0
    }

    /// Whether the SEP (key-signing-key) convention bit is set.
    #[must_use]
    pub const fn is_sep(&self) -> bool {
        self.flags & FLAG_SEP != 0
    }

    /// The public key bytes, algorithm-specific.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// The verbatim RDATA: the DS-digest and key-tag input.
    #[must_use]
    pub fn rdata(&self) -> &[u8] {
        &self.rdata
    }

    /// The RFC 4034 Appendix B key tag: a ones-complement-ish
    /// checksum over the verbatim RDATA. A selector hint, never a
    /// security check.
    #[must_use]
    pub fn key_tag(&self) -> u16 {
        let mut accumulator: u32 = 0;

        for (index, byte) in self.rdata.iter().enumerate() {
            accumulator += if index & 1 == 0 {
                u32::from(*byte) << 8
            } else {
                u32::from(*byte)
            };
        }
        accumulator += (accumulator >> 16) & 0xFFFF;

        // Truncation is the algorithm.
        #[allow(clippy::cast_possible_truncation)]
        {
            (accumulator & 0xFFFF) as u16
        }
    }
}

/// The bytes were not a valid DNSKEY RDATA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseDnskeyError {
    /// The fixed fields were truncated.
    #[error(transparent)]
    Truncated(#[from] WireError),

    /// The protocol octet was not 3.
    #[error("DNSKEY protocol {got}; RFC 4034 requires 3")]
    WrongProtocol {
        /// The octet found.
        got: u8,
    },
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn sample_rdata() -> Vec<u8> {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&0x0101u16.to_be_bytes()); // ZONE | SEP
        rdata.push(3); // protocol
        rdata.push(15); // ED25519
        rdata.extend_from_slice(&[0xAB; 32]);
        rdata
    }

    #[test]
    fn parses_flags_and_key() {
        let key = Dnskey::parse(&sample_rdata()).expect("parses");
        assert!(key.is_zone_key());
        assert!(key.is_sep());
        assert_eq!(key.algorithm(), Algorithm::ED25519);
        assert_eq!(key.public_key(), &[0xAB; 32]);
    }

    #[test]
    fn wrong_protocol_is_rejected() {
        let mut rdata = sample_rdata();
        rdata[2] = 2;
        assert!(matches!(
            Dnskey::parse(&rdata),
            Err(ParseDnskeyError::WrongProtocol { got: 2 })
        ));
    }

    #[test]
    fn key_tag_matches_the_rfc_reference_algorithm() {
        // Independent reimplementation of Appendix B as the oracle.
        let key = Dnskey::parse(&sample_rdata()).expect("parses");
        let rdata = key.rdata();

        let mut oracle: u32 = 0;
        for pair in rdata.chunks(2) {
            oracle += u32::from(pair[0]) << 8;
            if let Some(low) = pair.get(1) {
                oracle += u32::from(*low);
            }
        }
        oracle += (oracle >> 16) & 0xFFFF;

        assert_eq!(u32::from(key.key_tag()), oracle & 0xFFFF);
    }
}
