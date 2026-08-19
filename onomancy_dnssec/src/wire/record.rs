//! Resource-record framing in canonical wire form.
//!
//! ```text
//! ┌────────────┬───────┬───────┬───────┬──────────┬─────────┐
//! │ owner name │ type  │ class │ TTL   │ RDLENGTH │ RDATA   │
//! │ (variable) │ u16BE │ u16BE │ u32BE │  u16BE   │ (bytes) │
//! └────────────┴───────┴───────┴───────┴──────────┴─────────┘
//! ```
//!
//! RDATA is carried opaque here; typed views (DNSKEY, RRSIG, …) are
//! the next layer up. This codec frames, it never re-encodes.

use alloc::vec::Vec;
use core::fmt;

use onomancy_core::wire::{Reader, WireError};

use super::name::{Name, ParseNameError};

/// A resource-record type code.
///
/// Only the types validation touches get names; everything else stays
/// a number (and, per the strictness doctrine, gets rejected where the
/// walk requires a specific type — never silently repurposed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RrType(pub u16);

impl RrType {
    /// CNAME (5): indirection on the `_onomancy` owner name.
    pub const CNAME: Self = Self(5);
    /// DNSKEY (48): zone keys.
    pub const DNSKEY: Self = Self(48);
    /// DS (43): delegation signer digests at zone cuts.
    pub const DS: Self = Self(43);
    /// NSEC (47): authenticated denial of existence.
    pub const NSEC: Self = Self(47);
    /// NSEC3 (50): hashed authenticated denial.
    pub const NSEC3: Self = Self(50);
    /// RRSIG (46): the signatures themselves.
    pub const RRSIG: Self = Self(46);
    /// TXT (16): the binding record.
    pub const TXT: Self = Self(16);
}

impl fmt::Display for RrType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::CNAME => f.write_str("CNAME"),
            Self::DNSKEY => f.write_str("DNSKEY"),
            Self::DS => f.write_str("DS"),
            Self::NSEC => f.write_str("NSEC"),
            Self::NSEC3 => f.write_str("NSEC3"),
            Self::RRSIG => f.write_str("RRSIG"),
            Self::TXT => f.write_str("TXT"),
            Self(code) => write!(f, "TYPE{code}"),
        }
    }
}

/// The IN class code — the only class Onomancy records exist in.
pub const CLASS_IN: u16 = 1;

/// One resource record, RDATA opaque.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The canonical owner name.
    pub owner: Name,
    /// The record type.
    pub rtype: RrType,
    /// The class (validation requires IN; enforced by the walk, kept
    /// verbatim by the frame).
    pub class: u16,
    /// The TTL as carried (RFC 4034 canonical form uses the original
    /// TTL from the covering RRSIG; that substitution is the walk's
    /// job, not the parser's).
    pub ttl: u32,
    /// The record data, verbatim.
    pub rdata: Vec<u8>,
}

impl Record {
    /// Read one record.
    ///
    /// # Errors
    ///
    /// Returns [`ParseRecordError`] on a non-canonical owner name, a
    /// truncated fixed header, or an `RDLENGTH` that overruns the
    /// input.
    pub fn read(reader: &mut Reader<'_>) -> Result<Self, ParseRecordError> {
        let owner = Name::read(reader)?;
        let rtype = RrType(read_u16(reader)?);
        let class = read_u16(reader)?;
        let ttl = read_u32(reader)?;

        let rdlength = usize::from(read_u16(reader)?);
        let rdata = reader.take(rdlength)?.to_vec();

        Ok(Self {
            owner,
            rtype,
            class,
            ttl,
            rdata,
        })
    }

    /// Append the canonical wire form.
    pub fn write(&self, buf: &mut Vec<u8>) {
        self.owner.write(buf);
        buf.extend_from_slice(&self.rtype.0.to_be_bytes());
        buf.extend_from_slice(&self.class.to_be_bytes());
        buf.extend_from_slice(&self.ttl.to_be_bytes());
        // RDATA length fits u16 by construction on read; writes of
        // oversized RDATA are a caller bug surfaced by truncation.
        buf.extend_from_slice(
            &u16::try_from(self.rdata.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        buf.extend_from_slice(&self.rdata);
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

/// The bytes were not a canonically framed resource record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseRecordError {
    /// The owner name was malformed or non-canonical.
    #[error("owner name: {0}")]
    Name(#[from] ParseNameError),

    /// The fixed header or RDATA was truncated.
    #[error(transparent)]
    Truncated(#[from] WireError),
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use alloc::vec;

    fn sample() -> Record {
        Record {
            owner: "_onomancy.expede.wtf".parse().expect("parses"),
            rtype: RrType::TXT,
            class: CLASS_IN,
            ttl: 900,
            rdata: vec![0xAB; 17],
        }
    }

    #[test]
    fn write_read_roundtrip() {
        let record = sample();
        let mut buf = Vec::new();
        record.write(&mut buf);

        let mut reader = Reader::new(&buf).expect("under cap");
        let decoded = Record::read(&mut reader).expect("own encoding decodes");
        reader.finish().expect("fully consumed");
        assert_eq!(record, decoded);
    }

    #[test]
    fn rdlength_overrun_is_rejected_before_allocation() {
        let mut buf = Vec::new();
        sample().owner.write(&mut buf);
        buf.extend_from_slice(&RrType::TXT.0.to_be_bytes());
        buf.extend_from_slice(&CLASS_IN.to_be_bytes());
        buf.extend_from_slice(&900u32.to_be_bytes());
        buf.extend_from_slice(&u16::MAX.to_be_bytes()); // declares 65535
        buf.push(0xAB); // provides 1

        let mut reader = Reader::new(&buf).expect("under cap");
        assert!(matches!(
            Record::read(&mut reader),
            Err(ParseRecordError::Truncated(WireError::Truncated { .. }))
        ));
    }

    #[test]
    fn type_display_names_the_seven() {
        assert_eq!(alloc::format!("{}", RrType::DNSKEY), "DNSKEY");
        assert_eq!(alloc::format!("{}", RrType(65280)), "TYPE65280");
    }

    mod props {
        use super::*;

        /// Frame roundtrip: any record that reads re-writes to the
        /// exact consumed bytes.
        #[test]
        fn read_write_byte_identity() {
            bolero::check!().with_type::<Vec<u8>>().for_each(|bytes| {
                let Ok(mut reader) = Reader::new(bytes) else {
                    return;
                };

                if let Ok(record) = Record::read(&mut reader) {
                    let consumed = bytes.len() - reader.remaining();
                    let mut rewritten = Vec::new();
                    record.write(&mut rewritten);
                    assert_eq!(rewritten, bytes[..consumed], "one spelling per record");
                }
            });
        }
    }
}
