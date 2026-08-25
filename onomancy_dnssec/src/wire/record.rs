//! Resource-record framing in canonical wire form.
//!
//! The layout is DNS's, not ours: RFC 1035 §3.2.1, in the RFC 4034
//! §6 canonical form (uncompressed, lowercase owner).
//!
//! RDATA is carried opaque here; typed views (DNSKEY, RRSIG, …) are
//! the next layer up. This codec frames, it never re-encodes.

use alloc::vec::Vec;

use onomancy_core::wire::{Reader, WireError};

use super::rr_type::RrType;

use super::name::{Name, ParseNameError};

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

/// The IN class code — the only class Onomancy records exist in.
pub const CLASS_IN: u16 = 1;

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
