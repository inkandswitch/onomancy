//! Shared wire-codec machinery: strict cursors, canonical integers,
//! and the unit size cap.
//!
//! Every Onomancy proof artifact — certificate, rotation statement,
//! successor statement — is one self-contained byte unit whose decoding
//! is deterministic and strict: one byte string has at most one
//! reading, decoders never normalize, and every declared length is
//! validated against the remaining input *before* any allocation.
//!
//! Variable integers are [bijou64] (the [`bijoux`] crate): canonical by
//! construction, so there are no overlong forms to reject.
//!
//! [bijou64]: https://github.com/inkandswitch/bijou/blob/main/bijou64/SPEC.md

use alloc::vec::Vec;

/// Maximum size of one certificate or statement unit: 1 MiB.
///
/// Honest units run 10–100 KB (dominated by the DNSSEC chain); the cap
/// bounds adversarial memory, not honest growth, and is part of the
/// format contract.
pub const MAX_UNIT_BYTES: usize = 1 << 20;

/// A strict decoding cursor over one wire unit.
///
/// All reads are bounds-checked against the remaining input; a declared
/// length that overruns the unit is a decode failure, never an
/// allocation.
#[derive(Debug, Clone, Copy)]
pub struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Begin reading a unit, enforcing [`MAX_UNIT_BYTES`].
    ///
    /// # Errors
    ///
    /// Returns [`WireError::OversizeUnit`] when the unit exceeds the
    /// cap.
    pub const fn new(bytes: &'a [u8]) -> Result<Self, WireError> {
        if bytes.len() > MAX_UNIT_BYTES {
            return Err(WireError::OversizeUnit { len: bytes.len() });
        }

        Ok(Self { bytes, pos: 0 })
    }

    /// Bytes not yet consumed.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    /// Take exactly `need` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::Truncated`] when fewer than `need` bytes
    /// remain.
    pub fn take(&mut self, need: usize) -> Result<&'a [u8], WireError> {
        let have = self.remaining();

        if need > have {
            return Err(WireError::Truncated { need, have });
        }

        let end = self.pos + need;
        let taken = self.bytes.get(self.pos..end).ok_or(WireError::Truncated {
            need,
            have, // unreachable given the check above; stated for totality
        })?;
        self.pos = end;

        Ok(taken)
    }

    /// Take a fixed-width field.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::Truncated`] when fewer than `N` bytes
    /// remain.
    pub fn take_array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let bytes = self.take(N)?;
        bytes
            .try_into()
            .map_err(|_| WireError::Truncated { need: N, have: 0 })
    }

    /// Decode one bijou64 varint.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::Varint`] on a truncated or overflowing
    /// encoding.
    pub fn varint(&mut self) -> Result<u64, WireError> {
        let (value, consumed) =
            bijoux::u64::decode(self.bytes.get(self.pos..).unwrap_or_default())?;
        self.pos += consumed;

        Ok(value)
    }

    /// Decode a bijou64 length or count and validate it against the
    /// remaining input before it is ever used to allocate.
    ///
    /// `unit_width` is the minimum bytes each counted element occupies
    /// (1 for byte lengths).
    ///
    /// # Errors
    ///
    /// Returns [`WireError::LengthOverrun`] when the declared length,
    /// at `unit_width` bytes per element, exceeds the remaining input
    /// — before any allocation happens.
    pub fn bounded_len(&mut self, unit_width: usize) -> Result<usize, WireError> {
        let declared = self.varint()?;
        let have = self.remaining();

        let fits: Option<usize> = usize::try_from(declared)
            .ok()
            .and_then(|n| n.checked_mul(unit_width))
            .filter(|total| *total <= have);

        match fits {
            Some(_) => {
                // Cast is proven in-range by the filter above.
                #[allow(clippy::cast_possible_truncation)]
                Ok(declared as usize)
            }
            None => Err(WireError::LengthOverrun { declared, have }),
        }
    }

    /// Require that the whole unit was consumed.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::TrailingBytes`] when unconsumed bytes
    /// remain: not the canonical encoding of anything.
    pub const fn finish(self) -> Result<(), WireError> {
        let extra = self.remaining();

        if extra == 0 {
            Ok(())
        } else {
            Err(WireError::TrailingBytes { extra })
        }
    }
}

/// Append one bijou64 varint to a unit under construction.
pub(crate) fn put_varint(buf: &mut Vec<u8>, value: u64) {
    bijoux::u64::encode(value, buf);
}

/// A wire-level decode failure, independent of which unit or field it
/// occurred in. Unit codecs wrap this with field context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// A declared length or count implies bytes beyond the end of the
    /// unit. Rejected before allocation.
    #[error("declared length {declared} overruns the {have} remaining bytes")]
    LengthOverrun {
        /// The declared length or count.
        declared: u64,
        /// Bytes actually remaining in the unit.
        have: usize,
    },

    /// The unit exceeds [`MAX_UNIT_BYTES`].
    #[error("unit of {len} bytes exceeds the 1 MiB cap")]
    OversizeUnit {
        /// The oversize unit's length.
        len: usize,
    },

    /// The unit decoded fully but bytes remain: not the canonical
    /// encoding of anything.
    #[error("{extra} trailing bytes after a complete unit")]
    TrailingBytes {
        /// Number of unconsumed bytes.
        extra: usize,
    },

    /// The input ended inside a field.
    #[error("needed {need} bytes, had {have}")]
    Truncated {
        /// Bytes the field required.
        need: usize,
        /// Bytes that were available.
        have: usize,
    },

    /// A bijou64 varint failed to decode.
    #[error(transparent)]
    Varint(#[from] bijoux::u64::DecodeError),
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn length_overrun_is_rejected_before_allocation() {
        // Declares u64::MAX bytes follow; only 2 do.
        let mut unit = Vec::new();
        put_varint(&mut unit, u64::MAX);
        unit.extend_from_slice(&[1, 2]);

        let mut reader = Reader::new(&unit).expect("under cap");
        assert!(matches!(
            reader.bounded_len(1),
            Err(WireError::LengthOverrun { .. })
        ));
    }

    #[test]
    fn trailing_bytes_are_not_canonical() {
        let unit = vec![0u8; 3];
        let mut reader = Reader::new(&unit).expect("under cap");
        let _ = reader.take(2).expect("in bounds");
        assert_eq!(reader.finish(), Err(WireError::TrailingBytes { extra: 1 }));
    }

    #[test]
    fn oversize_units_never_get_a_reader() {
        let unit = vec![0u8; MAX_UNIT_BYTES + 1];
        assert!(matches!(
            Reader::new(&unit),
            Err(WireError::OversizeUnit { .. })
        ));
    }

    mod props {
        use super::*;

        /// Varint write → read roundtrips and consumes exactly its
        /// encoding.
        #[test]
        fn varint_roundtrip() {
            bolero::check!().with_type::<u64>().for_each(|value| {
                let mut buf = Vec::new();
                put_varint(&mut buf, *value);

                let mut reader = Reader::new(&buf).expect("under cap");
                assert_eq!(reader.varint(), Ok(*value));
                assert_eq!(reader.finish(), Ok(()));
            });
        }
    }
}
