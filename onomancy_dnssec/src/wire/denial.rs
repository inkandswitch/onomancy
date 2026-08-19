//! NSEC/NSEC3 RDATA views: authenticated denial of existence.
//!
//! Denial records prove what a zone does NOT contain — Onomancy needs
//! them to distinguish "no binding record" from a stripped-record
//! downgrade, and (D14) to prove no closer match exists when an answer
//! was wildcard-synthesized.
//!
//! ```text
//! NSEC:   next domain name (canonical) ‖ type bitmap
//! NSEC3:  hash alg u8 ‖ flags u8 ‖ iterations u16BE ‖
//!         salt len u8 ‖ salt ‖ hash len u8 ‖ next hashed ‖ bitmap
//! ```

use alloc::vec::Vec;

use onomancy_core::wire::{Reader, WireError};

use super::{
    name::{Name, ParseNameError},
    record::RrType,
};

/// An RFC 4034 §4.1.2 type bitmap: which RR types exist at a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeBitmap {
    /// (window, bitmap) blocks, ascending windows enforced at parse.
    blocks: Vec<(u8, Vec<u8>)>,
}

impl TypeBitmap {
    /// Read the remainder of an RDATA as a type bitmap.
    ///
    /// # Errors
    ///
    /// Returns [`ParseDenialError`] on truncation, an out-of-range
    /// block length (1–32), or non-ascending windows (the canonical
    /// form has exactly one spelling).
    pub fn read(reader: &mut Reader<'_>) -> Result<Self, ParseDenialError> {
        let mut blocks: Vec<(u8, Vec<u8>)> = Vec::new();

        while reader.remaining() > 0 {
            let [window] = reader.take_array::<1>()?;
            let [len] = reader.take_array::<1>()?;

            if len == 0 || len > 32 {
                return Err(ParseDenialError::BitmapBlockLength { len });
            }
            if let Some((previous, _)) = blocks.last()
                && *previous >= window
            {
                return Err(ParseDenialError::BitmapWindowOrder);
            }

            blocks.push((window, reader.take(usize::from(len))?.to_vec()));
        }

        Ok(Self { blocks })
    }

    /// Whether the bitmap asserts `rtype` exists at the name.
    #[must_use]
    pub fn contains(&self, rtype: RrType) -> bool {
        let [window, low] = rtype.0.to_be_bytes();
        let byte_index = usize::from(low / 8);
        let bit = 0x80u8 >> (low % 8);

        self.blocks
            .iter()
            .find(|(w, _)| *w == window)
            .and_then(|(_, bitmap)| bitmap.get(byte_index))
            .is_some_and(|byte| byte & bit != 0)
    }
}

/// A parsed NSEC RDATA: the next owner name in canonical zone order,
/// plus the types present at THIS name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nsec {
    next: Name,
    types: TypeBitmap,
}

impl Nsec {
    /// Strictly parse one NSEC RDATA (full consumption).
    ///
    /// # Errors
    ///
    /// Returns [`ParseDenialError`] on a non-canonical next name or a
    /// malformed bitmap.
    pub fn parse(rdata: &[u8]) -> Result<Self, ParseDenialError> {
        let mut reader = Reader::new(rdata)?;
        let next = Name::read(&mut reader)?;
        let types = TypeBitmap::read(&mut reader)?;

        Ok(Self { next, types })
    }

    /// The next owner name in the zone's canonical order — with the
    /// owner name, the range this record denies.
    #[must_use]
    pub const fn next(&self) -> &Name {
        &self.next
    }

    /// The types that DO exist at the owner name.
    #[must_use]
    pub const fn types(&self) -> &TypeBitmap {
        &self.types
    }
}

/// A parsed NSEC3 RDATA: hashed denial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nsec3 {
    flags: u8,
    hash_algorithm: u8,
    iterations: u16,
    next_hashed: Vec<u8>,
    salt: Vec<u8>,
    types: TypeBitmap,
}

impl Nsec3 {
    /// Strictly parse one NSEC3 RDATA (full consumption).
    ///
    /// # Errors
    ///
    /// Returns [`ParseDenialError`] on truncation or a malformed
    /// bitmap.
    pub fn parse(rdata: &[u8]) -> Result<Self, ParseDenialError> {
        let mut reader = Reader::new(rdata)?;

        let [hash_algorithm] = reader.take_array::<1>()?;
        let [flags] = reader.take_array::<1>()?;
        let iterations = u16::from_be_bytes(reader.take_array::<2>()?);

        let [salt_len] = reader.take_array::<1>()?;
        let salt = reader.take(usize::from(salt_len))?.to_vec();

        let [hash_len] = reader.take_array::<1>()?;
        let next_hashed = reader.take(usize::from(hash_len))?.to_vec();

        let types = TypeBitmap::read(&mut reader)?;

        Ok(Self {
            flags,
            hash_algorithm,
            iterations,
            next_hashed,
            salt,
            types,
        })
    }

    /// The hash algorithm (1 = SHA-1, the only defined value).
    #[must_use]
    pub const fn hash_algorithm(&self) -> u8 {
        self.hash_algorithm
    }

    /// The opt-out flag and reserved bits, verbatim.
    #[must_use]
    pub const fn flags(&self) -> u8 {
        self.flags
    }

    /// Additional hash iterations.
    #[must_use]
    pub const fn iterations(&self) -> u16 {
        self.iterations
    }

    /// The salt, verbatim.
    #[must_use]
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// The next hashed owner name in hash order.
    #[must_use]
    pub fn next_hashed(&self) -> &[u8] {
        &self.next_hashed
    }

    /// The types that DO exist at the matching name.
    #[must_use]
    pub const fn types(&self) -> &TypeBitmap {
        &self.types
    }
}

/// The bytes were not a valid denial RDATA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseDenialError {
    /// A bitmap block length outside 1–32.
    #[error("type-bitmap block of {len} bytes; blocks are 1-32")]
    BitmapBlockLength {
        /// The declared length.
        len: u8,
    },

    /// Bitmap windows out of ascending order: not canonical.
    #[error("type-bitmap windows must ascend")]
    BitmapWindowOrder,

    /// The NSEC next name was malformed or non-canonical.
    #[error("next name: {0}")]
    NextName(#[from] ParseNameError),

    /// The fields were truncated.
    #[error(transparent)]
    Truncated(#[from] WireError),
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use alloc::vec;

    /// A bitmap block asserting TXT (16) and RRSIG (46) exist.
    fn window_zero_block() -> Vec<u8> {
        // TXT = bit 16 → byte 2, bit 0x80; RRSIG = 46 → byte 5, 0x02.
        let mut block = vec![0u8; 6];
        block[2] = 0x80;
        block[5] = 0x02;

        let mut bytes = vec![0u8, 6];
        bytes.extend_from_slice(&block);
        bytes
    }

    #[test]
    fn nsec_parses_and_the_bitmap_answers() {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(b"\x05after\x06expede\x03wtf\x00");
        rdata.extend_from_slice(&window_zero_block());

        let nsec = Nsec::parse(&rdata).expect("parses");
        assert_eq!(alloc::format!("{}", nsec.next()), "after.expede.wtf");
        assert!(nsec.types().contains(RrType::TXT));
        assert!(nsec.types().contains(RrType::RRSIG));
        assert!(!nsec.types().contains(RrType::DNSKEY));
    }

    #[test]
    fn nsec3_parses_the_parameter_block() {
        let mut rdata = Vec::new();
        rdata.push(1); // SHA-1
        rdata.push(0); // flags
        rdata.extend_from_slice(&10u16.to_be_bytes());
        rdata.push(4);
        rdata.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // salt
        rdata.push(20);
        rdata.extend_from_slice(&[0x11; 20]); // next hashed
        rdata.extend_from_slice(&window_zero_block());

        let nsec3 = Nsec3::parse(&rdata).expect("parses");
        assert_eq!(nsec3.hash_algorithm(), 1);
        assert_eq!(nsec3.iterations(), 10);
        assert_eq!(nsec3.salt(), &[0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(nsec3.next_hashed().len(), 20);
        assert!(nsec3.types().contains(RrType::TXT));
    }

    #[test]
    fn out_of_order_windows_are_rejected() {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(b"\x01a\x00");
        rdata.extend_from_slice(&[1, 1, 0x80]); // window 1
        rdata.extend_from_slice(&[0, 1, 0x80]); // window 0: descends

        assert!(matches!(
            Nsec::parse(&rdata),
            Err(ParseDenialError::BitmapWindowOrder)
        ));
    }

    #[test]
    fn oversized_bitmap_blocks_are_rejected() {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(b"\x01a\x00");
        rdata.extend_from_slice(&[0, 33]);
        rdata.extend_from_slice(&[0u8; 33]);

        assert!(matches!(
            Nsec::parse(&rdata),
            Err(ParseDenialError::BitmapBlockLength { len: 33 })
        ));
    }
}
