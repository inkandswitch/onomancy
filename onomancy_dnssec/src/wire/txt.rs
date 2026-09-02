//! The TXT RDATA view: character strings.
//!
//! The layout is DNS's, not ours: RFC 1035 §3.3.14.
//!
//! Multiple strings within one TXT RDATA MUST be concatenated before
//! parsing the Onomancy grammar — the multi-string form exists only
//! for tolerance of splitting tooling, and
//! [`concatenated`](Txt::concatenated) is that rule.

use alloc::vec::Vec;

use onomancy_core::wire::{Reader, WireError};

/// A parsed TXT RDATA: one or more character strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Txt {
    strings: Vec<Vec<u8>>,
}

impl Txt {
    /// Strictly parse one TXT RDATA (full consumption). At least one
    /// character string is required (RFC 1035 §3.3.14).
    ///
    /// # Errors
    ///
    /// Returns [`ParseTxtError`] on truncation or an empty RDATA.
    pub fn parse(rdata: &[u8]) -> Result<Self, ParseTxtError> {
        let mut reader = Reader::new(rdata)?;
        let mut strings: Vec<Vec<u8>> = Vec::new();

        while reader.remaining() > 0 {
            let [len] = reader.take_array::<1>()?;
            strings.push(reader.take(usize::from(len))?.to_vec());
        }

        if strings.is_empty() {
            return Err(ParseTxtError::Empty);
        }

        Ok(Self { strings })
    }

    /// The character strings as carried.
    #[must_use]
    pub fn strings(&self) -> &[Vec<u8>] {
        &self.strings
    }

    /// The concatenation — the byte string the Onomancy TXT grammar
    /// parses (via `TxtRecord::classify`, after a UTF-8 check that
    /// non-text records fail into the unknown-record disposition).
    #[must_use]
    pub fn concatenated(&self) -> Vec<u8> {
        let mut joined = Vec::new();
        for string in &self.strings {
            joined.extend_from_slice(string);
        }
        joined
    }
}

/// The bytes were not a valid TXT RDATA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseTxtError {
    /// TXT RDATA carries at least one character string.
    #[error("empty TXT RDATA")]
    Empty,

    /// A declared string length overran the RDATA.
    #[error(transparent)]
    Truncated(#[from] WireError),
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn split_strings_concatenate() {
        let mut rdata = Vec::new();
        rdata.push(7);
        rdata.extend_from_slice(b"v=ONO0;");
        rdata.push(9);
        rdata.extend_from_slice(b"k=ed25519");

        let txt = Txt::parse(&rdata).expect("parses");
        assert_eq!(txt.strings().len(), 2);
        assert_eq!(txt.concatenated(), b"v=ONO0;k=ed25519");
    }

    #[test]
    fn truncated_strings_are_rejected() {
        let rdata = vec![5, b'a', b'b'];
        assert!(matches!(
            Txt::parse(&rdata),
            Err(ParseTxtError::Truncated(_))
        ));
    }

    #[test]
    fn empty_rdata_is_rejected() {
        assert!(matches!(Txt::parse(&[]), Err(ParseTxtError::Empty)));
    }

    /// A single zero-length character string is a valid, empty TXT —
    /// distinct from empty RDATA.
    #[test]
    fn a_zero_length_string_is_valid_and_empty() {
        let txt = Txt::parse(&[0]).expect("parses");
        assert_eq!(txt.strings(), &[Vec::new()]);
        assert!(txt.concatenated().is_empty());
    }

    mod props {
        use super::*;

        /// Concatenation length equals the sum of string lengths, and
        /// parseable RDATA is fully accounted for (strings + length
        /// prefixes = RDATA).
        #[test]
        fn strings_partition_the_rdata() {
            bolero::check!().with_type::<Vec<u8>>().for_each(|rdata| {
                if let Ok(txt) = Txt::parse(rdata) {
                    let content: usize = txt.strings().iter().map(Vec::len).sum();
                    assert_eq!(content + txt.strings().len(), rdata.len());
                    assert_eq!(txt.concatenated().len(), content);
                }
            });
        }
    }
}
