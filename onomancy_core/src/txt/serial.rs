//! The anti-replay serial (`n=`).

use core::fmt;

/// Maximum decimal digits in a serial (`u64::MAX` has 20).
pub const MAX_SERIAL_DIGITS: usize = 20;

/// The anti-replay serial: an opaque `u64` to verifiers, RECOMMENDED to
/// be `max(now_ms, last + 1)` for publishers.
///
/// The wire spelling is canonical decimal — no leading zeros, at most
/// [`MAX_SERIAL_DIGITS`] digits — so each serial has exactly one
/// spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Serial(u64);

impl Serial {
    /// Parse the canonical decimal spelling.
    ///
    /// # Errors
    ///
    /// Returns [`ParseSerialError`] pinpointing the first violation:
    /// empty, a non-digit byte (with its offset), a leading zero, too
    /// many digits, or `u64` overflow.
    pub fn parse(digits: &str) -> Result<Self, ParseSerialError> {
        if digits.is_empty() {
            return Err(ParseSerialError::Empty);
        }

        if let Some(at) = digits.bytes().position(|b| !b.is_ascii_digit()) {
            return Err(ParseSerialError::NotADigit { at });
        }

        if digits.len() > 1 && digits.starts_with('0') {
            return Err(ParseSerialError::LeadingZero);
        }

        if digits.len() > MAX_SERIAL_DIGITS {
            return Err(ParseSerialError::TooManyDigits { got: digits.len() });
        }

        // All digits, ≤ 20 of them: the only failure left is magnitude.
        digits
            .parse::<u64>()
            .map(Self)
            .map_err(|_| ParseSerialError::Overflow)
    }

    /// The numeric value.
    #[must_use]
    pub const fn value(&self) -> u64 {
        self.0
    }
}

impl From<u64> for Serial {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Serial> for u64 {
    fn from(serial: Serial) -> Self {
        serial.0
    }
}

impl fmt::Display for Serial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The serial violated its canonical-decimal grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseSerialError {
    /// `n=` with nothing after it.
    #[error("empty serial")]
    Empty,

    /// Canonical decimals of more than one digit never start with `0`.
    #[error("leading zero (canonical decimal has exactly one spelling)")]
    LeadingZero,

    /// A byte other than an ASCII digit, at the given offset.
    #[error("non-digit byte at offset {at}")]
    NotADigit {
        /// Byte offset of the first non-digit.
        at: usize,
    },

    /// The digits parse but exceed `u64::MAX`.
    #[error("serial exceeds u64::MAX")]
    Overflow,

    /// More digits than any `u64` value has.
    #[error("{got} digits; u64 serials have at most 20")]
    TooManyDigits {
        /// Digit count found.
        got: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_grammar_is_pinpointed() {
        assert_eq!(Serial::parse(""), Err(ParseSerialError::Empty));
        assert_eq!(Serial::parse("007"), Err(ParseSerialError::LeadingZero));
        assert_eq!(
            Serial::parse("1_0"),
            Err(ParseSerialError::NotADigit { at: 1 })
        );
        assert_eq!(
            Serial::parse("18446744073709551616"), // u64::MAX + 1: 20 digits
            Err(ParseSerialError::Overflow)
        );
        assert_eq!(
            Serial::parse("111111111111111111111"),
            Err(ParseSerialError::TooManyDigits { got: 21 })
        );
        assert_eq!(Serial::parse("0"), Ok(Serial::from(0)));
        assert_eq!(
            Serial::parse("18446744073709551615"),
            Ok(Serial::from(u64::MAX))
        );
    }

    mod props {
        use super::*;

        /// Every `u64` renders to a spelling that reparses to itself.
        #[test]
        fn canonical_decimal_roundtrip() {
            bolero::check!().with_type::<u64>().for_each(|value| {
                let serial = Serial::from(*value);
                let rendered = alloc::string::ToString::to_string(&serial);
                assert_eq!(Serial::parse(&rendered), Ok(serial));
            });
        }
    }
}
