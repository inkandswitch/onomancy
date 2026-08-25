//! The CNAME RDATA view (RFC 1035 §3.3.1): indirection on the
//! `_onomancy` owner name.
//!
//! The one protocol-relevant CNAME: chain validation follows (bounded)
//! indirection from the `_onomancy` owner name to wherever the TXT
//! actually lives. Address records have no protocol role at all.

use onomancy_core::wire::{Reader, WireError};

use super::name::{Name, ParseNameError};

/// A parsed CNAME RDATA: the canonical target name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cname {
    target: Name,
}

impl Cname {
    /// Strictly parse one CNAME RDATA (full consumption).
    ///
    /// # Errors
    ///
    /// Returns [`ParseCnameError`] on a non-canonical target or
    /// trailing bytes.
    pub fn parse(rdata: &[u8]) -> Result<Self, ParseCnameError> {
        let mut reader = Reader::new(rdata)?;
        let target = Name::read(&mut reader)?;
        reader.finish()?;

        Ok(Self { target })
    }

    /// Where the indirection points.
    #[must_use]
    pub const fn target(&self) -> &Name {
        &self.target
    }
}

/// The bytes were not a valid CNAME RDATA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseCnameError {
    /// The target name was malformed or non-canonical.
    #[error("target: {0}")]
    Target(#[from] ParseNameError),

    /// Truncated or trailing bytes.
    #[error(transparent)]
    Wire(#[from] WireError),
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_target_and_rejects_trailing_bytes() {
        let cname = Cname::parse(b"\x03txt\x06expede\x03wtf\x00").expect("parses");
        assert_eq!(alloc::format!("{}", cname.target()), "txt.expede.wtf");

        assert!(Cname::parse(b"\x03txt\x06expede\x03wtf\x00X").is_err());
    }
}
