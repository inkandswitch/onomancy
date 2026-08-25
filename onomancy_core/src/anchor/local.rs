//! The local anchor: `~`, your own root document.

use core::fmt;

use crate::{
    anchor::Anchor,
    name::{Name, ParseSegmentsError, parse_segments},
};

/// `~` — the petname root: your own signed root document, resolved
/// from context rather than carried in the name. Not shareable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Local;

impl Anchor for Local {
    type ParseError = ParseLocalNameError;

    fn parse_name(raw: &str) -> Result<Name<Self>, ParseLocalNameError> {
        let rest = raw
            .strip_prefix('~')
            .ok_or(ParseLocalNameError::MissingSigil)?;

        Ok(Name::from_parts(Self, parse_segments(rest)?))
    }

    fn fmt_anchor(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("~")
    }
}

/// The input could not be parsed as a local (`~`) name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseLocalNameError {
    /// Local names start with `~`.
    #[error("local names start with `~`")]
    MissingSigil,

    /// The path after the anchor was malformed.
    #[error(transparent)]
    Segments(#[from] ParseSegmentsError),
}
