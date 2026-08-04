//! Path segments: one edge hop each during resolution.

use alloc::string::String;
use core::fmt;

/// A single path segment: non-empty, no `/` or `#`, not `.` or `..`,
/// and no control characters.
///
/// Segments name edges in a document; each hop lands in another document
/// and consumes exactly one segment, so resolution terminates in
/// `len(segments)` steps.
///
/// Unicode is permitted (petnames are for humans); NFC normalization and
/// confusable handling are display-layer policies, not parse rules.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Segment(String);

impl Segment {
    /// Parse a single path segment.
    ///
    /// # Errors
    ///
    /// Returns [`ParseSegmentError`] for empty segments, `.` or `..`,
    /// embedded `/` or `#`, or control characters.
    pub fn parse(raw: &str) -> Result<Self, ParseSegmentError> {
        if raw.is_empty() {
            return Err(ParseSegmentError::Empty);
        }

        if raw == "." || raw == ".." {
            return Err(ParseSegmentError::DotSegment);
        }

        if raw.contains('/') {
            return Err(ParseSegmentError::EmbeddedSlash);
        }

        if raw.contains('#') {
            return Err(ParseSegmentError::ReservedHash);
        }

        if raw.chars().any(char::is_control) {
            return Err(ParseSegmentError::ControlCharacter);
        }

        Ok(Self(String::from(raw)))
    }

    /// View the segment as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The input was not a valid path segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseSegmentError {
    /// Control characters have no business in names.
    #[error("segments must not contain control characters")]
    ControlCharacter,

    /// `.` and `..` are rejected: no traversal semantics to exploit.
    #[error("`.` and `..` are not valid segments")]
    DotSegment,

    /// Segments are `/`-separated and cannot contain one.
    #[error("segments must not contain `/`")]
    EmbeddedSlash,

    /// Empty segments (doubled or trailing slashes) are rejected.
    #[error("segments must be non-empty")]
    Empty,

    /// `#` introduces pinned heads and cannot appear in a
    /// segment, in any anchor family.
    #[error("`#` is reserved for heads")]
    ReservedHash,
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn rejects_traversal_and_empties() {
        assert_eq!(Segment::parse(""), Err(ParseSegmentError::Empty));
        assert_eq!(Segment::parse("."), Err(ParseSegmentError::DotSegment));
        assert_eq!(Segment::parse(".."), Err(ParseSegmentError::DotSegment));
        assert_eq!(Segment::parse("a/b"), Err(ParseSegmentError::EmbeddedSlash));
        assert_eq!(Segment::parse("a#b"), Err(ParseSegmentError::ReservedHash));
        assert_eq!(
            Segment::parse("a\nb"),
            Err(ParseSegmentError::ControlCharacter)
        );
    }

    #[test]
    fn allows_human_friendly_unicode() {
        assert!(Segment::parse("bob-at-dweb-camp").is_ok());
        assert!(Segment::parse("日記").is_ok());
        assert!(
            Segment::parse("...").is_ok(),
            "only exact . and .. are special"
        );
    }

    #[test]
    fn allows_dotted_labels() {
        // Anchor discrimination is by sigil/scheme, so dots carry no
        // grammatical meaning: `~/bmann.ca` is the natural default
        // label after meeting `@bmann.ca`.
        assert!(Segment::parse("bmann.ca").is_ok());
        assert!(Segment::parse("blog.old").is_ok());
    }
}
