//! Edgenames: a trust anchor plus path segments.
//!
//! The trust anchor is decided _syntactically at parse time_:
//!
//! | Spelling             | Anchor kind        | Shareable |
//! |----------------------|--------------------|-----------|
//! | `~/bob/pics`         | [`local::Local`](crate::anchor::local::Local)   | no        |
//! | `automerge:3RF…/foo` | [`doc::DocAnchor`](crate::anchor::doc::DocAnchor) | yes       |
//!
//! Other anchor kinds live with their attestation machinery (each is
//! one sigil, one grammar, one crate) and slot in as further
//! [`Anchor`](crate::anchor::Anchor) implementations.
//!
//! Each spelling family is exactly one anchor kind, and each kind is a
//! type: [`Name<A>`] is generic over its [`Anchor`](crate::anchor::Anchor), so names
//! of different anchor kinds are different types. The closed
//! "everything a user can type" form lives at the edges, with the
//! crate that sees every supported kind.
//!
//! Doc anchors are Automerge URLs: `automerge:<bs58check-doc-id>`,
//! where the document ID is an ed25519 verifying key (Keyhive root
//! doc ID). Names carry no version pins — `#` is reserved — and
//! pinning is edge data, not grammar.
//!
//! # Examples
//!
//! ```
//! use onomancy_core::{
//!     anchor::{doc::DocAnchor, local::Local},
//!     name::Name,
//! };
//!
//! let local = Name::<Local>::parse("~/bob/pics").expect("valid local name");
//! assert_eq!(local.segments().len(), 2);
//!
//! let doc = Name::<DocAnchor>::parse(
//!     "automerge:2nBeEMDjAzFa9Ev2pxwejYrgCRmSLx96SbA24uhdMMTUktJWvK/blog",
//! )
//! .expect("valid doc-anchored name");
//! assert_eq!(doc.segments().len(), 1);
//! ```

pub mod segment;

use alloc::vec::Vec;
use core::fmt;

use crate::anchor::Anchor;
use segment::{ParseSegmentError, Segment};

/// A parsed edgename of one anchor kind: the anchor plus zero or more
/// path segments.
///
/// Anchor-only names (`~`, `automerge:3RF…`) are valid
/// and resolve to the anchor's root document itself.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name<A: Anchor> {
    anchor: A,
    segments: Vec<Segment>,
}

impl<A: Anchor> Name<A> {
    /// Parse a raw string as a name of this anchor kind.
    ///
    /// # Errors
    ///
    /// Returns the kind's own error when the sigil, anchor, segments,
    /// or kind-specific suffix are malformed.
    pub fn parse(raw: &str) -> Result<Self, A::ParseError> {
        A::parse_name(raw)
    }

    /// Assemble a name from already-validated parts.
    #[must_use]
    pub const fn from_parts(anchor: A, segments: Vec<Segment>) -> Self {
        Self { anchor, segments }
    }

    /// The trust anchor decided at parse time.
    #[must_use]
    pub const fn anchor(&self) -> &A {
        &self.anchor
    }

    /// The path segments; one edge hop each during resolution.
    #[must_use]
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }
}

impl<A: Anchor> fmt::Display for Name<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.anchor.fmt_anchor(f)?;

        for segment in &self.segments {
            write!(f, "/{segment}")?;
        }

        Ok(())
    }
}

#[cfg(feature = "serde")]
impl<A: Anchor> serde::Serialize for Name<A> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[cfg(feature = "serde")]
impl<'de, A: Anchor<ParseError: fmt::Display>> serde::Deserialize<'de> for Name<A> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = <alloc::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// Split `anchor[/segments…]` at the first `/`.
#[must_use]
pub fn split_anchor(raw: &str) -> (&str, &str) {
    match raw.find('/') {
        Some(at) => raw.split_at(at),
        None => (raw, ""),
    }
}

/// Parse everything after the anchor: empty, or `/`-led segments.
///
/// # Errors
///
/// Returns [`ParseSegmentsError`] when the remainder is non-empty but
/// not `/`-led, or any segment is invalid.
pub fn parse_segments(raw: &str) -> Result<Vec<Segment>, ParseSegmentsError> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }

    let rest = raw
        .strip_prefix('/')
        .ok_or(ParseSegmentsError::ExpectedSlashAfterAnchor)?;

    rest.split('/')
        .map(|s| Segment::parse(s).map_err(ParseSegmentsError::from))
        .collect()
}

/// The path portion of a name could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseSegmentsError {
    /// Something other than `/` followed the anchor (e.g. `~bob`).
    #[error("expected `/` after the anchor")]
    ExpectedSlashAfterAnchor,

    /// A path segment was malformed.
    #[error(transparent)]
    Segment(#[from] ParseSegmentError),
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use alloc::string::ToString;

    use crate::anchor::{doc, doc::DocAnchor, local, local::Local};

    use super::*;

    /// bs58check of `SigningKey::from_bytes(&[7u8; 32]).verifying_key()`.
    const DOC: &str = "2nBeEMDjAzFa9Ev2pxwejYrgCRmSLx96SbA24uhdMMTUktJWvK";

    #[test]
    fn doc_anchor_parses_and_roundtrips() {
        let raw = alloc::format!("automerge:{DOC}/blog");
        let name = Name::<DocAnchor>::parse(&raw).expect("valid doc anchor");
        assert_eq!(name.to_string(), raw);
    }

    #[test]
    fn version_pins_are_rejected_everywhere() {
        // `#` is reserved: names carry no version pins (pinning is
        // edge data, not grammar).
        assert_eq!(
            Name::<DocAnchor>::parse(&alloc::format!("automerge:{DOC}/blog#{DOC}")),
            Err(doc::ParseDocNameError::ReservedFragment)
        );
        assert_eq!(
            Name::<DocAnchor>::parse(&alloc::format!("automerge:{DOC}#")),
            Err(doc::ParseDocNameError::ReservedFragment)
        );
        assert!(Name::<Local>::parse("~/bob#pin").is_err());
    }

    #[test]
    fn local_names_parse_and_locals_need_a_slash() {
        assert!(
            Name::<Local>::parse("~")
                .expect("bare local root")
                .segments()
                .is_empty()
        );
        assert!(Name::<Local>::parse("~/bob/pics").is_ok());
        assert_eq!(
            Name::<Local>::parse("~bob"),
            Err(local::ParseLocalNameError::Segments(
                ParseSegmentsError::ExpectedSlashAfterAnchor
            ))
        );
    }

    #[test]
    fn kinds_never_fall_back_to_one_another() {
        assert_eq!(
            Name::<Local>::parse("automerge:whatever"),
            Err(local::ParseLocalNameError::MissingSigil)
        );
        assert!(matches!(
            Name::<DocAnchor>::parse("~/bob"),
            Err(doc::ParseDocNameError::MissingScheme)
        ));
    }

    #[test]
    fn anchor_only_names_are_valid() {
        let name =
            Name::<DocAnchor>::parse(&alloc::format!("automerge:{DOC}")).expect("anchor-only");
        assert!(name.segments().is_empty());
    }

    #[test]
    fn empty_and_dot_segments_are_rejected() {
        for bad in ["//a", "/a/", "/./a", "/../a"] {
            assert!(Name::<Local>::parse(&alloc::format!("~{bad}")).is_err());
        }
    }

    mod props {
        use super::*;

        #[test]
        fn parse_never_panics_and_roundtrips() {
            bolero::check!()
                .with_type::<alloc::string::String>()
                .for_each(|raw| {
                    if let Ok(name) = Name::<Local>::parse(raw) {
                        let printed = name.to_string();
                        let reparsed = Name::<Local>::parse(&printed).expect("reparses");
                        assert_eq!(name, reparsed, "print/parse roundtrip");
                    }

                    if let Ok(name) = Name::<DocAnchor>::parse(raw) {
                        let printed = name.to_string();
                        let reparsed = Name::<DocAnchor>::parse(&printed).expect("reparses");
                        assert_eq!(name, reparsed, "print/parse roundtrip");
                        assert_eq!(printed, reparsed.to_string(), "printing is stable");
                        assert!(!raw.contains('#'), "`#` never parses");
                    }
                });
        }
    }
}
