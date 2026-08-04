//! Edgenames: a trust anchor plus path segments.
//!
//! The trust anchor is decided _syntactically at parse time_:
//!
//! | Spelling             | Anchor            | Shareable |
//! |----------------------|-------------------|-----------|
//! | `~/bob/pics`         | [`Anchor::Local`] | no        |
//! | `@expede.wtf/foo`    | [`Anchor::Dns`]   | yes       |
//! | `automerge:3RF…/foo` | [`Anchor::Doc`]   | yes       |
//!
//! Each spelling family is exactly one anchor kind. `@` means DNS and
//! nothing else — dotless `@` names are flat parse errors, which deletes
//! the `@bob` vs `@bob.co` near-miss phishing class outright. Doc anchors
//! are Automerge URLs: `automerge:<bs58check-doc-id>[/segments][#head|head]`,
//! where the document ID is an ed25519 verifying key (Keyhive root doc
//! ID) and optional heads pin the anchor document to a point in time.
//!
//! # Examples
//!
//! ```
//! use onomancy_core::name::{Name, anchor::Anchor};
//!
//! let name = Name::parse("@EXPEDE.WTF./foo/bar").expect("valid DNS-anchored name");
//! assert!(matches!(name.anchor(), Anchor::Dns(d) if d.as_str() == "expede.wtf"));
//! assert_eq!(name.to_string(), "@expede.wtf/foo/bar");
//!
//! let local = Name::parse("~/bob/pics").expect("valid local name");
//! assert!(matches!(local.anchor(), Anchor::Local));
//!
//! let doc = Name::parse("automerge:2nBeEMDjAzFa9Ev2pxwejYrgCRmSLx96SbA24uhdMMTUktJWvK/blog")
//!     .expect("valid doc-anchored name");
//! assert!(matches!(doc.anchor(), Anchor::Doc(_)));
//! ```

pub mod anchor;
pub mod dns;
pub mod doc;
pub mod segment;

use alloc::vec::Vec;
use anchor::Anchor;
use core::fmt;
use dns::{DnsName, ParseDnsNameError};
use doc::{DocAnchor, Head, ParseDocAnchorError, ParseHeadError, SCHEME_PREFIX};
use segment::{ParseSegmentError, Segment};

/// A parsed edgename: a trust anchor, zero or more path segments, and —
/// for doc anchors only — zero or more pinned heads.
///
/// Anchor-only names (`@expede.wtf`, `~`, `automerge:3RF…`) are valid and
/// resolve to the anchor's root document itself.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name {
    anchor: Anchor,
    segments: Vec<Segment>,
    heads: Vec<Head>,
}

impl Name {
    /// Parse a raw string into a [`Name`].
    ///
    /// # Errors
    ///
    /// Returns [`ParseNameError`] when the sigil/scheme is missing, the
    /// anchor is malformed, any segment is invalid (per
    /// [`segment::Segment::parse`]), or heads are present but malformed.
    pub fn parse(raw: &str) -> Result<Self, ParseNameError> {
        if let Some(rest) = raw.strip_prefix('~') {
            return Ok(Self {
                anchor: Anchor::Local,
                segments: parse_segments(rest)?,
                heads: Vec::new(),
            });
        }

        if let Some(rest) = raw.strip_prefix(SCHEME_PREFIX) {
            let (main, heads) = match rest.split_once('#') {
                Some((main, heads_raw)) => (main, parse_heads(heads_raw)?),
                None => (rest, Vec::new()),
            };

            let (anchor_raw, segments_raw) = split_anchor(main);

            return Ok(Self {
                anchor: Anchor::Doc(DocAnchor::parse(anchor_raw)?),
                segments: parse_segments(segments_raw)?,
                heads,
            });
        }

        let rest = raw.strip_prefix('@').ok_or(ParseNameError::MissingSigil)?;
        let (anchor_raw, segments_raw) = split_anchor(rest);

        Ok(Self {
            anchor: Anchor::Dns(DnsName::parse(anchor_raw)?),
            segments: parse_segments(segments_raw)?,
            heads: Vec::new(),
        })
    }

    /// The trust anchor decided at parse time.
    #[must_use]
    pub const fn anchor(&self) -> &Anchor {
        &self.anchor
    }

    /// The path segments; one edge hop each during resolution.
    #[must_use]
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// Pinned heads on the anchor document. Empty for live names, and
    /// always empty for non-doc anchors.
    #[must_use]
    pub fn heads(&self) -> &[Head] {
        &self.heads
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.anchor)?;

        for segment in &self.segments {
            write!(f, "/{segment}")?;
        }

        for (i, head) in self.heads.iter().enumerate() {
            let separator = if i == 0 { '#' } else { '|' };
            write!(f, "{separator}{head}")?;
        }

        Ok(())
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Name {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Name {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = <alloc::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// Split `anchor[/segments…]` at the first `/`.
fn split_anchor(raw: &str) -> (&str, &str) {
    match raw.find('/') {
        Some(at) => raw.split_at(at),
        None => (raw, ""),
    }
}

/// Everything after the anchor: empty, or `/`-led segments.
fn parse_segments(raw: &str) -> Result<Vec<Segment>, ParseNameError> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }

    let rest = raw
        .strip_prefix('/')
        .ok_or(ParseNameError::ExpectedSlashAfterAnchor)?;

    rest.split('/')
        .map(|s| Segment::parse(s).map_err(ParseNameError::from))
        .collect()
}

/// Everything after `#`: one or more `|`-joined heads.
fn parse_heads(raw: &str) -> Result<Vec<Head>, ParseNameError> {
    if raw.is_empty() {
        return Err(ParseNameError::EmptyHeads);
    }

    raw.split('|')
        .map(|h| Head::parse(h).map_err(ParseNameError::from))
        .collect()
}

/// The input could not be parsed as an edgename.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseNameError {
    /// The DNS anchor was malformed (including dotless `@` names: `@`
    /// means DNS and nothing else).
    #[error(transparent)]
    Dns(#[from] ParseDnsNameError),

    /// The doc anchor payload was malformed.
    #[error(transparent)]
    Doc(#[from] ParseDocAnchorError),

    /// A `#` with nothing after it: pinned names need at least one head.
    #[error("`#` must be followed by at least one head")]
    EmptyHeads,

    /// Something other than `/` followed the anchor (e.g. `~bob`).
    #[error("expected `/` after the anchor")]
    ExpectedSlashAfterAnchor,

    /// A head was malformed.
    #[error(transparent)]
    Head(#[from] ParseHeadError),

    /// Names start with `~` (local), `@` (DNS), or `automerge:` (doc).
    #[error("name must start with `~` (local), `@` (DNS), or `automerge:` (doc anchor)")]
    MissingSigil,

    /// A path segment was malformed.
    #[error(transparent)]
    Segment(#[from] ParseSegmentError),
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    /// bs58check of `SigningKey::from_bytes(&[7u8; 32]).verifying_key()`.
    const DOC: &str = "2nBeEMDjAzFa9Ev2pxwejYrgCRmSLx96SbA24uhdMMTUktJWvK";

    /// bs58check of an arbitrary 32-byte change hash (same bytes as the
    /// doc vector — heads and keys share length and encoding).
    const HEAD: &str = "2nBeEMDjAzFa9Ev2pxwejYrgCRmSLx96SbA24uhdMMTUktJWvK";

    #[test]
    fn dotless_under_at_is_a_flat_parse_error() {
        assert_eq!(
            Name::parse("@bob"),
            Err(ParseNameError::Dns(ParseDnsNameError::Dotless))
        );
        assert_eq!(
            Name::parse("@z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"),
            Err(ParseNameError::Dns(ParseDnsNameError::Dotless)),
            "old-style multikey anchors are no longer keys under `@`"
        );
    }

    #[test]
    fn near_miss_domains_stay_domains() {
        let name = Name::parse("@bob.co").expect("dotted anchor is DNS");
        assert!(matches!(name.anchor(), Anchor::Dns(_)));
    }

    #[test]
    fn doc_anchor_parses() {
        let raw = alloc::format!("automerge:{DOC}/blog");
        let name = Name::parse(&raw).expect("valid doc anchor");
        assert!(matches!(name.anchor(), Anchor::Doc(_)));
        assert_eq!(name.to_string(), raw);
    }

    #[test]
    fn legacy_doc_ids_are_rejected_distinctly() {
        let legacy = bs58::encode(&[9u8; 16]).with_check().into_string();
        assert_eq!(
            Name::parse(&alloc::format!("automerge:{legacy}")),
            Err(ParseNameError::Doc(ParseDocAnchorError::LegacyDocumentId))
        );
    }

    #[test]
    fn heads_pin_doc_anchors() {
        let raw = alloc::format!("automerge:{DOC}/blog#{HEAD}");
        let name = Name::parse(&raw).expect("valid pinned name");
        assert_eq!(name.heads().len(), 1);
        assert_eq!(name.to_string(), raw);

        let multi = alloc::format!("automerge:{DOC}#{HEAD}|{HEAD}");
        let name = Name::parse(&multi).expect("multiple heads");
        assert_eq!(name.heads().len(), 2);
        assert_eq!(name.to_string(), multi);
    }

    #[test]
    fn empty_heads_are_rejected() {
        assert_eq!(
            Name::parse(&alloc::format!("automerge:{DOC}#")),
            Err(ParseNameError::EmptyHeads)
        );
    }

    #[test]
    fn hash_is_reserved_outside_doc_anchors() {
        assert!(
            matches!(
                Name::parse("@expede.wtf/foo#bar"),
                Err(ParseNameError::Segment(_))
            ),
            "`#` is reserved for heads and rejected in segments"
        );
    }

    #[test]
    fn local_names_parse_and_locals_need_a_slash() {
        assert!(matches!(
            Name::parse("~").expect("bare local root").anchor(),
            Anchor::Local
        ));
        assert!(Name::parse("~/bob/pics").is_ok());
        assert_eq!(
            Name::parse("~bob"),
            Err(ParseNameError::ExpectedSlashAfterAnchor)
        );
    }

    #[test]
    fn anchor_only_names_are_valid() {
        let name = Name::parse("@expede.wtf").expect("anchor-only DNS name");
        assert!(name.segments().is_empty());

        let name = Name::parse(&alloc::format!("automerge:{DOC}")).expect("anchor-only doc name");
        assert!(name.segments().is_empty());
        assert!(name.heads().is_empty());
    }

    #[test]
    fn empty_and_dot_segments_are_rejected() {
        assert!(Name::parse("@expede.wtf//a").is_err());
        assert!(Name::parse("@expede.wtf/a/").is_err());
        assert!(Name::parse("@expede.wtf/./a").is_err());
        assert!(Name::parse("@expede.wtf/../a").is_err());
    }

    #[test]
    fn parse_never_panics_and_roundtrips() {
        bolero::check!()
            .with_type::<alloc::string::String>()
            .for_each(|raw| {
                if let Ok(name) = Name::parse(raw) {
                    let printed = name.to_string();
                    let reparsed = Name::parse(&printed).expect("printed names reparse");
                    assert_eq!(name, reparsed, "print/parse roundtrip");
                    assert_eq!(printed, reparsed.to_string(), "printing is stable");
                }
            });
    }

    #[test]
    fn anchors_are_syntactically_disjoint() {
        bolero::check!()
            .with_type::<alloc::string::String>()
            .for_each(|raw| {
                if let Ok(name) = Name::parse(&alloc::format!("@{raw}")) {
                    assert!(
                        matches!(name.anchor(), Anchor::Dns(_)),
                        "`@` yields DNS anchors only"
                    );
                }

                if let Ok(name) = Name::parse(&alloc::format!("automerge:{raw}")) {
                    assert!(
                        matches!(name.anchor(), Anchor::Doc(_)),
                        "`automerge:` yields doc anchors only"
                    );
                    assert!(name.heads().is_empty() || raw.contains('#'));
                }

                if let Ok(name) = Name::parse(&alloc::format!("~{raw}")) {
                    assert!(
                        matches!(name.anchor(), Anchor::Local),
                        "`~` yields local anchors only"
                    );
                }
            });
    }
}
