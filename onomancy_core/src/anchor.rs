//! The trust-anchor contract: what a name can be rooted in.

pub mod doc;
pub mod local;

use core::fmt;

use crate::name::Name;

/// A trust-anchor kind a [`Name`] can be rooted in.
///
/// The spelling decides the anchor: each kind owns one sigil and one
/// full-name grammar, and there is no fallback between kinds —
/// ambiguity is a parse error, never a lookup-order decision. Kinds
/// with attestation machinery live with that machinery; core holds
/// only the substrate-neutral kinds ([`Local`](self::local::Local)
/// petname roots and [`DocAnchor`](self::doc::DocAnchor)
/// self-certifying documents).
pub trait Anchor: Sized {
    /// This kind's full-name parse error.
    type ParseError;

    /// Parse a complete name of this anchor kind: sigil, anchor,
    /// segments.
    ///
    /// # Errors
    ///
    /// Returns `Self::ParseError` when the input is not a well-formed
    /// name of this kind — including when the sigil belongs to a
    /// different kind: anchors never fall back to one another.
    fn parse_name(raw: &str) -> Result<Name<Self>, Self::ParseError>;

    /// Print the anchor in its sigil form (`~`, `automerge:3RF…`, or
    /// an extension kind's own sigil). Distinct from any bare
    /// [`Display`](core::fmt::Display) the anchor type has: the
    /// name-position spelling carries the sigil.
    ///
    /// # Errors
    ///
    /// Propagates formatter errors.
    fn fmt_anchor(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result;
}
