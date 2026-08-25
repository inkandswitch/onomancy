//! The closed user-input name form: everything a user can type.
//!
//! Each [`Name<A>`] is one anchor kind; `SupportedName` is the sigil
//! dispatcher for raw input. The set is closed on purpose — adding an
//! anchor kind is a protocol revision, and every `match` below gets a
//! compiler-forced audit when it happens.

use alloc::string::String;
use core::fmt;

use onomancy_core::{
    anchor::{
        doc::{DocAnchor, SCHEME_PREFIX},
        local::Local,
    },
    name::{Name, segment::Segment},
};

use crate::dns_name::{DnsName, ParseDnsAnchoredNameError};

/// A parsed name of any anchor kind, discriminated by sigil.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupportedName {
    /// `~/…` — the petname root.
    Local(Name<Local>),

    /// `@hostname/…` — DNSSEC-attested.
    Dns(Name<DnsName>),

    /// `automerge:…/…` — self-certifying.
    Doc(Name<DocAnchor>),
}

impl SupportedName {
    /// Parse raw input by sigil: `~` local, `@` DNS, `automerge:` doc.
    ///
    /// # Errors
    ///
    /// Returns [`ParseSupportedNameError`]: the matched kind's own error, or
    /// [`ParseSupportedNameError::MissingSigil`] when no sigil matches.
    pub fn parse(raw: &str) -> Result<Self, ParseSupportedNameError> {
        if raw.starts_with('~') {
            return Ok(Self::Local(Name::parse(raw)?));
        }

        if raw.starts_with(SCHEME_PREFIX) {
            return Ok(Self::Doc(Name::parse(raw)?));
        }

        if raw.starts_with('@') {
            return Ok(Self::Dns(Name::parse(raw)?));
        }

        Err(ParseSupportedNameError::MissingSigil)
    }

    /// The path segments, whatever the anchor kind.
    #[must_use]
    pub fn segments(&self) -> &[Segment] {
        match self {
            Self::Local(name) => name.segments(),
            Self::Dns(name) => name.segments(),
            Self::Doc(name) => name.segments(),
        }
    }

    /// The anchor in printed form (`~`, `@expede.wtf`, `automerge:…`).
    #[must_use]
    pub fn anchor_string(&self) -> String {
        use core::fmt::Write as _;

        let mut out = String::new();
        let _ = write!(out, "{}", DisplayAnchor(self));
        out
    }
}

impl fmt::Display for SupportedName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local(name) => name.fmt(f),
            Self::Dns(name) => name.fmt(f),
            Self::Doc(name) => name.fmt(f),
        }
    }
}

/// Adapter: the anchor half only, in sigil form.
struct DisplayAnchor<'a>(&'a SupportedName);

impl fmt::Display for DisplayAnchor<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use onomancy_core::anchor::Anchor as _;

        match self.0 {
            SupportedName::Local(name) => name.anchor().fmt_anchor(f),
            SupportedName::Dns(name) => name.anchor().fmt_anchor(f),
            SupportedName::Doc(name) => name.anchor().fmt_anchor(f),
        }
    }
}

/// The input matched no name grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseSupportedNameError {
    /// `@` name, malformed.
    #[error(transparent)]
    Dns(#[from] ParseDnsAnchoredNameError),

    /// `automerge:` name, malformed.
    #[error(transparent)]
    Doc(#[from] onomancy_core::anchor::doc::ParseDocNameError),

    /// `~` name, malformed.
    #[error(transparent)]
    Local(#[from] onomancy_core::anchor::local::ParseLocalNameError),

    /// Names start with `~` (local), `@` (DNS), or `automerge:` (doc).
    #[error("name must start with `~` (local), `@` (DNS), or `automerge:` (doc anchor)")]
    MissingSigil,
}
