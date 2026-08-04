//! Trust anchors, discriminated syntactically at parse time.

use super::{
    dns::DnsName,
    doc::{DocAnchor, SCHEME_PREFIX},
};
use core::fmt;

/// Where a name's authority is rooted.
///
/// The spelling decides the anchor: `~` is local, `@` is DNS, and
/// `automerge:` is a doc anchor. There is no fallback between families —
/// ambiguity is a parse error, never a lookup-order decision.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Anchor {
    /// `~` — your own signed root document. Not shareable.
    Local,

    /// `@expede.wtf` — DNSSEC-attested, normalized to a lowercase A-label
    /// form with no trailing dot.
    Dns(DnsName),

    /// `automerge:…` — an Automerge URL whose document ID is an ed25519
    /// verifying key (the Keyhive root doc ID). Self-certifying.
    Doc(DocAnchor),
}

impl fmt::Display for Anchor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local => f.write_str("~"),
            Self::Dns(dns) => write!(f, "@{dns}"),
            Self::Doc(doc) => write!(f, "{SCHEME_PREFIX}{doc}"),
        }
    }
}
