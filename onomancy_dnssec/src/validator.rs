//! The chain-validation walk (RFC 4034/4035) behind `ChainValidator`.
//!
//! ```text
//! anchors ──► link 0: root DNSKEY   (self-signed, anchor-matched)
//!                │
//!                ▼  per zone cut, strictly descending
//!             DS RRset              (signed by the CURRENT zone)
//!             child DNSKEY RRset    (self-signed, DS-matched)
//!                │
//!                ▼  bounded CNAME indirection permitted
//!             leaf TXT RRset ──────► ChainProof::Binding
//!         or  leaf NSEC denial ────► ChainProof::Absence
//!
//!             ∩-window accumulated over every RRSIG used;
//!             empty intersection = invalid ✗ (never had joint validity)
//! ```
//!
//! Everything is pure over the supplied bytes: the clock never
//! appears (grading at `now` is the derivation's job — this walk
//! reports the window, not a verdict about the present), and the
//! anchors are a constructor input.
//!
//! # v0 simplifications (tracked)
//!
//! - NSEC3 denial is not yet evaluated (needs SHA-1); chains relying
//!   on it fail closed as invalid.
//! - The wildcard no-closer-match check (D14) accepts any verified
//!   NSEC whose range covers the query name, rather than the full
//!   closest-encloser dance.

use alloc::{string::String, vec::Vec};

use onomancy_core::{
    cert::chain::DnssecChain,
    freshness::ChainWindow,
    name::dns::DnsName,
    time::UnixSeconds,
    txt::record::{Classified, TxtRecord},
};
use onomancy_protocol::verifier_state::seam::{ChainProof, ChainValidator, InvalidChain};

use crate::{
    anchor::TrustAnchor,
    crypto::{self, VerifyError},
    link::{Link, ParseLinkError},
    wire::{
        cname::Cname, denial::Nsec, dnskey::Dnskey, ds::Ds, name::Name, record::RrType,
        rrsig::Rrsig, txt::Txt,
    },
};

/// Maximum CNAME indirections followed on the `_onomancy` owner name.
const MAX_CNAME_HOPS: usize = 8;

/// The chain-validation walk, rooted at a trust-anchor set.
#[derive(Debug, Clone)]
pub struct Validator {
    anchors: Vec<TrustAnchor>,
}

impl Validator {
    /// A validator trusting the given anchor set.
    #[must_use]
    pub const fn new(anchors: Vec<TrustAnchor>) -> Self {
        Self { anchors }
    }

    /// A validator trusting the baked-in IANA root KSKs.
    #[must_use]
    pub fn iana() -> Self {
        Self::new(crate::anchor::iana_root_anchors())
    }

    /// Validate a chain for `hostname`'s `_onomancy` owner name, with
    /// the full error vocabulary. The [`ChainValidator`] impl wraps
    /// this and collapses errors to the seam's unit `InvalidChain`.
    ///
    /// # Errors
    ///
    /// Returns [`WalkError`] pinpointing the first violation: parse
    /// failures, an unanchored root, broken signatures, ordering
    /// violations, an empty ∩-window, a missing or wrong-owner leaf,
    /// or an unproven wildcard expansion.
    pub fn validate_detailed(
        &self,
        hostname: &DnsName,
        chain: &DnssecChain,
    ) -> Result<ChainProof, WalkError> {
        let links: Vec<Link> = chain
            .links()
            .iter()
            .map(Link::parse)
            .collect::<Result<_, _>>()?;

        let mut links = links.into_iter();
        let root_link = links.next().ok_or(WalkError::Empty)?;

        // Link 0: a DNSKEY RRset, self-signed and anchor-matched.
        let mut walk = WalkState::enter_anchored(&self.anchors, &root_link)?;
        let mut target = Name::onomancy_owner(hostname);
        let mut pending_ds: Option<(Name, Vec<Ds>)> = None;
        let mut cname_hops = 0usize;
        let mut denials: Vec<VerifiedDenial> = Vec::new();

        for link in links {
            match (link.rtype(), &pending_ds) {
                (RrType::DS, None) => {
                    pending_ds = Some(walk.verify_delegation(&link)?);
                }

                (RrType::DNSKEY, Some(_)) => {
                    let (child, ds_set) = pending_ds
                        .take()
                        .unwrap_or_else(|| unreachable!("matched Some"));
                    walk.descend(&link, &child, &ds_set)?;
                }

                (RrType::CNAME, None) => {
                    if cname_hops >= MAX_CNAME_HOPS {
                        return Err(WalkError::TooManyCnames);
                    }
                    cname_hops += 1;
                    target = walk.follow_cname(&link, &target)?;
                }

                (RrType::NSEC, None) => {
                    denials.push(walk.verify_denial(&link)?);
                }

                (RrType::NSEC3, None) => {
                    // Fails closed until SHA-1-backed NSEC3 evaluation
                    // lands.
                    return Err(WalkError::Nsec3Unsupported);
                }

                (RrType::TXT, None) => {
                    return walk.finish_binding(&link, &target, &denials);
                }

                (rtype, _) => {
                    return Err(WalkError::UnexpectedLink {
                        rtype,
                        awaiting_child_keys: pending_ds.is_some(),
                    });
                }
            }
        }

        // No TXT leaf: the chain must prove absence.
        walk.finish_absence(&target, &denials)
    }
}

impl ChainValidator for Validator {
    fn validate(
        &self,
        hostname: &DnsName,
        chain: &DnssecChain,
    ) -> Result<ChainProof, InvalidChain> {
        self.validate_detailed(hostname, chain).map_err(|error| {
            tracing::debug!(%hostname, %error, "chain validation failed");
            InvalidChain
        })
    }
}

/// The walk's moving parts: the zone whose keys are currently
/// trusted, and the accumulated window.
struct WalkState {
    zone: Name,
    keys: Vec<Dnskey>,
    window_inception: UnixSeconds,
    window_expiration: UnixSeconds,
}

/// One verified NSEC denial, retained for absence and D14 decisions.
struct VerifiedDenial {
    owner: Name,
    nsec: Nsec,
    inception: UnixSeconds,
}

impl WalkState {
    /// Enter the walk at an anchor-matched, self-signed DNSKEY `RRset`.
    fn enter_anchored(anchors: &[TrustAnchor], link: &Link) -> Result<Self, WalkError> {
        if link.rtype() != RrType::DNSKEY {
            return Err(WalkError::UnexpectedLink {
                rtype: link.rtype(),
                awaiting_child_keys: false,
            });
        }

        let keys = parse_keys(link)?;

        if !anchors
            .iter()
            .any(|anchor| keys.iter().any(|key| anchor.matches(link.owner(), key)))
        {
            return Err(WalkError::Unanchored);
        }

        let mut state = Self {
            zone: link.owner().clone(),
            keys,
            window_inception: UnixSeconds::from(0),
            window_expiration: UnixSeconds::from(u64::MAX),
        };

        // Self-signed: the RRset's own keys must verify it.
        state.verify_with_own_zone(link)?;

        Ok(state)
    }

    /// Verify a DS `RRset` introducing a child zone cut.
    fn verify_delegation(&mut self, link: &Link) -> Result<(Name, Vec<Ds>), WalkError> {
        let child = link.owner().clone();

        if !self.zone.is_ancestor_or_self_of(&child) || self.zone == child {
            return Err(WalkError::NotDescending);
        }

        self.verify_with_own_zone(link)?;

        let ds_set = link
            .rrset()
            .iter()
            .map(|record| Ds::parse(&record.rdata))
            .collect::<Result<Vec<Ds>, _>>()
            .map_err(|_| WalkError::MalformedRdata { rtype: RrType::DS })?;

        Ok((child, ds_set))
    }

    /// Cross a zone cut: a self-signed child DNSKEY `RRset` matching the
    /// pending DS set.
    fn descend(&mut self, link: &Link, child: &Name, ds_set: &[Ds]) -> Result<(), WalkError> {
        if link.rtype() != RrType::DNSKEY || link.owner() != child {
            return Err(WalkError::UnexpectedLink {
                rtype: link.rtype(),
                awaiting_child_keys: true,
            });
        }

        let keys = parse_keys(link)?;

        let ds_matched = keys.iter().any(|key| {
            ds_set
                .iter()
                .any(|ds| crypto::ds_matches(child, key, ds).is_ok())
        });
        if !ds_matched {
            return Err(WalkError::DsMismatch);
        }

        self.zone = child.clone();
        self.keys = keys;
        self.verify_with_own_zone(link)?;

        Ok(())
    }

    /// Follow one verified CNAME on the query target.
    fn follow_cname(&mut self, link: &Link, target: &Name) -> Result<Name, WalkError> {
        if link.owner() != target {
            return Err(WalkError::WrongOwner);
        }

        self.verify_signed_link(link)?;

        let record = link.rrset().first().ok_or(WalkError::MalformedRdata {
            rtype: RrType::CNAME,
        })?;
        let cname = Cname::parse(&record.rdata).map_err(|_| WalkError::MalformedRdata {
            rtype: RrType::CNAME,
        })?;

        Ok(cname.target().clone())
    }

    /// Verify and retain one NSEC denial.
    fn verify_denial(&mut self, link: &Link) -> Result<VerifiedDenial, WalkError> {
        let rrsig = self.verify_signed_link(link)?;
        let inception = rrsig.inception();

        let record = link.rrset().first().ok_or(WalkError::MalformedRdata {
            rtype: RrType::NSEC,
        })?;
        let nsec = Nsec::parse(&record.rdata).map_err(|_| WalkError::MalformedRdata {
            rtype: RrType::NSEC,
        })?;

        Ok(VerifiedDenial {
            owner: link.owner().clone(),
            nsec,
            inception,
        })
    }

    /// The leaf: a TXT `RRset` at the (possibly CNAME-followed) target.
    fn finish_binding(
        mut self,
        link: &Link,
        target: &Name,
        denials: &[VerifiedDenial],
    ) -> Result<ChainProof, WalkError> {
        if link.owner() != target {
            return Err(WalkError::WrongOwner);
        }

        let rrsig = self.verify_signed_link(link)?;
        let leaf_inception = rrsig.inception();

        // D14: a wildcard-expanded answer (RRSIG label count below the
        // owner's) needs a verified denial covering the query name —
        // otherwise a stripped exact-match answer is undetectable.
        if usize::from(rrsig.labels()) < target.labels().len()
            && !denials.iter().any(|denial| denial_covers(denial, target))
        {
            return Err(WalkError::WildcardWithoutDenial);
        }

        let records = parse_bindings(link);
        let window = self.window()?;

        Ok(ChainProof::Binding {
            leaf_inception,
            records,
            window,
        })
    }

    /// No TXT leaf: the retained denials must prove absence at the
    /// target.
    fn finish_absence(
        self,
        target: &Name,
        denials: &[VerifiedDenial],
    ) -> Result<ChainProof, WalkError> {
        let denial = denials
            .iter()
            .find(|denial| {
                // Exact owner match with no TXT bit, or a covering
                // range: both prove no binding record exists.
                (denial.owner == *target && !denial.nsec.types().contains(RrType::TXT))
                    || denial_covers(denial, target)
            })
            .ok_or(WalkError::MissingLeaf)?;

        let leaf_inception = denial.inception;
        let window = self.window()?;

        Ok(ChainProof::Absence {
            leaf_inception,
            window,
        })
    }

    /// Verify a link signed by the CURRENT zone over its own owner
    /// (DNSKEY/DS at the zone or cut).
    fn verify_with_own_zone(&mut self, link: &Link) -> Result<&'static str, WalkError> {
        self.verify_signed_link(link).map(|_| "ok")
    }

    /// Try every (signature, key) pair: signer must be the current
    /// zone; key-tag/algorithm hints narrow first, all zone keys as
    /// fallback (tags collide legally). Accumulates the ∩-window from
    /// the signature that verified.
    fn verify_signed_link(&mut self, link: &Link) -> Result<Rrsig, WalkError> {
        let mut last: WalkError = WalkError::NoUsableSignature;

        for rrsig in link.signatures() {
            if *rrsig.signer_name() != self.zone {
                last = WalkError::SignerMismatch;
                continue;
            }

            let hinted = self
                .keys
                .iter()
                .filter(|key| {
                    key.key_tag() == rrsig.key_tag() && key.algorithm() == rrsig.algorithm()
                })
                .chain(self.keys.iter());

            for key in hinted {
                match crypto::verify_rrsig(link, rrsig, key) {
                    Ok(()) => {
                        self.intersect(rrsig)?;
                        return Ok(rrsig.clone());
                    }
                    Err(error) => last = WalkError::Verify(error),
                }
            }
        }

        Err(last)
    }

    /// Narrow the accumulated window by one used signature.
    fn intersect(&mut self, rrsig: &Rrsig) -> Result<(), WalkError> {
        let window = rrsig.window().map_err(|_| WalkError::EmptyWindow)?;

        self.window_inception = self.window_inception.max(window.inception());
        self.window_expiration = self.window_expiration.min(window.expiration());

        if self.window_expiration < self.window_inception {
            return Err(WalkError::EmptyWindow);
        }

        Ok(())
    }

    /// The final ∩-window.
    fn window(&self) -> Result<ChainWindow, WalkError> {
        ChainWindow::new(self.window_inception, self.window_expiration)
            .map_err(|_| WalkError::EmptyWindow)
    }
}

/// Whether a verified NSEC denies existence of `target`: its range
/// `(owner, next)` covers the name in canonical order, with the
/// end-of-zone wraparound.
fn denial_covers(denial: &VerifiedDenial, target: &Name) -> bool {
    use core::cmp::Ordering;

    let after_owner = denial.owner.canonical_cmp(target) == Ordering::Less;
    let before_next = target.canonical_cmp(denial.nsec.next()) == Ordering::Less;
    let wraps = denial.nsec.next().canonical_cmp(&denial.owner) != Ordering::Greater;

    if wraps {
        after_owner || before_next
    } else {
        after_owner && before_next
    }
}

/// Parse a DNSKEY link's keys.
fn parse_keys(link: &Link) -> Result<Vec<Dnskey>, WalkError> {
    link.rrset()
        .iter()
        .map(|record| Dnskey::parse(&record.rdata))
        .collect::<Result<Vec<Dnskey>, _>>()
        .map_err(|_| WalkError::MalformedRdata {
            rtype: RrType::DNSKEY,
        })
}

/// Extract the parseable `ONO0` binding records from a proven TXT
/// `RRset`. Unknown records/versions are dispositioned out; a grammar
/// violation drops only its own record (D5 is per-record).
fn parse_bindings(link: &Link) -> Vec<TxtRecord> {
    link.rrset()
        .iter()
        .filter_map(|record| Txt::parse(&record.rdata).ok())
        .filter_map(|txt| String::from_utf8(txt.concatenated()).ok())
        .filter_map(|text| match TxtRecord::classify(&text) {
            Ok(Classified::Binding(record)) => Some(*record),
            Ok(Classified::UnknownRecord | Classified::UnknownVersion) | Err(_) => None,
        })
        .collect()
}

/// The chain failed validation. The seam collapses this to
/// `InvalidChain`; the detail exists for diagnostics and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WalkError {
    /// A child DNSKEY matched none of the delegation's DS records.
    #[error("child DNSKEY RRset matches no DS record")]
    DsMismatch,

    /// A chain with no links proves nothing.
    #[error("empty chain")]
    Empty,

    /// The RRSIG windows never jointly held: invalid ✗, not stale.
    #[error("empty ∩-window")]
    EmptyWindow,

    /// An RDATA failed to parse for its claimed type.
    #[error("malformed {rtype} RDATA")]
    MalformedRdata {
        /// The claimed type.
        rtype: RrType,
    },

    /// The chain ended without a TXT leaf or a denial covering the
    /// target.
    #[error("no leaf: neither TXT nor covering denial")]
    MissingLeaf,

    /// No signature named the current zone and verified under its
    /// keys.
    #[error("no usable signature on the link")]
    NoUsableSignature,

    /// A DS owner outside the current zone's subtree.
    #[error("delegation does not descend")]
    NotDescending,

    /// NSEC3 evaluation is not yet implemented; fails closed.
    #[error("NSEC3 denial not yet supported")]
    Nsec3Unsupported,

    /// A link failed to parse.
    #[error("link: {0}")]
    Parse(#[from] ParseLinkError),

    /// An RRSIG named a signer other than the current zone.
    #[error("RRSIG signer is not the current zone")]
    SignerMismatch,

    /// Too many CNAME indirections.
    #[error("more than {MAX_CNAME_HOPS} CNAME hops")]
    TooManyCnames,

    /// The root DNSKEY `RRset` matched no trust anchor.
    #[error("root keys match no trust anchor")]
    Unanchored,

    /// A link type that cannot appear at this point in the walk.
    #[error("unexpected {rtype} link (awaiting child keys: {awaiting_child_keys})")]
    UnexpectedLink {
        /// The type found.
        rtype: RrType,
        /// Whether a DS was pending its child DNSKEY.
        awaiting_child_keys: bool,
    },

    /// A signature-level failure (bad signature, unsupported
    /// algorithm, non-zone key, …).
    #[error(transparent)]
    Verify(#[from] VerifyError),

    /// A wildcard-expanded answer without a covering denial (D14).
    #[error("wildcard expansion without a no-closer-match proof")]
    WildcardWithoutDenial,

    /// A leaf or CNAME at an owner other than the query target.
    #[error("link owner is not the query target")]
    WrongOwner,
}
