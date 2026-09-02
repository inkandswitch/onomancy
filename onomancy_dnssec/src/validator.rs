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
//!             leaf TXT RRset ──────► ChainProof
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
//! Negative proofs are out of the protocol at v0: NSEC and
//! NSEC3 links are skipped unverified (they can prove nothing to this
//! walk), a chain without a provable TXT leaf is invalid, and
//! wildcard-expanded answers are rejected outright — the no-closer-
//! match proof they would need is a negative proof.

use alloc::{string::String, vec::Vec};

use onomancy_core::time::UnixSeconds;

use crate::{
    chain::DnssecChain,
    chain_proof::{ChainProof, ChainValidator, InvalidChain},
    dns_name::DnsName,
    freshness::ValidityWindow,
    txt::record::{Classified, TxtRecord},
};

use crate::{
    crypto::{self, VerifyError},
    link::{Link, ParseLinkError},
    trust_anchor::TrustAnchor,
    wire::{
        cname::Cname, dnskey::Dnskey, ds::Ds, name::Name, rr_type::RrType, rrsig::Rrsig, txt::Txt,
    },
};

/// Maximum CNAME indirections followed on the `_onomancy` owner name.
///
/// Public so the chain builder (`onomancy_chain`) can pin parity in a
/// test — the two limits must never drift apart silently.
pub const MAX_CNAME_HOPS: usize = 8;

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
        Self::new(crate::trust_anchor::iana_root_anchors())
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

                (RrType::NSEC | RrType::NSEC3, None) => {
                    // Denial links prove nothing at v0:
                    // skipped unverified, never chain-poisoning.
                }

                (RrType::TXT, None) => {
                    return walk.finish_binding(&link, &target);
                }

                (rtype, _) => {
                    return Err(WalkError::UnexpectedLink {
                        rtype,
                        awaiting_child_keys: pending_ds.is_some(),
                    });
                }
            }
        }

        // Without negative proofs there is no absence outcome: a
        // chain that never reaches a TXT leaf proves nothing.
        Err(WalkError::MissingLeaf)
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
    root_zone: Name,
    root_keys: Vec<Dnskey>,
    window_inception: UnixSeconds,
    window_expiration: UnixSeconds,
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
            keys: keys.clone(),
            root_zone: link.owner().clone(),
            root_keys: keys,
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

        // A target outside the current zone's subtree can never be
        // reached by descending: re-enter at the anchored root so the
        // chain can descend the target's own branch. Sound because the
        // CNAME itself was verified above and everything after re-entry
        // is verified from the same trust anchors; the freshness window
        // keeps intersecting across both branches.
        if !self.zone.is_ancestor_or_self_of(cname.target()) {
            self.zone = self.root_zone.clone();
            self.keys = self.root_keys.clone();
        }

        Ok(cname.target().clone())
    }

    /// The leaf: a TXT `RRset` at the (possibly CNAME-followed) target.
    fn finish_binding(mut self, link: &Link, target: &Name) -> Result<ChainProof, WalkError> {
        if link.owner() != target {
            return Err(WalkError::WrongOwner);
        }

        let rrsig = self.verify_signed_link(link)?;

        // A wildcard-expanded answer (RRSIG label count below the
        // owner's) would need a no-closer-match proof — a negative
        // proof, which v0 does not evaluate. Reject: a
        // legitimate wildcard at `_onomancy` is pathological anyway,
        // and accepting one unproven would let a stripped exact-match
        // answer go undetected.
        if usize::from(rrsig.labels()) < target.labels().len() {
            return Err(WalkError::WildcardExpansion);
        }

        let records = parse_bindings(link);
        let window = self.window()?;

        Ok(ChainProof { records, window })
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
                match rrsig.verify(link, key) {
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
    fn window(&self) -> Result<ValidityWindow, WalkError> {
        ValidityWindow::new(self.window_inception, self.window_expiration)
            .map_err(|_| WalkError::EmptyWindow)
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
/// violation drops only its own record — grammar rejection is
/// per-record, never RRset-wide.
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

    /// The chain ended without a TXT leaf: it proves nothing
    /// (negative proofs are out of the protocol at v0).
    #[error("no TXT leaf: the chain proves nothing")]
    MissingLeaf,

    /// No signature named the current zone and verified under its
    /// keys.
    #[error("no usable signature on the link")]
    NoUsableSignature,

    /// A DS owner outside the current zone's subtree.
    #[error("delegation does not descend")]
    NotDescending,

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

    /// A wildcard-expanded answer: its no-closer-match proof would be
    /// a negative proof, which v0 does not evaluate.
    #[error("wildcard-expanded answers are rejected at v0")]
    WildcardExpansion,

    /// A leaf or CNAME at an owner other than the query target.
    #[error("link owner is not the query target")]
    WrongOwner,
}
