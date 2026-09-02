//! Refusals that a `catch` block can tell apart.
//!
//! A thrown `Error` with only a message forces every caller into the
//! same shape: catch, and treat it as failure. That is wrong here in
//! a specific and costly way. A fresh chain whose generation key is
//! off the delegation path is *revocation working as designed* — the
//! zone has rotated the key away — but a handler that reads every
//! exception as a transport fault will present it as "the network is
//! down" and retry forever. The remedy a user infers from that
//! diagnosis is exactly the wrong one, and the true condition is one
//! the protocol went to some trouble to make detectable.
//!
//! So substantive refusals carry a `reason` property. Transport and
//! argument errors deliberately do not, which is itself the
//! discriminator: `"reason" in error` separates a verdict about
//! evidence from a failure to obtain any.

use js_sys::{Error, Reflect};
use onomancy_dnssec::certificate::DecodeCertificateError;
use onomancy_protocol::verifier::verdict::Rejection;
use wasm_bindgen::JsValue;

/// Declare the refusal vocabulary exactly once.
///
/// The enum, [`RefusalReason::ALL`], and [`RefusalReason::as_str`]
/// are all generated from the one list below, so no hand-kept copy
/// exists to drift: adding a `published` variant grows `ALL` by
/// construction, and the union drift test fails until the `.d.ts`
/// declares the new code.
macro_rules! refusal_reasons {
    (
        $(#[$enum_meta:meta])*
        pub enum RefusalReason {
            published {
                $($(#[$published_meta:meta])* $published:ident => $published_code:literal,)+
            }
            unpublished {
                $($(#[$unpublished_meta:meta])* $unpublished:ident => $unpublished_code:literal,)+
            }
        }
    ) => {
        $(#[$enum_meta])*
        pub enum RefusalReason {
            $($(#[$published_meta])* $published,)+
            $($(#[$unpublished_meta])* $unpublished,)+
        }

        impl RefusalReason {
            /// Every code this module can emit: generated from the
            /// same list that declares the variants, so it cannot be
            /// out of date with the enum. Whether the published
            /// `.d.ts` union agrees is what
            /// `the_declared_union_matches_the_emitted_codes` checks.
            pub const ALL: &'static [Self] = &[$(Self::$published,)+];

            /// The wire spelling, which is API and must not be
            /// reworded.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$published => $published_code,)+
                    $(Self::$unpublished => $unpublished_code,)+
                }
            }
        }
    };
}

refusal_reasons! {
    /// Why an operation was refused, as a type rather than a string.
    ///
    /// A type so the vocabulary has one home: the arms produce
    /// values, and the list that declares the variants is the list
    /// `ALL` and `as_str` are generated from — a code that no longer
    /// matches its declaration cannot be spelled.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum RefusalReason {
        published {
            /// The resolver was not reached. Retrying may work.
            Transport => "transport",

            /// DNS answered and carried no Onomancy record, or the
            /// document holds no certificate for this hostname.
            /// Retrying cannot help; absence is also never proof
            /// against a binding.
            NoBinding => "no-binding",

            /// This source holds no certificate for the document.
            /// Distinct from `NoBinding` only in which lookup came up
            /// empty.
            NoCertificateHeld => "no-certificate-held",

            /// The certificate ENTRY does not lead to a list: it
            /// chains a second hop, or holds something that is
            /// neither a list nor a reference.
            ///
            /// Not `Malformed`, which is about certificate BYTES and
            /// says "re-mint". Every certificate involved here may be
            /// fine — the document's entry is what needs fixing, by
            /// repointing it or restoring the list, and the likeliest
            /// author of the bad entry is an ordinary write by a
            /// collaborator, not whoever holds the certificate.
            BrokenIndirection => "broken-indirection",

            /// The hostname is not a DNS name, or cannot sit under
            /// `_onomancy`. The caller can see and fix this.
            InvalidHostname => "invalid-hostname",

            /// The bytes are not a well-formed certificate: framing, a
            /// wrong unit tag, or a non-canonical encoding. A wiring
            /// bug, not a forgery — the usual cause is passing the
            /// wrong buffer.
            Malformed => "malformed",

            /// The bytes are a well-formed certificate whose signature
            /// does not verify. Deliberately NOT merged with
            /// `Malformed`: one is "you sent me the wrong thing", the
            /// other is "someone altered this", and they want opposite
            /// reactions.
            InvalidSignature => "invalid-signature",

            /// The certificate binds a hostname other than the one
            /// asked for.
            HostnameMismatch => "hostname-mismatch",

            /// Records arrived and failed validation from the trust
            /// anchors.
            ChainRejected => "chain-rejected",

            /// The chain is sound; the certificate's signer is not
            /// delegated by the document it binds. Kept apart from
            /// `ChainRejected` because the zone is fine and the
            /// signing key is wrong — merged, it sends someone to
            /// debug DNSSEC over a key problem.
            SignerNotAuthorized => "signer-not-authorized",

            /// The chain is sound and the signer authorized, but the
            /// zone's proven records name a different document.
            DocumentNotAttested => "document-not-attested",

            /// A fresh chain whose delegation path lacks the
            /// zone-attested generation key: revocation working as
            /// designed.
            GenerationOffPath => "generation-off-path",
        }
        unpublished {
            /// Not a refusal at all, and deliberately **not** in
            /// [`Self::ALL`] or in the published union.
            ///
            /// A deferral is a grade, returned as a value by both
            /// entry points. It reaches this type only if a future
            /// path renders a grade as a refusal — a bug. Publishing
            /// a code for it would oblige every consumer to handle a
            /// case that cannot legitimately occur, so it emits an
            /// undeclared string instead, which lands in a `switch`
            /// default where an impossible value belongs.
            NotARefusal => "deferred",
        }
    }
}

/// Build a refusal carrying both a human message and a stable code.
#[must_use]
pub fn error(message: &str, reason: RefusalReason) -> JsValue {
    let error = Error::new(message);

    // Reflect::set on a fresh Error cannot fail.
    drop(Reflect::set(
        &error,
        &JsValue::from_str("reason"),
        &JsValue::from_str(reason.as_str()),
    ));

    error.into()
}

/// The code for a certificate rejection.
///
/// Kept beside [`crate::verify::rejection_message`] deliberately: the
/// prose may be reworded freely, the code may not, and having them
/// adjacent makes that asymmetry visible when either is edited.
#[must_use]
pub const fn reason(rejection: &Rejection) -> RefusalReason {
    match rejection {
        Rejection::ChainRejected => RefusalReason::ChainRejected,
        Rejection::SignerNotAuthorized => RefusalReason::SignerNotAuthorized,
        Rejection::DocumentNotAttested => RefusalReason::DocumentNotAttested,
        Rejection::GenerationOffPath => RefusalReason::GenerationOffPath,
        Rejection::HostnameMismatch { .. } => RefusalReason::HostnameMismatch,

        // A signature that does not verify is a different event from
        // bytes that were never a certificate, and only one of them
        // is a security signal.
        Rejection::Decode(DecodeCertificateError::Malformed(malformed)) => match malformed {
            onomancy_core::signed::payload::Malformed::InvalidSignature => {
                RefusalReason::InvalidSignature
            }
            onomancy_core::signed::payload::Malformed::WrongTag { .. } => RefusalReason::Malformed,
        },
        Rejection::Decode(_) => RefusalReason::Malformed,

        // Unreachable by construction: intercepted by both callers
        // and returned as a grade. Mapping it to a real code would
        // mislabel an impossible case as a real one.
        Rejection::Deferred(_) => RefusalReason::NotARefusal,
    }
}
/// The stable code for a failed live walk.
///
/// Split by **what a caller should do about it**, which is the only
/// distinction a UI can act on:
///
/// - `transport` — the resolver was not reached. Retrying may work.
/// - `no-binding` — DNS answered and there is no Onomancy record to
///   prove. Retrying cannot help; the name is simply not bound.
/// - `chain-rejected` — records existed and failed validation. A
///   security signal, not a connectivity one.
/// - `invalid-hostname` — the input is not a DNS name. The user can
///   see and fix this.
///
/// The first two are the pair that matters: they share a message
/// shape (`no TXT RRset with signatures at …` arises from an empty
/// answer as readily as from a half-failed fetch) while wanting
/// opposite remedies, so telling a user to check their connection
/// over an unbound name is the failure this exists to prevent.
#[cfg(feature = "doh")]
#[must_use]
pub const fn walk_reason(error: &crate::doh::FetchChainError) -> RefusalReason {
    use crate::doh::FetchChainError;
    use onomancy_chain::builder::BuildError;

    match error {
        FetchChainError::Transport(_) => RefusalReason::Transport,

        // DNS answered and carried no Onomancy record.
        FetchChainError::Build(BuildError::MissingRrset { .. }) => RefusalReason::NoBinding,

        // A name too long to sit under `_onomancy` is the caller's to
        // fix and is visible to them. Reporting it as a chain
        // rejection would claim a security failure over a typo — the
        // wrong-remedy bug this module exists to prevent.
        FetchChainError::Build(BuildError::UnrepresentableName(_)) => {
            RefusalReason::InvalidHostname
        }

        // Answers arrived and could not be framed into a chain.
        FetchChainError::Build(
            BuildError::Encode(_) | BuildError::OversizeChain { .. } | BuildError::TooManyCnames,
        ) => RefusalReason::ChainRejected,
    }
}

/// The code for a chain that was fetched but did not validate.
///
/// An absent leaf is `NoBinding` rather than a rejection: the chain
/// was well-formed and proved nothing, which is the unbound case
/// arriving one stage later than [`walk_reason`] catches it.
///
/// Spelled out rather than wildcarded on purpose. A new `WalkError`
/// variant would inherit `ChainRejected` silently under a `_` arm;
/// exhaustiveness turns that into a compile error at the site that
/// must choose.
#[cfg(feature = "doh")]
#[must_use]
pub const fn validation_reason(error: &onomancy_dnssec::validator::WalkError) -> RefusalReason {
    use onomancy_dnssec::validator::WalkError;

    match error {
        // DNS answered; nothing was proven.
        WalkError::Empty | WalkError::MissingLeaf => RefusalReason::NoBinding,

        // Records arrived and failed to hold up: a security signal.
        WalkError::DsMismatch
        | WalkError::EmptyWindow
        | WalkError::MalformedRdata { .. }
        | WalkError::NoUsableSignature
        | WalkError::NotDescending
        | WalkError::Parse(_)
        | WalkError::SignerMismatch
        | WalkError::TooManyCnames
        | WalkError::Unanchored
        | WalkError::UnexpectedLink { .. }
        | WalkError::Verify(_)
        | WalkError::WildcardExpansion
        | WalkError::WrongOwner => RefusalReason::ChainRejected,
    }
}

#[cfg(all(test, feature = "doh"))]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use onomancy_dnssec::validator::WalkError;

    /// `ALL` is generated from the same list that declares the
    /// variants, so it cannot drift from the enum. What still needs
    /// asserting is the boundary: the one unpublished variant stays
    /// unpublished.
    #[test]
    fn a_non_refusal_is_never_published() {
        assert!(!RefusalReason::ALL.contains(&RefusalReason::NotARefusal));
    }

    /// The pair that shares a remedy boundary: one is worth retrying
    /// and the other never is, so they must never collapse together.
    #[test]
    fn absence_and_unreachability_are_different_reasons() {
        let unreachable = walk_reason(&crate::doh::FetchChainError::Transport(
            crate::doh::DohError::NoFetch,
        ));
        let absent = walk_reason(&crate::doh::FetchChainError::Build(
            onomancy_chain::builder::BuildError::MissingRrset {
                owner: String::from("_onomancy.example.com"),
                rtype: hickory_proto::rr::RecordType::TXT,
            },
        ));

        assert_eq!(unreachable, RefusalReason::Transport);
        assert_eq!(absent, RefusalReason::NoBinding);
        assert_ne!(unreachable, absent);
    }

    /// A name that cannot sit under `_onomancy` is the caller's to
    /// fix. Reporting it as a chain rejection would claim a security
    /// failure over a typo — the regression this arm was enumerated
    /// to prevent, asserted rather than left to the comment.
    #[test]
    fn an_unrepresentable_name_is_the_callers_fault_not_a_security_signal() {
        let too_long = onomancy_chain::builder::BuildError::UnrepresentableName(
            hickory_proto::ProtoError::from("name too long"),
        );

        assert_eq!(
            walk_reason(&crate::doh::FetchChainError::Build(too_long)),
            RefusalReason::InvalidHostname
        );
    }

    /// An empty chain is the unbound case, not a security signal:
    /// nothing arrived to be suspicious of.
    #[test]
    fn an_empty_chain_is_not_a_security_signal() {
        assert_eq!(
            validation_reason(&WalkError::Empty),
            RefusalReason::NoBinding
        );
        assert_eq!(
            validation_reason(&WalkError::MissingLeaf),
            RefusalReason::NoBinding
        );
    }

    /// Evidence that arrived and failed is a security signal, and
    /// must not be reported as mere absence.
    #[test]
    fn a_failed_signature_is_a_security_signal() {
        for failure in [
            WalkError::Unanchored,
            WalkError::DsMismatch,
            WalkError::NoUsableSignature,
            WalkError::SignerMismatch,
            WalkError::WrongOwner,
        ] {
            assert_eq!(
                validation_reason(&failure),
                RefusalReason::ChainRejected,
                "{failure:?} must read as a security signal"
            );
        }
    }

    /// Wrong bytes and altered bytes are different events. Merging
    /// them tells a caller with a wiring bug that they may be under
    /// attack, and a caller under attack that they mistyped.
    #[test]
    fn a_bad_signature_is_not_the_same_as_the_wrong_buffer() {
        use onomancy_core::signed::payload::Malformed;

        let altered = Rejection::Decode(DecodeCertificateError::Malformed(
            Malformed::InvalidSignature,
        ));
        let wrong_thing =
            Rejection::Decode(DecodeCertificateError::Malformed(Malformed::WrongTag {
                expected: *b"ONC\x00",
                got: *b"ONR\x00",
            }));

        assert_eq!(reason(&altered), RefusalReason::InvalidSignature);
        assert_eq!(reason(&wrong_thing), RefusalReason::Malformed);
        assert_ne!(reason(&altered), reason(&wrong_thing));
    }

    /// Every code Rust can emit must be declared to TypeScript, and
    /// every declared member must be reachable. Two spellings of one
    /// contract in two languages, with nothing else keeping them
    /// aligned.
    #[test]
    fn the_declared_union_matches_the_emitted_codes() {
        let declared = declared_union();

        for reason in RefusalReason::ALL {
            assert!(
                declared.contains(&reason.as_str()),
                "`{}` is emitted by Rust but absent from RefusalReason",
                reason.as_str()
            );
        }

        for member in &declared {
            assert!(
                RefusalReason::ALL.iter().any(|r| r.as_str() == *member),
                "`{member}` is declared to TypeScript but no Rust path emits it"
            );
        }
    }

    /// A grade must stay out of the refusal union: publishing it
    /// would make consumers handle a case only a bug could produce.
    #[test]
    fn a_grade_is_not_a_declared_refusal() {
        assert!(!declared_union().contains(&RefusalReason::NotARefusal.as_str()));
    }

    /// The members of the published union, by quoted string only —
    /// the block carries comments, and a substring search over the
    /// whole file would also match *other* unions (`"deferred"`
    /// appears in `Freshness`, which is exactly the confusion this
    /// avoids).
    fn declared_union() -> Vec<&'static str> {
        let after = crate::shapes::TYPES
            .split("export type RefusalReason =")
            .nth(1)
            .expect("RefusalReason is declared");

        after
            .split(';')
            .next()
            .expect("the union terminates")
            .split('|')
            .filter_map(|part| {
                let opening = part.find('"')?;
                let rest = part.get(opening + 1..)?;
                let closing = rest.find('"')?;

                rest.get(..closing)
            })
            .collect()
    }
}
