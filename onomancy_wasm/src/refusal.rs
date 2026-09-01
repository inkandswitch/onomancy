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
use onomancy_protocol::verifier::verdict::Rejection;
use wasm_bindgen::JsValue;

/// Build a refusal carrying both a human message and a stable code.
#[must_use]
pub fn error(message: &str, reason: &str) -> JsValue {
    let error = Error::new(message);

    // Reflect::set on a fresh Error cannot fail.
    drop(Reflect::set(
        &error,
        &JsValue::from_str("reason"),
        &JsValue::from_str(reason),
    ));

    error.into()
}

/// The stable code for a rejection.
///
/// Kept beside [`crate::verify::rejection_message`] deliberately: the
/// prose may be reworded freely, the code may not, and having them
/// adjacent makes that asymmetry visible when either is edited.
#[must_use]
pub const fn reason(rejection: &Rejection) -> &'static str {
    match rejection {
        Rejection::ChainRejected => "chain-rejected",
        Rejection::Decode(_) => "decode",
        Rejection::GenerationOffPath => "generation-off-path",
        Rejection::HostnameMismatch { .. } => "hostname-mismatch",

        // Unreachable by construction: a deferral is a *grade*,
        // intercepted by both callers and returned as a value, so it
        // never becomes a refusal. Deliberately absent from the
        // published `RefusalReason` union — a consumer must never
        // have to handle it — and asserted below rather than trusted
        // to this comment.
        Rejection::Deferred(_) => DEFERRED_IS_A_GRADE,
    }
}

/// The non-code for a deferral. Never published, never a member of
/// `RefusalReason`; see [`reason`].
pub(crate) const DEFERRED_IS_A_GRADE: &str = "deferred";

/// Every code this module can put on a thrown error.
///
/// This list and the published `RefusalReason` union are two
/// spellings of one contract in two languages, and nothing else keeps
/// them aligned — a Rust arm added without its TypeScript member
/// would reach consumers as a value their compiler rejects.
#[cfg_attr(not(test), allow(dead_code))] // half of a contract the tests check
pub(crate) const CODES: &[&str] = &[
    "chain-rejected",
    "decode",
    "generation-off-path",
    "hostname-mismatch",
    "invalid-hostname",
    "no-binding",
    "no-certificate-held",
    "transport",
];

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
pub const fn walk_reason(error: &crate::doh::FetchChainError) -> &'static str {
    use crate::doh::FetchChainError;
    use onomancy_chain::builder::BuildError;

    match error {
        FetchChainError::Transport(_) => "transport",

        // DNS answered and carried no Onomancy record.
        FetchChainError::Build(BuildError::MissingRrset { .. }) => "no-binding",

        // A name too long to sit under `_onomancy` is the caller's to
        // fix and is visible to them. Reporting it as a chain
        // rejection would claim a security failure over a typo — the
        // wrong-remedy bug this module exists to prevent, and what a
        // `_` arm here did until it was enumerated.
        FetchChainError::Build(BuildError::UnrepresentableName(_)) => "invalid-hostname",

        // Answers arrived and could not be framed into a chain.
        FetchChainError::Build(
            BuildError::Encode(_) | BuildError::OversizeChain { .. } | BuildError::TooManyCnames,
        ) => "chain-rejected",
    }
}

/// The stable code for a chain that was fetched but did not validate.
///
/// An absent leaf is `no-binding` rather than a rejection: the chain
/// was well-formed and proved nothing, which is the unbound case
/// arriving one stage later than [`walk_reason`] catches it.
///
/// Spelled out rather than wildcarded on purpose. A new `WalkError`
/// variant would inherit `chain-rejected` silently under a `_` arm —
/// a correct mapping falsified by a change elsewhere, which is the
/// failure this codebase has now met twice. Exhaustiveness turns that
/// into a compile error at the site that must choose.
#[cfg(feature = "doh")]
#[must_use]
pub const fn validation_reason(error: &onomancy_dnssec::validator::WalkError) -> &'static str {
    use onomancy_dnssec::validator::WalkError;

    match error {
        // DNS answered; nothing was proven.
        WalkError::Empty | WalkError::MissingLeaf => "no-binding",

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
        | WalkError::WrongOwner => "chain-rejected",
    }
}

#[cfg(all(test, feature = "doh"))]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use onomancy_dnssec::validator::WalkError;

    /// The pair that shares a remedy boundary: one is worth retrying
    /// and the other never is, so they must never collapse together.
    #[test]
    fn absence_and_unreachability_are_different_reasons() {
        let absent = validation_reason(&WalkError::MissingLeaf);
        let unreachable = walk_reason(&crate::doh::FetchChainError::Transport(
            crate::doh::DohError::NoFetch,
        ));

        assert_eq!(absent, "no-binding");
        assert_eq!(unreachable, "transport");
        assert_ne!(absent, unreachable);
    }

    /// An empty chain is the unbound case, not a security signal:
    /// nothing arrived to be suspicious of.
    #[test]
    fn an_empty_chain_is_not_a_security_signal() {
        assert_eq!(validation_reason(&WalkError::Empty), "no-binding");
    }

    /// Evidence that arrived and failed is a security signal, and
    /// must not be reported as mere absence.
    #[test]
    fn a_failed_signature_is_a_security_signal() {
        assert_eq!(validation_reason(&WalkError::Unanchored), "chain-rejected");
        assert_eq!(validation_reason(&WalkError::DsMismatch), "chain-rejected");
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod contract {
    use super::*;

    /// The members of the published `RefusalReason` union.
    ///
    /// Parsed from the quoted strings only: the union carries comment
    /// lines, and a substring search over the whole file would also
    /// match members of *other* unions — `"deferred"` appears in
    /// `Freshness`, which is exactly the confusion this avoids.
    fn declared() -> Vec<&'static str> {
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

    /// Every code Rust can emit must be a member of the union
    /// TypeScript is given.
    ///
    /// These are one contract written twice in two languages, which
    /// is the shape that goes stale: a new Rust arm would reach
    /// consumers as a string their compiler rejects, and nothing in
    /// either language would notice.
    #[test]
    fn every_code_is_declared() {
        for code in CODES {
            assert!(
                declared().contains(code),
                "`{code}` is emitted by Rust but absent from the RefusalReason union"
            );
        }
    }

    /// And the converse: a declared member no Rust path emits is a
    /// case consumers write dead handlers for.
    #[test]
    fn every_declared_member_is_reachable() {
        for member in declared() {
            assert!(
                CODES.contains(&member),
                "`{member}` is declared to TypeScript but no Rust path emits it"
            );
        }
    }

    /// A deferral is a grade, so its non-code must stay out of *this*
    /// union: publishing it would make consumers handle a case only a
    /// bug could produce.
    #[test]
    fn deferred_is_not_a_refusal_reason() {
        assert!(!CODES.contains(&DEFERRED_IS_A_GRADE));
        assert!(!declared().contains(&DEFERRED_IS_A_GRADE));
    }
}
