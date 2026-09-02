//! One-shot certificate verification: the dns-anchor pipeline for a
//! single unit, sharing the derivation's stage-1/4 machinery so the
//! two paths cannot drift.
//!
//! ```text
//! bytes ─► decode (strict + signature) ─► hostname check
//!       ─► chain validation (seam)      ─► TXT cross-check + selection
//!       ─► deferral (skew / not-yet-begun)
//!       ─► graded freshness at `now`    ─► generation rules
//!       ─► Verdict { fresh ✓ / stale ⚠, … }
//! ```
//!
//! A verdict is about ONE certificate against ONE clock reading. What
//! it deliberately does NOT decide: succession, lineage ratchets,
//! incumbency, pending — those are functions of the evidence SET, and
//! live in [`derive`](crate::derive). Use this for "is this unit
//! well-formed and zone-rooted?", use `derive` for "what do I believe
//! about this name?".

use ed25519_dalek::VerifyingKey;

use onomancy_core::{anchor::doc::DocAnchor, time::UnixSeconds};
use onomancy_dnssec::{
    certificate::{Certificate, DecodeCertificateError},
    dns_name::DnsName,
    freshness::{Freshness, ValidityWindow},
    txt::{generation_key::GenerationKey, serial::Serial},
};

use onomancy_dnssec::chain_proof::ChainValidator;

use crate::verifier::state::{self, authority_verifier::AuthorityVerifier};

/// A verified certificate's graded standing at one clock reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// The verified unit (signature checked at decode; chain checked
    /// here).
    pub certificate: Certificate,

    /// The bound document.
    pub document: DocAnchor,

    /// Fresh ✓ (window covers `now`) or stale ⚠ (once-valid).
    /// Staleness is a risk signal, never a forgery signal.
    pub freshness: Freshness,

    /// The attested generation key from the proven TXT record.
    pub generation: GenerationKey,

    /// Whether the delegation chain lies on the delegation path for the attested generation.
    /// With a fresh chain this is always `OnPath` (verification rejects
    /// otherwise); with a stale chain the check is provisional.
    pub generation_check: GenerationCheck,

    /// The proven serial for this document (highest in the `RRset`).
    pub serial: Serial,

    /// The chain's ∩-window: what "was zone-rooted during" means.
    pub window: ValidityWindow,
}

impl Verdict {
    /// Whether this verdict's certificate claims the signer `key`.
    /// (Authority — whether that signer is admin-delegated — remains
    /// the carriage's claim, checked via Keyhive.)
    #[must_use]
    pub fn signed_by(&self, key: &VerifyingKey) -> bool {
        self.certificate.signer() == key
    }
}

/// What a deferral was judged against.
///
/// Deferral precedes freshness, so no grade exists yet; these are the
/// established facts a caller needs to tell a clock difference from a
/// genuine wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeferredEvidence {
    /// The bound document — chain-proven and TXT-cross-checked.
    pub document: DocAnchor,

    /// The proven serial. Compare against the clock in milliseconds:
    /// a serial beyond `now + skew` is one of the two deferral causes.
    pub serial: Serial,

    /// The chain's ∩-window. A window whose inception is still ahead
    /// of the clock is the other cause.
    pub window: ValidityWindow,
}

/// The standing of the delegation-chain/generation-key check
/// (dns-anchor, Generation Key).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GenerationCheck {
    /// Stale chain and the attested `g=` is not on the delegation path:
    /// provisional — surfaced, re-checked when fresher evidence
    /// arrives (a fresh chain in this state is rejected instead).
    Provisional,

    /// The delegation chain lies on the delegation path for the attested `g=`.
    OnPath,
}

/// Verify one certificate unit for `expected_hostname` at `now`.
///
/// # Errors
///
/// Returns [`Rejection`] pinpointing the failure: strict-decode or
/// signature failure, a hostname other than expected, an invalid
/// chain, a proven `RRset` that does not attest the certificate's
/// document, a deferral (never malformed — re-evaluate later), or a
/// fresh chain whose delegation path lacks the attested `g=`.
pub fn verify<V: ChainValidator, A: AuthorityVerifier>(
    bytes: &[u8],
    expected_hostname: &DnsName,
    now: UnixSeconds,
    validator: &V,
    authority: &A,
) -> Result<Verdict, Rejection> {
    let certificate = Certificate::decode(bytes)?;

    if certificate.hostname() != expected_hostname {
        return Err(Rejection::HostnameMismatch {
            found: certificate.hostname().clone(),
        });
    }

    // Chain validation + TXT cross-check + record selection: the
    // derivation's own stage-1 path, verbatim.
    let evidence = state::validate_record(
        &certificate,
        certificate.digest().erase(),
        validator,
        authority,
    )
    .map_err(|rejected| match rejected {
        state::RecordRejected::Chain => Rejection::ChainRejected,
        state::RecordRejected::Signer => Rejection::SignerNotAuthorized,
        state::RecordRejected::Unattested => Rejection::DocumentNotAttested,
    })?;

    // Deferral precedes everything, including freshness.
    if state::is_deferred(&evidence, now) {
        return Err(Rejection::Deferred(alloc::boxed::Box::new(
            DeferredEvidence {
                document: evidence.document,
                serial: evidence.key.serial,
                window: evidence.window,
            },
        )));
    }

    let freshness = state::freshness(&evidence, now);

    // Fresh + off-path is a rejection; stale + off-path is
    // provisional.
    let generation_check = if evidence.generation_on_path {
        GenerationCheck::OnPath
    } else if freshness == Freshness::Fresh {
        return Err(Rejection::GenerationOffPath);
    } else {
        GenerationCheck::Provisional
    };

    Ok(Verdict {
        document: evidence.document,
        freshness,
        generation: evidence.generation,
        generation_check,
        serial: evidence.key.serial,
        window: evidence.window,
        certificate,
    })
}

/// The certificate did not verify.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Rejection {
    /// The chain never validated from the trust anchors.
    #[error("the DNSSEC chain did not validate from the trust anchors")]
    ChainRejected,

    /// The chain is sound, but the certificate's signer is not
    /// authorized by the document it claims to bind.
    ///
    /// Separate from [`Self::ChainRejected`] because the remedy is
    /// different in kind: the zone is fine and the signing key is
    /// wrong. Merged, this sends someone to debug DNSSEC over what is
    /// really "you signed with a key that document does not delegate
    /// to".
    #[error(
        "the signer is not authorized by the document this certificate binds \
         — the chain is sound; the signing key is not delegated by that document"
    )]
    SignerNotAuthorized,

    /// The chain is sound and the signer authorized, but no proven
    /// TXT record names this certificate's document.
    #[error("the zone's proven records do not name this certificate's document")]
    DocumentNotAttested,

    /// The unit was not a canonical, validly signed `ONC\x00` unit.
    #[error("decode: {0}")]
    Decode(#[from] DecodeCertificateError),

    /// Deferred, not malformed: a far-future serial (beyond the skew
    /// bound) or a not-yet-begun window. Re-evaluate when the clock
    /// reaches it.
    ///
    /// Carries what deferral is judged against, because the refusal
    /// asserts a clock disagreement and a caller cannot confirm that
    /// from prose. Everything here is already proven when deferral is
    /// decided — chain validated, TXT cross-checked, signer
    /// authorized — so this is evidence not yet in force, rather than
    /// evidence found wanting.
    #[error("deferred: not considered until the clock reaches it")]
    Deferred(alloc::boxed::Box<DeferredEvidence>),

    /// A fresh chain whose delegation path lacks the
    /// attested `g=`.
    #[error("fresh chain does not lie on the delegation path for the attested generation key")]
    GenerationOffPath,

    /// The certificate binds a hostname other than the expected one.
    #[error("certificate binds {found}, not the expected hostname")]
    HostnameMismatch {
        /// The hostname the certificate actually binds.
        found: DnsName,
    },
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::{
        test_utils::{binding, binding_carrying, doc, generation, host},
        verifier::state::memory::{authority::MemoryAuthority, validator::MemoryValidator},
    };
    use alloc::vec;
    use testresult::TestResult;

    const NOW: u64 = 1_755_000_000;

    #[test]
    fn a_fresh_genuine_certificate_verifies() -> TestResult {
        let b = binding(1, 11, 1, 100, (NOW - 1_000, NOW + 1_000), 50)?;
        let validator = MemoryValidator::default().with(host(), &b.chain, b.proof.clone());

        let verdict = verify(
            &b.cert.encode(),
            &host(),
            UnixSeconds::from(NOW),
            &validator,
            &MemoryAuthority::default(),
        )
        .expect("verifies");

        assert_eq!(verdict.document, doc(1));
        assert_eq!(verdict.generation, generation(11));
        assert_eq!(verdict.serial, Serial::from(100));
        assert_eq!(verdict.freshness, Freshness::Fresh);
        assert_eq!(verdict.generation_check, GenerationCheck::OnPath);
        assert_eq!(
            verdict.window,
            crate::test_utils::window(NOW - 1_000, NOW + 1_000),
            "the ∩-window rides the verdict for the caller's grading"
        );
        Ok(())
    }

    #[test]
    fn stale_grades_rather_than_rejects() -> TestResult {
        let b = binding(1, 11, 2, 100, (NOW - 9_000, NOW - 1_000), 50)?;
        let validator = MemoryValidator::default().with(host(), &b.chain, b.proof.clone());

        let verdict = verify(
            &b.cert.encode(),
            &host(),
            UnixSeconds::from(NOW),
            &validator,
            &MemoryAuthority::default(),
        )
        .expect("stale is a grade, not a rejection");

        assert_eq!(verdict.freshness, Freshness::Stale);
        assert_eq!(
            verdict.document,
            doc(1),
            "the stale path extracts the same facts as the fresh one"
        );
        assert_eq!(verdict.generation, generation(11));
        assert_eq!(verdict.serial, Serial::from(100));
        assert_eq!(verdict.generation_check, GenerationCheck::OnPath);
        Ok(())
    }

    #[test]
    fn d10_rejects_fresh_but_grades_stale_provisional() -> TestResult {
        let fresh = binding(1, 11, 3, 100, (NOW - 1_000, NOW + 1_000), 50)?;
        let stale = binding(1, 11, 4, 100, (NOW - 9_000, NOW - 1_000), 50)?;
        let authority = MemoryAuthority::default().off_path(&generation(11));

        let validator = MemoryValidator::default()
            .with(host(), &fresh.chain, fresh.proof.clone())
            .with(host(), &stale.chain, stale.proof.clone());

        assert_eq!(
            verify(
                &fresh.cert.encode(),
                &host(),
                UnixSeconds::from(NOW),
                &validator,
                &authority,
            ),
            Err(Rejection::GenerationOffPath)
        );

        let verdict = verify(
            &stale.cert.encode(),
            &host(),
            UnixSeconds::from(NOW),
            &validator,
            &authority,
        )
        .expect("stale + off_paths is provisional");
        assert_eq!(verdict.generation_check, GenerationCheck::Provisional);
        Ok(())
    }

    #[test]
    fn far_future_serials_defer() -> TestResult {
        let b = binding(
            1,
            11,
            6,
            NOW * 1000 + 6 * 60 * 1000,
            (NOW - 1_000, NOW + 1_000),
            50,
        )?;
        let validator = MemoryValidator::default().with(host(), &b.chain, b.proof.clone());

        let rejection = verify(
            &b.cert.encode(),
            &host(),
            UnixSeconds::from(NOW),
            &validator,
            &MemoryAuthority::default(),
        )
        .expect_err("a far-future serial defers");

        let Rejection::Deferred(evidence) = rejection else {
            panic!("expected deferral, got {rejection:?}");
        };

        // The deferral carries what it was judged against: this
        // serial is the cause, and it outruns the clock.
        assert!(
            evidence.serial.value() > NOW * 1000,
            "the serial that caused deferral must be readable from it"
        );
        Ok(())
    }

    #[test]
    fn not_yet_begun_windows_defer() -> TestResult {
        // The second deferral cause: the chain's window has not begun
        // — evidence not yet in force, never malformed.
        let b = binding(1, 11, 9, 100, (NOW + 1_000, NOW + 2_000), 50)?;
        let validator = MemoryValidator::default().with(host(), &b.chain, b.proof.clone());

        let rejection = verify(
            &b.cert.encode(),
            &host(),
            UnixSeconds::from(NOW),
            &validator,
            &MemoryAuthority::default(),
        )
        .expect_err("a not-yet-begun window defers");

        let Rejection::Deferred(evidence) = rejection else {
            panic!("expected deferral, got {rejection:?}");
        };

        // The window is the cause this time, and it is readable.
        assert!(
            evidence.window.inception() > UnixSeconds::from(NOW),
            "the not-yet-begun window must be readable from the deferral"
        );
        assert_eq!(evidence.document, doc(1));
        Ok(())
    }

    #[test]
    fn a_certificate_for_another_hostname_is_refused_by_name() -> TestResult {
        // The one rejection that needs no validator at all: the
        // certificate binds a different hostname, and the refusal
        // carries WHICH one — a caller distinguishing "wrong name"
        // from "bad zone" needs the found name, not prose.
        let b = binding(1, 11, 1, 100, (NOW - 1_000, NOW + 1_000), 50)?;
        let expected = onomancy_dnssec::dns_name::DnsName::parse("example.org")?;

        assert_eq!(
            verify(
                &b.cert.encode(),
                &expected,
                UnixSeconds::from(NOW),
                &MemoryValidator::default(),
                &MemoryAuthority::default(),
            ),
            Err(Rejection::HostnameMismatch { found: host() })
        );
        Ok(())
    }

    #[test]
    fn unregistered_chains_are_rejected() -> TestResult {
        let b = binding(1, 11, 1, 100, (NOW - 1_000, NOW + 1_000), 50)?;
        // Validator knows nothing about this chain.
        let validator = MemoryValidator::default();

        assert_eq!(
            verify(
                &b.cert.encode(),
                &host(),
                UnixSeconds::from(NOW),
                &validator,
                &MemoryAuthority::default(),
            ),
            Err(Rejection::ChainRejected)
        );
        Ok(())
    }

    /// A sound chain with an unauthorized signer is a KEY problem,
    /// named as one.
    ///
    /// Three refusals used to collapse into `ChainRejected`: a bad
    /// chain, an unauthorized signer, and a zone naming a different
    /// document. This pins the middle one — the case where the zone's
    /// DNSSEC is fine and the certificate was simply signed by a key
    /// the document does not delegate to. Reporting it as a chain
    /// failure sends the holder to debug DNS they cannot fix.
    #[test]
    fn an_unauthorized_signer_is_not_a_chain_failure() -> TestResult {
        let b = binding(1, 11, 1, 100, (NOW - 1_000, NOW + 1_000), 50)?;
        let validator = MemoryValidator::default().with(host(), &b.chain, b.proof.clone());

        // Same certificate, same chain — the only change is that the
        // document now denies this signer.
        let authority = MemoryAuthority::default().deny(doc(1), b.cert.signer());

        assert_eq!(
            verify(
                &b.cert.encode(),
                &host(),
                UnixSeconds::from(NOW),
                &validator,
                &authority,
            ),
            Err(Rejection::SignerNotAuthorized)
        );
        Ok(())
    }
    /// A sound chain that names someone else's document is its own
    /// refusal, not a chain failure.
    ///
    /// The distinction is the whole point: `ChainRejected` sends a
    /// caller to their zone's DNSSEC, which here is perfectly fine.
    /// What is wrong is *which document* the zone names.
    #[test]
    fn a_chain_naming_another_document_is_not_a_chain_failure() -> TestResult {
        // The chain proves a TXT attesting doc(2); the cert claims
        // doc(1).
        let b = binding(1, 11, 1, 100, (NOW - 1_000, NOW + 1_000), 50)?;
        let wrong = binding(2, 22, 5, 100, (NOW - 1_000, NOW + 1_000), 50)?;
        let validator = MemoryValidator::default().with(host(), &b.chain, wrong.proof.clone());

        assert_eq!(
            verify(
                &b.cert.encode(),
                &host(),
                UnixSeconds::from(NOW),
                &validator,
                &MemoryAuthority::default(),
            ),
            Err(Rejection::DocumentNotAttested)
        );
        Ok(())
    }

    /// Any single bit flip anywhere in the unit is never a
    /// DIFFERENT accepted verdict: it fails somewhere — decode for
    /// signed-region flips, chain validation for attached-region
    /// ones — or (defensively stated) verifies to the identical
    /// verdict. Generalizes the old fixed-offset byte-40 flip, whose
    /// magic offset was coupled to the wire layout.
    #[test]
    fn no_bit_flip_yields_a_different_verdict() {
        let b = binding_carrying(1, 11, 7, 100, (NOW - 1_000, NOW + 1_000), 50, vec![])
            .expect("under the unit cap");
        let bytes = b.cert.encode();
        let validator = MemoryValidator::default().with(host(), &b.chain, b.proof.clone());
        let authority = MemoryAuthority::default();

        let baseline = verify(
            &bytes,
            &host(),
            UnixSeconds::from(NOW),
            &validator,
            &authority,
        )
        .expect("the untampered unit verifies");

        bolero::check!()
            .with_type::<(usize, u8)>()
            .for_each(|&(position, bit)| {
                let mut flipped = bytes.clone();
                let at = position % flipped.len();
                if let Some(byte) = flipped.get_mut(at) {
                    *byte ^= 1 << (bit % 8);
                }

                match verify(
                    &flipped,
                    &host(),
                    UnixSeconds::from(NOW),
                    &validator,
                    &authority,
                ) {
                    Err(_) => (),
                    Ok(verdict) => assert_eq!(
                        verdict,
                        baseline,
                        "a flip at byte {at} bit {} produced a DIFFERENT \
                         accepted verdict",
                        bit % 8
                    ),
                }
            });
    }
}
