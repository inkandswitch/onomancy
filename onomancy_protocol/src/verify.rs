//! One-shot certificate verification: the dns-anchor pipeline for a
//! single unit, sharing the derivation's stage-1/4 machinery so the
//! two paths cannot drift.
//!
//! ```text
//! bytes ─► decode (strict + signature) ─► hostname check
//!       ─► chain validation (seam)      ─► TXT cross-check + selection
//!       ─► deferral (skew / not-yet-begun)
//!       ─► graded freshness at `now`    ─► generation rules (D10)
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

use onomancy_core::{
    certificate::{Certificate, DecodeCertificateError},
    freshness::{ChainWindow, Freshness},
    name::{dns::DnsName, doc::DocAnchor},
    time::UnixSeconds,
    txt::{generation_key::GenerationKey, serial::Serial},
};

use crate::verifier_state::{
    self,
    seam::{AuthorityVerifier, ChainValidator},
};

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
    /// With a fresh chain this is always `OnPath` (D10 rejects
    /// otherwise); with a stale chain the check is provisional.
    pub generation_check: GenerationCheck,

    /// The proven serial for this document (highest in the `RRset`).
    pub serial: Serial,

    /// The chain's ∩-window: what "was zone-rooted during" means.
    pub window: ChainWindow,
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

/// The D10 standing of the delegation-chain/generation-key check.
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
/// fresh chain whose delegation path lacks the attested `g=` (D10).
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
    let evidence = verifier_state::validate_record(
        &certificate,
        certificate.digest().erase(),
        validator,
        authority,
    )
    .ok_or(Rejection::ChainRejected)?;

    // Deferral precedes everything, including freshness.
    if verifier_state::is_deferred(&evidence, now) {
        return Err(Rejection::Deferred);
    }

    let freshness = verifier_state::freshness(&evidence, now);

    // D10: fresh + off_paths is a rejection; stale + off_paths is
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
    /// The chain never validated from the trust anchor, or the proven
    /// `RRset` does not attest the certificate's own document.
    #[error("chain rejected or does not attest the certificate's document")]
    ChainRejected,

    /// The unit was not a canonical, validly signed `ONC\x00` unit.
    #[error("decode: {0}")]
    Decode(#[from] DecodeCertificateError),

    /// Deferred, not malformed: a far-future serial (beyond the skew
    /// bound) or a not-yet-begun window. Re-evaluate when the clock
    /// reaches it.
    #[error("deferred: not considered until the clock reaches it")]
    Deferred,

    /// D10: a fresh chain whose delegation path lacks the
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
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{
        test_utils::{binding, binding_carrying, doc, generation, host},
        verifier_state::memory::{MemoryAuthority, MemoryValidator},
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

        assert_eq!(
            verify(
                &b.cert.encode(),
                &host(),
                UnixSeconds::from(NOW),
                &validator,
                &MemoryAuthority::default(),
            ),
            Err(Rejection::Deferred)
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

    #[test]
    fn document_cross_check_rejects_mismatches() -> TestResult {
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
            Err(Rejection::ChainRejected)
        );
        Ok(())
    }

    #[test]
    fn tampered_bytes_fail_at_decode() -> TestResult {
        let b = binding_carrying(1, 11, 7, 100, (NOW - 1_000, NOW + 1_000), 50, vec![])?;
        let mut bytes = b.cert.encode();
        if let Some(byte) = bytes.get_mut(40) {
            *byte ^= 0x01;
        }

        assert!(matches!(
            verify(
                &bytes,
                &host(),
                UnixSeconds::from(NOW),
                &MemoryValidator::default(),
                &MemoryAuthority::default(),
            ),
            Err(Rejection::Decode(_))
        ));
        Ok(())
    }
}
