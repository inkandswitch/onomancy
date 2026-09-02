//! Ceremony conformance: Plans verify by construction — a returned
//! Plan derived correctly against a simulated zone, and a ceremony
//! that would sabotage its own binding refuses to plan at all.

#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::unwrap_used)]

use ed25519_dalek::SigningKey;
use onomancy_core::{anchor::doc::DocAnchor, delegation_chain::DelegationChain};
use onomancy_dnssec::{
    dns_name::DnsName,
    txt::{generation_key::GenerationKey, record::TxtRecord, serial::Serial},
};
use onomancy_protocol::verifier::state::memory::authority::MemoryAuthority;
use onomancy_publish::{
    ceremony::{CeremonyError, bind::Bind, migrate::Migrate, refresh::Refresh, rotate::Rotate},
    plan::{ArtifactKind, DnsOp, Postcondition},
    signer::Signer,
};
use testresult::TestResult;

const NOW_MS: u64 = 1_755_000_000_000;

fn signer(seed: u8) -> Signer {
    Signer::new(SigningKey::from_bytes(&[seed; 32]))
}

fn doc(seed: u8) -> DocAnchor {
    DocAnchor::from(SigningKey::from_bytes(&[seed; 32]).verifying_key())
}

fn generation(seed: u8) -> GenerationKey {
    GenerationKey::from(SigningKey::from_bytes(&[seed; 32]).verifying_key())
}

fn hostname() -> DnsName {
    DnsName::parse("example.com").expect("valid hostname")
}

#[test]
fn bind_emits_a_verified_plan() -> TestResult {
    let plan = Bind {
        hostname: hostname(),
        document: doc(1),
        generation: generation(2),
        heads: vec![],
        lineage: vec![],
        carriage: DelegationChain::default(),
    }
    .plan(NOW_MS, &signer(1), &MemoryAuthority::default())?;

    assert_eq!(plan.dns_ops.len(), 1, "one TXT publish");
    assert!(matches!(plan.dns_ops[0], DnsOp::PublishTxt { .. }));
    assert_eq!(plan.artifacts.len(), 1);
    assert_eq!(plan.artifacts[0].kind, ArtifactKind::Certificate);
    assert!(plan.postconditions.iter().any(|p| matches!(
        p,
        Postcondition::VerifiesFresh(fresh)
            if fresh.document == doc(1) && fresh.generation == generation(2)
    )));
    assert!(
        plan.postconditions.iter().any(|p| matches!(
            p,
            Postcondition::EffectiveSerialAtLeast { serial, .. }
                if *serial == Serial::from(NOW_MS)
        )),
        "the ratchet floor is the plan's own serial"
    );
    Ok(())
}

/// The module's central claim, refused for real: a plan is a witness
/// only against the authority its verifiers will run, so a carriage
/// the authority rejects fails at PLAN time — not at the first
/// verifier.
#[test]
fn a_rejecting_authority_refuses_the_plan() {
    let bind = Bind {
        hostname: hostname(),
        document: doc(1),
        generation: generation(2),
        heads: vec![],
        lineage: vec![],
        carriage: DelegationChain::default(),
    };

    // An off-path generation: the derivation D10-rejects the fresh
    // record, so nothing derives — the same verdict every live
    // verifier would reach.
    let off_path = bind.clone().plan(
        NOW_MS,
        &signer(1),
        &MemoryAuthority::default().off_path(&generation(2)),
    );
    assert_eq!(off_path.unwrap_err(), CeremonyError::DerivesNothing);

    // A denied certificate signer: the certificate contributes no
    // candidacy under seam parity, so nothing derives.
    let denied = bind.plan(
        NOW_MS,
        &signer(1),
        &MemoryAuthority::default().deny(doc(1), &SigningKey::from_bytes(&[1; 32]).verifying_key()),
    );
    assert_eq!(denied.unwrap_err(), CeremonyError::DerivesNothing);
}

/// The encoder cap surfaces as a ceremony error: a carriage too
/// large to ride the certificate's attached region refuses at
/// signing, before any simulation.
#[test]
fn oversize_carriages_refuse_at_plan_time() {
    use onomancy_core::delegation_chain::SignedDelegationBytes;

    let oversize = Bind {
        hostname: hostname(),
        document: doc(1),
        generation: generation(2),
        heads: vec![],
        lineage: vec![],
        carriage: DelegationChain::from(vec![SignedDelegationBytes::from(vec![
            0u8;
            2 * 1024 * 1024
        ])]),
    }
    .plan(NOW_MS, &signer(1), &MemoryAuthority::default());

    assert!(matches!(oversize, Err(CeremonyError::Oversize(_))));
}

#[test]
fn rotate_emits_statement_and_certificate() -> TestResult {
    let plan = Rotate {
        hostname: hostname(),
        document: doc(1),
        replaced: generation(2),
        prior_lineage: vec![],
        carriage: DelegationChain::default(),
    }
    .plan(NOW_MS, &signer(3), &signer(1), &MemoryAuthority::default())?;

    assert_eq!(plan.artifacts.len(), 2, "certificate + standalone ONR");
    assert!(
        plan.artifacts
            .iter()
            .any(|a| a.kind == ArtifactKind::RotationStatement)
    );
    assert!(plan.postconditions.iter().any(|p| matches!(
        p,
        Postcondition::VerifiesFresh(fresh) if fresh.generation == generation(3)
    )));
    Ok(())
}

#[test]
fn rotate_refuses_generation_reuse() {
    // Rotating BACK to a generation the lineage already retired:
    // publishing this would make the owner's own lineage a permanent
    // surfaced fork — the ceremony refuses at plan time.
    let first = Rotate {
        hostname: hostname(),
        document: doc(1),
        replaced: generation(2),
        prior_lineage: vec![],
        carriage: DelegationChain::default(),
    }
    .plan(NOW_MS, &signer(3), &signer(1), &MemoryAuthority::default())
    .expect("first rotation plans");

    // Recover the signed statement from the plan for the next step.
    let statement = onomancy_dnssec::statement::rotation::RotationStatement::decode(
        &first
            .artifacts
            .iter()
            .find(|a| a.kind == ArtifactKind::RotationStatement)
            .expect("statement artifact")
            .bytes,
    )
    .expect("own artifact decodes");

    let reuse = Rotate {
        hostname: hostname(),
        document: doc(1),
        replaced: generation(3),
        prior_lineage: vec![statement],
        carriage: DelegationChain::default(),
    }
    .plan(
        NOW_MS + 1000,
        &signer(2),
        &signer(1),
        &MemoryAuthority::default(),
    ); // signer(2) = retired G

    assert_eq!(reuse.unwrap_err(), CeremonyError::GenerationReuse);
}

#[test]
fn rotate_catches_forks_the_reuse_check_cannot_see() -> TestResult {
    // A double-replace hiding in prior_lineage: G2 already retired
    // toward G3, and this ceremony retires G2 again toward G4. The
    // simple reuse check passes (G4 is new) — the simulated
    // derivation catches the set-wise fork.
    let earlier = onomancy_dnssec::statement::rotation::RotationStatement::sign(
        &doc(1),
        &generation(2),
        &SigningKey::from_bytes(&[3; 32]),
        DelegationChain::default(),
    )?;

    let forked = Rotate {
        hostname: hostname(),
        document: doc(1),
        replaced: generation(2), // second replacement of G2
        prior_lineage: vec![earlier],
        carriage: DelegationChain::default(),
    }
    .plan(NOW_MS, &signer(4), &signer(1), &MemoryAuthority::default());

    assert_eq!(forked.unwrap_err(), CeremonyError::WouldFork);
    Ok(())
}

#[test]
fn migrate_dual_publishes_and_proves_continuity() -> TestResult {
    let retained = TxtRecord::new(Serial::from(NOW_MS - 10_000), generation(2), doc(1));

    let plan = Migrate {
        hostname: hostname(),
        predecessor: doc(1),
        successor: doc(5),
        retained,
        successor_generation: generation(6),
        lineage: vec![],
        carriage: DelegationChain::default(),
    }
    .plan(NOW_MS, &signer(1), &signer(5), &MemoryAuthority::default())?;

    assert_eq!(plan.dns_ops.len(), 2, "retain old + publish new");
    assert!(matches!(plan.dns_ops[0], DnsOp::RetainTxt { .. }));
    assert!(matches!(plan.dns_ops[1], DnsOp::PublishTxt { .. }));
    assert!(
        plan.artifacts
            .iter()
            .any(|a| a.kind == ArtifactKind::SuccessorStatement)
    );
    // The simulation already asserted the successor wins the
    // dual-publish derivation via the proof (not zone-state luck);
    // the postcondition states the continuity claim explicitly.
    assert!(plan.postconditions.iter().any(|p| matches!(
        p,
        Postcondition::VerifiesFresh(fresh)
            if fresh.document == doc(5) && fresh.generation == generation(6)
    )));
    Ok(())
}

#[test]
fn refresh_is_keyless_and_zone_untouched() -> TestResult {
    // Bind first, then refresh the certificate against the records
    // the plan itself would publish.
    let bind = Bind {
        hostname: hostname(),
        document: doc(1),
        generation: generation(2),
        heads: vec![],
        lineage: vec![],
        carriage: DelegationChain::default(),
    };
    let bound = bind.plan(NOW_MS, &signer(1), &MemoryAuthority::default())?;

    let certificate = onomancy_dnssec::certificate::Certificate::decode(&bound.artifacts[0].bytes)?;
    let record = *bound.dns_ops[0].record();

    let refreshed = Refresh {
        certificate,
        chain: onomancy_dnssec::chain::DnssecChain::from(vec![vec![0xAB; 8].into()]),
        records: vec![record],
    }
    .plan(
        onomancy_core::time::UnixSeconds::from(NOW_MS / 1000),
        &MemoryAuthority::default(),
    )?;

    assert!(refreshed.dns_ops.is_empty(), "refresh never touches DNS");
    assert_eq!(refreshed.artifacts.len(), 1);

    // The refresh actually happened: the artifact decodes, is the
    // SAME certificate (untouched signed region), and carries the
    // new chain rather than the bind's empty one.
    let original = onomancy_dnssec::certificate::Certificate::decode(&bound.artifacts[0].bytes)?;
    let refreshed_cert =
        onomancy_dnssec::certificate::Certificate::decode(&refreshed.artifacts[0].bytes)?;
    assert!(
        original.same_certificate(&refreshed_cert),
        "same signed region: no key was involved"
    );
    assert_eq!(
        refreshed_cert.dnssec_chain().links().len(),
        1,
        "the fresh chain rode along"
    );
    assert!(
        original.dnssec_chain().links().is_empty(),
        "which the bind's certificate did not have"
    );
    Ok(())
}

/// The refresh's own pre-simulation refusal: records that prove a
/// DIFFERENT document cannot refresh this certificate — the error a
/// user hits when refreshing against the wrong zone fetch.
#[test]
fn refreshing_against_another_documents_records_derives_nothing() -> TestResult {
    let bound = Bind {
        hostname: hostname(),
        document: doc(1),
        generation: generation(2),
        heads: vec![],
        lineage: vec![],
        carriage: DelegationChain::default(),
    }
    .plan(NOW_MS, &signer(1), &MemoryAuthority::default())?;
    let certificate = onomancy_dnssec::certificate::Certificate::decode(&bound.artifacts[0].bytes)?;

    // The zone fetch proves doc(9)'s record, not doc(1)'s.
    let refused = Refresh {
        certificate,
        chain: onomancy_dnssec::chain::DnssecChain::from(vec![vec![0xAB; 8].into()]),
        records: vec![TxtRecord::new(Serial::from(NOW_MS), generation(2), doc(9))],
    }
    .plan(
        onomancy_core::time::UnixSeconds::from(NOW_MS / 1000),
        &MemoryAuthority::default(),
    );

    assert_eq!(refused.unwrap_err(), CeremonyError::DerivesNothing);
    Ok(())
}

#[test]
fn full_lifecycle_bind_rotate_migrate() -> TestResult {
    // The publisher's whole life, each step verified by construction.
    let host = hostname();

    // Bind under G2…
    Bind {
        hostname: host.clone(),
        document: doc(1),
        generation: generation(2),
        heads: vec![],
        lineage: vec![],
        carriage: DelegationChain::default(),
    }
    .plan(NOW_MS, &signer(1), &MemoryAuthority::default())?;

    // …rotate to G3…
    let rotated = Rotate {
        hostname: host.clone(),
        document: doc(1),
        replaced: generation(2),
        prior_lineage: vec![],
        carriage: DelegationChain::default(),
    }
    .plan(
        NOW_MS + 1_000,
        &signer(3),
        &signer(1),
        &MemoryAuthority::default(),
    )?;
    let rotated_record = *rotated.dns_ops[0].record();

    // …then migrate the name to a new document.
    let migrated = Migrate {
        hostname: host,
        predecessor: doc(1),
        successor: doc(5),
        retained: rotated_record,
        successor_generation: generation(6),
        lineage: vec![],
        carriage: DelegationChain::default(),
    }
    .plan(
        NOW_MS + 2_000,
        &signer(1),
        &signer(5),
        &MemoryAuthority::default(),
    )?;

    assert_eq!(migrated.dns_ops.len(), 2);
    Ok(())
}
