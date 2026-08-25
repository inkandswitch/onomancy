//! Ceremony conformance: Plans verify by construction — a returned
//! Plan derived correctly against a simulated zone, and a ceremony
//! that would sabotage its own binding refuses to plan at all.

#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::unwrap_used)]

use ed25519_dalek::SigningKey;
use onomancy_core::{
    name::{dns::DnsName, doc::DocAnchor},
    txt::{generation_key::GenerationKey, record::TxtRecord, serial::Serial},
};
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
        carriage: vec![],
    }
    .plan(NOW_MS, &signer(1))?;

    assert_eq!(plan.dns_ops.len(), 1, "one TXT publish");
    assert!(matches!(plan.dns_ops[0], DnsOp::PublishTxt { .. }));
    assert_eq!(plan.artifacts.len(), 1);
    assert_eq!(plan.artifacts[0].kind, ArtifactKind::Certificate);
    assert!(plan.postconditions.iter().any(|p| matches!(
        p,
        Postcondition::VerifiesFresh(fresh) if fresh.document == doc(1)
    )));
    Ok(())
}

#[test]
fn rotate_emits_statement_and_certificate() -> TestResult {
    let plan = Rotate {
        hostname: hostname(),
        document: doc(1),
        replaced: generation(2),
        prior_lineage: vec![],
        carriage: vec![],
    }
    .plan(NOW_MS, &signer(3), &signer(1))?;

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
        carriage: vec![],
    }
    .plan(NOW_MS, &signer(3), &signer(1))
    .expect("first rotation plans");

    // Recover the signed statement from the plan for the next step.
    let statement = onomancy_core::statement::rotation::RotationStatement::decode(
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
        carriage: vec![],
    }
    .plan(NOW_MS + 1000, &signer(2), &signer(1)); // signer(2) = retired G

    assert_eq!(reuse.unwrap_err(), CeremonyError::GenerationReuse);
}

#[test]
fn rotate_catches_forks_the_reuse_check_cannot_see() -> TestResult {
    // A double-replace hiding in prior_lineage: G2 already retired
    // toward G3, and this ceremony retires G2 again toward G4. The
    // simple reuse check passes (G4 is new) — the simulated
    // derivation catches the set-wise fork.
    let earlier = onomancy_core::statement::rotation::RotationStatement::sign(
        &doc(1),
        &generation(2),
        &SigningKey::from_bytes(&[3; 32]),
        vec![],
    )?;

    let forked = Rotate {
        hostname: hostname(),
        document: doc(1),
        replaced: generation(2), // second replacement of G2
        prior_lineage: vec![earlier],
        carriage: vec![],
    }
    .plan(NOW_MS, &signer(4), &signer(1));

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
        carriage: vec![],
    }
    .plan(NOW_MS, &signer(1), &signer(5))?;

    assert_eq!(plan.dns_ops.len(), 2, "retain old + publish new");
    assert!(matches!(plan.dns_ops[0], DnsOp::RetainTxt { .. }));
    assert!(matches!(plan.dns_ops[1], DnsOp::PublishTxt { .. }));
    assert!(
        plan.artifacts
            .iter()
            .any(|a| a.kind == ArtifactKind::SuccessorStatement)
    );
    // The simulation already asserted the successor wins the
    // dual-publish derivation via the proof (not zone-state luck).
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
        carriage: vec![],
    };
    let bound = bind.plan(NOW_MS, &signer(1))?;

    let certificate = onomancy_core::certificate::Certificate::decode(&bound.artifacts[0].bytes)?;
    let record = *bound.dns_ops[0].record();

    let refreshed = Refresh {
        certificate,
        chain: onomancy_core::certificate::chain::DnssecChain::from(vec![vec![0xAB; 8].into()]),
        records: vec![record],
    }
    .plan(onomancy_core::time::UnixSeconds::from(NOW_MS / 1000))?;

    assert!(refreshed.dns_ops.is_empty(), "refresh never touches DNS");
    assert_eq!(refreshed.artifacts.len(), 1);
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
        carriage: vec![],
    }
    .plan(NOW_MS, &signer(1))?;

    // …rotate to G3…
    let rotated = Rotate {
        hostname: host.clone(),
        document: doc(1),
        replaced: generation(2),
        prior_lineage: vec![],
        carriage: vec![],
    }
    .plan(NOW_MS + 1_000, &signer(3), &signer(1))?;
    let rotated_record = *rotated.dns_ops[0].record();

    // …then migrate the name to a new document.
    let migrated = Migrate {
        hostname: host,
        predecessor: doc(1),
        successor: doc(5),
        retained: rotated_record,
        successor_generation: generation(6),
        lineage: vec![],
        carriage: vec![],
    }
    .plan(NOW_MS + 2_000, &signer(1), &signer(5))?;

    assert_eq!(migrated.dns_ops.len(), 2);
    Ok(())
}
