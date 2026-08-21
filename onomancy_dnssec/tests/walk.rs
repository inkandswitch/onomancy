//! End-to-end walk tests over the shared synthetic two-zone tree
//! (root → expede.wtf → `_onomancy` leaf), signed with real Ed25519
//! keys via `test_utils`.

#![allow(clippy::indexing_slicing, clippy::panic)]

use onomancy_core::{
    cert::chain::{ChainLink, DnssecChain},
    name::dns::DnsName,
    time::UnixSeconds,
    txt::serial::Serial,
};
use onomancy_protocol::verifier_state::seam::{ChainProof, ChainValidator as _};
use testresult::TestResult;

use onomancy_dnssec::{
    test_utils::{binding_chain, fixtures, link, txt_record, zone, ChainWindows, Zone},
    validator::{Validator, WalkError},
    wire::{
        name::Name,
        record::{Record, RrType, CLASS_IN},
    },
};

fn hostname() -> TestResult<DnsName> {
    Ok(DnsName::parse("expede.wtf")?)
}

fn leaf() -> TestResult<Record> {
    Ok(txt_record(&hostname()?, &fixtures::fixture_txt_text()))
}

/// The happy-path chain with per-link windows exercising the ∩.
fn happy_chain(root: &Zone, child: &Zone) -> TestResult<DnssecChain> {
    Ok(binding_chain(
        root,
        child,
        leaf()?,
        ChainWindows {
            root: (1_000, 5_000),
            delegation: (1_200, 6_000),
            child: (1_100, 4_500),
            leaf: (1_500, 4_000),
        },
    ))
}

#[test]
fn a_genuine_chain_walks_to_a_binding_proof() -> TestResult {
    let root = zone(".", 1);
    let child = zone("expede.wtf", 2);
    let validator = Validator::new(vec![root.anchor()]);

    let ChainProof { records, window } =
        validator.validate_detailed(&hostname()?, &happy_chain(&root, &child)?)?;

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].serial(), Serial::from(fixtures::FIXTURE_SERIAL));
    // ∩-window: max inception 1500, min expiration 4000.
    assert_eq!(window.inception(), UnixSeconds::from(1_500));
    assert_eq!(window.expiration(), UnixSeconds::from(4_000));
    Ok(())
}

#[test]
fn unanchored_roots_are_rejected() -> TestResult {
    let root = zone(".", 1);
    let child = zone("expede.wtf", 2);
    let wrong = zone(".", 9);

    let validator = Validator::new(vec![wrong.anchor()]);
    assert_eq!(
        validator.validate_detailed(&hostname()?, &happy_chain(&root, &child)?),
        Err(WalkError::Unanchored)
    );
    Ok(())
}

#[test]
fn a_tampered_leaf_fails_the_walk() -> TestResult {
    let root = zone(".", 1);
    let child = zone("expede.wtf", 2);
    let chain = happy_chain(&root, &child)?;

    // Flip one byte inside the TXT link's RDATA region.
    let mut links: Vec<ChainLink> = chain.links().to_vec();
    let mut leaf_bytes = links[3].as_bytes().to_vec();
    let at = leaf_bytes.len() / 2;
    leaf_bytes[at] ^= 0x01;
    links[3] = ChainLink::from(leaf_bytes);

    let validator = Validator::new(vec![root.anchor()]);
    let outcome = validator.validate_detailed(&hostname()?, &DnssecChain::from(links));

    assert!(outcome.is_err(), "tampered leaf must not validate");
    Ok(())
}

#[test]
fn disjoint_windows_are_invalid_not_stale() -> TestResult {
    let root = zone(".", 1);
    let child = zone("expede.wtf", 2);

    let chain = binding_chain(
        &root,
        &child,
        leaf()?,
        ChainWindows {
            root: (1_000, 2_000),
            delegation: (1_000, 2_000),
            child: (1_000, 2_000),
            // Leaf window begins after every other window has ended.
            leaf: (3_000, 4_000),
        },
    );

    let validator = Validator::new(vec![root.anchor()]);
    assert_eq!(
        validator.validate_detailed(&hostname()?, &chain),
        Err(WalkError::EmptyWindow)
    );
    Ok(())
}

#[test]
fn mismatched_ds_blocks_the_descent() -> TestResult {
    let root = zone(".", 1);
    let child = zone("expede.wtf", 2);
    let imposter = zone("expede.wtf", 9);

    let txt = leaf()?;
    // DS commits to the REAL child; the chain presents the imposter's
    // keys.
    let ds = Zone::ds_record_for(&child);
    let window = (1_000, 5_000);

    let chain = DnssecChain::from(vec![
        link(&[
            root.dnskey_record.clone(),
            root.rrsig(core::slice::from_ref(&root.dnskey_record), window),
        ]),
        link(&[ds.clone(), root.rrsig(&[ds], window)]),
        link(&[
            imposter.dnskey_record.clone(),
            imposter.rrsig(core::slice::from_ref(&imposter.dnskey_record), window),
        ]),
        link(&[txt.clone(), imposter.rrsig(&[txt], window)]),
    ]);

    let validator = Validator::new(vec![root.anchor()]);
    assert_eq!(
        validator.validate_detailed(&hostname()?, &chain),
        Err(WalkError::DsMismatch)
    );
    Ok(())
}

#[test]
fn denial_only_chains_prove_nothing() -> TestResult {
    // Negative proofs are out at v0 (ADR-045): a chain whose leaf is
    // an NSEC denial — even validly signed — is not a proof of
    // anything, and the denial link itself is skipped unverified.
    let root = zone(".", 1);
    let child = zone("expede.wtf", 2);

    let mut nsec_rdata = Vec::new();
    let next: onomancy_dnssec::wire::name::Name = "zzz.expede.wtf".parse()?;
    next.write(&mut nsec_rdata);
    nsec_rdata.extend_from_slice(&[0, 1, 0x40]); // bitmap: A exists

    let nsec = Record {
        owner: child.name.clone(),
        rtype: RrType::NSEC,
        class: CLASS_IN,
        ttl: 900,
        rdata: nsec_rdata,
    };
    let ds = Zone::ds_record_for(&child);
    let window = (1_000, 5_000);

    let chain = DnssecChain::from(vec![
        link(&[
            root.dnskey_record.clone(),
            root.rrsig(core::slice::from_ref(&root.dnskey_record), window),
        ]),
        link(&[ds.clone(), root.rrsig(&[ds], window)]),
        link(&[
            child.dnskey_record.clone(),
            child.rrsig(core::slice::from_ref(&child.dnskey_record), window),
        ]),
        link(&[nsec.clone(), child.rrsig(&[nsec], (2_000, 4_500))]),
    ]);

    let validator = Validator::new(vec![root.anchor()]);
    assert_eq!(
        validator.validate_detailed(&hostname()?, &chain),
        Err(WalkError::MissingLeaf)
    );
    Ok(())
}

#[test]
fn the_seam_collapses_detail_to_invalid_chain() -> TestResult {
    let root = zone(".", 1);
    let child = zone("expede.wtf", 2);

    let validator = Validator::new(vec![root.anchor()]);
    assert!(validator
        .validate(&hostname()?, &happy_chain(&root, &child)?)
        .is_ok());
    assert!(validator
        .validate(&hostname()?, &DnssecChain::default())
        .is_err());
    Ok(())
}

/// A CNAME record at `owner` pointing at `target`.
fn cname_record(owner: Name, target: &Name) -> Record {
    let mut rdata = Vec::new();
    target.write(&mut rdata);

    Record {
        owner,
        rtype: RrType::CNAME,
        class: CLASS_IN,
        ttl: 900,
        rdata,
    }
}

/// A CNAME into a *sibling* zone: the walk re-enters at the anchored
/// root and descends the target's own branch. This is the chain shape
/// `chain_assembly` emits for cross-zone indirection.
#[test]
fn a_cross_zone_cname_reroots_and_walks_to_the_target_branch() -> TestResult {
    let root = zone(".", 1);
    let source = zone("expede.wtf", 2);
    let target_zone = zone("example.net", 3);
    let validator = Validator::new(vec![root.anchor()]);

    let target_owner: Name = "binding.example.net".parse()?;
    let cname = cname_record(Name::onomancy_owner(&hostname()?), &target_owner);
    let txt = Record {
        owner: target_owner,
        ..txt_record(&hostname()?, &fixtures::fixture_txt_text())
    };

    let source_ds = Zone::ds_record_for(&source);
    let target_ds = Zone::ds_record_for(&target_zone);
    let window = (1_000, 5_000);

    let chain = DnssecChain::from(vec![
        link(&[
            root.dnskey_record.clone(),
            root.rrsig(core::slice::from_ref(&root.dnskey_record), window),
        ]),
        link(&[source_ds.clone(), root.rrsig(&[source_ds], window)]),
        link(&[
            source.dnskey_record.clone(),
            source.rrsig(core::slice::from_ref(&source.dnskey_record), window),
        ]),
        // The hop out of the subtree, signed by the source zone…
        link(&[cname.clone(), source.rrsig(&[cname], window)]),
        // …then the target's branch, descended from the ROOT again.
        link(&[target_ds.clone(), root.rrsig(&[target_ds], window)]),
        link(&[
            target_zone.dnskey_record.clone(),
            target_zone.rrsig(core::slice::from_ref(&target_zone.dnskey_record), window),
        ]),
        link(&[txt.clone(), target_zone.rrsig(&[txt], window)]),
    ]);

    let ChainProof { records, .. } = validator.validate_detailed(&hostname()?, &chain)?;
    assert_eq!(records.len(), 1);
    Ok(())
}

/// Without the target branch's cuts, the cross-zone TXT must NOT
/// verify — re-rooting alone confers nothing.
#[test]
fn a_cross_zone_cname_without_target_cuts_is_rejected() -> TestResult {
    let root = zone(".", 1);
    let source = zone("expede.wtf", 2);
    let target_zone = zone("example.net", 3);
    let validator = Validator::new(vec![root.anchor()]);

    let target_owner: Name = "binding.example.net".parse()?;
    let cname = cname_record(Name::onomancy_owner(&hostname()?), &target_owner);
    let txt = Record {
        owner: target_owner,
        ..txt_record(&hostname()?, &fixtures::fixture_txt_text())
    };

    let source_ds = Zone::ds_record_for(&source);
    let window = (1_000, 5_000);

    let chain = DnssecChain::from(vec![
        link(&[
            root.dnskey_record.clone(),
            root.rrsig(core::slice::from_ref(&root.dnskey_record), window),
        ]),
        link(&[source_ds.clone(), root.rrsig(&[source_ds], window)]),
        link(&[
            source.dnskey_record.clone(),
            source.rrsig(core::slice::from_ref(&source.dnskey_record), window),
        ]),
        link(&[cname.clone(), source.rrsig(&[cname], window)]),
        // No DS/DNSKEY for example.net: the TXT is signed by keys the
        // walk has never anchored.
        link(&[txt.clone(), target_zone.rrsig(&[txt], window)]),
    ]);

    assert!(validator.validate_detailed(&hostname()?, &chain).is_err());
    Ok(())
}
