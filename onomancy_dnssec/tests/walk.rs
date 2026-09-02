//! End-to-end walk tests over the shared synthetic two-zone tree
//! (root → expede.wtf → `_onomancy` leaf), signed with real Ed25519
//! keys via `test_utils`.

#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

use onomancy_core::time::UnixSeconds;
use onomancy_dnssec::{
    chain::{ChainLink, DnssecChain},
    chain_proof::{ChainProof, ChainValidator as _, InvalidChain},
    crypto::VerifyError,
    dns_name::DnsName,
    txt::serial::Serial,
};
use testresult::TestResult;

use onomancy_dnssec::{
    test_utils::{ChainWindows, Zone, binding_chain, fixtures, link, txt_record, zone},
    validator::{MAX_CNAME_HOPS, Validator, WalkError},
    wire::{
        name::{Name, ParseNameError},
        record::{CLASS_IN, Record},
        rr_type::RrType,
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
fn hostnames_too_long_for_the_service_label_are_unrepresentable() -> TestResult {
    // 63 + 63 + 63 + 52 octets and three dots: 244 presentation
    // octets — legal hostname grammar (≤ 253), but `_onomancy.`
    // leaves wire room for only 243.
    let long = format!("{a}.{a}.{a}.{b}", a = "a".repeat(63), b = "b".repeat(52));
    let hostname = DnsName::parse(&long)?;

    let root = zone(".", 1);
    let child = zone("expede.wtf", 2);
    let validator = Validator::new(vec![root.anchor()]);

    assert_eq!(
        validator.validate_detailed(&hostname, &happy_chain(&root, &child)?),
        Err(WalkError::UnrepresentableName(ParseNameError::NameTooLong))
    );
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
    // Negative proofs are out at v0: a chain whose leaf is
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

    // The seam is pure delegation: the SAME proof on the Ok side (a
    // seam impl returning a wrong-but-Ok proof would be a live bug),
    // and detail collapsed to the unit error on the Err side.
    let chain = happy_chain(&root, &child)?;
    assert_eq!(
        validator.validate(&hostname()?, &chain),
        validator
            .validate_detailed(&hostname()?, &chain)
            .map_err(|_| InvalidChain)
    );

    assert_eq!(
        validator.validate(&hostname()?, &DnssecChain::default()),
        Err(InvalidChain)
    );
    Ok(())
}

#[test]
fn an_empty_chain_is_empty_not_merely_invalid() -> TestResult {
    let root = zone(".", 1);
    let validator = Validator::new(vec![root.anchor()]);

    assert_eq!(
        validator.validate_detailed(&hostname()?, &DnssecChain::default()),
        Err(WalkError::Empty)
    );
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
/// `onomancy_chain` emits for cross-zone indirection.
#[test]
fn a_cross_zone_cname_reroots_and_walks_to_the_target_branch() -> TestResult {
    let root = zone(".", 1);
    let source = zone("expede.wtf", 2);
    let target_zone = zone("example.net", 3);
    let validator = Validator::new(vec![root.anchor()]);

    let target_owner: Name = "binding.example.net".parse()?;
    let cname = cname_record(Name::onomancy_owner(&hostname()?)?, &target_owner);
    let txt = Record {
        owner: target_owner,
        ..txt_record(&hostname()?, &fixtures::fixture_txt_text())
    };

    let source_ds = Zone::ds_record_for(&source);
    let target_ds = Zone::ds_record_for(&target_zone);

    // Distinct windows on both sides of the re-root: the ∩ must keep
    // accumulating across branches (the doc comment's claim, tested).
    let chain = DnssecChain::from(vec![
        link(&[
            root.dnskey_record.clone(),
            root.rrsig(core::slice::from_ref(&root.dnskey_record), (1_000, 5_000)),
        ]),
        link(&[source_ds.clone(), root.rrsig(&[source_ds], (1_100, 5_500))]),
        link(&[
            source.dnskey_record.clone(),
            source.rrsig(core::slice::from_ref(&source.dnskey_record), (1_050, 4_800)),
        ]),
        // The hop out of the subtree, signed by the source zone…
        link(&[cname.clone(), source.rrsig(&[cname], (1_200, 6_000))]),
        // …then the target's branch, descended from the ROOT again.
        link(&[target_ds.clone(), root.rrsig(&[target_ds], (1_500, 4_400))]),
        link(&[
            target_zone.dnskey_record.clone(),
            target_zone.rrsig(
                core::slice::from_ref(&target_zone.dnskey_record),
                (1_300, 4_200),
            ),
        ]),
        link(&[txt.clone(), target_zone.rrsig(&[txt], (1_400, 4_300))]),
    ]);

    let ChainProof { records, window } = validator.validate_detailed(&hostname()?, &chain)?;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].serial(), Serial::from(fixtures::FIXTURE_SERIAL));
    // ∩ across BOTH branches: max inception 1500, min expiration 4200.
    assert_eq!(window.inception(), UnixSeconds::from(1_500));
    assert_eq!(window.expiration(), UnixSeconds::from(4_200));
    Ok(())
}

/// A CNAME staying INSIDE the current zone but landing under a
/// deeper signed cut: no re-root — the parent zone signs the child's
/// DS and the walk descends the cut. This is the chain shape
/// `onomancy_chain` emits for in-zone indirection (its
/// `in_zone_cnames_descend_intermediate_deeper_cuts` test builds
/// exactly this sequence).
#[test]
fn an_in_zone_cname_descends_a_deeper_cut_without_rerooting() -> TestResult {
    let root = zone(".", 1);
    let source = zone("expede.wtf", 2);
    let deeper = zone("certs.expede.wtf", 3);
    let validator = Validator::new(vec![root.anchor()]);

    let target_owner: Name = "binding.certs.expede.wtf".parse()?;
    let cname = cname_record(Name::onomancy_owner(&hostname()?)?, &target_owner);
    let txt = Record {
        owner: target_owner,
        ..txt_record(&hostname()?, &fixtures::fixture_txt_text())
    };

    let source_ds = Zone::ds_record_for(&source);
    let deeper_ds = Zone::ds_record_for(&deeper);

    // Distinct per-link windows: the ∩ must keep accumulating through
    // the deeper cut.
    let chain = DnssecChain::from(vec![
        link(&[
            root.dnskey_record.clone(),
            root.rrsig(core::slice::from_ref(&root.dnskey_record), (1_000, 5_000)),
        ]),
        link(&[source_ds.clone(), root.rrsig(&[source_ds], (1_100, 5_500))]),
        link(&[
            source.dnskey_record.clone(),
            source.rrsig(core::slice::from_ref(&source.dnskey_record), (1_050, 4_800)),
        ]),
        // The in-zone hop, signed by the source zone…
        link(&[cname.clone(), source.rrsig(&[cname], (1_200, 6_000))]),
        // …then the deeper cut, its DS signed by the SOURCE zone (no
        // re-root: the source's links are not repeated).
        link(&[
            deeper_ds.clone(),
            source.rrsig(&[deeper_ds], (1_600, 4_600)),
        ]),
        link(&[
            deeper.dnskey_record.clone(),
            deeper.rrsig(core::slice::from_ref(&deeper.dnskey_record), (1_300, 4_100)),
        ]),
        link(&[txt.clone(), deeper.rrsig(&[txt], (1_400, 4_300))]),
    ]);

    let ChainProof { records, window } = validator.validate_detailed(&hostname()?, &chain)?;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].serial(), Serial::from(fixtures::FIXTURE_SERIAL));
    // ∩ through the deeper cut: max inception 1600, min expiration 4100.
    assert_eq!(window.inception(), UnixSeconds::from(1_600));
    assert_eq!(window.expiration(), UnixSeconds::from(4_100));
    Ok(())
}

/// Without the deeper cut's links, a TXT signed by the child zone's
/// keys must NOT verify: the walk never descended to those keys.
#[test]
fn an_in_zone_cname_to_a_deeper_cut_without_its_links_is_rejected() -> TestResult {
    let root = zone(".", 1);
    let source = zone("expede.wtf", 2);
    let deeper = zone("certs.expede.wtf", 3);
    let validator = Validator::new(vec![root.anchor()]);

    let target_owner: Name = "binding.certs.expede.wtf".parse()?;
    let cname = cname_record(Name::onomancy_owner(&hostname()?)?, &target_owner);
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
        // No DS/DNSKEY for certs.expede.wtf: the TXT is signed by
        // keys the walk has never descended to.
        link(&[txt.clone(), deeper.rrsig(&[txt], window)]),
    ]);

    // Exactly SignerMismatch: the walk still trusts expede.wtf's keys,
    // and the RRSIG names certs.expede.wtf. A different error here
    // would mean the un-descended-keys rejection went dead.
    assert_eq!(
        validator.validate_detailed(&hostname()?, &chain),
        Err(WalkError::SignerMismatch)
    );
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
    let cname = cname_record(Name::onomancy_owner(&hostname()?)?, &target_owner);
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

    // Exactly SignerMismatch: after the re-root the current zone is
    // the ROOT, and the RRSIG names example.net.
    assert_eq!(
        validator.validate_detailed(&hostname()?, &chain),
        Err(WalkError::SignerMismatch)
    );
    Ok(())
}

/// A chain descending to `expede.wtf`, then `hops` in-zone CNAME
/// indirections on the `_onomancy` owner, ending at a TXT leaf.
fn chain_with_cname_hops(root: &Zone, child: &Zone, hops: usize) -> TestResult<DnssecChain> {
    let window = (1_000, 5_000);
    let ds = Zone::ds_record_for(child);

    let mut links = vec![
        link(&[
            root.dnskey_record.clone(),
            root.rrsig(core::slice::from_ref(&root.dnskey_record), window),
        ]),
        link(&[ds.clone(), root.rrsig(&[ds], window)]),
        link(&[
            child.dnskey_record.clone(),
            child.rrsig(core::slice::from_ref(&child.dnskey_record), window),
        ]),
    ];

    let mut owner = Name::onomancy_owner(&hostname()?)?;
    for hop in 0..hops {
        let target: Name = format!("hop{hop}.expede.wtf").parse()?;
        let cname = cname_record(owner, &target);
        links.push(link(&[cname.clone(), child.rrsig(&[cname], window)]));
        owner = target;
    }

    let txt = Record {
        owner,
        ..txt_record(&hostname()?, &fixtures::fixture_txt_text())
    };
    links.push(link(&[txt.clone(), child.rrsig(&[txt], window)]));

    Ok(DnssecChain::from(links))
}

/// The CNAME bound, both sides: exactly `MAX_CNAME_HOPS` hops still
/// validate; one more is rejected as `TooManyCnames`. The bound is
/// semi-exhaustively swept so an off-by-one cannot hide at any count.
#[test]
fn cname_hops_validate_up_to_the_bound_and_fail_past_it() -> TestResult {
    let root = zone(".", 1);
    let child = zone("expede.wtf", 2);
    let validator = Validator::new(vec![root.anchor()]);

    for hops in 0..=MAX_CNAME_HOPS {
        let proof =
            validator.validate_detailed(&hostname()?, &chain_with_cname_hops(&root, &child, hops)?);
        assert!(proof.is_ok(), "{hops} hops must validate: {proof:?}");
    }

    assert_eq!(
        validator.validate_detailed(
            &hostname()?,
            &chain_with_cname_hops(&root, &child, MAX_CNAME_HOPS + 1)?
        ),
        Err(WalkError::TooManyCnames)
    );
    Ok(())
}

/// A CNAME loop (A→B→A→…) is terminated BY the hop bound — nothing
/// else in the walk stops it.
#[test]
fn cname_loops_are_terminated_by_the_hop_bound() -> TestResult {
    let root = zone(".", 1);
    let child = zone("expede.wtf", 2);
    let validator = Validator::new(vec![root.anchor()]);
    let window = (1_000, 5_000);
    let ds = Zone::ds_record_for(&child);

    let a = Name::onomancy_owner(&hostname()?)?;
    let b: Name = "b.expede.wtf".parse()?;
    let a_to_b = cname_record(a.clone(), &b);
    let b_to_a = cname_record(b, &a);

    let mut links = vec![
        link(&[
            root.dnskey_record.clone(),
            root.rrsig(core::slice::from_ref(&root.dnskey_record), window),
        ]),
        link(&[ds.clone(), root.rrsig(&[ds], window)]),
        link(&[
            child.dnskey_record.clone(),
            child.rrsig(core::slice::from_ref(&child.dnskey_record), window),
        ]),
    ];
    for hop in 0..=MAX_CNAME_HOPS {
        let cname = if hop % 2 == 0 { &a_to_b } else { &b_to_a };
        links.push(link(&[
            cname.clone(),
            child.rrsig(core::slice::from_ref(cname), window),
        ]));
    }

    assert_eq!(
        validator.validate_detailed(&hostname()?, &DnssecChain::from(links)),
        Err(WalkError::TooManyCnames)
    );
    Ok(())
}

/// Parent overreach across a cut: a leaf signed by the ROOT zone's
/// keys after the walk has descended to the child MUST be rejected as
/// a signer mismatch — a parent cannot speak for names below a cut it
/// has delegated away.
#[test]
fn a_parent_signed_leaf_below_the_cut_is_a_signer_mismatch() -> TestResult {
    let root = zone(".", 1);
    let child = zone("expede.wtf", 2);
    let validator = Validator::new(vec![root.anchor()]);
    let window = (1_000, 5_000);
    let ds = Zone::ds_record_for(&child);
    let txt = leaf()?;

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
        // The overreach: the ROOT signs the leaf below the cut.
        link(&[txt.clone(), root.rrsig(&[txt], window)]),
    ]);

    assert_eq!(
        validator.validate_detailed(&hostname()?, &chain),
        Err(WalkError::SignerMismatch)
    );
    Ok(())
}

/// A DS introducing a SIBLING zone (not below the current one) breaks
/// the strict-descent rule.
#[test]
fn a_sideways_delegation_is_not_descending() -> TestResult {
    let root = zone(".", 1);
    let child = zone("expede.wtf", 2);
    let sibling = zone("example.net", 3);
    let validator = Validator::new(vec![root.anchor()]);
    let window = (1_000, 5_000);

    let child_ds = Zone::ds_record_for(&child);
    let sibling_ds = Zone::ds_record_for(&sibling);
    let txt = leaf()?;

    let chain = DnssecChain::from(vec![
        link(&[
            root.dnskey_record.clone(),
            root.rrsig(core::slice::from_ref(&root.dnskey_record), window),
        ]),
        link(&[child_ds.clone(), root.rrsig(&[child_ds], window)]),
        link(&[
            child.dnskey_record.clone(),
            child.rrsig(core::slice::from_ref(&child.dnskey_record), window),
        ]),
        // example.net is NOT below expede.wtf: sideways, not down.
        link(&[sibling_ds.clone(), child.rrsig(&[sibling_ds], window)]),
        link(&[
            sibling.dnskey_record.clone(),
            sibling.rrsig(core::slice::from_ref(&sibling.dnskey_record), window),
        ]),
        link(&[txt.clone(), child.rrsig(&[txt], window)]),
    ]);

    assert_eq!(
        validator.validate_detailed(&hostname()?, &chain),
        Err(WalkError::NotDescending)
    );
    Ok(())
}

/// A DS at the CURRENT zone's own name (a self-delegation) also
/// violates strict descent: `zone == child` is not down either.
#[test]
fn a_self_delegation_is_not_descending() -> TestResult {
    let root = zone(".", 1);
    let child = zone("expede.wtf", 2);
    let validator = Validator::new(vec![root.anchor()]);
    let window = (1_000, 5_000);

    let ds = Zone::ds_record_for(&child);
    let self_ds = Record {
        owner: root.name.clone(),
        ..Zone::ds_record_for(&child)
    };
    let txt = leaf()?;

    let chain = DnssecChain::from(vec![
        link(&[
            root.dnskey_record.clone(),
            root.rrsig(core::slice::from_ref(&root.dnskey_record), window),
        ]),
        // A DS at the root's own name while the current zone IS the
        // root: not a descent.
        link(&[self_ds.clone(), root.rrsig(&[self_ds], window)]),
        link(&[ds.clone(), root.rrsig(&[ds], window)]),
        link(&[
            child.dnskey_record.clone(),
            child.rrsig(core::slice::from_ref(&child.dnskey_record), window),
        ]),
        link(&[txt.clone(), child.rrsig(&[txt], window)]),
    ]);

    assert_eq!(
        validator.validate_detailed(&hostname()?, &chain),
        Err(WalkError::NotDescending)
    );
    Ok(())
}

/// A validly-SIGNED link carrying garbage DS RDATA: signatures cover
/// bytes, not parseability, so this branch is reachable behind a good
/// signature and must fail as malformed RDATA — never verify-then-
/// crash, never pass.
#[test]
fn garbage_ds_rdata_behind_a_valid_signature_is_malformed() -> TestResult {
    let root = zone(".", 1);
    let child = zone("expede.wtf", 2);
    let validator = Validator::new(vec![root.anchor()]);
    let window = (1_000, 5_000);

    let garbage_ds = Record {
        rdata: vec![0xFF, 0xEE, 0xDD],
        ..Zone::ds_record_for(&child)
    };
    let txt = leaf()?;

    let chain = DnssecChain::from(vec![
        link(&[
            root.dnskey_record.clone(),
            root.rrsig(core::slice::from_ref(&root.dnskey_record), window),
        ]),
        // The root GENUINELY signs the garbage bytes.
        link(&[garbage_ds.clone(), root.rrsig(&[garbage_ds], window)]),
        link(&[
            child.dnskey_record.clone(),
            child.rrsig(core::slice::from_ref(&child.dnskey_record), window),
        ]),
        link(&[txt.clone(), child.rrsig(&[txt], window)]),
    ]);

    assert_eq!(
        validator.validate_detailed(&hostname()?, &chain),
        Err(WalkError::MalformedRdata { rtype: RrType::DS })
    );
    Ok(())
}

/// Garbage CNAME RDATA behind a valid signature: same rule at the
/// indirection hop.
#[test]
fn garbage_cname_rdata_behind_a_valid_signature_is_malformed() -> TestResult {
    let root = zone(".", 1);
    let child = zone("expede.wtf", 2);
    let validator = Validator::new(vec![root.anchor()]);
    let window = (1_000, 5_000);
    let ds = Zone::ds_record_for(&child);

    let garbage_cname = Record {
        owner: Name::onomancy_owner(&hostname()?)?,
        rtype: RrType::CNAME,
        class: CLASS_IN,
        ttl: 900,
        rdata: vec![0xFF, 0xFF],
    };

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
        link(&[garbage_cname.clone(), child.rrsig(&[garbage_cname], window)]),
    ]);

    assert_eq!(
        validator.validate_detailed(&hostname()?, &chain),
        Err(WalkError::MalformedRdata {
            rtype: RrType::CNAME
        })
    );
    Ok(())
}

/// Garbage DNSKEY RDATA at a cut: rejected before any DS matching or
/// signature work.
#[test]
fn garbage_child_dnskey_rdata_is_malformed() -> TestResult {
    let root = zone(".", 1);
    let child = zone("expede.wtf", 2);
    let validator = Validator::new(vec![root.anchor()]);
    let window = (1_000, 5_000);
    let ds = Zone::ds_record_for(&child);

    let garbage_dnskey = Record {
        rdata: vec![0x01],
        ..child.dnskey_record.clone()
    };
    let txt = leaf()?;

    let chain = DnssecChain::from(vec![
        link(&[
            root.dnskey_record.clone(),
            root.rrsig(core::slice::from_ref(&root.dnskey_record), window),
        ]),
        link(&[ds.clone(), root.rrsig(&[ds], window)]),
        link(&[
            garbage_dnskey.clone(),
            child.rrsig(&[garbage_dnskey], window),
        ]),
        link(&[txt.clone(), child.rrsig(&[txt], window)]),
    ]);

    assert_eq!(
        validator.validate_detailed(&hostname()?, &chain),
        Err(WalkError::MalformedRdata {
            rtype: RrType::DNSKEY
        })
    );
    Ok(())
}

/// A leaf at an owner other than the query target — with NO CNAME
/// explaining the move — is a spliced answer for the wrong name.
#[test]
fn a_leaf_at_the_wrong_owner_without_a_cname_is_rejected() -> TestResult {
    let root = zone(".", 1);
    let child = zone("expede.wtf", 2);
    let validator = Validator::new(vec![root.anchor()]);
    let window = (1_000, 5_000);
    let ds = Zone::ds_record_for(&child);

    let elsewhere: Name = "elsewhere.expede.wtf".parse()?;
    let txt = Record {
        owner: elsewhere,
        ..txt_record(&hostname()?, &fixtures::fixture_txt_text())
    };

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
        link(&[txt.clone(), child.rrsig(&[txt], window)]),
    ]);

    assert_eq!(
        validator.validate_detailed(&hostname()?, &chain),
        Err(WalkError::WrongOwner)
    );
    Ok(())
}

/// A link mixing record types fails at the link grammar — surfacing
/// as a Parse error, before any trust decisions.
#[test]
fn a_mixed_rrset_link_fails_at_parse() -> TestResult {
    let root = zone(".", 1);
    let child = zone("expede.wtf", 2);
    let validator = Validator::new(vec![root.anchor()]);
    let window = (1_000, 5_000);

    let ds = Zone::ds_record_for(&child);
    let txt = leaf()?;
    // One link framing a DS AND a TXT: not an RRset.
    let mixed = link(&[ds.clone(), txt, root.rrsig(&[ds], window)]);

    let chain = DnssecChain::from(vec![
        link(&[
            root.dnskey_record.clone(),
            root.rrsig(core::slice::from_ref(&root.dnskey_record), window),
        ]),
        mixed,
    ]);

    assert!(matches!(
        validator.validate_detailed(&hostname()?, &chain),
        Err(WalkError::Parse(_))
    ));
    Ok(())
}

/// An RRSIG claiming an unsupported algorithm in an otherwise-valid
/// chain: invalid ✗, never insecure-but-ok. (The zone key is Ed25519,
/// so the mismatch surfaces at the key/signature algorithm check; the
/// unsupported-dispatch arm itself is unit-pinned in `crypto.rs`.)
#[test]
fn an_unsupported_signature_algorithm_never_validates() -> TestResult {
    let root = zone(".", 1);
    let child = zone("expede.wtf", 2);
    let validator = Validator::new(vec![root.anchor()]);
    let window = (1_000, 5_000);
    let ds = Zone::ds_record_for(&child);

    let txt = leaf()?;
    let mut leaf_rrsig = child.rrsig(core::slice::from_ref(&txt), window);
    // RRSIG RDATA layout: type covered (2), then the algorithm octet.
    // 5 = RSA/SHA-1: unsupported at v0 (D13).
    leaf_rrsig.rdata[2] = 5;

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
        link(&[txt, leaf_rrsig]),
    ]);

    assert_eq!(
        validator.validate_detailed(&hostname()?, &chain),
        Err(WalkError::Verify(VerifyError::AlgorithmMismatch {
            key: onomancy_dnssec::wire::algorithm::Algorithm::ED25519,
            signature: onomancy_dnssec::wire::algorithm::Algorithm::new(5),
        }))
    );
    Ok(())
}

/// Key tags are hints, not commitments (they collide legally): an
/// RRSIG whose tag field names the WRONG key of a two-key zone must
/// still verify via the all-keys fallback.
#[test]
fn a_misleading_key_tag_hint_falls_back_to_every_zone_key() -> TestResult {
    let anchored = zone(".", 1);
    let cosigner = zone(".", 5);
    let child = zone("expede.wtf", 2);
    let window = (1_000, 5_000);
    let ds = Zone::ds_record_for(&child);
    let txt = leaf()?;

    // Two keys at the root; the hint must actually mislead.
    assert_ne!(anchored.dnskey().key_tag(), cosigner.dnskey().key_tag());

    // The root DNSKEY RRset carries BOTH keys; every root-signed link
    // is signed by the CO-SIGNER but hints the ANCHORED key's tag.
    let root_keys = [
        anchored.dnskey_record.clone(),
        cosigner.dnskey_record.clone(),
    ];
    let misleading = |rrset: &[Record]| -> Record {
        cosigner.rrsig_with_key_tag(rrset, window, anchored.dnskey().key_tag())
    };

    let chain = DnssecChain::from(vec![
        link(&[
            root_keys[0].clone(),
            root_keys[1].clone(),
            misleading(&root_keys),
        ]),
        link(&[ds.clone(), misleading(&[ds])]),
        link(&[
            child.dnskey_record.clone(),
            child.rrsig(core::slice::from_ref(&child.dnskey_record), window),
        ]),
        link(&[txt.clone(), child.rrsig(&[txt], window)]),
    ]);

    // Anchor on the ANCHORED key: entry succeeds via the anchor match,
    // and every verification succeeds only if the hinted-key miss
    // falls back to the co-signer.
    let validator = Validator::new(vec![anchored.anchor()]);
    let ChainProof { records, .. } = validator.validate_detailed(&hostname()?, &chain)?;
    assert_eq!(records[0].serial(), Serial::from(fixtures::FIXTURE_SERIAL));
    Ok(())
}

/// Denial links are skipped UNVERIFIED on the success path too: an
/// interposed NSEC whose RRSIG window would empty the ∩ must not
/// touch the proof window.
#[test]
fn a_skipped_denial_never_narrows_the_proof_window() -> TestResult {
    let root = zone(".", 1);
    let child = zone("expede.wtf", 2);
    let validator = Validator::new(vec![root.anchor()]);
    let window = (1_000, 5_000);
    let ds = Zone::ds_record_for(&child);
    let txt = leaf()?;

    let mut nsec_rdata = Vec::new();
    let next: Name = "zzz.expede.wtf".parse()?;
    next.write(&mut nsec_rdata);
    nsec_rdata.extend_from_slice(&[0, 1, 0x40]); // bitmap: A exists
    let nsec = Record {
        owner: child.name.clone(),
        rtype: RrType::NSEC,
        class: CLASS_IN,
        ttl: 900,
        rdata: nsec_rdata,
    };

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
        // The denial, signed under a window DISJOINT from every other
        // link: intersecting it would empty the ∩ and fail the walk.
        link(&[nsec.clone(), child.rrsig(&[nsec], (10, 20))]),
        link(&[txt.clone(), child.rrsig(&[txt], window)]),
    ]);

    let ChainProof { window: proof, .. } = validator.validate_detailed(&hostname()?, &chain)?;
    assert_eq!(proof.inception(), UnixSeconds::from(1_000));
    assert_eq!(proof.expiration(), UnixSeconds::from(5_000));
    Ok(())
}

/// A TXT record at the leaf whose rdata is used verbatim (already
/// character-string framed or deliberately garbage).
const fn raw_txt(owner: Name, rdata: Vec<u8>) -> Record {
    Record {
        owner,
        rtype: RrType::TXT,
        class: CLASS_IN,
        ttl: 900,
        rdata,
    }
}

/// Grammar rejection is per-record, never RRset-wide: junk TXT
/// records co-resident with a valid ONO0 record are dispositioned
/// out, and exactly the valid record survives.
#[test]
fn leaf_grammar_rejection_is_per_record_never_rrset_wide() -> TestResult {
    let root = zone(".", 1);
    let child = zone("expede.wtf", 2);
    let validator = Validator::new(vec![root.anchor()]);
    let window = (1_000, 5_000);
    let ds = Zone::ds_record_for(&child);
    let owner = Name::onomancy_owner(&hostname()?)?;

    let valid = leaf()?;
    let rrset = vec![
        valid.clone(),
        // An SPF-shaped foreigner (dispositioned, not an error).
        raw_txt(owner.clone(), b"\x0Bv=spf1 -all".to_vec()),
        // Invalid UTF-8 (dropped by the text decode).
        raw_txt(owner.clone(), vec![0x02, 0xFF, 0xFE]),
        // A future version (dispositioned as unknown).
        raw_txt(owner.clone(), b"\x09v=ONO9;x=".to_vec()),
        // Not even a TXT character string (fails the TXT wire parse).
        raw_txt(owner.clone(), vec![0xFF]),
    ];
    let mut records = rrset.clone();
    records.push(child.rrsig(&rrset, window));

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
        link(&records),
    ]);

    let ChainProof { records, .. } = validator.validate_detailed(&hostname()?, &chain)?;
    assert_eq!(records.len(), 1, "exactly the valid record survives");
    assert_eq!(records[0].serial(), Serial::from(fixtures::FIXTURE_SERIAL));
    Ok(())
}

mod props {
    use super::*;

    /// Any single bit flip anywhere in the chain either fails the
    /// walk or leaves the proof IDENTICAL to the untampered one —
    /// never a different accepted proof. (The weaker "always fails"
    /// form is wrong by design: RFC 4035 substitutes the RRSIG's
    /// original TTL into the signed message, so flips confined to
    /// received-TTL bytes legitimately verify to the same proof.)
    #[test]
    fn a_bit_flip_never_yields_a_different_accepted_proof() {
        let root = zone(".", 1);
        let child = zone("expede.wtf", 2);
        let validator = Validator::new(vec![root.anchor()]);
        let hostname = hostname().expect("valid literal");
        let chain = happy_chain(&root, &child).expect("chain builds");
        let baseline = validator
            .validate_detailed(&hostname, &chain)
            .expect("the untampered chain validates");

        bolero::check!().with_type::<(u8, u16, u8)>().for_each(
            |&(link_pick, byte_pick, bit_pick)| {
                let mut links: Vec<ChainLink> = chain.links().to_vec();
                let li = usize::from(link_pick) % links.len();
                let mut bytes = links[li].as_bytes().to_vec();
                let bi = usize::from(byte_pick) % bytes.len();
                let bit = 1u8 << (bit_pick % 8);
                bytes[bi] ^= bit;
                links[li] = ChainLink::from(bytes);

                match validator.validate_detailed(&hostname, &DnssecChain::from(links)) {
                    Err(_) => {}
                    Ok(proof) => assert_eq!(
                        proof, baseline,
                        "flip link {li} byte {bi} bit {bit:#04x} produced a DIFFERENT proof"
                    ),
                }
            },
        );
    }

    /// The proof window is exactly the ∩ of every link window; a
    /// jointly-empty ∩ is `EmptyWindow` — invalid ✗, never stale.
    #[test]
    fn the_proof_window_is_the_intersection_of_every_link_window() {
        let root = zone(".", 1);
        let child = zone("expede.wtf", 2);
        let validator = Validator::new(vec![root.anchor()]);
        let hostname = hostname().expect("valid literal");
        let txt = leaf().expect("leaf builds");

        bolero::check!()
            .with_type::<[(u32, u32); 4]>()
            .for_each(|raw| {
                let norm = |(a, b): (u32, u32)| (a.min(b), a.max(b));
                let [w_root, w_delegation, w_child, w_leaf] = raw.map(norm);
                let chain = binding_chain(
                    &root,
                    &child,
                    txt.clone(),
                    ChainWindows {
                        root: w_root,
                        delegation: w_delegation,
                        child: w_child,
                        leaf: w_leaf,
                    },
                );

                let inception = w_root.0.max(w_delegation.0).max(w_child.0).max(w_leaf.0);
                let expiration = w_root.1.min(w_delegation.1).min(w_child.1).min(w_leaf.1);

                match validator.validate_detailed(&hostname, &chain) {
                    Ok(proof) => {
                        assert!(inception <= expiration);
                        assert_eq!(
                            proof.window.inception(),
                            UnixSeconds::from(u64::from(inception))
                        );
                        assert_eq!(
                            proof.window.expiration(),
                            UnixSeconds::from(u64::from(expiration))
                        );
                    }
                    Err(WalkError::EmptyWindow) => assert!(expiration < inception),
                    Err(other) => panic!("unexpected walk error: {other}"),
                }
            });
    }

    /// Anchoring is exactly root-key membership in the anchor set:
    /// decoy anchors never admit the chain, and the genuine anchor
    /// always does — regardless of the decoys around it.
    #[test]
    fn anchoring_is_exactly_root_key_membership() {
        let root = zone(".", 1);
        let child = zone("expede.wtf", 2);
        let hostname = hostname().expect("valid literal");
        let chain = happy_chain(&root, &child).expect("chain builds");

        bolero::check!()
            .with_type::<(Vec<u8>, bool)>()
            .for_each(|(decoy_seeds, include_real)| {
                // Seeds ORed past the fixture range: never the real key.
                let mut anchors: Vec<_> = decoy_seeds
                    .iter()
                    .take(4)
                    .map(|seed| zone(".", seed | 0x80).anchor())
                    .collect();
                if *include_real {
                    anchors.push(root.anchor());
                }

                let outcome = Validator::new(anchors).validate_detailed(&hostname, &chain);
                if *include_real {
                    assert!(outcome.is_ok(), "the genuine anchor must admit the chain");
                } else {
                    assert_eq!(outcome, Err(WalkError::Unanchored));
                }
            });
    }

    /// P5 generalized: arbitrary junk rdatas riding the leaf `RRset`
    /// never break, never pollute, and never evict the valid record.
    #[test]
    fn junk_leaf_neighbors_never_survive_disposition() {
        let root = zone(".", 1);
        let child = zone("expede.wtf", 2);
        let validator = Validator::new(vec![root.anchor()]);
        let hostname = hostname().expect("valid literal");
        let window = (1_000, 5_000);
        let ds = Zone::ds_record_for(&child);
        let owner = Name::onomancy_owner(&hostname).expect("fits under the service label");
        let valid = leaf().expect("leaf builds");

        let prefix = vec![
            link(&[
                root.dnskey_record.clone(),
                root.rrsig(core::slice::from_ref(&root.dnskey_record), window),
            ]),
            link(&[ds.clone(), root.rrsig(&[ds], window)]),
            link(&[
                child.dnskey_record.clone(),
                child.rrsig(core::slice::from_ref(&child.dnskey_record), window),
            ]),
        ];

        bolero::check!()
            .with_type::<Vec<Vec<u8>>>()
            .for_each(|garbage| {
                let mut rrset = vec![valid.clone()];
                rrset.extend(
                    garbage
                        .iter()
                        .take(4)
                        .map(|bytes| bytes.iter().copied().take(64).collect::<Vec<u8>>())
                        // A junk rdata equal to the valid record's
                        // would BE a second valid record, not junk.
                        .filter(|rdata| *rdata != valid.rdata)
                        .map(|rdata| raw_txt(owner.clone(), rdata)),
                );
                let mut records = rrset.clone();
                records.push(child.rrsig(&rrset, window));

                let mut links = prefix.clone();
                links.push(link(&records));

                let proof = validator
                    .validate_detailed(&hostname, &DnssecChain::from(links))
                    .expect("the valid record must survive its neighbors");
                assert_eq!(proof.records.len(), 1);
                assert_eq!(
                    proof.records[0].serial(),
                    Serial::from(fixtures::FIXTURE_SERIAL)
                );
            });
    }
}
