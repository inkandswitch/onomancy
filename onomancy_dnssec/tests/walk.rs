//! End-to-end walk tests over a synthetic two-zone tree
//! (root → expede.wtf → `_onomancy` leaf), signed with real Ed25519
//! keys. The same builder becomes the 3a.6 fixture generator.

#![allow(clippy::indexing_slicing, clippy::panic)]

use ed25519_dalek::{Signer as _, SigningKey};
use onomancy_core::{
    cert::chain::{ChainLink, DnssecChain},
    name::{dns::DnsName, doc::DocAnchor},
    time::UnixSeconds,
    txt::{generation_key::GenerationKey, record::TxtRecord, serial::Serial},
};
use onomancy_proto::derive::seam::{ChainProof, ChainValidator as _};
use testresult::TestResult;

use onomancy_dnssec::{
    anchor::TrustAnchor,
    crypto,
    validator::{Validator, WalkError},
    wire::{
        algorithm::Algorithm,
        dnskey::Dnskey,
        ds::DigestType,
        name::Name,
        record::{Record, RrType, CLASS_IN},
    },
};

/// A synthetic zone: a name and its (single) Ed25519 zone key.
struct Zone {
    name: Name,
    signing: SigningKey,
    dnskey_record: Record,
}

fn zone(name: &str, seed: u8) -> TestResult<Zone> {
    let signing = SigningKey::from_bytes(&[seed; 32]);

    let mut rdata = Vec::new();
    rdata.extend_from_slice(&0x0101u16.to_be_bytes()); // ZONE | SEP
    rdata.push(3);
    rdata.push(Algorithm::ED25519.0);
    rdata.extend_from_slice(signing.verifying_key().as_bytes());

    let name: Name = name.parse()?;
    let dnskey_record = Record {
        owner: name.clone(),
        rtype: RrType::DNSKEY,
        class: CLASS_IN,
        ttl: 3600,
        rdata,
    };

    Ok(Zone {
        name,
        signing,
        dnskey_record,
    })
}

impl Zone {
    fn dnskey(&self) -> TestResult<Dnskey> {
        Ok(Dnskey::parse(&self.dnskey_record.rdata)?)
    }

    /// The DS-form anchor committing to this zone's key.
    fn anchor(&self) -> TestResult<TrustAnchor> {
        let key = self.dnskey()?;

        Ok(TrustAnchor {
            algorithm: Algorithm::ED25519,
            digest: crypto::ds_digest(&self.name, &key).into(),
            key_tag: key.key_tag(),
            zone: self.name.clone(),
        })
    }

    /// A DS record (held in the PARENT zone) committing to `child`.
    fn ds_record_for(child: &Zone) -> TestResult<Record> {
        let key = child.dnskey()?;
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&key.key_tag().to_be_bytes());
        rdata.push(Algorithm::ED25519.0);
        rdata.push(DigestType::SHA256.0);
        rdata.extend_from_slice(crypto::ds_digest(&child.name, &key).as_bytes());

        Ok(Record {
            owner: child.name.clone(),
            rtype: RrType::DS,
            class: CLASS_IN,
            ttl: 3600,
            rdata,
        })
    }

    /// Sign an `RRset` (RFC 4035 §5.3.2 assembly) into an RRSIG
    /// record.
    fn rrsig(&self, rrset: &[Record], window: (u32, u32)) -> TestResult<Record> {
        let owner = &rrset[0].owner;
        let labels = u8::try_from(owner.labels().len())?;

        let mut preamble = Vec::new();
        preamble.extend_from_slice(&rrset[0].rtype.0.to_be_bytes());
        preamble.push(Algorithm::ED25519.0);
        preamble.push(labels);
        preamble.extend_from_slice(&rrset[0].ttl.to_be_bytes());
        preamble.extend_from_slice(&window.1.to_be_bytes()); // expiration
        preamble.extend_from_slice(&window.0.to_be_bytes()); // inception
        preamble.extend_from_slice(&self.dnskey()?.key_tag().to_be_bytes());
        self.name.write(&mut preamble);

        let mut rdatas: Vec<&[u8]> = rrset.iter().map(|r| r.rdata.as_slice()).collect();
        rdatas.sort_unstable();
        rdatas.dedup();

        let mut owner_wire = Vec::new();
        owner.write(&mut owner_wire);

        let mut message = preamble.clone();
        for rdata in rdatas {
            message.extend_from_slice(&owner_wire);
            message.extend_from_slice(&rrset[0].rtype.0.to_be_bytes());
            message.extend_from_slice(&CLASS_IN.to_be_bytes());
            message.extend_from_slice(&rrset[0].ttl.to_be_bytes());
            message.extend_from_slice(&u16::try_from(rdata.len())?.to_be_bytes());
            message.extend_from_slice(rdata);
        }

        let mut rdata = preamble;
        rdata.extend_from_slice(&self.signing.sign(&message).to_bytes());

        Ok(Record {
            owner: owner.clone(),
            rtype: RrType::RRSIG,
            class: CLASS_IN,
            ttl: rrset[0].ttl,
            rdata,
        })
    }
}

/// Frame records into one chain link.
fn link(records: &[Record]) -> ChainLink {
    let mut bytes = Vec::new();
    for record in records {
        record.write(&mut bytes);
    }
    ChainLink::from(bytes)
}

/// A valid ONO0 TXT record for the leaf.
fn ono_txt_rdata() -> TestResult<Vec<u8>> {
    let record = TxtRecord::new(
        Serial::from(1_755_000_000_000),
        GenerationKey::from(SigningKey::from_bytes(&[40; 32]).verifying_key()),
        DocAnchor::from(SigningKey::from_bytes(&[41; 32]).verifying_key()),
    );
    let text = record.to_string();

    let mut rdata = Vec::new();
    rdata.push(u8::try_from(text.len())?);
    rdata.extend_from_slice(text.as_bytes());
    Ok(rdata)
}

fn hostname() -> TestResult<DnsName> {
    Ok(DnsName::parse("expede.wtf")?)
}

fn leaf_owner() -> TestResult<Name> {
    Ok(Name::onomancy_owner(&hostname()?))
}

fn txt_record() -> TestResult<Record> {
    Ok(Record {
        owner: leaf_owner()?,
        rtype: RrType::TXT,
        class: CLASS_IN,
        ttl: 900,
        rdata: ono_txt_rdata()?,
    })
}

/// The happy-path chain: root DNSKEY, DS, child DNSKEY, TXT leaf.
fn happy_chain(root: &Zone, child: &Zone) -> TestResult<DnssecChain> {
    let txt = txt_record()?;
    let ds = Zone::ds_record_for(child)?;

    Ok(DnssecChain::from(vec![
        link(&[
            root.dnskey_record.clone(),
            root.rrsig(std::slice::from_ref(&root.dnskey_record), (1_000, 5_000))?,
        ]),
        link(&[ds.clone(), root.rrsig(&[ds], (1_200, 6_000))?]),
        link(&[
            child.dnskey_record.clone(),
            child.rrsig(std::slice::from_ref(&child.dnskey_record), (1_100, 4_500))?,
        ]),
        link(&[txt.clone(), child.rrsig(&[txt], (1_500, 4_000))?]),
    ]))
}

#[test]
fn a_genuine_chain_walks_to_a_binding_proof() -> TestResult {
    let root = zone(".", 1)?;
    let child = zone("expede.wtf", 2)?;
    let validator = Validator::new(vec![root.anchor()?]);

    let proof = validator.validate_detailed(&hostname()?, &happy_chain(&root, &child)?)?;

    let ChainProof::Binding {
        leaf_inception,
        records,
        window,
    } = proof
    else {
        panic!("expected a binding proof");
    };

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].serial(), Serial::from(1_755_000_000_000));
    // ∩-window: max inception 1500, min expiration 4000.
    assert_eq!(window.inception(), UnixSeconds::from(1_500));
    assert_eq!(window.expiration(), UnixSeconds::from(4_000));
    assert_eq!(leaf_inception, UnixSeconds::from(1_500));
    Ok(())
}

#[test]
fn unanchored_roots_are_rejected() -> TestResult {
    let root = zone(".", 1)?;
    let child = zone("expede.wtf", 2)?;
    let wrong = zone(".", 9)?;

    let validator = Validator::new(vec![wrong.anchor()?]);
    assert_eq!(
        validator.validate_detailed(&hostname()?, &happy_chain(&root, &child)?),
        Err(WalkError::Unanchored)
    );
    Ok(())
}

#[test]
fn a_tampered_leaf_fails_the_walk() -> TestResult {
    let root = zone(".", 1)?;
    let child = zone("expede.wtf", 2)?;
    let chain = happy_chain(&root, &child)?;

    // Flip one byte inside the TXT link's RDATA region.
    let mut links: Vec<ChainLink> = chain.links().to_vec();
    let mut leaf_bytes = links[3].as_bytes().to_vec();
    let at = leaf_bytes.len() / 2;
    leaf_bytes[at] ^= 0x01;
    links[3] = ChainLink::from(leaf_bytes);

    let validator = Validator::new(vec![root.anchor()?]);
    let outcome = validator.validate_detailed(&hostname()?, &DnssecChain::from(links));

    assert!(outcome.is_err(), "tampered leaf must not validate");
    Ok(())
}

#[test]
fn disjoint_windows_are_invalid_not_stale() -> TestResult {
    let root = zone(".", 1)?;
    let child = zone("expede.wtf", 2)?;

    let txt = txt_record()?;
    let ds = Zone::ds_record_for(&child)?;

    let chain = DnssecChain::from(vec![
        link(&[
            root.dnskey_record.clone(),
            root.rrsig(std::slice::from_ref(&root.dnskey_record), (1_000, 2_000))?,
        ]),
        link(&[ds.clone(), root.rrsig(&[ds], (1_000, 2_000))?]),
        link(&[
            child.dnskey_record.clone(),
            child.rrsig(std::slice::from_ref(&child.dnskey_record), (1_000, 2_000))?,
        ]),
        // Leaf window begins after every other window has ended.
        link(&[txt.clone(), child.rrsig(&[txt], (3_000, 4_000))?]),
    ]);

    let validator = Validator::new(vec![root.anchor()?]);
    assert_eq!(
        validator.validate_detailed(&hostname()?, &chain),
        Err(WalkError::EmptyWindow)
    );
    Ok(())
}

#[test]
fn mismatched_ds_blocks_the_descent() -> TestResult {
    let root = zone(".", 1)?;
    let child = zone("expede.wtf", 2)?;
    let imposter = zone("expede.wtf", 9)?;

    let txt = txt_record()?;
    // DS commits to the REAL child; the chain presents the imposter's
    // keys.
    let ds = Zone::ds_record_for(&child)?;

    let chain = DnssecChain::from(vec![
        link(&[
            root.dnskey_record.clone(),
            root.rrsig(std::slice::from_ref(&root.dnskey_record), (1_000, 5_000))?,
        ]),
        link(&[ds.clone(), root.rrsig(&[ds], (1_000, 5_000))?]),
        link(&[
            imposter.dnskey_record.clone(),
            imposter.rrsig(
                std::slice::from_ref(&imposter.dnskey_record),
                (1_000, 5_000),
            )?,
        ]),
        link(&[txt.clone(), imposter.rrsig(&[txt], (1_000, 5_000))?]),
    ]);

    let validator = Validator::new(vec![root.anchor()?]);
    assert_eq!(
        validator.validate_detailed(&hostname()?, &chain),
        Err(WalkError::DsMismatch)
    );
    Ok(())
}

#[test]
fn nsec_denial_proves_absence() -> TestResult {
    let root = zone(".", 1)?;
    let child = zone("expede.wtf", 2)?;

    // NSEC from the zone apex to zzz.expede.wtf: covers the
    // _onomancy owner in canonical order.
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
    let ds = Zone::ds_record_for(&child)?;

    let chain = DnssecChain::from(vec![
        link(&[
            root.dnskey_record.clone(),
            root.rrsig(std::slice::from_ref(&root.dnskey_record), (1_000, 5_000))?,
        ]),
        link(&[ds.clone(), root.rrsig(&[ds], (1_000, 5_000))?]),
        link(&[
            child.dnskey_record.clone(),
            child.rrsig(std::slice::from_ref(&child.dnskey_record), (1_000, 5_000))?,
        ]),
        link(&[nsec.clone(), child.rrsig(&[nsec], (2_000, 4_500))?]),
    ]);

    let validator = Validator::new(vec![root.anchor()?]);
    let proof = validator.validate_detailed(&hostname()?, &chain)?;

    let ChainProof::Absence {
        leaf_inception,
        window,
    } = proof
    else {
        panic!("expected an absence proof");
    };

    assert_eq!(leaf_inception, UnixSeconds::from(2_000));
    assert_eq!(window.inception(), UnixSeconds::from(2_000));
    assert_eq!(window.expiration(), UnixSeconds::from(4_500));
    Ok(())
}

#[test]
fn the_seam_collapses_detail_to_invalid_chain() -> TestResult {
    let root = zone(".", 1)?;
    let child = zone("expede.wtf", 2)?;

    let validator = Validator::new(vec![root.anchor()?]);
    assert!(validator
        .validate(&hostname()?, &happy_chain(&root, &child)?)
        .is_ok());
    assert!(validator
        .validate(&hostname()?, &DnssecChain::default())
        .is_err());
    Ok(())
}
