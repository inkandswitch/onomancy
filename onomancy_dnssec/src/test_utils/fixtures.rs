//! The fixture catalog: every checked-in chain in `tests/fixtures/`,
//! defined ONCE — the generator example writes these, and
//! `tests/fixtures.rs` asserts each file still produces its declared
//! outcome. A fixture is (name, chain, expectation); the anchor for
//! all of them is [`fixture_anchor`].

use alloc::{format, string::String, vec, vec::Vec};
use ed25519_dalek::SigningKey;

use crate::{
    chain::{ChainLink, DnssecChain},
    dns_name::DnsName,
    txt::{generation_key::GenerationKey, record::TxtRecord, serial::Serial},
};
use onomancy_core::anchor::doc::DocAnchor;

use super::{binding_chain, link, txt_record, zone, ChainWindows, Zone};
use crate::{
    trust_anchor::TrustAnchor,
    wire::{
        name::Name,
        record::{Record, CLASS_IN},
        rr_type::RrType,
    },
};

/// The window every well-formed fixture link is signed under.
pub const FIXTURE_WINDOW: (u32, u32) = (1_754_000_000, 1_756_000_000);

/// The serial carried by fixture binding records (ms convention).
pub const FIXTURE_SERIAL: u64 = 1_755_000_000_000;

/// What a fixture must produce under [`fixture_anchor`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expectation {
    /// Validates to a proof carrying [`FIXTURE_SERIAL`].
    Binding,

    /// MUST fail validation (mutation vectors — including denial-only
    /// and wildcard chains, since negative proofs are out at v0).
    Invalid,
}

/// The root zone every fixture chains from.
#[must_use]
pub fn fixture_root() -> Zone {
    zone(".", 1)
}

/// The child zone (`expede.wtf`) fixtures bind under.
#[must_use]
pub fn fixture_child() -> Zone {
    zone("expede.wtf", 2)
}

/// The anchor set fixtures validate against.
#[must_use]
pub fn fixture_anchor() -> Vec<TrustAnchor> {
    vec![fixture_root().anchor()]
}

/// The hostname fixtures bind.
///
/// # Panics
///
/// Never: the literal is valid.
#[must_use]
#[allow(clippy::expect_used)]
pub fn fixture_hostname() -> DnsName {
    DnsName::parse("expede.wtf").expect("valid literal")
}

/// A valid ONO0 record text with seeded keys.
#[must_use]
pub fn fixture_txt_text() -> String {
    format!(
        "{}",
        TxtRecord::new(
            Serial::from(FIXTURE_SERIAL),
            GenerationKey::from(SigningKey::from_bytes(&[40; 32]).verifying_key()),
            DocAnchor::from(SigningKey::from_bytes(&[41; 32]).verifying_key()),
        )
    )
}

/// Every fixture: (file stem, chain, expected outcome).
#[must_use]
pub fn all_fixtures() -> Vec<(&'static str, DnssecChain, Expectation)> {
    vec![
        ("valid_binding", valid_binding(), Expectation::Binding),
        ("denial_only", denial_only(), Expectation::Invalid),
        ("tampered_leaf", tampered_leaf(), Expectation::Invalid),
        ("disjoint_windows", disjoint_windows(), Expectation::Invalid),
        ("ds_mismatch", ds_mismatch(), Expectation::Invalid),
        ("missing_leaf", missing_leaf(), Expectation::Invalid),
        ("wildcard", wildcard(), Expectation::Invalid),
        (
            "wildcard_with_denial",
            wildcard_with_denial(),
            Expectation::Invalid,
        ),
        ("misordered_links", misordered_links(), Expectation::Invalid),
    ]
}

fn leaf() -> Record {
    txt_record(&fixture_hostname(), &fixture_txt_text())
}

fn valid_binding() -> DnssecChain {
    binding_chain(
        &fixture_root(),
        &fixture_child(),
        leaf(),
        ChainWindows::uniform(FIXTURE_WINDOW),
    )
}

/// An NSEC at the zone apex — a denial link, which the walk skips
/// unverified at v0.
fn absence_nsec() -> Record {
    let mut rdata = Vec::new();
    // Never panics: the literal is valid.
    #[allow(clippy::expect_used)]
    let next: Name = "zzz.expede.wtf".parse().expect("valid literal");
    next.write(&mut rdata);
    rdata.extend_from_slice(&[0, 1, 0x40]); // bitmap: A exists

    Record {
        owner: fixture_child().name,
        rtype: RrType::NSEC,
        class: CLASS_IN,
        ttl: 900,
        rdata,
    }
}

/// A chain whose leaf is only a denial: proves nothing at v0.
fn denial_only() -> DnssecChain {
    let root = fixture_root();
    let child = fixture_child();
    let nsec = absence_nsec();
    let ds = Zone::ds_record_for(&child);

    DnssecChain::from(vec![
        link(&[
            root.dnskey_record.clone(),
            root.rrsig(core::slice::from_ref(&root.dnskey_record), FIXTURE_WINDOW),
        ]),
        link(&[ds.clone(), root.rrsig(&[ds], FIXTURE_WINDOW)]),
        link(&[
            child.dnskey_record.clone(),
            child.rrsig(core::slice::from_ref(&child.dnskey_record), FIXTURE_WINDOW),
        ]),
        link(&[nsec.clone(), child.rrsig(&[nsec], FIXTURE_WINDOW)]),
    ])
}

fn tampered_leaf() -> DnssecChain {
    let chain = valid_binding();
    let mut links: Vec<ChainLink> = chain.links().to_vec();

    if let Some(last) = links.pop() {
        let mut bytes = last.as_bytes().to_vec();
        let at = bytes.len() / 2;
        if let Some(byte) = bytes.get_mut(at) {
            *byte ^= 0x01;
        }
        links.push(ChainLink::from(bytes));
    }

    DnssecChain::from(links)
}

fn disjoint_windows() -> DnssecChain {
    binding_chain(
        &fixture_root(),
        &fixture_child(),
        leaf(),
        ChainWindows {
            root: (1_000, 2_000),
            delegation: (1_000, 2_000),
            child: (1_000, 2_000),
            leaf: (3_000, 4_000),
        },
    )
}

fn ds_mismatch() -> DnssecChain {
    let root = fixture_root();
    let child = fixture_child();
    let imposter = zone("expede.wtf", 9);
    let txt = leaf();
    // DS commits to the real child; the chain presents the imposter.
    let ds = Zone::ds_record_for(&child);

    DnssecChain::from(vec![
        link(&[
            root.dnskey_record.clone(),
            root.rrsig(core::slice::from_ref(&root.dnskey_record), FIXTURE_WINDOW),
        ]),
        link(&[ds.clone(), root.rrsig(&[ds], FIXTURE_WINDOW)]),
        link(&[
            imposter.dnskey_record.clone(),
            imposter.rrsig(
                core::slice::from_ref(&imposter.dnskey_record),
                FIXTURE_WINDOW,
            ),
        ]),
        link(&[txt.clone(), imposter.rrsig(&[txt], FIXTURE_WINDOW)]),
    ])
}

fn missing_leaf() -> DnssecChain {
    let chain = valid_binding();
    let mut links: Vec<ChainLink> = chain.links().to_vec();
    links.pop(); // drop the TXT: neither binding nor denial remains

    DnssecChain::from(links)
}

/// The leaf signed as `*.expede.wtf` (labels = 2): wildcard-expanded
/// answers are rejected outright at v0 (their no-closer-match proof
/// would be a negative proof).
fn wildcard() -> DnssecChain {
    let root = fixture_root();
    let child = fixture_child();
    let txt = leaf();
    let ds = Zone::ds_record_for(&child);

    DnssecChain::from(vec![
        link(&[
            root.dnskey_record.clone(),
            root.rrsig(core::slice::from_ref(&root.dnskey_record), FIXTURE_WINDOW),
        ]),
        link(&[ds.clone(), root.rrsig(&[ds], FIXTURE_WINDOW)]),
        link(&[
            child.dnskey_record.clone(),
            child.rrsig(core::slice::from_ref(&child.dnskey_record), FIXTURE_WINDOW),
        ]),
        link(&[
            txt.clone(),
            child.rrsig_with_labels(&[txt], FIXTURE_WINDOW, 2),
        ]),
    ])
}

/// The same wildcard expansion WITH a (skipped, unverified) denial
/// link present: still rejected — denials prove nothing at v0, and
/// their mere presence must not soften the wildcard rule.
fn wildcard_with_denial() -> DnssecChain {
    let root = fixture_root();
    let child = fixture_child();
    let txt = leaf();
    let nsec = absence_nsec();
    let ds = Zone::ds_record_for(&child);

    DnssecChain::from(vec![
        link(&[
            root.dnskey_record.clone(),
            root.rrsig(core::slice::from_ref(&root.dnskey_record), FIXTURE_WINDOW),
        ]),
        link(&[ds.clone(), root.rrsig(&[ds], FIXTURE_WINDOW)]),
        link(&[
            child.dnskey_record.clone(),
            child.rrsig(core::slice::from_ref(&child.dnskey_record), FIXTURE_WINDOW),
        ]),
        link(&[nsec.clone(), child.rrsig(&[nsec], FIXTURE_WINDOW)]),
        link(&[
            txt.clone(),
            child.rrsig_with_labels(&[txt], FIXTURE_WINDOW, 2),
        ]),
    ])
}

/// The valid chain with the DS and child-DNSKEY links swapped: the
/// walk's ordering rules MUST reject it.
fn misordered_links() -> DnssecChain {
    let chain = valid_binding();
    let mut links: Vec<ChainLink> = chain.links().to_vec();
    links.swap(1, 2);

    DnssecChain::from(links)
}
