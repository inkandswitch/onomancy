//! Deterministic synthetic-zone factories for conformance tests and
//! fixture generation.
//!
//! Feature-gated (`test_utils`), never part of the validation surface.
//! Zones are Ed25519-keyed from stable seeds, so a chain generated
//! here is byte-identical across crates and runs — which is what makes
//! the checked-in fixtures reproducible and the derive-conformance
//! replay meaningful.

use alloc::{vec, vec::Vec};

pub mod fixtures;
use ed25519_dalek::{Signer as _, SigningKey};

use crate::{
    certificate::chain::{ChainLink, DnssecChain},
    dns_name::DnsName,
};

use crate::{
    crypto,
    trust_anchor::TrustAnchor,
    wire::{
        algorithm::Algorithm,
        digest_type::DigestType,
        dnskey::Dnskey,
        name::Name,
        record::{CLASS_IN, Record},
        rr_type::RrType,
    },
};

/// A synthetic zone: a name and its (single) Ed25519 zone key.
#[derive(Debug)]
pub struct Zone {
    /// The zone's canonical name.
    pub name: Name,
    signing: SigningKey,
    /// The zone's DNSKEY record (ZONE|SEP flags, protocol 3,
    /// Ed25519).
    pub dnskey_record: Record,
}

/// Build a zone from a stable seed.
///
/// # Panics
///
/// Panics on an invalid `name` literal — fixture-construction error,
/// not runtime input.
#[must_use]
#[allow(clippy::expect_used)]
pub fn zone(name: &str, seed: u8) -> Zone {
    let signing = SigningKey::from_bytes(&[seed; 32]);

    let mut rdata = Vec::new();
    rdata.extend_from_slice(&0x0101u16.to_be_bytes()); // ZONE | SEP
    rdata.push(3);
    rdata.push(Algorithm::ED25519.code());
    rdata.extend_from_slice(signing.verifying_key().as_bytes());

    let name: Name = name.parse().expect("zone name literal parses");
    let dnskey_record = Record {
        owner: name.clone(),
        rtype: RrType::DNSKEY,
        class: CLASS_IN,
        ttl: 3600,
        rdata,
    };

    Zone {
        name,
        signing,
        dnskey_record,
    }
}

impl Zone {
    /// The parsed zone key.
    ///
    /// # Panics
    ///
    /// Never: the record was built valid.
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn dnskey(&self) -> Dnskey {
        Dnskey::parse(&self.dnskey_record.rdata).expect("built valid")
    }

    /// The DS-form anchor committing to this zone's key.
    #[must_use]
    pub fn anchor(&self) -> TrustAnchor {
        let key = self.dnskey();

        TrustAnchor {
            algorithm: Algorithm::ED25519,
            digest: crypto::ds_digest(&self.name, &key).into(),
            key_tag: key.key_tag(),
            zone: self.name.clone(),
        }
    }

    /// A DS record (held in the PARENT zone) committing to `child`.
    #[must_use]
    pub fn ds_record_for(child: &Zone) -> Record {
        let key = child.dnskey();
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&key.key_tag().to_be_bytes());
        rdata.push(Algorithm::ED25519.code());
        rdata.push(DigestType::SHA256.code());
        rdata.extend_from_slice(crypto::ds_digest(&child.name, &key).as_bytes());

        Record {
            owner: child.name.clone(),
            rtype: RrType::DS,
            class: CLASS_IN,
            ttl: 3600,
            rdata,
        }
    }

    /// Sign an `RRset` (RFC 4035 §5.3.2 construction) into an RRSIG
    /// record, with the owner's own label count.
    ///
    /// # Panics
    ///
    /// Panics on empty `RRset`s or oversized RDATA — fixture bugs.
    #[must_use]
    pub fn rrsig(&self, rrset: &[Record], window: (u32, u32)) -> Record {
        let labels = rrset
            .first()
            .map_or(0, |record| record.owner.labels().len());
        self.rrsig_with_labels(rrset, window, labels)
    }

    /// [`rrsig`](Self::rrsig) with an explicit label count — labels
    /// below the owner's simulate wildcard expansion (D14 inputs).
    ///
    /// # Panics
    ///
    /// Panics on empty `RRset`s or oversized RDATA — fixture bugs.
    #[must_use]
    #[allow(clippy::expect_used, clippy::indexing_slicing)]
    pub fn rrsig_with_labels(&self, rrset: &[Record], window: (u32, u32), labels: usize) -> Record {
        let owner = &rrset[0].owner;

        let mut preamble = Vec::new();
        preamble.extend_from_slice(&rrset[0].rtype.code().to_be_bytes());
        preamble.push(Algorithm::ED25519.code());
        preamble.push(u8::try_from(labels).expect("small label counts"));
        preamble.extend_from_slice(&rrset[0].ttl.to_be_bytes());
        preamble.extend_from_slice(&window.1.to_be_bytes()); // expiration
        preamble.extend_from_slice(&window.0.to_be_bytes()); // inception
        preamble.extend_from_slice(&self.dnskey().key_tag().to_be_bytes());
        self.name.write(&mut preamble);

        let mut rdatas: Vec<&[u8]> = rrset.iter().map(|r| r.rdata.as_slice()).collect();
        rdatas.sort_unstable();
        rdatas.dedup();

        // Wildcard-expanded RRsets are signed under the `*.<suffix>`
        // owner form.
        let signed_owner = if labels < owner.labels().len() {
            let mut wildcard: Vec<Vec<u8>> = vec![b"*".to_vec()];
            wildcard.extend(
                owner
                    .labels()
                    .iter()
                    .skip(owner.labels().len() - labels)
                    .cloned(),
            );
            Name::from_labels(wildcard)
        } else {
            owner.clone()
        };
        let mut owner_wire = Vec::new();
        signed_owner.write(&mut owner_wire);

        let mut message = preamble.clone();
        for rdata in rdatas {
            message.extend_from_slice(&owner_wire);
            message.extend_from_slice(&rrset[0].rtype.code().to_be_bytes());
            message.extend_from_slice(&CLASS_IN.to_be_bytes());
            message.extend_from_slice(&rrset[0].ttl.to_be_bytes());
            message.extend_from_slice(&u16::try_from(rdata.len()).expect("small").to_be_bytes());
            message.extend_from_slice(rdata);
        }

        let mut rdata = preamble;
        rdata.extend_from_slice(&self.signing.sign(&message).to_bytes());

        Record {
            owner: owner.clone(),
            rtype: RrType::RRSIG,
            class: CLASS_IN,
            ttl: rrset[0].ttl,
            rdata,
        }
    }
}

/// Frame records into one chain link.
#[must_use]
pub fn link(records: &[Record]) -> ChainLink {
    let mut bytes = Vec::new();
    for record in records {
        record.write(&mut bytes);
    }
    ChainLink::from(bytes)
}

/// A TXT record at `_onomancy.<hostname>` carrying `text` as one
/// character string.
///
/// # Panics
///
/// Panics when `text` exceeds one character string — fixture bug.
#[must_use]
#[allow(clippy::expect_used)]
pub fn txt_record(hostname: &DnsName, text: &str) -> Record {
    let mut rdata = Vec::new();
    rdata.push(u8::try_from(text.len()).expect("fits one character string"));
    rdata.extend_from_slice(text.as_bytes());

    Record {
        owner: Name::onomancy_owner(hostname),
        rtype: RrType::TXT,
        class: CLASS_IN,
        ttl: 900,
        rdata,
    }
}

/// A four-link binding chain: root DNSKEY → DS → child DNSKEY → TXT,
/// with per-link windows.
#[must_use]
pub fn binding_chain(root: &Zone, child: &Zone, txt: Record, windows: ChainWindows) -> DnssecChain {
    let ds = Zone::ds_record_for(child);

    DnssecChain::from(vec![
        link(&[
            root.dnskey_record.clone(),
            root.rrsig(core::slice::from_ref(&root.dnskey_record), windows.root),
        ]),
        link(&[ds.clone(), root.rrsig(&[ds], windows.delegation)]),
        link(&[
            child.dnskey_record.clone(),
            child.rrsig(core::slice::from_ref(&child.dnskey_record), windows.child),
        ]),
        link(&[txt.clone(), child.rrsig(&[txt], windows.leaf)]),
    ])
}

/// Per-link RRSIG windows for [`binding_chain`].
#[derive(Debug, Clone, Copy)]
pub struct ChainWindows {
    /// Root DNSKEY window.
    pub root: (u32, u32),
    /// DS window.
    pub delegation: (u32, u32),
    /// Child DNSKEY window.
    pub child: (u32, u32),
    /// Leaf TXT window.
    pub leaf: (u32, u32),
}

impl ChainWindows {
    /// All four links share one window — the common fixture case,
    /// where the chain's ∩-window IS the leaf window.
    #[must_use]
    pub const fn uniform(window: (u32, u32)) -> Self {
        Self {
            root: window,
            delegation: window,
            child: window,
            leaf: window,
        }
    }
}
