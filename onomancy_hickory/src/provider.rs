//! Chain assembly: recursive-resolver answers → framed links.
//!
//! The assembler mirrors the validator's expected grammar (root
//! DNSKEY; DS + child DNSKEY per signed cut; CNAME hops; TXT leaf)
//! but PROVES nothing — it selects and frames bytes. Suffixes without
//! a DS `RRset` are simply not cuts (or not signed ones); either way no
//! link is emitted and the validator renders the verdict.

// Foreign-enum wildcards are deliberate: any RData shape this courier
// does not recognize is simply not the record it is looking for.
#![allow(clippy::wildcard_enum_match_arm)]

use std::net::SocketAddr;

use hickory_proto::{
    rr::{Name, RData, Record, RecordType},
    serialize::binary::{BinEncodable, BinEncoder},
};
use onomancy_core::{
    cert::chain::{ChainLink, DnssecChain},
    name::dns::DnsName,
};
use onomancy_protocol::chain_provider::ChainProvider;

use crate::stub::{QueryError, StubResolver};

/// Bounded CNAME indirection, matching the validator's own limit.
const MAX_CNAME_HOPS: usize = 8;

/// The native chain courier: assembles a hostname's full DNSSEC chain
/// by querying one recursive resolver.
#[derive(Debug, Clone, Copy)]
pub struct HickoryProvider {
    stub: StubResolver,
}

impl HickoryProvider {
    /// A provider querying the recursive resolver at `server`.
    #[must_use]
    pub const fn new(server: SocketAddr) -> Self {
        Self {
            stub: StubResolver::new(server),
        }
    }

    /// A provider over a pre-configured stub.
    #[must_use]
    pub const fn from_stub(stub: StubResolver) -> Self {
        Self { stub }
    }

    /// Fetch and frame the full chain for `hostname`'s `_onomancy`
    /// owner name.
    ///
    /// # Errors
    ///
    /// Returns [`FetchChainError`] for transport failures and for
    /// answers that cannot even be framed (no TXT leaf, missing
    /// signatures, runaway CNAME chains). Framability is not
    /// validity: a framed chain may still fail the validator.
    pub async fn assemble(&self, hostname: &DnsName) -> Result<DnssecChain, FetchChainError> {
        let owner = onomancy_owner(hostname)?;
        let mut links: Vec<ChainLink> = Vec::new();

        // Link 0: the root DNSKEY RRset.
        let root_keys = self.stub.query(&Name::root(), RecordType::DNSKEY).await?;
        links.push(frame_rrset(&root_keys, &Name::root(), RecordType::DNSKEY)?);

        // Per suffix, root-outward: a DS RRset marks a signed cut.
        for depth in 1..=owner.num_labels() {
            let zone = owner.trim_to(usize::from(depth));

            let ds_answer = self.stub.query(&zone, RecordType::DS).await?;
            if !has_data(&ds_answer, &zone, RecordType::DS) {
                continue; // not a zone cut, or an unsigned one
            }

            links.push(frame_rrset(&ds_answer, &zone, RecordType::DS)?);

            let keys = self.stub.query(&zone, RecordType::DNSKEY).await?;
            links.push(frame_rrset(&keys, &zone, RecordType::DNSKEY)?);
        }

        // The leaf: TXT at the owner, CNAME hops framed along the way.
        let leaf_answer = self.stub.query(&owner, RecordType::TXT).await?;
        links.extend(leaf_links(&owner, &leaf_answer)?);

        Ok(DnssecChain::from(links))
    }
}

impl ChainProvider for HickoryProvider {
    type Error = FetchChainError;

    async fn chain(&self, hostname: &DnsName) -> Result<DnssecChain, FetchChainError> {
        self.assemble(hostname).await
    }
}

/// `_onomancy.<hostname>.` as a hickory name.
fn onomancy_owner(hostname: &DnsName) -> Result<Name, FetchChainError> {
    Name::from_ascii(format!("_onomancy.{hostname}."))
        .map_err(|_| FetchChainError::UnrepresentableName)
}

/// Whether `answers` holds any data record of `rtype` at `owner`.
fn has_data(answers: &[Record], owner: &Name, rtype: RecordType) -> bool {
    answers
        .iter()
        .any(|r| r.record_type() == rtype && r.name == *owner)
}

/// Frame one link: the `rtype` `RRset` at `owner` followed by the
/// RRSIGs covering it there — uncompressed, canonical-form records.
fn frame_rrset(
    answers: &[Record],
    owner: &Name,
    rtype: RecordType,
) -> Result<ChainLink, FetchChainError> {
    let data: Vec<&Record> = answers
        .iter()
        .filter(|r| r.record_type() == rtype && r.name == *owner)
        .collect();
    let signatures: Vec<&Record> = answers
        .iter()
        .filter(|r| covered_type(r) == Some(u16::from(rtype)) && r.name == *owner)
        .collect();

    if data.is_empty() || signatures.is_empty() {
        return Err(FetchChainError::MissingRrset {
            owner: owner.to_ascii(),
            rtype,
        });
    }

    let mut bytes = Vec::new();
    for record in data.into_iter().chain(signatures) {
        encode_canonical(record, &mut bytes)?;
    }

    Ok(ChainLink::from(bytes))
}

/// The CNAME hops (in follow order) and the TXT leaf, one link each.
fn leaf_links(owner: &Name, answers: &[Record]) -> Result<Vec<ChainLink>, FetchChainError> {
    let mut links = Vec::new();
    let mut current = owner.clone();

    for _ in 0..=MAX_CNAME_HOPS {
        if has_data(answers, &current, RecordType::TXT) {
            links.push(frame_rrset(answers, &current, RecordType::TXT)?);
            return Ok(links);
        }

        let Some(target) = answers.iter().find_map(|r| match &r.data {
            RData::CNAME(cname) if r.name == current => Some(cname.0.clone()),
            _ => None,
        }) else {
            return Err(FetchChainError::MissingRrset {
                owner: current.to_ascii(),
                rtype: RecordType::TXT,
            });
        };

        links.push(frame_rrset(answers, &current, RecordType::CNAME)?);
        current = target;
    }

    Err(FetchChainError::TooManyCnames)
}

/// The type an RRSIG record covers (the first two RDATA octets),
/// `None` for non-RRSIG records.
///
/// Without hickory's DNSSEC feature, RRSIG RDATA arrives as opaque
/// `Unknown` bytes — RFC 3597 forbids compression inside unknown-type
/// RDATA (and RFC 4034 forbids it in RRSIG specifically), so the raw
/// bytes are exactly the wire form the validator needs.
fn covered_type(record: &Record) -> Option<u16> {
    match &record.data {
        RData::Unknown { code, rdata } if *code == RecordType::RRSIG => {
            let bytes = rdata.anything.as_slice();
            Some(u16::from_be_bytes([*bytes.first()?, *bytes.get(1)?]))
        }
        _ => None,
    }
}

/// Append one record in uncompressed, DNSSEC-canonical wire form.
fn encode_canonical(record: &Record, bytes: &mut Vec<u8>) -> Result<(), FetchChainError> {
    let mut buffer = Vec::new();
    let mut encoder = BinEncoder::new(&mut buffer);
    encoder.set_canonical_form(true);
    record
        .emit(&mut encoder)
        .map_err(|_| FetchChainError::Encode)?;
    bytes.extend_from_slice(&buffer);
    Ok(())
}

/// Chain assembly failed — transport trouble or unframeable answers,
/// never a validity verdict (that is the validator's).
#[derive(Debug, thiserror::Error)]
pub enum FetchChainError {
    /// A record could not be re-encoded to wire form.
    #[error("record could not be re-encoded")]
    Encode,

    /// An expected `RRset` (or its covering RRSIG) was absent.
    #[error("no {rtype} RRset with signatures at {owner}")]
    MissingRrset {
        /// The owner name queried.
        owner: String,
        /// The record type sought.
        rtype: RecordType,
    },

    /// A transport-level query failure.
    #[error(transparent)]
    Query(#[from] QueryError),

    /// The CNAME chain exceeded the hop bound.
    #[error("more than {MAX_CNAME_HOPS} CNAME hops")]
    TooManyCnames,

    /// The hostname does not fit in a DNS wire name with the
    /// `_onomancy` label prepended.
    #[error("hostname does not fit under the _onomancy label")]
    UnrepresentableName,
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::{NULL, TXT};
    use onomancy_dnssec::{link::Link, wire::record::RrType};
    use testresult::TestResult;

    fn owner() -> Name {
        Name::from_ascii("_onomancy.example.com.").expect("valid name")
    }

    fn txt_record(at: &Name) -> Record {
        Record::from_rdata(
            at.clone(),
            300,
            RData::TXT(TXT::new(vec!["onomancy v=0".to_string()])),
        )
    }

    /// A structurally valid RRSIG record covering `covered` at `at` —
    /// parseable, never verifiable.
    fn rrsig_record(at: &Name, covered: RecordType) -> Record {
        let mut rdata: Vec<u8> = Vec::new();
        rdata.extend(u16::from(covered).to_be_bytes()); // type covered
        rdata.push(13); // algorithm: ECDSA P-256
        rdata.push(3); // labels
        rdata.extend(300u32.to_be_bytes()); // original TTL
        rdata.extend(1_760_000_000u32.to_be_bytes()); // expiration
        rdata.extend(1_750_000_000u32.to_be_bytes()); // inception
        rdata.extend(4242u16.to_be_bytes()); // key tag
        rdata.push(0); // signer: the root name
        rdata.extend([0xAB; 64]); // signature

        Record::from_rdata(
            at.clone(),
            300,
            RData::Unknown {
                code: RecordType::RRSIG,
                rdata: NULL::with(rdata),
            },
        )
    }

    fn cname_record(at: &Name, target: &Name) -> Record {
        Record::from_rdata(
            at.clone(),
            300,
            RData::CNAME(hickory_proto::rr::rdata::CNAME(target.clone())),
        )
    }

    #[test]
    fn framed_links_parse_under_the_strict_validator_grammar() -> TestResult {
        let at = owner();
        let answers = vec![txt_record(&at), rrsig_record(&at, RecordType::TXT)];

        let link = frame_rrset(&answers, &at, RecordType::TXT)?;
        let parsed = Link::parse(&link)?;

        assert_eq!(parsed.rtype(), RrType::TXT);
        Ok(())
    }

    #[test]
    fn leaf_links_follow_cnames_in_order() -> TestResult {
        let at = owner();
        let target = Name::from_ascii("alias.example.net.").expect("valid name");

        // Answer-section order deliberately scrambled: grouping is by
        // (owner, type), never by arrival order.
        let answers = vec![
            txt_record(&target),
            rrsig_record(&at, RecordType::CNAME),
            cname_record(&at, &target),
            rrsig_record(&target, RecordType::TXT),
        ];

        let links = leaf_links(&at, &answers)?;
        assert_eq!(links.len(), 2, "one CNAME hop, one TXT leaf");

        assert_eq!(Link::parse(&links[0])?.rtype(), RrType::CNAME);
        assert_eq!(Link::parse(&links[1])?.rtype(), RrType::TXT);
        Ok(())
    }

    #[test]
    fn missing_signatures_are_unframeable() {
        let at = owner();
        let unsigned = vec![txt_record(&at)];

        assert!(matches!(
            frame_rrset(&unsigned, &at, RecordType::TXT),
            Err(FetchChainError::MissingRrset { .. })
        ));
    }

    #[test]
    fn missing_leaves_are_unframeable() {
        // ADR-045: no negative proofs — a courier cannot fabricate a
        // chain for a name without a TXT RRset, and says so.
        let at = owner();

        assert!(matches!(
            leaf_links(&at, &[]),
            Err(FetchChainError::MissingRrset { .. })
        ));
    }

    #[test]
    fn cname_loops_hit_the_hop_bound() {
        let at = owner();
        let answers = vec![
            cname_record(&at, &at), // self-loop
            rrsig_record(&at, RecordType::CNAME),
        ];

        assert!(matches!(
            leaf_links(&at, &answers),
            Err(FetchChainError::TooManyCnames)
        ));
    }
}
