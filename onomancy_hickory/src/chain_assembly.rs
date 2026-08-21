//! Chain assembly: recursive-resolver answers → framed links,
//! generic over the transport.
//!
//! The assembler mirrors the validator's expected grammar (root
//! DNSKEY; DS + child DNSKEY per signed cut; CNAME hops; TXT leaf)
//! but PROVES nothing — it selects and frames bytes. Suffixes without
//! a DS `RRset` are simply not cuts (or not signed ones); either way no
//! link is emitted and the validator renders the verdict.
//!
//! Transports plug in through [`Query`]: the OS-socket stub resolver
//! (this crate, `sockets` feature) and the Wasm `DoH` client
//! (`onomancy_wasm`) share every line above the socket.

// Foreign-enum wildcards are deliberate: any RData shape this courier
// does not recognize is simply not the record it is looking for.
#![allow(clippy::wildcard_enum_match_arm)]

use core::future::Future;

use hickory_proto::{
    op::{Edns, Message, MessageType, OpCode, Query as DnsQuery, ResponseCode},
    rr::{Name, RData, Record, RecordType},
    serialize::binary::{BinEncodable, BinEncoder},
};
use onomancy_core::{
    cert::chain::{ChainLink, DnssecChain},
    name::dns::DnsName,
};

/// Bounded CNAME indirection, matching the validator's own limit.
pub const MAX_CNAME_HOPS: usize = 8;

/// EDNS advertised payload size (the DNS-flag-day value).
pub const EDNS_PAYLOAD: u16 = 1232;

/// One DNS question to a recursive resolver — the transport seam.
///
/// Implementations return the answer-section records for `NoError`
/// and `NXDomain` responses (empty is meaningful: a suffix that is
/// not a zone cut probes exactly like this) and error on transport
/// failure or refusal.
pub trait Query {
    /// Transport-level failure — never a validity verdict.
    type Error: core::error::Error;

    /// The answer-section records for `name`/`rtype`.
    fn answers(
        &self,
        name: &Name,
        rtype: RecordType,
    ) -> impl Future<Output = Result<Vec<Record>, Self::Error>>;
}

/// Fetch and frame the full chain for `hostname`'s `_onomancy` owner
/// name, one [`Query`] at a time.
///
/// # Errors
///
/// Returns [`AssembleError`] for transport failures and for answers
/// that cannot even be framed (no TXT leaf, missing signatures,
/// runaway CNAME chains). Framability is not validity: a framed
/// chain may still fail the validator.
pub async fn assemble<Q: Query>(
    query: &Q,
    hostname: &DnsName,
) -> Result<DnssecChain, AssembleError<Q::Error>> {
    let owner = onomancy_owner(hostname)?;
    let mut links: Vec<ChainLink> = Vec::new();

    // Link 0: the root DNSKEY RRset.
    let root_keys = query
        .answers(&Name::root(), RecordType::DNSKEY)
        .await
        .map_err(AssembleError::Transport)?;
    links.push(frame_rrset(&root_keys, &Name::root(), RecordType::DNSKEY)?);

    let mut current_zone = descend_cuts(query, &owner, &mut links).await?;

    // The leaf: TXT at the owner, CNAME hops framed along the way. A
    // hop out of the deepest descended zone re-descends the target's
    // branch root-down, matching the validator's re-root rule.
    let leaf_answer = query
        .answers(&owner, RecordType::TXT)
        .await
        .map_err(AssembleError::Transport)?;

    let mut current = owner;
    for _ in 0..=MAX_CNAME_HOPS {
        if has_data(&leaf_answer, &current, RecordType::TXT) {
            links.push(frame_rrset(&leaf_answer, &current, RecordType::TXT)?);
            return Ok(DnssecChain::from(links));
        }

        let Some(target) = leaf_answer.iter().find_map(|r| match &r.data {
            RData::CNAME(cname) if r.name == current => Some(cname.0.clone()),
            _ => None,
        }) else {
            return Err(AssembleError::MissingRrset {
                owner: current.to_ascii(),
                rtype: RecordType::TXT,
            });
        };

        links.push(frame_rrset(&leaf_answer, &current, RecordType::CNAME)?);

        if !current_zone.zone_of(&target) {
            current_zone = descend_cuts(query, &target, &mut links).await?;
        }
        current = target;
    }

    Err(AssembleError::TooManyCnames)
}

/// Probe every suffix of `name` root-outward, framing a DS + DNSKEY
/// link pair per signed cut. Returns the deepest cut descended (the
/// root when there is none).
async fn descend_cuts<Q: Query>(
    query: &Q,
    name: &Name,
    links: &mut Vec<ChainLink>,
) -> Result<Name, AssembleError<Q::Error>> {
    let mut deepest = Name::root();

    for depth in 1..=name.num_labels() {
        let zone = name.trim_to(usize::from(depth));

        let ds_answer = query
            .answers(&zone, RecordType::DS)
            .await
            .map_err(AssembleError::Transport)?;
        if !has_data(&ds_answer, &zone, RecordType::DS) {
            continue; // not a zone cut, or an unsigned one
        }

        links.push(frame_rrset(&ds_answer, &zone, RecordType::DS)?);

        let keys = query
            .answers(&zone, RecordType::DNSKEY)
            .await
            .map_err(AssembleError::Transport)?;
        links.push(frame_rrset(&keys, &zone, RecordType::DNSKEY)?);

        deepest = zone;
    }

    Ok(deepest)
}

/// A recursion-desired, checking-disabled, DNSSEC-OK query message.
///
/// `CD` is set because judging is not the upstream's job: the
/// verifier wants the bytes even when the resolver's own validator
/// calls them bogus. Pass `id: 0` for `DoH` (RFC 9250/8484 cache
/// friendliness); socket transports use a per-query ID.
#[must_use]
pub fn build_query(name: &Name, rtype: RecordType, id: u16) -> Message {
    let mut edns = Edns::new();
    edns.set_dnssec_ok(true);
    edns.set_max_payload(EDNS_PAYLOAD);
    edns.set_version(0);

    // `Message::new` rather than `Message::query()`: the latter is
    // std-gated (it mints a random ID), and the ID is ours to choose.
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.metadata.checking_disabled = true;
    message
        .add_query(DnsQuery::query(name.clone(), rtype))
        .set_edns(edns);
    message
}

/// The answer section of an accepted response: `NoError` and
/// `NXDomain` both count (empty answers are meaningful), anything
/// else is a refusal.
///
/// # Errors
///
/// Returns [`Refused`] for every other response code.
pub fn accepted_answers(message: Message) -> Result<Vec<Record>, Refused> {
    match message.metadata.response_code {
        ResponseCode::NoError | ResponseCode::NXDomain => Ok(message.answers),
        code => Err(Refused { code }),
    }
}

/// `_onomancy.<hostname>.` as a hickory name.
fn onomancy_owner<E>(hostname: &DnsName) -> Result<Name, AssembleError<E>> {
    Name::from_ascii(format!("_onomancy.{hostname}."))
        .map_err(|_| AssembleError::UnrepresentableName)
}

/// Whether `answers` holds any data record of `rtype` at `owner`.
fn has_data(answers: &[Record], owner: &Name, rtype: RecordType) -> bool {
    answers
        .iter()
        .any(|r| r.record_type() == rtype && r.name == *owner)
}

/// Frame one link: the `rtype` `RRset` at `owner` followed by the
/// RRSIGs covering it there — uncompressed, canonical-form records.
fn frame_rrset<E>(
    answers: &[Record],
    owner: &Name,
    rtype: RecordType,
) -> Result<ChainLink, AssembleError<E>> {
    let data: Vec<&Record> = answers
        .iter()
        .filter(|r| r.record_type() == rtype && r.name == *owner)
        .collect();
    let signatures: Vec<&Record> = answers
        .iter()
        .filter(|r| covered_type(r) == Some(u16::from(rtype)) && r.name == *owner)
        .collect();

    if data.is_empty() || signatures.is_empty() {
        return Err(AssembleError::MissingRrset {
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
fn encode_canonical<E>(record: &Record, bytes: &mut Vec<u8>) -> Result<(), AssembleError<E>> {
    let mut buffer = Vec::new();
    let mut encoder = BinEncoder::new(&mut buffer);
    encoder.set_canonical_form(true);
    record
        .emit(&mut encoder)
        .map_err(|_| AssembleError::Encode)?;
    bytes.extend_from_slice(&buffer);
    Ok(())
}

/// The upstream refused the query (SERVFAIL, REFUSED, …).
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("upstream returned {code}")]
pub struct Refused {
    /// The response code.
    pub code: ResponseCode,
}

/// Chain assembly failed — transport trouble or unframeable answers,
/// never a validity verdict (that is the validator's).
#[derive(Debug, thiserror::Error)]
pub enum AssembleError<E> {
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

    /// The CNAME chain exceeded the hop bound.
    #[error("more than {MAX_CNAME_HOPS} CNAME hops")]
    TooManyCnames,

    /// A transport-level query failure.
    #[error(transparent)]
    Transport(E),

    /// The hostname does not fit in a DNS wire name with the
    /// `_onomancy` label prepended.
    #[error("hostname does not fit under the _onomancy label")]
    UnrepresentableName,
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use core::{
        convert::Infallible,
        future::{self, Future},
        pin::pin,
        task::{Context, Poll, Waker},
    };
    use std::collections::HashMap;

    use super::*;
    use hickory_proto::rr::rdata::{NULL, TXT};
    use onomancy_dnssec::{link::Link, wire::record::RrType};
    use testresult::TestResult;

    /// The tests never hit a transport: pin the error parameter.
    type TestError = AssembleError<Infallible>;

    /// A canned-answer transport: every query is answered from the
    /// map, unlisted queries answer empty.
    struct MapQuery(HashMap<(Name, RecordType), Vec<Record>>);

    impl Query for MapQuery {
        type Error = Infallible;

        fn answers(
            &self,
            name: &Name,
            rtype: RecordType,
        ) -> impl Future<Output = Result<Vec<Record>, Infallible>> {
            future::ready(Ok(self
                .0
                .get(&(name.clone(), rtype))
                .cloned()
                .unwrap_or_default()))
        }
    }

    /// Drive an always-ready future to completion (`MapQuery` never
    /// suspends).
    fn run<F: Future>(future: F) -> F::Output {
        let mut future = pin!(future);
        let mut context = Context::from_waker(Waker::noop());
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => output,
            Poll::Pending => unreachable!("MapQuery futures are always ready"),
        }
    }

    fn owner() -> Name {
        Name::from_ascii("_onomancy.example.com.").expect("valid name")
    }

    fn hostname() -> TestResult<DnsName> {
        Ok(DnsName::parse("example.com")?)
    }

    /// A structurally valid DNSKEY record at `at` (RFC 3597 bytes).
    fn dnskey_record(at: &Name) -> Record {
        let mut rdata: Vec<u8> = Vec::new();
        rdata.extend(257u16.to_be_bytes()); // flags: KSK
        rdata.push(3); // protocol
        rdata.push(13); // algorithm
        rdata.extend([0xCD; 64]); // key material

        Record::from_rdata(
            at.clone(),
            300,
            RData::Unknown {
                code: RecordType::DNSKEY,
                rdata: NULL::with(rdata),
            },
        )
    }

    /// A structurally valid DS record at `at`.
    fn ds_record(at: &Name) -> Record {
        let mut rdata: Vec<u8> = Vec::new();
        rdata.extend(4242u16.to_be_bytes()); // key tag
        rdata.push(13); // algorithm
        rdata.push(2); // digest type: SHA-256
        rdata.extend([0xEF; 32]); // digest

        Record::from_rdata(
            at.clone(),
            300,
            RData::Unknown {
                code: RecordType::DS,
                rdata: NULL::with(rdata),
            },
        )
    }

    /// The minimal transport: a signed root DNSKEY plus `extra`
    /// canned answers.
    fn transport(extra: Vec<((Name, RecordType), Vec<Record>)>) -> MapQuery {
        let root = Name::root();
        let mut map = HashMap::from([(
            (root.clone(), RecordType::DNSKEY),
            vec![
                dnskey_record(&root),
                rrsig_record(&root, RecordType::DNSKEY),
            ],
        )]);
        map.extend(extra);
        MapQuery(map)
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

        let link: ChainLink = frame_rrset::<Infallible>(&answers, &at, RecordType::TXT)?;
        let parsed = Link::parse(&link)?;

        assert_eq!(parsed.rtype(), RrType::TXT);
        Ok(())
    }

    #[test]
    fn assembled_leaves_follow_cnames_in_order() -> TestResult {
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
        let query = transport(vec![((at, RecordType::TXT), answers)]);

        let chain = run(assemble(&query, &hostname()?))?;
        let links = chain.links();
        assert_eq!(links.len(), 3, "root keys, one CNAME hop, one TXT leaf");

        assert_eq!(Link::parse(&links[1])?.rtype(), RrType::CNAME);
        assert_eq!(Link::parse(&links[2])?.rtype(), RrType::TXT);
        Ok(())
    }

    #[test]
    fn cross_zone_cnames_redescend_the_target_branch() -> TestResult {
        let at = owner();
        let source_zone = Name::from_ascii("example.com.").expect("valid name");
        let target = Name::from_ascii("binding.example.net.").expect("valid name");
        let target_zone = Name::from_ascii("example.net.").expect("valid name");

        let leaf_answers = vec![
            cname_record(&at, &target),
            rrsig_record(&at, RecordType::CNAME),
            txt_record(&target),
            rrsig_record(&target, RecordType::TXT),
        ];
        let query = transport(vec![
            (
                (source_zone.clone(), RecordType::DS),
                vec![
                    ds_record(&source_zone),
                    rrsig_record(&source_zone, RecordType::DS),
                ],
            ),
            (
                (source_zone.clone(), RecordType::DNSKEY),
                vec![
                    dnskey_record(&source_zone),
                    rrsig_record(&source_zone, RecordType::DNSKEY),
                ],
            ),
            (
                (target_zone.clone(), RecordType::DS),
                vec![
                    ds_record(&target_zone),
                    rrsig_record(&target_zone, RecordType::DS),
                ],
            ),
            (
                (target_zone.clone(), RecordType::DNSKEY),
                vec![
                    dnskey_record(&target_zone),
                    rrsig_record(&target_zone, RecordType::DNSKEY),
                ],
            ),
            ((at, RecordType::TXT), leaf_answers),
        ]);

        let chain = run(assemble(&query, &hostname()?))?;
        let types: Vec<RrType> = chain
            .links()
            .iter()
            .map(|link| Ok(Link::parse(link)?.rtype()))
            .collect::<Result<_, onomancy_dnssec::link::ParseLinkError>>()?;

        // Root keys, the source branch, the hop, then the TARGET
        // branch re-descended from the root — the validator's re-root
        // shape.
        assert_eq!(
            types,
            vec![
                RrType::DNSKEY,
                RrType::DS,
                RrType::DNSKEY,
                RrType::CNAME,
                RrType::DS,
                RrType::DNSKEY,
                RrType::TXT,
            ],
        );
        Ok(())
    }

    #[test]
    fn missing_signatures_are_unframeable() {
        let at = owner();
        let unsigned = vec![txt_record(&at)];

        assert!(matches!(
            frame_rrset::<Infallible>(&unsigned, &at, RecordType::TXT),
            Err(TestError::MissingRrset { .. })
        ));
    }

    #[test]
    fn missing_leaves_are_unframeable() -> TestResult {
        // ADR-045: no negative proofs — a courier cannot fabricate a
        // chain for a name without a TXT RRset, and says so.
        let query = transport(vec![]);

        assert!(matches!(
            run(assemble(&query, &hostname()?)),
            Err(TestError::MissingRrset { .. })
        ));
        Ok(())
    }

    #[test]
    fn cname_loops_hit_the_hop_bound() -> TestResult {
        let at = owner();
        let answers = vec![
            cname_record(&at, &at), // self-loop
            rrsig_record(&at, RecordType::CNAME),
        ];
        let query = transport(vec![((at, RecordType::TXT), answers)]);

        assert!(matches!(
            run(assemble(&query, &hostname()?)),
            Err(TestError::TooManyCnames)
        ));
        Ok(())
    }
}
