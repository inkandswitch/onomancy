//! The chain-building walk as a sans-IO state machine.
//!
//! One question is in flight at a time; the next question depends
//! only on accumulated answers, so the whole walk is a
//! needs-query-out / records-in machine. [`ChainBuilder::answer`]
//! consumes the machine and either hands it back with the next
//! [`Question`] or yields the framed [`DnssecChain`] — a finished or
//! failed machine cannot be answered again.

use hickory_proto::{
    ProtoError,
    rr::{Name, RData, Record, RecordType},
    serialize::binary::{BinEncodable, BinEncoder},
};
use onomancy_core::wire::MAX_UNIT_BYTES;
use onomancy_dnssec::{
    certificate::chain::{ChainLink, DnssecChain},
    dns_name::DnsName,
};

use crate::question::Question;

/// Bounded CNAME indirection, matching the validator's own limit.
pub const MAX_CNAME_HOPS: usize = 8;

/// The chain-builder state machine: root DNSKEY, DS + DNSKEY per
/// signed cut, then the TXT leaf with bounded CNAME re-roots.
#[derive(Debug)]
pub struct ChainBuilder {
    links: Links,
    /// The deepest cut descended so far (the root before any cut).
    current_zone: Name,
    phase: Phase,
}

impl ChainBuilder {
    /// Begin building the chain for `hostname`'s `_onomancy` owner
    /// name. The first question is always the root DNSKEY `RRset`.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError::UnrepresentableName`] when the
    /// hostname does not fit under the `_onomancy` label.
    pub fn start(hostname: &DnsName) -> Result<(Self, Question), BuildError> {
        let owner = onomancy_owner(hostname)?;
        let builder = Self {
            links: Links::default(),
            current_zone: Name::root(),
            phase: Phase::RootKeys { owner },
        };
        let question = Question {
            name: Name::root(),
            rtype: RecordType::DNSKEY,
        };
        Ok((builder, question))
    }

    /// Feed the answer-section records for the question this machine
    /// last asked.
    ///
    /// Consumes the machine: [`Step::Ask`] hands it back for the next
    /// round, [`Step::Done`] is the framed chain. Framability is not
    /// validity: a framed chain may still fail the validator.
    ///
    /// Non-matching records error at the frame — with one deliberate
    /// exception: a DS probe whose answer holds no matching DS data
    /// reads as "not a signed cut" and the descent moves on
    /// (absence is never proven at v0), so records answering the wrong
    /// question are absorbed there rather than rejected.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError`] for answers that cannot be framed
    /// (no TXT leaf, missing signatures, runaway CNAME chains, a
    /// chain past the unit cap).
    pub fn answer(self, records: Vec<Record>) -> Result<Step, BuildError> {
        let Self {
            mut links,
            current_zone,
            phase,
        } = self;

        match phase {
            Phase::RootKeys { owner } => {
                links.push(frame_rrset(&records, &Name::root(), RecordType::DNSKEY)?)?;
                descend(
                    links,
                    owner.clone(),
                    1,
                    Name::root(),
                    Resume::Leaf { owner },
                )
            }

            Phase::Descent(descent) => descent.answer(links, &records),

            Phase::Leaf { owner } => {
                let walk = Walk {
                    answers: records,
                    current: owner,
                    remaining: MAX_CNAME_HOPS + 1,
                };
                walk.advance(links, &current_zone)
            }
        }
    }
}

/// One turn of the machine: the next question, or the finished chain.
#[derive(Debug)]
#[must_use]
#[allow(clippy::large_enum_variant)] // transient: destructured immediately, never stored
pub enum Step {
    /// Ask this question, then feed the answer to [`ChainBuilder::answer`].
    Ask(ChainBuilder, Question),

    /// Every link is framed; the machine is spent.
    Done(DnssecChain),
}

/// Where the machine is between question and answer.
#[derive(Debug)]
enum Phase {
    /// Awaiting the root DNSKEY `RRset` (the first question).
    RootKeys { owner: Name },

    /// Probing/framing signed cuts down one branch.
    Descent(Descent),

    /// Awaiting the TXT answer at the `_onomancy` owner.
    Leaf { owner: Name },
}

/// The framed links plus a running byte total enforcing the unit cap:
/// a chain that could never ride a certificate's attached region
/// (`MAX_UNIT_BYTES`) is unframeable by construction, bounding what a
/// malicious resolver can make the machine hold.
#[derive(Debug, Default)]
struct Links {
    links: Vec<ChainLink>,
    bytes: usize,
}

impl Links {
    fn push(&mut self, link: ChainLink) -> Result<(), BuildError> {
        self.bytes = self.bytes.saturating_add(link.as_bytes().len());

        if self.bytes > MAX_UNIT_BYTES {
            return Err(BuildError::OversizeChain { bytes: self.bytes });
        }

        self.links.push(link);
        Ok(())
    }

    fn into_chain(self) -> DnssecChain {
        DnssecChain::from(self.links)
    }
}

/// A cut descent down one branch: probe each suffix of `name` from a
/// starting depth, framing a DS + DNSKEY link pair per signed cut.
#[derive(Debug)]
struct Descent {
    /// The full name whose branch is being descended.
    name: Name,
    /// The label depth of the suffix just asked about (1-based).
    depth: u8,
    /// Which record of the current cut the machine awaits.
    awaiting: Cut,
    /// The deepest signed cut framed so far.
    deepest: Name,
    /// What to do once every suffix is probed.
    resume: Resume,
}

impl Descent {
    fn answer(mut self, mut links: Links, records: &[Record]) -> Result<Step, BuildError> {
        let zone = self.name.trim_to(usize::from(self.depth));

        match self.awaiting {
            Cut::Ds => {
                if !has_data(records, &zone, RecordType::DS) {
                    return self.next_cut(links); // not a zone cut, or an unsigned one
                }

                links.push(frame_rrset(records, &zone, RecordType::DS)?)?;
                self.awaiting = Cut::Dnskey;
                let question = Question {
                    name: zone,
                    rtype: RecordType::DNSKEY,
                };
                Ok(Step::Ask(self.suspend(links), question))
            }

            Cut::Dnskey => {
                links.push(frame_rrset(records, &zone, RecordType::DNSKEY)?)?;
                self.deepest = zone;
                self.next_cut(links)
            }
        }
    }

    /// Move to the next suffix's DS probe, or finish the descent.
    fn next_cut(mut self, links: Links) -> Result<Step, BuildError> {
        if self.depth >= self.name.num_labels() {
            return finish_descent(links, self.deepest, self.resume);
        }

        self.depth += 1;
        self.awaiting = Cut::Ds;
        let question = Question {
            name: self.name.trim_to(usize::from(self.depth)),
            rtype: RecordType::DS,
        };
        Ok(Step::Ask(self.suspend(links), question))
    }

    /// Repack this descent into a suspended machine.
    fn suspend(self, links: Links) -> ChainBuilder {
        ChainBuilder {
            links,
            // Unread while descending; `finish_descent` sets the real one.
            current_zone: Name::root(),
            phase: Phase::Descent(self),
        }
    }
}

/// Which record of a cut a descent awaits.
#[derive(Debug)]
enum Cut {
    Ds,
    Dnskey,
}

/// What a finished descent resumes.
#[derive(Debug)]
enum Resume {
    /// Ask for the TXT leaf at the `_onomancy` owner (first descent).
    Leaf { owner: Name },

    /// Continue walking an already-held leaf answer (mid-walk descent).
    Walk(Walk),
}

/// The CNAME walk over one leaf answer: recursive resolvers return
/// the whole CNAME chain plus the final TXT in a single answer
/// section, so no further leaf queries are needed — only cut descents
/// for hop targets (root-down on a cross-zone hop, below the current
/// zone for an in-zone target under a deeper cut).
#[derive(Debug)]
struct Walk {
    answers: Vec<Record>,
    current: Name,
    /// TXT checks left before the hop bound trips.
    remaining: usize,
}

impl Walk {
    /// Frame leaf links until done, out of hops, or suspended on a
    /// cut descent for a hop target. Pure: consumes no new answers.
    fn advance(mut self, mut links: Links, current_zone: &Name) -> Result<Step, BuildError> {
        loop {
            if self.remaining == 0 {
                return Err(BuildError::TooManyCnames);
            }
            self.remaining -= 1;

            if has_data(&self.answers, &self.current, RecordType::TXT) {
                links.push(frame_rrset(&self.answers, &self.current, RecordType::TXT)?)?;
                return Ok(Step::Done(links.into_chain()));
            }

            #[allow(clippy::wildcard_enum_match_arm)] // any other RData is not a CNAME
            let Some(target) = self.answers.iter().find_map(|record| match &record.data {
                RData::CNAME(cname) if record.name == self.current => Some(cname.0.clone()),
                _ => None,
            }) else {
                return Err(BuildError::MissingRrset {
                    owner: self.current.to_ascii(),
                    rtype: RecordType::TXT,
                });
            };

            links.push(frame_rrset(
                &self.answers,
                &self.current,
                RecordType::CNAME,
            )?)?;

            // Descend whatever signed cuts the target's branch holds
            // that are not already framed: a hop out of the deepest
            // descended zone re-descends root-down (the validator's
            // re-root rule); a hop WITHIN it may still land under a
            // deeper cut, so probe the labels below the current zone.
            let (from_depth, base) = if current_zone.zone_of(&target) {
                (current_zone.num_labels() + 1, current_zone.clone())
            } else {
                (1, Name::root())
            };
            self.current = target.clone();

            if from_depth <= target.num_labels() {
                return descend(links, target, from_depth, base, Resume::Walk(self));
            }
        }
    }
}

/// Descend `name`'s branch from `from_depth` (1-based): ask about
/// that suffix, or resume immediately when no suffixes remain.
/// `deepest` seeds the resulting zone when no new cut is framed.
fn descend(
    links: Links,
    name: Name,
    from_depth: u8,
    deepest: Name,
    resume: Resume,
) -> Result<Step, BuildError> {
    if from_depth > name.num_labels() {
        return finish_descent(links, deepest, resume);
    }

    let descent = Descent {
        depth: from_depth,
        awaiting: Cut::Ds,
        deepest,
        resume,
        name,
    };
    let question = Question {
        name: descent.name.trim_to(usize::from(from_depth)),
        rtype: RecordType::DS,
    };
    Ok(Step::Ask(descent.suspend(links), question))
}

/// Resume after a descent: the deepest cut becomes the current zone.
fn finish_descent(links: Links, deepest: Name, resume: Resume) -> Result<Step, BuildError> {
    match resume {
        Resume::Leaf { owner } => {
            let question = Question {
                name: owner.clone(),
                rtype: RecordType::TXT,
            };
            let builder = ChainBuilder {
                links,
                current_zone: deepest,
                phase: Phase::Leaf { owner },
            };
            Ok(Step::Ask(builder, question))
        }

        Resume::Walk(walk) => walk.advance(links, &deepest),
    }
}

/// `_onomancy.<hostname>.` as a hickory name.
fn onomancy_owner(hostname: &DnsName) -> Result<Name, BuildError> {
    Name::from_ascii(format!("_onomancy.{hostname}.")).map_err(BuildError::UnrepresentableName)
}

/// Whether `answers` holds any data record of `rtype` at `owner`.
fn has_data(answers: &[Record], owner: &Name, rtype: RecordType) -> bool {
    answers
        .iter()
        .any(|record| record.record_type() == rtype && record.name == *owner)
}

/// Frame one link: the `rtype` `RRset` at `owner` followed by the
/// RRSIGs covering it there — uncompressed, canonical-form records.
fn frame_rrset(
    answers: &[Record],
    owner: &Name,
    rtype: RecordType,
) -> Result<ChainLink, BuildError> {
    let data: Vec<&Record> = answers
        .iter()
        .filter(|record| record.record_type() == rtype && record.name == *owner)
        .collect();
    let signatures: Vec<&Record> = answers
        .iter()
        .filter(|record| covered_type(record) == Some(u16::from(rtype)) && record.name == *owner)
        .collect();

    if data.is_empty() || signatures.is_empty() {
        return Err(BuildError::MissingRrset {
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
/// Read from re-encoded wire bytes, never from the `RData` enum
/// shape: with hickory's DNSSEC feature off, RRSIG rides as RFC 3597
/// `Unknown` bytes, but Cargo feature unification in a downstream
/// build can silently switch it to the typed variant — the wire form
/// is identical either way, so this stays correct under both.
fn covered_type(record: &Record) -> Option<u16> {
    if record.record_type() != RecordType::RRSIG {
        return None;
    }

    let mut rdata = Vec::new();
    let mut encoder = BinEncoder::new(&mut rdata);
    encoder.set_canonical_form(true);
    record.data.emit(&mut encoder).ok()?;

    Some(u16::from_be_bytes([*rdata.first()?, *rdata.get(1)?]))
}

/// Append one record in uncompressed, DNSSEC-canonical wire form.
fn encode_canonical(record: &Record, bytes: &mut Vec<u8>) -> Result<(), BuildError> {
    let mut buffer = Vec::new();
    let mut encoder = BinEncoder::new(&mut buffer);
    encoder.set_canonical_form(true);
    record.emit(&mut encoder).map_err(BuildError::Encode)?;
    bytes.extend_from_slice(&buffer);
    Ok(())
}

/// Chain building failed — unframeable answers, never a transport
/// failure (the driver's) and never a validity verdict (the
/// validator's).
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// A record could not be re-encoded to wire form.
    #[error("record could not be re-encoded")]
    Encode(#[source] ProtoError),

    /// An expected `RRset` (or its covering RRSIG) was absent.
    #[error("no {rtype} RRset with signatures at {owner}")]
    MissingRrset {
        /// The owner name queried.
        owner: String,
        /// The record type sought.
        rtype: RecordType,
    },

    /// The framed links outgrew the certificate unit cap
    /// (`MAX_UNIT_BYTES`); such a chain could never ride a
    /// certificate's attached region.
    #[error("framed chain of {bytes} bytes exceeds the unit cap")]
    OversizeChain {
        /// The running total that crossed the cap.
        bytes: usize,
    },

    /// The CNAME chain exceeded the hop bound.
    #[error("more than {MAX_CNAME_HOPS} CNAME hops")]
    TooManyCnames,

    /// The hostname does not fit in a DNS wire name with the
    /// `_onomancy` label prepended.
    #[error("hostname does not fit under the _onomancy label")]
    UnrepresentableName(#[source] ProtoError),
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use hickory_proto::rr::rdata::{CNAME, NULL, TXT};
    use onomancy_dnssec::{
        link::{Link, ParseLinkError},
        validator::MAX_CNAME_HOPS as VALIDATOR_MAX_CNAME_HOPS,
        wire::rr_type::RrType,
    };
    use testresult::TestResult;

    /// Canned answers: drive the machine to completion from the map,
    /// answering unlisted questions with empty records. No futures,
    /// no executor — the machine is synchronous.
    fn drive(
        answers: &HashMap<(Name, RecordType), Vec<Record>>,
        hostname: &DnsName,
    ) -> Result<DnssecChain, BuildError> {
        let (mut builder, mut question) = ChainBuilder::start(hostname)?;

        loop {
            let records = answers
                .get(&(question.name.clone(), question.rtype))
                .cloned()
                .unwrap_or_default();

            match builder.answer(records)? {
                Step::Ask(next, asked) => {
                    builder = next;
                    question = asked;
                }
                Step::Done(chain) => return Ok(chain),
            }
        }
    }

    /// The link types of a framed chain, parsed under the strict
    /// validator grammar.
    fn link_types(chain: &DnssecChain) -> TestResult<Vec<RrType>> {
        Ok(chain
            .links()
            .iter()
            .map(|link| Ok(Link::parse(link)?.rtype()))
            .collect::<Result<_, ParseLinkError>>()?)
    }

    /// A signed DS + DNSKEY answer pair for `zone`.
    fn signed_cut(zone: &Name) -> [((Name, RecordType), Vec<Record>); 2] {
        [
            (
                (zone.clone(), RecordType::DS),
                vec![ds_record(zone), rrsig_record(zone, RecordType::DS)],
            ),
            (
                (zone.clone(), RecordType::DNSKEY),
                vec![dnskey_record(zone), rrsig_record(zone, RecordType::DNSKEY)],
            ),
        ]
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

    /// The minimal answer map: a signed root DNSKEY plus `extra`
    /// canned answers.
    fn transport(
        extra: Vec<((Name, RecordType), Vec<Record>)>,
    ) -> HashMap<(Name, RecordType), Vec<Record>> {
        let root = Name::root();
        let mut map = HashMap::from([(
            (root.clone(), RecordType::DNSKEY),
            vec![
                dnskey_record(&root),
                rrsig_record(&root, RecordType::DNSKEY),
            ],
        )]);
        map.extend(extra);
        map
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
        Record::from_rdata(at.clone(), 300, RData::CNAME(CNAME(target.clone())))
    }

    #[test]
    fn framed_links_parse_under_the_strict_validator_grammar() -> TestResult {
        let at = owner();
        let answers = vec![txt_record(&at), rrsig_record(&at, RecordType::TXT)];

        let link: ChainLink = frame_rrset(&answers, &at, RecordType::TXT)?;
        let parsed = Link::parse(&link)?;

        assert_eq!(parsed.rtype(), RrType::TXT);
        Ok(())
    }

    #[test]
    fn leaves_follow_cnames_in_order() -> TestResult {
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
        let map = transport(vec![((at, RecordType::TXT), answers)]);

        let chain = drive(&map, &hostname()?)?;
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
        let mut extra: Vec<((Name, RecordType), Vec<Record>)> = Vec::new();
        extra.extend(signed_cut(&source_zone));
        extra.extend(signed_cut(&target_zone));
        extra.push(((at, RecordType::TXT), leaf_answers));
        let map = transport(extra);

        let chain = drive(&map, &hostname()?)?;

        // Root keys, the source branch, the hop, then the TARGET
        // branch re-descended from the root — the validator's re-root
        // shape.
        assert_eq!(
            link_types(&chain)?,
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
    fn in_zone_cnames_descend_intermediate_deeper_cuts() -> TestResult {
        // CNAME target stays inside the current zone but lands under
        // a DEEPER signed cut: the walk must frame that cut's DS +
        // DNSKEY, or the (legitimate, validatable) chain can never
        // validate.
        let at = owner();
        let source_zone = Name::from_ascii("example.com.").expect("valid name");
        let child_zone = Name::from_ascii("certs.example.com.").expect("valid name");
        let target = Name::from_ascii("binding.certs.example.com.").expect("valid name");

        let leaf_answers = vec![
            cname_record(&at, &target),
            rrsig_record(&at, RecordType::CNAME),
            txt_record(&target),
            rrsig_record(&target, RecordType::TXT),
        ];
        let mut extra: Vec<((Name, RecordType), Vec<Record>)> = Vec::new();
        extra.extend(signed_cut(&source_zone));
        extra.extend(signed_cut(&child_zone));
        extra.push(((at, RecordType::TXT), leaf_answers));
        let map = transport(extra);

        let chain = drive(&map, &hostname()?)?;

        // Root keys, the source cut, the hop, then the child cut
        // probed below the current zone (no re-root: example.com's
        // links are not re-framed).
        assert_eq!(
            link_types(&chain)?,
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
    fn in_zone_cnames_without_deeper_cuts_stay_flat() -> TestResult {
        // Same-zone target with no intervening signed cut: DS probes
        // below the current zone come back empty and no extra links
        // are framed.
        let at = owner();
        let source_zone = Name::from_ascii("example.com.").expect("valid name");
        let target = Name::from_ascii("binding.pages.example.com.").expect("valid name");

        let leaf_answers = vec![
            cname_record(&at, &target),
            rrsig_record(&at, RecordType::CNAME),
            txt_record(&target),
            rrsig_record(&target, RecordType::TXT),
        ];
        let mut extra: Vec<((Name, RecordType), Vec<Record>)> = Vec::new();
        extra.extend(signed_cut(&source_zone));
        extra.push(((at, RecordType::TXT), leaf_answers));
        let map = transport(extra);

        let chain = drive(&map, &hostname()?)?;

        assert_eq!(
            link_types(&chain)?,
            vec![
                RrType::DNSKEY,
                RrType::DS,
                RrType::DNSKEY,
                RrType::CNAME,
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
            frame_rrset(&unsigned, &at, RecordType::TXT),
            Err(BuildError::MissingRrset { .. })
        ));
    }

    #[test]
    fn missing_leaves_are_unframeable() -> TestResult {
        // No negative proofs at v0 — a courier cannot fabricate a
        // chain for a name without a TXT RRset, and says so.
        let map = transport(vec![]);

        assert!(matches!(
            drive(&map, &hostname()?),
            Err(BuildError::MissingRrset { .. })
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
        let map = transport(vec![((at, RecordType::TXT), answers)]);

        assert!(matches!(
            drive(&map, &hostname()?),
            Err(BuildError::TooManyCnames)
        ));
        Ok(())
    }

    #[test]
    fn oversize_chains_are_unframeable() -> TestResult {
        // A malicious resolver stuffing giant RRsets hits the unit
        // cap instead of growing the machine without bound.
        let at = owner();
        let mut answers: Vec<Record> = (0..1100)
            .map(|_| {
                Record::from_rdata(
                    at.clone(),
                    300,
                    RData::TXT(TXT::new(vec!["x".repeat(255); 4])),
                )
            })
            .collect();
        answers.push(rrsig_record(&at, RecordType::TXT));
        let map = transport(vec![((at, RecordType::TXT), answers)]);

        assert!(matches!(
            drive(&map, &hostname()?),
            Err(BuildError::OversizeChain { .. })
        ));
        Ok(())
    }

    #[test]
    fn hop_bound_matches_the_validator() {
        assert_eq!(MAX_CNAME_HOPS, VALIDATOR_MAX_CNAME_HOPS);
    }
}
