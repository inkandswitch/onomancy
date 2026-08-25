//! The assembly walk as a sans-IO state machine.
//!
//! One question is in flight at a time; the next question depends
//! only on accumulated answers, so the whole walk is a
//! needs-query-out / records-in machine. [`Assembly::answer`]
//! consumes the machine and either hands it back with the next
//! [`Question`] or yields the framed [`DnssecChain`] — a finished or
//! failed machine cannot be answered again.

// Foreign-enum wildcards are deliberate: any RData shape this
// assembler does not recognize is simply not the record it is
// looking for.
#![allow(clippy::wildcard_enum_match_arm)]

use hickory_proto::{
    rr::{Name, RData, Record, RecordType},
    serialize::binary::{BinEncodable, BinEncoder},
};
use onomancy_core::{
    cert::chain::{ChainLink, DnssecChain},
    name::dns::DnsName,
};

use crate::question::Question;

/// Bounded CNAME indirection, matching the validator's own limit.
pub const MAX_CNAME_HOPS: usize = 8;

/// The chain-assembly state machine: root DNSKEY, DS + DNSKEY per
/// signed cut, then the TXT leaf with bounded CNAME re-roots.
#[derive(Debug)]
pub struct Assembly {
    links: Vec<ChainLink>,
    /// The deepest cut descended so far (the root before any cut).
    current_zone: Name,
    phase: Phase,
}

impl Assembly {
    /// Begin assembling the chain for `hostname`'s `_onomancy` owner
    /// name. The first question is always the root DNSKEY `RRset`.
    ///
    /// # Errors
    ///
    /// Returns [`AssembleError::UnrepresentableName`] when the
    /// hostname does not fit under the `_onomancy` label.
    pub fn start(hostname: &DnsName) -> Result<(Self, Question), AssembleError> {
        let owner = onomancy_owner(hostname)?;
        let assembly = Self {
            links: Vec::new(),
            current_zone: Name::root(),
            phase: Phase::RootKeys { owner },
        };
        let question = Question {
            name: Name::root(),
            rtype: RecordType::DNSKEY,
        };
        Ok((assembly, question))
    }

    /// Feed the answer-section records for the question this machine
    /// last asked.
    ///
    /// Consumes the machine: [`Step::Ask`] hands it back for the next
    /// round, [`Step::Done`] is the framed chain. Framability is not
    /// validity: a framed chain may still fail the validator.
    ///
    /// # Errors
    ///
    /// Returns [`AssembleError`] for answers that cannot be framed
    /// (no TXT leaf, missing signatures, runaway CNAME chains).
    pub fn answer(self, records: Vec<Record>) -> Result<Step, AssembleError> {
        let Self {
            mut links,
            current_zone,
            phase,
        } = self;

        match phase {
            Phase::RootKeys { owner } => {
                links.push(frame_rrset(&records, &Name::root(), RecordType::DNSKEY)?);
                descend(links, owner.clone(), Resume::Leaf { owner })
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
    /// Ask this question, then feed the answer to [`Assembly::answer`].
    Ask(Assembly, Question),

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

/// A root-down cut descent: probe every suffix of `name`, framing a
/// DS + DNSKEY link pair per signed cut.
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
    fn answer(
        mut self,
        mut links: Vec<ChainLink>,
        records: &[Record],
    ) -> Result<Step, AssembleError> {
        let zone = self.name.trim_to(usize::from(self.depth));

        match self.awaiting {
            Cut::Ds => {
                if !has_data(records, &zone, RecordType::DS) {
                    return self.next_cut(links); // not a zone cut, or an unsigned one
                }

                links.push(frame_rrset(records, &zone, RecordType::DS)?);
                self.awaiting = Cut::Dnskey;
                let question = Question {
                    name: zone,
                    rtype: RecordType::DNSKEY,
                };
                Ok(Step::Ask(self.suspend(links), question))
            }

            Cut::Dnskey => {
                links.push(frame_rrset(records, &zone, RecordType::DNSKEY)?);
                self.deepest = zone;
                self.next_cut(links)
            }
        }
    }

    /// Move to the next suffix's DS probe, or finish the descent.
    fn next_cut(mut self, links: Vec<ChainLink>) -> Result<Step, AssembleError> {
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
    fn suspend(self, links: Vec<ChainLink>) -> Assembly {
        Assembly {
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

    /// Continue walking an already-held leaf answer (re-root descent).
    Walk(Walk),
}

/// The CNAME walk over one leaf answer: recursive resolvers return
/// the whole CNAME chain plus the final TXT in a single answer
/// section, so no further leaf queries are needed — only re-root
/// descents for cross-zone hops.
#[derive(Debug)]
struct Walk {
    answers: Vec<Record>,
    current: Name,
    /// TXT checks left before the hop bound trips.
    remaining: usize,
}

impl Walk {
    /// Frame leaf links until done, out of hops, or suspended on a
    /// cross-zone re-root descent. Pure: consumes no new answers.
    fn advance(
        mut self,
        mut links: Vec<ChainLink>,
        current_zone: &Name,
    ) -> Result<Step, AssembleError> {
        loop {
            if self.remaining == 0 {
                return Err(AssembleError::TooManyCnames);
            }
            self.remaining -= 1;

            if has_data(&self.answers, &self.current, RecordType::TXT) {
                links.push(frame_rrset(&self.answers, &self.current, RecordType::TXT)?);
                return Ok(Step::Done(DnssecChain::from(links)));
            }

            let Some(target) = self.answers.iter().find_map(|record| match &record.data {
                RData::CNAME(cname) if record.name == self.current => Some(cname.0.clone()),
                _ => None,
            }) else {
                return Err(AssembleError::MissingRrset {
                    owner: self.current.to_ascii(),
                    rtype: RecordType::TXT,
                });
            };

            links.push(frame_rrset(
                &self.answers,
                &self.current,
                RecordType::CNAME,
            )?);

            // A hop out of the deepest descended zone re-descends the
            // target's branch root-down, matching the validator's
            // re-root rule.
            let rerooted = !current_zone.zone_of(&target);
            self.current = target.clone();

            if rerooted {
                return descend(links, target, Resume::Walk(self));
            }
        }
    }
}

/// Start a root-down descent of `name`'s branch: ask about the
/// shallowest suffix, or resume immediately when there is none.
fn descend(links: Vec<ChainLink>, name: Name, resume: Resume) -> Result<Step, AssembleError> {
    if name.num_labels() == 0 {
        return finish_descent(links, Name::root(), resume);
    }

    let descent = Descent {
        depth: 1,
        awaiting: Cut::Ds,
        deepest: Name::root(),
        resume,
        name,
    };
    let question = Question {
        name: descent.name.trim_to(1),
        rtype: RecordType::DS,
    };
    Ok(Step::Ask(descent.suspend(links), question))
}

/// Resume after a descent: the deepest cut becomes the current zone.
fn finish_descent(
    links: Vec<ChainLink>,
    deepest: Name,
    resume: Resume,
) -> Result<Step, AssembleError> {
    match resume {
        Resume::Leaf { owner } => {
            let question = Question {
                name: owner.clone(),
                rtype: RecordType::TXT,
            };
            let assembly = Assembly {
                links,
                current_zone: deepest,
                phase: Phase::Leaf { owner },
            };
            Ok(Step::Ask(assembly, question))
        }

        Resume::Walk(walk) => walk.advance(links, &deepest),
    }
}

/// `_onomancy.<hostname>.` as a hickory name.
fn onomancy_owner(hostname: &DnsName) -> Result<Name, AssembleError> {
    Name::from_ascii(format!("_onomancy.{hostname}."))
        .map_err(|_| AssembleError::UnrepresentableName)
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
) -> Result<ChainLink, AssembleError> {
    let data: Vec<&Record> = answers
        .iter()
        .filter(|record| record.record_type() == rtype && record.name == *owner)
        .collect();
    let signatures: Vec<&Record> = answers
        .iter()
        .filter(|record| covered_type(record) == Some(u16::from(rtype)) && record.name == *owner)
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
fn encode_canonical(record: &Record, bytes: &mut Vec<u8>) -> Result<(), AssembleError> {
    let mut buffer = Vec::new();
    let mut encoder = BinEncoder::new(&mut buffer);
    encoder.set_canonical_form(true);
    record
        .emit(&mut encoder)
        .map_err(|_| AssembleError::Encode)?;
    bytes.extend_from_slice(&buffer);
    Ok(())
}

/// Chain assembly failed — unframeable answers, never a transport
/// failure (the driver's) and never a validity verdict (the
/// validator's).
#[derive(Debug, thiserror::Error)]
pub enum AssembleError {
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

    /// The hostname does not fit in a DNS wire name with the
    /// `_onomancy` label prepended.
    #[error("hostname does not fit under the _onomancy label")]
    UnrepresentableName,
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use hickory_proto::rr::rdata::{NULL, TXT};
    use onomancy_dnssec::{link::Link, wire::record::RrType};
    use testresult::TestResult;

    /// Canned answers: drive the machine to completion from the map,
    /// answering unlisted questions with empty records. No futures,
    /// no executor — the machine is synchronous.
    fn drive(
        answers: &HashMap<(Name, RecordType), Vec<Record>>,
        hostname: &DnsName,
    ) -> Result<DnssecChain, AssembleError> {
        let (mut assembly, mut question) = Assembly::start(hostname)?;

        loop {
            let records = answers
                .get(&(question.name.clone(), question.rtype))
                .cloned()
                .unwrap_or_default();

            match assembly.answer(records)? {
                Step::Ask(next, asked) => {
                    assembly = next;
                    question = asked;
                }
                Step::Done(chain) => return Ok(chain),
            }
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

        let link: ChainLink = frame_rrset(&answers, &at, RecordType::TXT)?;
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
        let map = transport(vec![
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

        let chain = drive(&map, &hostname()?)?;
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
            frame_rrset(&unsigned, &at, RecordType::TXT),
            Err(AssembleError::MissingRrset { .. })
        ));
    }

    #[test]
    fn missing_leaves_are_unframeable() -> TestResult {
        // ADR-045: no negative proofs — a courier cannot fabricate a
        // chain for a name without a TXT RRset, and says so.
        let map = transport(vec![]);

        assert!(matches!(
            drive(&map, &hostname()?),
            Err(AssembleError::MissingRrset { .. })
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
            Err(AssembleError::TooManyCnames)
        ));
        Ok(())
    }
}
