//! `derive(store, now, judgment)`: the binding-cache derivation.
//!
//! The store is the only state. Every piece of verifier state — the
//! accepted binding, the effective serial, tenure, lineage forks,
//! pending and contested sets, unbound status, divergence badges — is
//! a deterministic pure function of **what evidence you hold**, never
//! of when it arrived: sync is set union, gossip races decide nothing,
//! and where evidence is genuinely ambiguous the output is *contested*
//! and surfaced.
//!
//! ```text
//!            store ─┐
//!              now ─┼─► derive ─► Derivation (state)
//!         judgment ─┤               │
//!             pins ─┘               ▼ diff vs previous
//!                                 events (surfacing — the caller's job)
//! ```
//!
//! # Stages
//!
//! A normative evaluation order; each stage reads only earlier stages'
//! outputs, so the derivation is acyclic and total:
//!
//! 1. validate & extract   4. grade chains      7. serial & tenure
//! 2. exclude & defer      5. resolve document  8. absence & divergence
//! 3. lineage & forks      6. grade the binding
//!
//! # Module Organization
//!
//! - [`store`] — the grow-only item store
//! - [`judgment`] — the judgment-document view (claims, acceptances,
//!   resets)
//! - [`seam`] — the [`ChainValidator`](seam::ChainValidator) and
//!   [`AuthorityVerifier`](seam::AuthorityVerifier) oracles
//! - [`output`] — the derived-state vocabulary
//! - [`memory`] — table-driven fakes for conformance tests

pub mod judgment;
pub mod memory;
pub mod output;
pub mod seam;
pub mod store;

use alloc::{vec, vec::Vec};

use onomancy_core::{
    cert::Certificate,
    collections::{Map, Set},
    content_hash::ContentHash,
    freshness::{ChainWindow, Freshness, Grade},
    name::{dns::DnsName, doc::DocAnchor},
    statement::{rotation::RotationStatement, successor::SuccessorStatement},
    time::UnixSeconds,
    txt::generation_key::GenerationKey,
    zone_state::ZoneStateKey,
};

use self::{
    judgment::Judgment,
    output::{
        AcceptedBinding, BindingGrade, Derivation, Divergence, DivergenceSource, Fork, HostState,
        SuccessionFork,
    },
    seam::{AuthorityVerifier, ChainProof, ChainValidator},
    store::{Item, Store},
};
use crate::ladder::{self, Contender, Continuity, Verdict};

/// Serial deferral bound: 5 minutes of clock skew, in the serial's
/// millisecond convention.
const SKEW_MS: u64 = 5 * 60 * 1000;

/// Derive all verifier state from the evidence held.
///
/// Pure and total: the same `(store, now, judgment, pins)` yield the
/// same outputs on any device, in any implementation — including under
/// any permutation of the store. `pins` are the user's pinned targets,
/// read by stage 8's divergence badges only.
#[must_use]
#[allow(clippy::implicit_hasher)] // house Map alias, not a hashing seam
pub fn derive<V: ChainValidator, A: AuthorityVerifier>(
    store: &Store,
    now: UnixSeconds,
    judgment: &Judgment,
    pins: &Map<DnsName, Vec<DocAnchor>>,
    validator: &V,
    authority: &A,
) -> Derivation {
    // Stage 1: validate and extract.
    let evidence = validate_and_extract(store, validator, authority);

    // Hostname universe: everything any input mentions.
    let mut hostnames: Set<DnsName> = Set::default();
    hostnames.extend(evidence.records.iter().map(|r| r.hostname.clone()));
    hostnames.extend(evidence.absences.iter().map(|a| a.hostname.clone()));
    hostnames.extend(evidence.successors.iter().map(|s| s.hostname.clone()));
    hostnames.extend(judgment.claims.iter().map(|c| c.hostname.clone()));
    hostnames.extend(judgment.acceptances.keys().cloned());
    hostnames.extend(pins.keys().cloned());

    let mut hosts: Map<DnsName, HostState> = Map::default();

    for hostname in hostnames {
        let state = derive_host(&hostname, &evidence, now, judgment, pins);
        hosts.insert(hostname, state);
    }

    Derivation { hosts }
}

/// Derive one hostname's state (stages 2–8 are per-hostname).
fn derive_host(
    hostname: &DnsName,
    evidence: &Evidence,
    now: UnixSeconds,
    judgment: &Judgment,
    pins: &Map<DnsName, Vec<DocAnchor>>,
) -> HostState {
    // Stage 2: exclude and defer.
    let empty = Set::default();
    let excluded = judgment.resets.get(hostname).unwrap_or(&empty);
    let rotation_exclusions = global_rotation_exclusions(judgment);

    let considered: Vec<&BindingEvidence> = {
        let mut records: Vec<&BindingEvidence> = evidence
            .records
            .iter()
            .filter(|r| r.hostname == *hostname)
            .filter(|r| !excluded.contains(&r.hash))
            .filter(|r| !is_deferred(r, now))
            .collect();
        // Deterministic evaluation order regardless of store order.
        records.sort_unstable_by_key(|r| (r.document, r.key, r.hash));
        records
    };

    // Stage 3: lineage — heads, protected prefix, fork-implicated
    // suffix, per document (rotation statements are document-scoped).
    let lineage = build_lineage(evidence, &rotation_exclusions);

    // Stage 4: grade chains; apply the generation rules. A fresh
    // record attesting a protected generation is D12a fork territory:
    // it survives WITH a surfaced fork, never a silent rejection.
    let mut generation_forks: Vec<Fork> = Vec::new();
    let surviving: Vec<&BindingEvidence> = considered
        .iter()
        .copied()
        .filter(|r| match generation_rule(r, now, &lineage) {
            Disposition::Keep => true,
            Disposition::Reject => false,
            Disposition::KeepSurfacingFork => {
                generation_forks.push(Fork {
                    document: r.document,
                    at: r.generation,
                });
                true
            }
        })
        .collect();

    let mut forks: Vec<Fork> = lineage
        .forks
        .iter()
        .filter(|f| considered.iter().any(|r| r.document == f.document))
        .copied()
        .chain(generation_forks)
        .collect();
    forks.sort_unstable();
    forks.dedup();

    // Stage 5: resolve the document.
    let graph = ProofGraph::for_hostname(evidence, hostname, excluded);
    let resolution = resolve_document(&surviving, &graph, hostname, now, judgment, evidence);

    // Stage 6: grade the binding.
    let accepted = resolution.accepted.map(|(document, generation)| {
        let fresh_support = surviving
            .iter()
            .any(|r| r.document == document && freshness(r, now) == Freshness::Fresh);

        AcceptedBinding {
            document,
            generation,
            grade: if fresh_support {
                BindingGrade::Confirmed
            } else {
                BindingGrade::Provisional
            },
        }
    });

    // Stage 7: effective serial and tenure.
    let (effective_serial, tenure) = accepted.map_or((None, None), |binding| {
        let of_doc: Vec<&&BindingEvidence> = surviving
            .iter()
            .filter(|r| r.document == binding.document)
            .collect();

        // The accepted record is the LADDER-winning record of the
        // accepted document — fresh-first, then zone-state key — so a
        // fresh record with a lower serial wins and its downward
        // serial surfaces as a ratchet reset in the diff (D4a).
        let serial = of_doc
            .iter()
            .max_by_key(|r| (freshness(r, now) == Freshness::Fresh, r.key))
            .map(|r| r.key.serial);
        let span = tenure_span(&of_doc);

        (serial, span)
    });

    // Stage 8: absence, then divergence against the POST-mask output.
    let unbound = derive_unbound(hostname, evidence, &surviving, now, excluded);
    let masked = resolution.contested || unbound;
    let output_binding = if masked { None } else { accepted };
    let divergence = derive_divergence(hostname, output_binding.as_ref(), judgment, pins);

    HostState {
        accepted: output_binding,
        contested: resolution.contested,
        divergence,
        effective_serial: if masked { None } else { effective_serial },
        forks,
        pending: resolution.pending,
        succession_forks: graph.forks,
        tenure,
        unbound,
    }
}

// ————————————————————————— stage 1 —————————————————————————

/// Stage 1's output: validated, typed evidence with extraction
/// provenance.
#[derive(Debug, Default)]
struct Evidence {
    absences: Vec<AbsenceEvidence>,
    held: Set<ContentHash>,
    records: Vec<BindingEvidence>,
    rotations: Vec<RotationEvidence>,
    successors: Vec<SuccessorEvidence>,
}

/// One validated binding record's derivation-relevant facts.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BindingEvidence {
    document: DocAnchor,
    generation: GenerationKey,
    hash: ContentHash,
    hostname: DnsName,
    key: ZoneStateKey,
    leaf_inception: UnixSeconds,
    /// Whether the delegation chain threads the attested `g=` (D10).
    threads_generation: bool,
    window: ChainWindow,
}

/// A validated proven-absence record.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AbsenceEvidence {
    hash: ContentHash,
    hostname: DnsName,
    leaf_inception: UnixSeconds,
    window: ChainWindow,
}

/// Extraction provenance for a carried statement: excluded only when
/// named directly, or when NOT standalone and every carrier is
/// excluded (statements independently carried by a non-excluded item
/// survive a reset).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Provenance {
    carriers: Vec<ContentHash>,
    standalone: bool,
}

impl Provenance {
    fn record(&mut self, carrier: Option<ContentHash>) {
        match carrier {
            None => self.standalone = true,
            Some(hash) => {
                if !self.carriers.contains(&hash) {
                    self.carriers.push(hash);
                }
            }
        }
    }

    fn excluded(&self, own_hash: ContentHash, excluded: &Set<ContentHash>) -> bool {
        if excluded.contains(&own_hash) {
            return true;
        }
        if self.standalone {
            return false;
        }

        // Extracted-only: excluded when every carrier is.
        !self.carriers.is_empty() && self.carriers.iter().all(|c| excluded.contains(c))
    }
}

/// A valid rotation statement (document-scoped).
#[derive(Debug, Clone, PartialEq, Eq)]
struct RotationEvidence {
    hash: ContentHash,
    provenance: Provenance,
    replaced: GenerationKey,
    root_doc: DocAnchor,
    successor: GenerationKey,
}

/// A valid successor statement (hostname-scoped).
#[derive(Debug, Clone, PartialEq, Eq)]
struct SuccessorEvidence {
    hash: ContentHash,
    hostname: DnsName,
    predecessor: DocAnchor,
    provenance: Provenance,
    successor: DocAnchor,
}

fn validate_and_extract<V: ChainValidator, A: AuthorityVerifier>(
    store: &Store,
    validator: &V,
    authority: &A,
) -> Evidence {
    let mut evidence = Evidence::default();

    for item in store.items() {
        let hash = item.content_hash();
        evidence.held.insert(hash);

        match item {
            Item::Record(certificate) => {
                // Extraction is closed over DECODABLE carriers, before
                // any chain judgment: a superseded certificate whose
                // chain is stale or absent still yields its carried
                // statements (they are independently signed units, and
                // gap-bridging needs exactly those bytes).
                for statement in certificate.lineage() {
                    extract_rotation(&mut evidence, authority, statement, Some(hash));
                }
                if let Some(statement) = certificate.predecessor() {
                    extract_successor(&mut evidence, authority, statement, Some(hash));
                }

                if let Some(binding) = validate_record(certificate, hash, validator, authority) {
                    evidence.records.push(binding);
                }
            }

            Item::ChainRefresh { hostname, chain } => {
                let Ok(ChainProof::Binding {
                    leaf_inception,
                    records,
                    window,
                }) = validator.validate(hostname, chain)
                else {
                    continue;
                };

                // A bare refresh proves the whole RRset: each record
                // is candidate evidence (dual-publish carries several
                // documents); the ladder selects downstream.
                evidence
                    .records
                    .extend(records.iter().map(|record| BindingEvidence {
                        document: *record.document(),
                        generation: *record.generation(),
                        hash,
                        hostname: hostname.clone(),
                        key: ZoneStateKey {
                            window_end: window.expiration(),
                            serial: record.serial(),
                            // Bare refreshes sort below equal-window,
                            // equal-serial certificate items.
                            issued_at: UnixSeconds::from(0),
                        },
                        leaf_inception,
                        // No delegation chain to check: D10 is a
                        // certificate rule.
                        threads_generation: true,
                        window,
                    }));
            }

            Item::Absence { hostname, chain } => {
                let Ok(ChainProof::Absence {
                    leaf_inception,
                    window,
                }) = validator.validate(hostname, chain)
                else {
                    continue;
                };

                evidence.absences.push(AbsenceEvidence {
                    hash,
                    hostname: hostname.clone(),
                    leaf_inception,
                    window,
                });
            }

            Item::Rotation(statement) => {
                extract_rotation(&mut evidence, authority, statement, None);
            }

            Item::Successor(statement) => {
                extract_successor(&mut evidence, authority, statement, None);
            }
        }
    }

    evidence
}

/// Validate one certificate item into a binding record: chain proof,
/// TXT cross-check, D10 threading input.
fn validate_record<V: ChainValidator, A: AuthorityVerifier>(
    certificate: &Certificate,
    hash: ContentHash,
    validator: &V,
    authority: &A,
) -> Option<BindingEvidence> {
    let Ok(ChainProof::Binding {
        leaf_inception,
        records,
        window,
    }) = validator.validate(certificate.hostname(), certificate.dnssec_chain())
    else {
        return None;
    };

    // Cross-check: the chain-proven RRset must attest the
    // certificate's own document. Among matching records — several is
    // legal within one window (migration dual-publish) — the highest
    // serial is the zone's word for this document.
    let record = records
        .iter()
        .filter(|record| record.document() == certificate.root_doc())
        .max_by_key(|record| record.serial())?;

    let threads_generation = authority.threads(certificate.delegation_chain(), record.generation());

    Some(BindingEvidence {
        document: *certificate.root_doc(),
        generation: *record.generation(),
        hash,
        hostname: certificate.hostname().clone(),
        key: ZoneStateKey {
            window_end: window.expiration(),
            serial: record.serial(),
            issued_at: certificate.issued_at(),
        },
        leaf_inception,
        threads_generation,
        window,
    })
}

fn extract_rotation<A: AuthorityVerifier>(
    evidence: &mut Evidence,
    authority: &A,
    statement: &RotationStatement,
    carrier: Option<ContentHash>,
) {
    // Signature validity was settled at decode; carriage authority is
    // the remaining validity condition (B9: invalid statements are
    // discarded entirely — no lineage effect, never fork evidence).
    if !authority.authorizes(
        statement.root_doc(),
        statement.successor().verifying_key(),
        statement.authority(),
    ) {
        return;
    }

    let hash = statement.digest().into();

    if let Some(existing) = evidence.rotations.iter_mut().find(|r| r.hash == hash) {
        existing.provenance.record(carrier);
        return;
    }

    let mut provenance = Provenance::default();
    provenance.record(carrier);

    evidence.rotations.push(RotationEvidence {
        hash,
        provenance,
        replaced: *statement.replaced(),
        root_doc: *statement.root_doc(),
        successor: *statement.successor(),
    });
}

fn extract_successor<A: AuthorityVerifier>(
    evidence: &mut Evidence,
    authority: &A,
    statement: &SuccessorStatement,
    carrier: Option<ContentHash>,
) {
    if !authority.authorizes(
        statement.predecessor_doc(),
        statement.signer(),
        statement.authority(),
    ) {
        return;
    }

    let hash = statement.digest().into();

    if let Some(existing) = evidence.successors.iter_mut().find(|s| s.hash == hash) {
        existing.provenance.record(carrier);
        return;
    }

    let mut provenance = Provenance::default();
    provenance.record(carrier);

    evidence.successors.push(SuccessorEvidence {
        hash,
        hostname: statement.hostname().clone(),
        predecessor: *statement.predecessor_doc(),
        provenance,
        successor: *statement.successor_doc(),
    });
}

// ————————————————————————— stage 2 —————————————————————————

/// Rotation statements are document-scoped: an exclusion from ANY
/// hostname's reset removes the statement for its document everywhere.
fn global_rotation_exclusions(judgment: &Judgment) -> Set<ContentHash> {
    let mut all: Set<ContentHash> = Set::default();
    for excluded in judgment.resets.values() {
        all.extend(excluded.iter().copied());
    }
    all
}

/// Deferral: far-future serials (beyond the skew bound, in the
/// serial's millisecond convention) and not-yet-begun windows are not
/// considered until the clock reaches them. Deferral precedes
/// everything, including freshness.
fn is_deferred(record: &BindingEvidence, now: UnixSeconds) -> bool {
    let now_ms = now.value().saturating_mul(1000);
    let far_future = record.key.serial.value() > now_ms.saturating_add(SKEW_MS);

    far_future || record.window.grade(now) == Grade::NotYetBegun
}

// ————————————————————————— stage 3 —————————————————————————

/// Stage 3's output: per-document generation history, scoped by the
/// heads rule (ADR-042 / Heads and the Protected Prefix).
#[derive(Debug, Default)]
struct LineageView {
    forks: Vec<Fork>,
    /// Fork-implicated generations, per document: D12a territory.
    implicated: Set<(DocAnchor, GenerationKey)>,
    /// The protected prefix, per document: D12 stays armed here.
    protected: Set<(DocAnchor, GenerationKey)>,
}

fn build_lineage(evidence: &Evidence, excluded: &Set<ContentHash>) -> LineageView {
    let mut rotations: Vec<&RotationEvidence> = evidence
        .rotations
        .iter()
        .filter(|r| !r.provenance.excluded(r.hash, excluded))
        .collect();
    rotations.sort_unstable_by_key(|r| (r.root_doc, r.replaced, r.successor, r.hash));
    rotations.dedup_by_key(|r| (r.root_doc, r.replaced, r.successor));

    let mut view = LineageView::default();

    let mut documents: Vec<DocAnchor> = rotations.iter().map(|r| r.root_doc).collect();
    documents.sort_unstable();
    documents.dedup();

    for document in documents {
        let of_doc: Vec<&&RotationEvidence> = rotations
            .iter()
            .filter(|r| r.root_doc == document)
            .collect();

        // Set-wise chain-shape checks (D18): double-replace and
        // cycles from generation-key reuse. A double SUCCESSOR with
        // distinct replaced keys is a legal convergence merge — fork
        // repair requires it, and only the successor key's holder can
        // mint one (statements are signed BY the successor).
        let mut fork_points: Vec<GenerationKey> = Vec::new();

        for (index, rotation) in of_doc.iter().enumerate() {
            for other in of_doc.iter().skip(index + 1) {
                if rotation.replaced == other.replaced {
                    fork_points.push(rotation.replaced);
                }
            }
        }
        if let Some(reused) = find_cycle(&of_doc) {
            fork_points.push(reused);
        }

        fork_points.sort_unstable();
        fork_points.dedup();

        // Heads: successors never replaced. A single head settles the
        // lineage — every replaced generation is protected, however
        // contested the route was (all branches were retired). Cycles
        // never settle (a cycle has no head at all along its loop).
        let heads = lineage_heads(&of_doc);
        let has_cycle = find_cycle(&of_doc).is_some();

        if (heads.len() <= 1 && !has_cycle) || fork_points.is_empty() {
            for rotation in &of_doc {
                view.protected.insert((document, rotation.replaced));
            }
        } else {
            // Unresolved fork: the implicated suffix is the fork
            // points plus everything forward-reachable from them.
            let implicated = forward_closure(&fork_points, &of_doc);

            for rotation in &of_doc {
                if implicated.contains(&rotation.replaced) {
                    view.implicated.insert((document, rotation.replaced));
                } else {
                    view.protected.insert((document, rotation.replaced));
                }
            }
            for key in &implicated {
                view.implicated.insert((document, *key));
            }
        }

        for at in fork_points {
            view.forks.push(Fork { document, at });
        }
    }

    view.forks.sort_unstable();
    view
}

/// The lineage's heads: successor keys that no statement replaces.
fn lineage_heads(rotations: &[&&RotationEvidence]) -> Vec<GenerationKey> {
    let mut heads: Vec<GenerationKey> = rotations
        .iter()
        .map(|r| r.successor)
        .filter(|successor| rotations.iter().all(|r| r.replaced != *successor))
        .collect();
    heads.sort_unstable();
    heads.dedup();
    heads
}

/// Generations reachable from the fork points (inclusive), walking
/// replaced → successor edges.
fn forward_closure(
    fork_points: &[GenerationKey],
    rotations: &[&&RotationEvidence],
) -> Vec<GenerationKey> {
    let mut reached: Vec<GenerationKey> = fork_points.to_vec();
    let mut frontier: Vec<GenerationKey> = fork_points.to_vec();

    while let Some(key) = frontier.pop() {
        for rotation in rotations {
            if rotation.replaced == key && !reached.contains(&rotation.successor) {
                reached.push(rotation.successor);
                frontier.push(rotation.successor);
            }
        }
    }

    reached.sort_unstable();
    reached
}

/// Detect a cycle in the replaced → successor graph; returns a key on
/// the cycle (a retired generation reappearing as a successor).
fn find_cycle(rotations: &[&&RotationEvidence]) -> Option<GenerationKey> {
    for start in rotations {
        let mut current = start.successor;

        for _ in 0..rotations.len() {
            let Some(next) = rotations.iter().find(|r| r.replaced == current) else {
                break;
            };
            current = next.successor;

            if current == start.replaced {
                return Some(start.replaced);
            }
        }
    }

    None
}

// ————————————————————————— stage 4 —————————————————————————

fn freshness(record: &BindingEvidence, now: UnixSeconds) -> Freshness {
    match record.window.grade(now) {
        Grade::Fresh => Freshness::Fresh,
        // NotYetBegun was deferred at stage 2.
        Grade::NotYetBegun | Grade::Stale => Freshness::Stale,
    }
}

/// A record's fate under the generation rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Disposition {
    Keep,
    /// D12a: a fresh chain contradicting settled lineage is competing
    /// valid evidence — it survives, loudly.
    KeepSurfacingFork,
    Reject,
}

/// D10 and D12/D12a: the generation rules.
fn generation_rule(
    record: &BindingEvidence,
    now: UnixSeconds,
    lineage: &LineageView,
) -> Disposition {
    let fresh = freshness(record, now) == Freshness::Fresh;

    // D10: a fresh record whose delegation chain does not thread the
    // attested g= is rejected.
    if fresh && !record.threads_generation {
        return Disposition::Reject;
    }

    let slot = (record.document, record.generation);

    if lineage.protected.contains(&slot) {
        // D12 for stale history: a protected-prefix generation is a
        // provable rewind. A FRESH chain attesting it is competing
        // valid observation (D12a): surfaced, never hard-rejected.
        return if fresh {
            Disposition::KeepSurfacingFork
        } else {
            Disposition::Reject
        };
    }

    if lineage.implicated.contains(&slot) {
        // Fork-implicated suffix: surfaced, never silently preferred
        // or rejected.
        return Disposition::KeepSurfacingFork;
    }

    Disposition::Keep
}

// ————————————————————————— stage 5 —————————————————————————

#[derive(Debug, Default)]
struct DocumentResolution {
    accepted: Option<(DocAnchor, GenerationKey)>,
    contested: bool,
    pending: Vec<DocAnchor>,
}

/// The hostname's succession-proof graph, with D16 forks isolated:
/// traversal never crosses a fork point.
#[derive(Debug, Default)]
struct ProofGraph {
    edges: Vec<(DocAnchor, DocAnchor)>,
    forks: Vec<SuccessionFork>,
}

impl ProofGraph {
    fn for_hostname(evidence: &Evidence, hostname: &DnsName, excluded: &Set<ContentHash>) -> Self {
        let mut edges: Vec<(DocAnchor, DocAnchor)> = evidence
            .successors
            .iter()
            .filter(|s| s.hostname == *hostname)
            .filter(|s| !s.provenance.excluded(s.hash, excluded))
            .map(|s| (s.predecessor, s.successor))
            .collect();
        edges.sort_unstable();
        edges.dedup();

        // D16: one predecessor, competing valid successors = a fork.
        let mut forks: Vec<SuccessionFork> = Vec::new();
        let mut predecessors: Vec<DocAnchor> = edges.iter().map(|(pred, _)| *pred).collect();
        predecessors.sort_unstable();
        predecessors.dedup();

        for predecessor in predecessors {
            let successors: Vec<DocAnchor> = edges
                .iter()
                .filter(|(pred, _)| *pred == predecessor)
                .map(|(_, succ)| *succ)
                .collect();

            if successors.len() > 1 {
                forks.push(SuccessionFork {
                    predecessor,
                    successors,
                });
            }
        }

        Self { edges, forks }
    }

    /// Whether `document` is a fork point (D16 stops traversal here).
    fn is_fork_point(&self, document: DocAnchor) -> bool {
        self.forks.iter().any(|f| f.predecessor == document)
    }

    /// The unique-successor chain from `from`: proofs are followed one
    /// hop at a time, stopping at forks (D16) and cycles.
    fn chain_from(&self, from: DocAnchor) -> Vec<DocAnchor> {
        let mut chain = vec![from];
        let mut current = from;

        loop {
            if self.is_fork_point(current) {
                return chain;
            }

            let next = self
                .edges
                .iter()
                .find(|(pred, _)| *pred == current)
                .map(|(_, succ)| *succ);

            match next {
                Some(successor) if !chain.contains(&successor) => {
                    chain.push(successor);
                    current = successor;
                }
                _ => return chain,
            }
        }
    }

    /// Whether an unforked proof path connects `from` to `to`.
    fn proves(&self, from: DocAnchor, to: DocAnchor) -> bool {
        from != to && self.chain_from(from).contains(&to)
    }
}

fn resolve_document(
    surviving: &[&BindingEvidence],
    graph: &ProofGraph,
    hostname: &DnsName,
    now: UnixSeconds,
    judgment: &Judgment,
    evidence: &Evidence,
) -> DocumentResolution {
    // Best record per candidate document (same-document zone-state
    // order is total), in a deterministic order.
    let best: Vec<&BindingEvidence> = {
        let mut documents: Vec<DocAnchor> = surviving.iter().map(|r| r.document).collect();
        documents.sort_unstable();
        documents.dedup();

        documents
            .into_iter()
            .filter_map(|document| {
                surviving
                    .iter()
                    .filter(|r| r.document == document)
                    .max_by_key(|r| r.key)
                    .copied()
            })
            .collect()
    };

    let Some((&first_candidate, _)) = best.split_first() else {
        return DocumentResolution::default();
    };

    // Ladder-maximal candidate as the UNDOMINATED set: order- and
    // implementation-independent, unlike a fold. Exactly one
    // undominated candidate = the maximum; anything else (equivocation,
    // forks, rung cycles) = contested.
    let undominated: Vec<&BindingEvidence> = best
        .iter()
        .filter(|candidate| {
            !best.iter().any(|other| {
                other.document != candidate.document
                    && ladder_verdict(other, candidate, graph, now) == Verdict::Left
            })
        })
        .copied()
        .collect();

    let mut contested = undominated.len() != 1;
    // Under a dominance cycle (undominated empty) the output is
    // contested and masked; the fallback feeds masked internals only,
    // deterministically (best is document-sorted).
    let maximal = undominated.first().copied().unwrap_or(first_candidate);

    // The winning acceptance, by the receipts rule.
    let acceptance = winning_acceptance(hostname, judgment, evidence, &mut contested);

    // Incumbency: acceptance-backed, extended along proofs up to the
    // first fork (D16); else the ladder-maximal candidate (graded
    // provisional at stage 6 when its support is stale — B10).
    let incumbent = acceptance.map_or(maximal.document, |document| {
        *graph.chain_from(document).last().unwrap_or(&document)
    });

    // Eligibility: the pending doctrine (B1). Every stale, unproven
    // non-incumbent candidate is pending — not just the maximal one.
    let accepted_document = if maximal.document == incumbent || contested {
        incumbent
    } else {
        let eligible = freshness(maximal, now) == Freshness::Fresh
            || graph.proves(incumbent, maximal.document);

        if eligible {
            maximal.document
        } else {
            incumbent
        }
    };

    // B1: every stale candidate attesting a document other than the
    // judgment-backed incumbent, without a proof, badges pending — not
    // just the maximal challenger. The incumbent itself never does:
    // when displaced, that surfaces as a binding change, not a badge.
    let mut pending: Vec<DocAnchor> = best
        .iter()
        .filter(|candidate| {
            candidate.document != accepted_document && candidate.document != incumbent
        })
        .filter(|candidate| freshness(candidate, now) == Freshness::Stale)
        // A valid proof in EITHER direction removes the badge: a
        // proven successor is routine continuation, and a proven
        // predecessor is superseded history — neither is an unproven
        // challenger.
        .filter(|candidate| {
            !graph.proves(accepted_document, candidate.document)
                && !graph.proves(candidate.document, accepted_document)
        })
        .map(|candidate| candidate.document)
        .collect();
    pending.sort_unstable();
    pending.dedup();

    // The accepted document's ladder-winning record carries the
    // attested generation (fresh-first, then key — the D4a order).
    let generation = surviving
        .iter()
        .filter(|r| r.document == accepted_document)
        .max_by_key(|r| (freshness(r, now) == Freshness::Fresh, r.key))
        .map(|r| r.generation);

    DocumentResolution {
        accepted: generation.map(|g| (accepted_document, g)),
        contested,
        pending,
    }
}

/// One pair's ladder verdict, with rung 1 computed from the proofs.
fn ladder_verdict(
    left: &BindingEvidence,
    right: &BindingEvidence,
    graph: &ProofGraph,
    now: UnixSeconds,
) -> Verdict {
    let continuity = match (
        graph.proves(left.document, right.document),
        graph.proves(right.document, left.document),
    ) {
        (true, true) => Continuity::Fork,
        (true, false) => Continuity::RightNewer,
        (false, true) => Continuity::LeftNewer,
        (false, false) => Continuity::Silent,
    };

    ladder::compare(
        &as_contender(left, now),
        &as_contender(right, now),
        continuity,
    )
}

fn as_contender(record: &BindingEvidence, now: UnixSeconds) -> Contender {
    Contender {
        document: record.document,
        freshness: freshness(record, now),
        key: record.key,
    }
}

/// Resolve possibly-concurrent acceptances by the receipts rule:
/// greatest zone-state key among cited records held in evidence.
/// Receipt ties for different documents are contested (B13).
fn winning_acceptance(
    hostname: &DnsName,
    judgment: &Judgment,
    evidence: &Evidence,
    contested: &mut bool,
) -> Option<DocAnchor> {
    let empty = Set::default();
    let excluded = judgment.resets.get(hostname).unwrap_or(&empty);
    let acceptances = judgment.acceptances.get(hostname)?;

    let mut ranked: Vec<(ZoneStateKey, DocAnchor)> = acceptances
        .iter()
        .filter_map(|acceptance| {
            // Inert when any cited item is reset-excluded; not-yet-
            // evaluable until every cited item is held.
            if acceptance.cited.iter().any(|hash| excluded.contains(hash)) {
                return None;
            }
            if !acceptance
                .cited
                .iter()
                .all(|hash| evidence.held.contains(hash))
            {
                return None;
            }

            // Receipt shape: every cited item a record for THIS
            // hostname, at least one attesting the acceptance's
            // document. Malformed receipts contribute nothing.
            let cited_records: Vec<&BindingEvidence> = evidence
                .records
                .iter()
                .filter(|r| acceptance.cited.contains(&r.hash))
                .collect();

            if cited_records.len() != acceptance.cited.len()
                || cited_records.iter().any(|r| r.hostname != *hostname)
                || !cited_records
                    .iter()
                    .any(|r| r.document == acceptance.document)
            {
                return None;
            }

            cited_records
                .iter()
                .map(|r| r.key)
                .max()
                .map(|key| (key, acceptance.document))
        })
        .collect();

    ranked.sort_unstable();

    let (best_key, winner) = *ranked.last()?;

    if ranked
        .iter()
        .any(|(key, document)| *key == best_key && *document != winner)
    {
        *contested = true;
        return None;
    }

    Some(winner)
}

// ————————————————————— stages 7 and 8 —————————————————————

/// The tenure span: earliest chain-window inception to latest window
/// end among the accepted document's surviving records.
fn tenure_span(records: &[&&BindingEvidence]) -> Option<ChainWindow> {
    let inception = records.iter().map(|r| r.window.inception()).min()?;
    let expiration = records.iter().map(|r| r.window.expiration()).max()?;

    // Spanning valid windows is valid: min ≤ every inception ≤ its
    // own expiration ≤ max.
    ChainWindow::new(inception, expiration).ok()
}

/// B12: fresh ✓ proven absence whose leaf RRSIG inception is strictly
/// later than every surviving binding record's yields unbound. Stale
/// absence proofs prove only past absence.
fn derive_unbound(
    hostname: &DnsName,
    evidence: &Evidence,
    surviving: &[&BindingEvidence],
    now: UnixSeconds,
    excluded: &Set<ContentHash>,
) -> bool {
    evidence
        .absences
        .iter()
        .filter(|a| a.hostname == *hostname)
        .filter(|a| !excluded.contains(&a.hash))
        .filter(|a| a.window.grade(now) == Grade::Fresh)
        .any(|absence| {
            surviving
                .iter()
                .all(|record| absence.leaf_inception > record.leaf_inception)
        })
}

/// Stage 8's divergence badges: claims and pins that disagree with the
/// (post-mask) accepted binding.
fn derive_divergence(
    hostname: &DnsName,
    accepted: Option<&AcceptedBinding>,
    judgment: &Judgment,
    pins: &Map<DnsName, Vec<DocAnchor>>,
) -> Vec<Divergence> {
    let Some(binding) = accepted else {
        return Vec::new();
    };

    let mut divergence: Vec<Divergence> = Vec::new();

    for claim in judgment.claims.iter().filter(|c| c.hostname == *hostname) {
        if claim.document != binding.document {
            divergence.push(Divergence {
                alleged: claim.document,
                source: DivergenceSource::Claim,
            });
        }
    }

    for pin in pins.get(hostname).into_iter().flatten() {
        if *pin != binding.document {
            divergence.push(Divergence {
                alleged: *pin,
                source: DivergenceSource::Pin,
            });
        }
    }

    divergence.sort_unstable();
    divergence.dedup();
    divergence
}
