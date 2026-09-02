//! `derive(store, now, decisions)`: the binding-cache derivation.
//!
//! The store is the only state. Every piece of verifier state — the
//! accepted binding, the effective serial, tenure, lineage forks,
//! pending and contested sets, divergence badges — is
//! a deterministic pure function of **what evidence you hold**, never
//! of when it arrived: sync is set union, gossip races decide nothing,
//! and where evidence is genuinely ambiguous the output is *contested*
//! and surfaced.
//!
//! ```text
//!            store ─┐
//!              now ─┼─► derive ─► VerifierState (state)
//!         decisions ─┤               │
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
//! - [`decisions`] — the decisions-document view (claims, acceptances,
//!   resets)
//! - [`seam`] — the [`ChainValidator`](chain_proof::ChainValidator) and
//!   [`AuthorityVerifier`](authority_verifier::AuthorityVerifier) oracles
//! - [`output`] — the derived-state vocabulary
//! - [`memory`] — table-driven fakes for conformance tests

pub mod authority_verifier;
pub mod binding_state;
pub mod decisions;
pub mod diff;
pub mod memory;
pub mod prune;
pub mod store;

use alloc::{vec, vec::Vec};

use onomancy_core::{
    anchor::doc::DocAnchor,
    collections::{Map, Set},
    delegation_chain::DelegationChain,
    digest::{Blake3, Digest},
    time::UnixSeconds,
};
use onomancy_dnssec::{
    certificate::Certificate,
    chain::DnssecChain,
    chain_proof::{ChainProof, ChainValidator},
    dns_name::DnsName,
    freshness::{Freshness, Grade, ValidityWindow},
    statement::{rotation::RotationStatement, successor::SuccessorStatement},
    txt::generation_key::GenerationKey,
    zone_state_key::ZoneStateKey,
};

use self::{
    authority_verifier::AuthorityVerifier,
    binding_state::{
        AcceptedBinding, BindingGrade, BindingState, ContinuityGrade, Divergence, DivergenceSource,
        Fork, SuccessionFork,
    },
    decisions::Decisions,
    diff::Event,
    store::{Store, item::Item},
};
use crate::ladder::{self, Contender, Continuity, Verdict};

/// Serial deferral bound: 5 minutes of clock skew, in the serial's
/// millisecond convention.
const SKEW_MS: u64 = 5 * 60 * 1000;

/// Everything the verifier believes, per hostname: the deterministic
/// derivation of the binding-cache store, the clock reading, and the
/// decision document.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerifierState {
    /// Per-hostname conclusions.
    pub bindings: Map<DnsName, BindingState>,
}

impl VerifierState {
    /// Compute all verifier state from the evidence held — the spec's
    /// `derive(store, now, decisions)`.
    ///
    /// Pure and total: the same `(store, now, decisions, pins)` yield
    /// the same outputs on any device, in any implementation —
    /// including under any permutation of the store. `pins` are the
    /// user's pinned targets, read by stage 8's divergence badges
    /// only.
    #[must_use]
    #[allow(clippy::implicit_hasher)] // house Map alias, not a hashing seam
    pub fn compute<V: ChainValidator, A: AuthorityVerifier>(
        store: &Store,
        now: UnixSeconds,
        decisions: &Decisions,
        pins: &Map<DnsName, Vec<DocAnchor>>,
        validator: &V,
        authority: &A,
    ) -> Self {
        // Stage 1: validate and extract.
        let evidence = validate_and_extract(store, validator, authority);

        // Hostname universe: everything any input mentions.
        let mut hostnames: Set<DnsName> = Set::default();
        hostnames.extend(evidence.records.iter().map(|r| r.hostname.clone()));
        hostnames.extend(evidence.successors.iter().map(|s| s.hostname.clone()));
        hostnames.extend(decisions.claims.iter().map(|c| c.hostname.clone()));
        hostnames.extend(decisions.acceptances.keys().cloned());
        hostnames.extend(pins.keys().cloned());

        let mut bindings: Map<DnsName, BindingState> = Map::default();

        for hostname in hostnames {
            let state = derive_host(&hostname, &evidence, now, decisions, pins, authority);
            bindings.insert(hostname, state);
        }

        Self { bindings }
    }

    /// The surfaced changes from `previous` to `self`, in a
    /// deterministic order (hostnames sorted, kinds in fixed
    /// sequence).
    #[must_use]
    pub fn diff(&self, previous: &Self) -> Vec<Event> {
        let mut hostnames: Vec<&DnsName> = self
            .bindings
            .keys()
            .chain(previous.bindings.keys())
            .collect();
        hostnames.sort_unstable();
        hostnames.dedup();

        let empty = BindingState::default();
        let mut events = Vec::new();

        for hostname in hostnames {
            let before = previous.bindings.get(hostname).unwrap_or(&empty);
            let after = self.bindings.get(hostname).unwrap_or(&empty);

            for kind in diff::host_diff(before, after) {
                events.push(Event {
                    hostname: hostname.clone(),
                    kind,
                });
            }
        }

        events
    }
}

/// Derive one hostname's state (stages 2–8 are per-hostname).
fn derive_host<A: AuthorityVerifier>(
    hostname: &DnsName,
    evidence: &Evidence,
    now: UnixSeconds,
    decisions: &Decisions,
    pins: &Map<DnsName, Vec<DocAnchor>>,
    authority: &A,
) -> BindingState {
    // Stage 2: exclude and defer.
    let empty = Set::default();
    let excluded = decisions.resets.get(hostname).unwrap_or(&empty);
    let rotation_exclusions = global_rotation_exclusions(decisions);

    let considered: Vec<&BindingEvidence> = {
        let mut records: Vec<&BindingEvidence> = evidence
            .records
            .iter()
            .filter(|r| r.hostname == *hostname)
            .filter(|r| !excluded.contains(&r.hash))
            .filter(|r| !is_deferred(r, now))
            .collect();

        // A bare chain refresh is the zone's word alone, so it rides
        // only beside a certificate record for the same document.
        // Judged after exclusion — a reset that clears a document's
        // certificates clears its refreshes' standing with them — but
        // before the stage-4 generation rules, so this filter is only
        // the first cut: stage 5 restricts candidacy to
        // certificate-attested survivors again.
        let corroborated: Set<DocAnchor> = records
            .iter()
            .filter(|r| r.attestation == Attestation::Certificate)
            .map(|r| r.document)
            .collect();
        records.retain(|r| {
            r.attestation == Attestation::Certificate || corroborated.contains(&r.document)
        });

        // Deterministic evaluation order regardless of store order.
        records.sort_unstable_by_key(|r| (r.document, r.key, r.hash));
        records
    };

    // Stage 3: lineage — heads, protected prefix, fork-implicated
    // suffix, per document (rotation statements are document-scoped).
    let lineage = build_lineage(evidence, &rotation_exclusions);

    // Stage 4: grade chains; apply the generation rules.
    let graded = apply_generation_rules(&considered, now, &lineage);
    let surviving = graded.surviving;
    let generation_contested = graded.contested_documents;

    let mut forks: Vec<Fork> = lineage
        .forks
        .iter()
        .filter(|f| considered.iter().any(|r| r.document == f.document))
        .copied()
        .chain(graded.forks)
        .collect();
    forks.sort_unstable();
    forks.dedup();

    // Stage 5: resolve the document.
    let graph = ProofGraph::for_hostname(evidence, hostname, excluded);
    let ctx = LadderContext {
        authority,
        graph: &graph,
        lineage: &lineage,
        now,
    };
    let resolution = resolve_document(&surviving, &ctx, hostname, decisions, evidence);

    // Stage 6: grade the binding. Fresh support confirms — unless
    // continuity to the accepted document holds only through
    // provisional bridge hops, which caps the grade at provisional
    // (the opportunistic re-check obligation).
    let accepted = resolution.accepted.map(|(document, generation)| {
        let fresh_support = surviving
            .iter()
            .any(|r| r.document == document && freshness(r, now) == Freshness::Fresh);

        AcceptedBinding {
            continuity: resolution.continuity,
            document,
            generation,
            grade: if fresh_support && resolution.continuity != ContinuityGrade::Bridged {
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
        // accepted document — fresh-first, then lineage descent, then
        // zone-state key — so a fresh record with a lower serial wins
        // and its downward serial surfaces as a ratchet reset in the
        // diff as a ratchet reset.
        let mut already_surfaced = false;
        let serial = best_of_document(&surviving, binding.document, &ctx, &mut already_surfaced)
            .map(|r| r.key.serial);
        let span = tenure_span(&of_doc);

        (serial, span)
    });

    // When the document that would be accepted has an
    // open, uncorroborated generation contest — a fresh chain and a
    // valid statement pointing opposite ways with no zone history to
    // arbitrate — the output is contested like every other
    // equivocation. Resolution falls to pins and the use-time prompt;
    // repair is the convergence merge. A contest on a document that
    // does NOT win masks nothing: the fork alone surfaces it.
    let contested = resolution.contested
        || accepted
            .as_ref()
            .is_some_and(|binding| generation_contested.contains(&binding.document));

    // Stage 8: divergence against the POST-mask output.
    let masked = contested;
    let output_binding = if masked { None } else { accepted };
    let divergence = derive_divergence(hostname, output_binding.as_ref(), decisions, pins);

    BindingState {
        accepted: output_binding,
        contested,
        divergence,
        effective_serial: if masked { None } else { effective_serial },
        forks,
        losing_acceptances: resolution.losing_acceptances,
        pending: resolution.pending,
        succession_forks: graph.forks,
        tenure,
    }
}

/// Stage 1's output: validated, typed evidence with extraction
/// provenance.
#[derive(Debug, Default)]
struct Evidence {
    held: Set<Digest<Blake3, [u8]>>,
    records: Vec<BindingEvidence>,
    rotations: Vec<RotationEvidence>,
    successors: Vec<SuccessorEvidence>,
}

/// One validated binding record's derivation-relevant facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BindingEvidence {
    /// What vouches for this record's document.
    pub(crate) attestation: Attestation,
    pub(crate) document: DocAnchor,
    pub(crate) generation: GenerationKey,
    pub(crate) hash: Digest<Blake3, [u8]>,
    pub(crate) hostname: DnsName,
    pub(crate) key: ZoneStateKey,
    /// Whether the delegation chain lies on the delegation path for
    /// the attested `g=` (dns-anchor, Generation Key).
    pub(crate) generation_on_path: bool,
    pub(crate) window: ValidityWindow,
}

/// What vouches for a binding record's document.
///
/// A binding needs both directions (dns-anchor, Verification): the
/// zone's TXT record names the document, and the certificate proves
/// the document accepts the hostname. A record extracted from a bare
/// chain refresh carries the zone's word only — it corroborates a
/// document some certificate record already attests, and MUST NOT
/// make a document a candidate on its own (binding-cache, The
/// Store).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Attestation {
    /// Extracted from a validated certificate: signature verified,
    /// signer authorized, TXT cross-checked, generation path judged
    /// against the
    /// certificate's own carriage.
    Certificate,

    /// Extracted from a bare chain refresh: the zone direction only.
    ChainOnly,
}

/// Extraction provenance for a carried statement: excluded only when
/// named directly, or when NOT standalone and every carrier is
/// excluded (statements independently carried by a non-excluded item
/// survive a reset).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Provenance {
    carriers: Vec<Digest<Blake3, Certificate>>,
    standalone: bool,
}

impl Provenance {
    fn record(&mut self, carrier: Option<Digest<Blake3, Certificate>>) {
        match carrier {
            None => self.standalone = true,
            Some(hash) => {
                if !self.carriers.contains(&hash) {
                    self.carriers.push(hash);
                }
            }
        }
    }

    fn excluded(
        &self,
        own_hash: Digest<Blake3, [u8]>,
        excluded: &Set<Digest<Blake3, [u8]>>,
    ) -> bool {
        if excluded.contains(&own_hash) {
            return true;
        }
        if self.standalone {
            return false;
        }

        // Extracted-only: excluded when every carrier is.
        !self.carriers.is_empty() && self.carriers.iter().all(|c| excluded.contains(&c.erase()))
    }
}

/// A valid rotation statement (document-scoped).
#[derive(Debug, Clone, PartialEq, Eq)]
struct RotationEvidence {
    hash: Digest<Blake3, RotationStatement>,
    provenance: Provenance,
    replaced: GenerationKey,
    root_doc: DocAnchor,
    successor: GenerationKey,
}

/// A valid successor statement (hostname-scoped).
#[derive(Debug, Clone, PartialEq, Eq)]
struct SuccessorEvidence {
    /// The statement's authority carriage, kept for stage 5's
    /// departing-hop path-membership check (bridging-hop grading).
    carriage: DelegationChain,
    hash: Digest<Blake3, SuccessorStatement>,
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
    /// A refresh item deferred to the second extraction pass, so it
    /// is judged against every validated certificate carriage
    /// regardless of store order.
    struct PendingRefresh<'a> {
        hostname: &'a DnsName,
        chain: &'a DnssecChain,
        hash: Digest<Blake3, [u8]>,
    }

    let mut evidence = Evidence::default();

    // Carriages of certificates that VALIDATED (chain proven, signer
    // authorized): the only delegation evidence a bare refresh may be
    // judged against.
    let mut validated_carriages: Vec<(DnsName, DocAnchor, &DelegationChain)> = Vec::new();
    let mut refreshes: Vec<PendingRefresh<'_>> = Vec::new();

    for item in store.items() {
        let hash = item.content_hash();
        evidence.held.insert(hash);

        match item {
            Item::Record(certificate) => {
                // Extraction is closed over DECODABLE carriers, before
                // any chain decisions: a superseded certificate whose
                // chain is stale or absent still yields its carried
                // statements (they are independently signed units, and
                // gap-bridging needs exactly those bytes).
                for statement in certificate.lineage() {
                    extract_rotation(
                        &mut evidence,
                        authority,
                        statement,
                        Some(certificate.digest()),
                    );
                }
                if let Some(statement) = certificate.predecessor() {
                    extract_successor(
                        &mut evidence,
                        authority,
                        statement,
                        Some(certificate.digest()),
                    );
                }

                if let Some(binding) = validate_record(certificate, hash, validator, authority) {
                    validated_carriages.push((
                        binding.hostname.clone(),
                        binding.document,
                        certificate.delegation_chain(),
                    ));
                    evidence.records.push(binding);
                }
            }

            // Deferred to the second pass: a refresh's generation-path standing
            // is judged against validated certificate carriages, and
            // store order must not decide which certificates it sees.
            Item::ChainRefresh { hostname, chain } => refreshes.push(PendingRefresh {
                hostname,
                chain,
                hash,
            }),

            Item::Rotation(statement) => {
                extract_rotation(&mut evidence, authority, statement, None);
            }

            Item::Successor(statement) => {
                extract_successor(&mut evidence, authority, statement, None);
            }
        }
    }

    for PendingRefresh {
        hostname,
        chain,
        hash,
    } in refreshes
    {
        let Ok(ChainProof { records, window }) = validator.validate(hostname, chain) else {
            continue;
        };

        // A bare refresh proves the whole RRset — as corroborating
        // evidence, never candidacy (stage 5 restricts the
        // candidate universe to certificate-attested survivors).
        // Within one RRset, several records for one document are
        // legal only as migration dual-publish ACROSS documents; for
        // a single document the highest serial is the zone's word,
        // exactly as `validate_record` reads it on the certificate
        // path — emitting every serial as its own row would make one
        // refresh item contest itself.
        let mut documents: Vec<DocAnchor> = records.iter().map(|r| *r.document()).collect();
        documents.sort_unstable();
        documents.dedup();

        for document in documents {
            let Some(record) = records
                .iter()
                .filter(|r| r.document() == &document)
                .max_by_key(|r| r.serial())
            else {
                continue;
            };

            // The generation path is judged, never assumed: the refresh carries
            // no carriage of its own, so its attested generation is on
            // a delegation path only if some VALIDATED certificate's
            // carriage for this same binding puts it there. No such
            // certificate ⇒ fail closed — a zone-capture attacker
            // must not be able to swap the accepted generation key
            // with a bare refresh (dns-anchor, Generation Key: positive path
            // membership).
            let generation_on_path = validated_carriages
                .iter()
                .filter(|(h, d, _)| h == hostname && *d == document)
                .any(|(_, _, carriage)| authority.on_path(carriage, record.generation()));

            evidence.records.push(BindingEvidence {
                attestation: Attestation::ChainOnly,
                document,
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
                generation_on_path,
                window,
            });
        }
    }

    evidence
}

/// Validate one certificate item into a binding record: chain proof,
/// TXT cross-check, generation-path input.
pub(crate) fn validate_record<V: ChainValidator, A: AuthorityVerifier>(
    certificate: &Certificate,
    hash: Digest<Blake3, [u8]>,
    validator: &V,
    authority: &A,
) -> Option<BindingEvidence> {
    let Ok(ChainProof { records, window }) =
        validator.validate(certificate.hostname(), certificate.dnssec_chain())
    else {
        return None;
    };

    // Seam parity with statements: a certificate whose signer is
    // not authorized by its own document contributes nothing. Vacuous
    // under `MemoryAuthority` (tests only); real under
    // `KeyhiveAuthority`, which replays the carriage.
    if !authority.authorizes(
        certificate.root_doc(),
        certificate.signer(),
        certificate.delegation_chain(),
    ) {
        return None;
    }

    // Cross-check: the chain-proven RRset must attest the
    // certificate's own document. Among matching records — several is
    // legal within one window (migration dual-publish) — the highest
    // serial is the zone's word for this document.
    let record = records
        .iter()
        .filter(|record| record.document() == certificate.root_doc())
        .max_by_key(|record| record.serial())?;

    let generation_on_path = authority.on_path(certificate.delegation_chain(), record.generation());

    Some(BindingEvidence {
        attestation: Attestation::Certificate,
        document: *certificate.root_doc(),
        generation: *record.generation(),
        hash,
        hostname: certificate.hostname().clone(),
        key: ZoneStateKey {
            window_end: window.expiration(),
            serial: record.serial(),
            issued_at: certificate.issued_at(),
        },
        generation_on_path,
        window,
    })
}

fn extract_rotation<A: AuthorityVerifier>(
    evidence: &mut Evidence,
    authority: &A,
    statement: &RotationStatement,
    carrier: Option<Digest<Blake3, Certificate>>,
) {
    // Signature validity was settled at decode; carriage authority is
    // the remaining validity condition (invalid statements are
    // discarded entirely — no lineage effect, never fork evidence).
    if !authority.authorizes(
        statement.root_doc(),
        statement.successor().verifying_key(),
        statement.authority(),
    ) {
        return;
    }

    let hash = statement.digest();

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
    carrier: Option<Digest<Blake3, Certificate>>,
) {
    if !authority.authorizes(
        statement.predecessor_doc(),
        statement.signer(),
        statement.authority(),
    ) {
        return;
    }

    let hash = statement.digest();

    if let Some(existing) = evidence.successors.iter_mut().find(|s| s.hash == hash) {
        existing.provenance.record(carrier);
        return;
    }

    let mut provenance = Provenance::default();
    provenance.record(carrier);

    evidence.successors.push(SuccessorEvidence {
        carriage: statement.authority().clone(),
        hash,
        hostname: statement.hostname().clone(),
        predecessor: *statement.predecessor_doc(),
        provenance,
        successor: *statement.successor_doc(),
    });
}

/// Stage 2 (exclusion): rotation statements are document-scoped — an
/// exclusion from ANY hostname's reset removes the statement for its
/// document everywhere.
fn global_rotation_exclusions(decisions: &Decisions) -> Set<Digest<Blake3, [u8]>> {
    let mut all: Set<Digest<Blake3, [u8]>> = Set::default();
    for excluded in decisions.resets.values() {
        all.extend(excluded.iter().copied());
    }
    all
}

/// Deferral: far-future serials (beyond the skew bound, in the
/// serial's millisecond convention) and not-yet-begun windows are not
/// considered until the clock reaches them. Deferral precedes
/// everything, including freshness.
pub(crate) fn is_deferred(record: &BindingEvidence, now: UnixSeconds) -> bool {
    let now_ms = now.value().saturating_mul(1000);
    let far_future = record.key.serial.value() > now_ms.saturating_add(SKEW_MS);

    far_future || record.window.grade(now) == Grade::NotYetBegun
}

/// Stage 3's output: per-document generation history, scoped by the
/// heads rule (the Heads and the Protected Prefix rule).
#[derive(Debug, Default)]
struct LineageView {
    /// The replaced → successor edges, per document (exclusion-
    /// filtered and deduped): rung 1's same-document vocabulary.
    edges: Vec<(DocAnchor, GenerationKey, GenerationKey)>,
    forks: Vec<Fork>,
    /// Fork-implicated generations, per document: fork territory,
    /// where the rewind rule is suspended.
    implicated: Set<(DocAnchor, GenerationKey)>,
    /// The protected prefix, per document: the rewind rule stays
    /// armed here.
    protected: Set<(DocAnchor, GenerationKey)>,
}

impl LineageView {
    /// Whether `descendant` is strictly forward-reachable from
    /// `ancestor` along the document's replaced → successor edges —
    /// signed descent, rung 1's same-document half.
    fn descends(
        &self,
        document: DocAnchor,
        ancestor: GenerationKey,
        descendant: GenerationKey,
    ) -> bool {
        let mut reached: Vec<GenerationKey> = vec![ancestor];
        let mut frontier: Vec<GenerationKey> = vec![ancestor];

        while let Some(key) = frontier.pop() {
            for (doc, replaced, successor) in &self.edges {
                if *doc == document && *replaced == key {
                    if *successor == descendant {
                        return true;
                    }
                    if !reached.contains(successor) {
                        reached.push(*successor);
                        frontier.push(*successor);
                    }
                }
            }
        }

        false
    }
}

fn build_lineage(evidence: &Evidence, excluded: &Set<Digest<Blake3, [u8]>>) -> LineageView {
    let mut rotations: Vec<&RotationEvidence> = evidence
        .rotations
        .iter()
        .filter(|r| !r.provenance.excluded(r.hash.erase(), excluded))
        .collect();
    rotations.sort_unstable_by_key(|r| (r.root_doc, r.replaced, r.successor, r.hash));
    rotations.dedup_by_key(|r| (r.root_doc, r.replaced, r.successor));

    let mut view = LineageView {
        edges: rotations
            .iter()
            .map(|r| (r.root_doc, r.replaced, r.successor))
            .collect(),
        ..LineageView::default()
    };

    let mut documents: Vec<DocAnchor> = rotations.iter().map(|r| r.root_doc).collect();
    documents.sort_unstable();
    documents.dedup();

    for document in documents {
        let of_doc: Vec<&&RotationEvidence> = rotations
            .iter()
            .filter(|r| r.root_doc == document)
            .collect();

        // Set-wise chain-shape checks: double-replace and
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

/// Stage 4: graded freshness at the caller's single clock reading.
pub(crate) fn freshness(record: &BindingEvidence, now: UnixSeconds) -> Freshness {
    match record.window.grade(now) {
        Grade::Fresh => Freshness::Fresh,
        // NotYetBegun was deferred at stage 2.
        Grade::NotYetBegun | Grade::Stale => Freshness::Stale,
    }
}

/// Stage 4's output: the surviving records, the forks the generation
/// rules surfaced, and the documents whose generation is contested
/// (the uncorroborated-rewind residual).
struct GradedRecords<'a> {
    surviving: Vec<&'a BindingEvidence>,
    forks: Vec<Fork>,
    contested_documents: Set<DocAnchor>,
}

/// Stage 4: apply the generation rules to the considered set. A
/// fresh record attesting a protected generation splits on the
/// zone's own attested history (the monotone-generation clock): a
/// CORROBORATED rewind is rejected with the fork surfaced; the
/// uncorroborated residual survives and contests its document —
/// neither side of a 1-vs-1 equivocation wins silently.
fn apply_generation_rules<'a>(
    considered: &[&'a BindingEvidence],
    now: UnixSeconds,
    lineage: &LineageView,
) -> GradedRecords<'a> {
    let mut forks: Vec<Fork> = Vec::new();
    let mut contested_documents: Set<DocAnchor> = Set::default();

    let surviving: Vec<&'a BindingEvidence> = considered
        .iter()
        .copied()
        .filter(|r| {
            let fork = Fork {
                document: r.document,
                at: r.generation,
            };

            match generation_rule(r, now, lineage, considered) {
                Disposition::Keep => true,
                Disposition::Reject => false,
                Disposition::KeepSurfacingFork => {
                    forks.push(fork);
                    true
                }
                Disposition::KeepContesting => {
                    forks.push(fork);
                    contested_documents.insert(r.document);
                    true
                }
                Disposition::RejectSurfacingFork => {
                    forks.push(fork);
                    false
                }
            }
        })
        .collect();

    GradedRecords {
        surviving,
        forks,
        contested_documents,
    }
}

/// A record's fate under the generation rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Disposition {
    Keep,
    /// Fork-implicated evidence survives, loudly.
    KeepSurfacingFork,
    /// An UNCORROBORATED fresh rewind survives, loudly,
    /// and the document derives contested while the fork stands —
    /// picking either side of a 1-vs-1 equivocation silently would
    /// hand one of two indistinguishable attackers the win.
    KeepContesting,
    Reject,
    /// A corroborated rewind: rejected, but the fork surfaces — the
    /// owner must see that their zone is publishing a retired key.
    RejectSurfacingFork,
}

/// The generation rules: path membership, the rewind rule, and its
/// fork-competition residual (dns-anchor, Generation Key; Heads and
/// the Protected Prefix).
///
/// `considered` is the hostname's post-exclusion, post-deferral
/// record set — the corroboration witness pool for the monotone-
/// generation check below.
fn generation_rule(
    record: &BindingEvidence,
    now: UnixSeconds,
    lineage: &LineageView,
    considered: &[&BindingEvidence],
) -> Disposition {
    let fresh = freshness(record, now) == Freshness::Fresh;

    // A fresh record whose delegation path lacks the
    // attested g= is rejected.
    if fresh && !record.generation_on_path {
        return Disposition::Reject;
    }

    let slot = (record.document, record.generation);

    if lineage.protected.contains(&slot) {
        // A stale protected-prefix attestation is a provable
        // rewind with no competing fresh observation — rejected.
        if !fresh {
            return Disposition::Reject;
        }

        // A FRESH protected-prefix attestation is one of two
        // indistinguishable-looking events, and the zone's own
        // attested-generation history is the monotone clock that
        // separates them: if any considered record attests a
        // lineage-LATER generation for this document, the zone was
        // observed moving forward and is now attesting backward — a
        // CORROBORATED rewind, 2-vs-1 against the fresh chain, and
        // the attacker needs zone control they demonstrably have.
        // Rejected, with the fork surfaced so the owner learns their
        // zone is publishing a retired key. Without corroboration
        // (the true kill-switch / slow-zone ambiguity: a statement
        // alone claims the succession) the record survives and the
        // document derives contested — neither side wins silently.
        let corroborated = considered.iter().any(|other| {
            other.document == record.document
                && lineage.descends(record.document, record.generation, other.generation)
        });

        return if corroborated {
            Disposition::RejectSurfacingFork
        } else {
            Disposition::KeepContesting
        };
    }

    if lineage.implicated.contains(&slot) {
        // Fork-implicated suffix: surfaced, never silently preferred
        // or rejected.
        return Disposition::KeepSurfacingFork;
    }

    Disposition::Keep
}

/// Stage 5's working state: the receipts contest for one hostname.
#[derive(Debug, Default)]
struct DocumentResolution {
    accepted: Option<(DocAnchor, GenerationKey)>,
    contested: bool,
    continuity: ContinuityGrade,
    losing_acceptances: Vec<DocAnchor>,
    pending: Vec<DocAnchor>,
}

/// The hostname's succession-proof graph, with succession forks isolated:
/// traversal never crosses a fork point.
#[derive(Debug, Default)]
struct ProofGraph<'e> {
    edges: Vec<(DocAnchor, DocAnchor)>,
    forks: Vec<SuccessionFork>,
    /// The filtered statements behind the edges, kept for stage 5's
    /// departing-hop path-membership check (bridging-hop grading).
    statements: Vec<&'e SuccessorEvidence>,
}

impl<'e> ProofGraph<'e> {
    fn for_hostname(
        evidence: &'e Evidence,
        hostname: &DnsName,
        excluded: &Set<Digest<Blake3, [u8]>>,
    ) -> Self {
        let mut statements: Vec<&'e SuccessorEvidence> = evidence
            .successors
            .iter()
            .filter(|s| s.hostname == *hostname)
            .filter(|s| !s.provenance.excluded(s.hash.erase(), excluded))
            .collect();
        statements.sort_unstable_by_key(|s| s.hash);

        let mut edges: Vec<(DocAnchor, DocAnchor)> = statements
            .iter()
            .map(|s| (s.predecessor, s.successor))
            .collect();
        edges.sort_unstable();
        edges.dedup();

        // One predecessor, competing valid successors = a fork.
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

        Self {
            edges,
            forks,
            statements,
        }
    }

    /// Whether `document` is a fork point (traversal stops here).
    fn is_fork_point(&self, document: DocAnchor) -> bool {
        self.forks.iter().any(|f| f.predecessor == document)
    }

    /// The unique-successor chain from `from`: proofs are followed one
    /// hop at a time, stopping at forks and cycles.
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

/// The ladder's pooled-evidence inputs, threaded through stage 5.
struct LadderContext<'a, A> {
    authority: &'a A,
    graph: &'a ProofGraph<'a>,
    lineage: &'a LineageView,
    now: UnixSeconds,
}

fn resolve_document<A: AuthorityVerifier>(
    surviving: &[&BindingEvidence],
    ctx: &LadderContext<'_, A>,
    hostname: &DnsName,
    decisions: &Decisions,
    evidence: &Evidence,
) -> DocumentResolution {
    // Best record per candidate document, by the full within-document
    // ladder (freshness, then lineage descent, then zone-state key),
    // in a deterministic order.
    let mut internally_contested = false;
    let best: Vec<&BindingEvidence> = {
        // Candidates are the documents of surviving CERTIFICATE-
        // attested records (binding-cache, stage 5): "surviving" is a
        // post-stage-4 predicate, so a document whose only
        // certificate died under the generation rules is no candidate however
        // fresh its bare refreshes — the stage-2 corroboration filter
        // ran before the generation rules and cannot be trusted for
        // candidacy. Surviving ChainOnly rows still corroborate: they
        // feed freshness, tenure, and the per-document ladder of
        // documents that ARE candidates.
        let mut documents: Vec<DocAnchor> = surviving
            .iter()
            .filter(|r| r.attestation == Attestation::Certificate)
            .map(|r| r.document)
            .collect();
        documents.sort_unstable();
        documents.dedup();

        documents
            .into_iter()
            .filter_map(|document| {
                best_of_document(surviving, document, ctx, &mut internally_contested)
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
                    && ladder_verdict(other, candidate, ctx) == Verdict::Left
            })
        })
        .copied()
        .collect();

    let mut contested = internally_contested;
    // Under a dominance cycle (undominated empty) the output is
    // contested and masked; the fallback feeds masked internals only,
    // deterministically (best is document-sorted).
    let maximal = undominated.first().copied().unwrap_or(first_candidate);

    // The winning acceptance, by the receipts rule; its losers are
    // surfaced through the output state. Receipt ties contest
    // unconditionally — they are the user's own conflicting records.
    let acceptance_resolution = winning_acceptance(hostname, decisions, evidence, &mut contested);
    let acceptance = acceptance_resolution.winner;

    // Incumbency: acceptance-backed, extended along proofs up to the
    // first fork; else the ladder-maximal candidate (graded
    // provisional at stage 6 when its support is stale).
    let incumbent = acceptance.map_or(maximal.document, |document| {
        *ctx.graph.chain_from(document).last().unwrap_or(&document)
    });

    // A cross-document tie contests only among ELIGIBLE candidates
    // (binding-cache stage 5). A
    // stale, unproven challenger is pending however late
    // its zone-state key reads — and two of them must not do
    // together what one cannot do alone: blank an acceptance-backed
    // incumbent. With no acceptance there is no incumbent to defend,
    // and any non-unique undominated set is a contest. A
    // dominance cycle (empty undominated set) is pathological and
    // contests regardless.
    contested |= if acceptance.is_some() && !undominated.is_empty() {
        let eligible_documents: Set<DocAnchor> = undominated
            .iter()
            .filter(|record| {
                record.document == incumbent
                    || freshness(record, ctx.now) == Freshness::Fresh
                    || ctx.graph.proves(incumbent, record.document)
            })
            .map(|record| record.document)
            .collect();

        eligible_documents.len() > 1
    } else {
        undominated.len() != 1
    };

    // Eligibility: the pending doctrine. Every stale, unproven
    // non-incumbent candidate is pending — not just the maximal one.
    let accepted_document = if maximal.document == incumbent || contested {
        incumbent
    } else {
        let eligible = freshness(maximal, ctx.now) == Freshness::Fresh
            || ctx.graph.proves(incumbent, maximal.document);

        if eligible {
            maximal.document
        } else {
            incumbent
        }
    };

    // Bridging-hop grading (dns-anchor, Bridging History Gaps): only
    // the hop DEPARTING the acceptance-backed document can ever be
    // fully checked — every subsequent hop is provisional, with no
    // generation-key memory to check attestation against.
    let continuity = match acceptance {
        None => ContinuityGrade::Unmoved,
        Some(base) if base == accepted_document => ContinuityGrade::Unmoved,
        Some(base) => {
            let chain = ctx.graph.chain_from(base);

            match chain.iter().position(|d| *d == accepted_document) {
                None => ContinuityGrade::Unproven,
                Some(1) if fully_checked_departure(base, accepted_document, surviving, ctx) => {
                    ContinuityGrade::Proven
                }
                Some(_) => ContinuityGrade::Bridged,
            }
        }
    };

    // Every stale candidate attesting a document other than the
    // decision-backed incumbent, without a proof, badges pending — not
    // just the maximal challenger. The incumbent itself never does:
    // when displaced, that surfaces as a binding change, not a badge.
    let mut pending: Vec<DocAnchor> = best
        .iter()
        .filter(|candidate| {
            candidate.document != accepted_document && candidate.document != incumbent
        })
        .filter(|candidate| freshness(candidate, ctx.now) == Freshness::Stale)
        // A valid proof in EITHER direction removes the badge: a
        // proven successor is routine continuation, and a proven
        // predecessor is superseded history — neither is an unproven
        // challenger.
        .filter(|candidate| {
            !ctx.graph.proves(accepted_document, candidate.document)
                && !ctx.graph.proves(candidate.document, accepted_document)
        })
        .map(|candidate| candidate.document)
        .collect();
    pending.sort_unstable();
    pending.dedup();

    // The accepted document's ladder-winning record carries the
    // attested generation (fresh-first, then lineage descent, then
    // key — fresh-first, with rung 1's same-document half).
    let generation = best
        .iter()
        .find(|r| r.document == accepted_document)
        .map(|r| r.generation);

    DocumentResolution {
        accepted: generation.map(|g| (accepted_document, g)),
        contested,
        continuity,
        losing_acceptances: acceptance_resolution.losers,
        pending,
    }
}

/// Whether the hop departing `base` toward `next` is fully checked:
/// the departing document has fresh support in the pooled store, and
/// some valid statement for the hop has its last-known generation
/// (ladder-best) on-path. Anything less grades the hop
/// provisional.
fn fully_checked_departure<A: AuthorityVerifier>(
    base: DocAnchor,
    next: DocAnchor,
    surviving: &[&BindingEvidence],
    ctx: &LadderContext<'_, A>,
) -> bool {
    let fresh_support = surviving
        .iter()
        .any(|r| r.document == base && freshness(r, ctx.now) == Freshness::Fresh);

    if !fresh_support {
        return false;
    }

    let mut ignored = false;
    let Some(last_known) = best_of_document(surviving, base, ctx, &mut ignored) else {
        return false;
    };

    ctx.graph
        .statements
        .iter()
        .filter(|s| s.predecessor == base && s.successor == next)
        .any(|s| ctx.authority.on_path(&s.carriage, &last_known.generation))
}

/// The document's ladder-best record: the undominated set under the
/// full within-document ladder (freshness, then lineage descent, then
/// zone-state key). Exactly one undominated record is the winner;
/// anything else (a lineage cycle, or a rung-1/rung-2 comparison
/// cycle) marks the resolution contested and falls back to the
/// highest-key record deterministically — surfaced, never silently
/// picked.
fn best_of_document<'e, A: AuthorityVerifier>(
    surviving: &[&'e BindingEvidence],
    document: DocAnchor,
    ctx: &LadderContext<'_, A>,
    contested: &mut bool,
) -> Option<&'e BindingEvidence> {
    let mut of_doc: Vec<&BindingEvidence> = surviving
        .iter()
        .filter(|r| r.document == document)
        .copied()
        .collect();

    // Interchangeable spellings — same generation, same zone state —
    // collapse to the smallest-hash representative.
    of_doc.sort_unstable_by_key(|r| (r.key, r.generation, r.hash));
    of_doc.dedup_by(|a, b| a.generation == b.generation && a.key == b.key);

    let undominated: Vec<&BindingEvidence> = of_doc
        .iter()
        .filter(|candidate| {
            !of_doc.iter().any(|other| {
                other.hash != candidate.hash
                    && ladder_verdict(other, candidate, ctx) == Verdict::Left
            })
        })
        .copied()
        .collect();

    match undominated.as_slice() {
        [] | [_, _, ..] => {
            if !of_doc.is_empty() {
                *contested = true;
            }
            of_doc.last().copied()
        }
        [winner] => Some(*winner),
    }
}

/// One pair's ladder verdict, with rung 1 computed from the pooled
/// evidence: succession proofs across documents, signed lineage
/// descent within one.
fn ladder_verdict<A: AuthorityVerifier>(
    left: &BindingEvidence,
    right: &BindingEvidence,
    ctx: &LadderContext<'_, A>,
) -> Verdict {
    let ordered = if left.document == right.document {
        (
            ctx.lineage
                .descends(left.document, left.generation, right.generation),
            ctx.lineage
                .descends(left.document, right.generation, left.generation),
        )
    } else {
        (
            ctx.graph.proves(left.document, right.document),
            ctx.graph.proves(right.document, left.document),
        )
    };

    let continuity = match ordered {
        (true, true) => Continuity::Fork,
        (true, false) => Continuity::RightNewer,
        (false, true) => Continuity::LeftNewer,
        (false, false) => Continuity::Silent,
    };

    ladder::compare(
        &as_contender(left, ctx.now),
        &as_contender(right, ctx.now),
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
/// Receipt ties for different documents are contested.
/// The receipts rule's outcome: the winner, and the losers it
/// outranked — surfaced, never silently dropped (stage 5: "the loser
/// is surfaced").
#[derive(Debug, Default)]
struct AcceptanceResolution {
    winner: Option<DocAnchor>,
    losers: Vec<DocAnchor>,
}

fn winning_acceptance(
    hostname: &DnsName,
    decisions: &Decisions,
    evidence: &Evidence,
    contested: &mut bool,
) -> AcceptanceResolution {
    let empty = Set::default();
    let excluded = decisions.resets.get(hostname).unwrap_or(&empty);
    let Some(acceptances) = decisions.acceptances.get(hostname) else {
        return AcceptanceResolution::default();
    };

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
            // Judged per ITEM, never by row count: one cited item can
            // legally yield several evidence rows (a bare refresh of
            // a dual-publish RRset carries one row per document), and
            // a row-count comparison would silently void exactly
            // those receipts.
            let cited_records: Vec<&BindingEvidence> = evidence
                .records
                .iter()
                .filter(|r| acceptance.cited.contains(&r.hash))
                .collect();

            let every_cited_item_is_a_record = acceptance
                .cited
                .iter()
                .all(|hash| cited_records.iter().any(|r| r.hash == *hash));

            if !every_cited_item_is_a_record
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

    let Some(&(best_key, winner)) = ranked.last() else {
        return AcceptanceResolution::default();
    };

    // Strictly-outranked acceptance documents lose — and are
    // surfaced. Documents tied at the best key are the contest
    // itself, not losers.
    let mut losers: Vec<DocAnchor> = ranked
        .iter()
        .filter(|(key, _)| *key < best_key)
        .map(|(_, document)| *document)
        .filter(|document| {
            !ranked
                .iter()
                .any(|(key, doc)| *key == best_key && doc == document)
        })
        .collect();
    losers.sort_unstable();
    losers.dedup();

    if ranked
        .iter()
        .any(|(key, document)| *key == best_key && *document != winner)
    {
        *contested = true;
        return AcceptanceResolution {
            winner: None,
            losers,
        };
    }

    AcceptanceResolution {
        winner: Some(winner),
        losers,
    }
}

/// Stages 7 and 8 (output assembly): the tenure span — earliest
/// chain-window inception to latest window end among the accepted
/// document's surviving records.
fn tenure_span(records: &[&&BindingEvidence]) -> Option<ValidityWindow> {
    let inception = records.iter().map(|r| r.window.inception()).min()?;
    let expiration = records.iter().map(|r| r.window.expiration()).max()?;

    // Spanning valid windows is valid: min ≤ every inception ≤ its
    // own expiration ≤ max.
    ValidityWindow::new(inception, expiration).ok()
}

/// Stage 8's divergence badges: claims and pins that disagree with the
/// (post-mask) accepted binding.
fn derive_divergence(
    hostname: &DnsName,
    accepted: Option<&AcceptedBinding>,
    decisions: &Decisions,
    pins: &Map<DnsName, Vec<DocAnchor>>,
) -> Vec<Divergence> {
    let Some(binding) = accepted else {
        return Vec::new();
    };

    let mut divergence: Vec<Divergence> = Vec::new();

    for claim in decisions.claims.iter().filter(|c| c.hostname == *hostname) {
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
