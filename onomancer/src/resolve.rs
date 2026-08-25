//! `onomancer resolve`: live chain fetch → DNSSEC walk → verdict.

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use clap::Args;
use onomancy_core::{
    cert::Certificate,
    collections::Map,
    freshness::Freshness,
    name::dns::DnsName,
    statement::{rotation::RotationStatement, successor::SuccessorStatement},
    time::UnixSeconds,
};
use onomancy_dnssec::validator::{Validator, WalkError};
use onomancy_hickory::provider::FetchChainError;
use onomancy_keyhive::authority::KeyhiveAuthority;
use onomancy_protocol::{
    verifier_state::{
        VerifierState,
        decisions::Decisions,
        diff::{Event, EventKind},
        store::Item,
    },
    verify::{self, Rejection},
};

use crate::{
    say,
    store_dir::{self, StoreDirError},
};

/// Fetch, validate, and grade a hostname's binding.
#[derive(Debug, Args)]
pub(crate) struct Resolve {
    /// The hostname to resolve (display form accepted).
    #[arg(long)]
    hostname: String,

    /// Recursive resolver (default: system resolvers, then 1.1.1.1).
    #[arg(long)]
    resolver: Option<SocketAddr>,

    /// A gossiped/fetched ONC certificate to verify fully (its own
    /// attached chain is what gets validated).
    #[arg(long)]
    cert: Option<PathBuf>,

    /// Write the fetched chain (framed links) here — e.g. to capture
    /// a fixture.
    #[arg(long)]
    chain_out: Option<PathBuf>,

    /// Stateful mode: a store directory of unit files. The live fetch
    /// is judged against ALL held evidence, and changes since the last
    /// run surface as events.
    #[arg(long)]
    store: Option<PathBuf>,

    /// Extra unit files (.onc/.onr/.ons — e.g. gossiped) to ingest
    /// into the store this run.
    #[arg(long, requires = "store")]
    ingest: Vec<PathBuf>,
}

impl Resolve {
    /// Run the pipeline and print what the evidence supports.
    ///
    /// # Errors
    ///
    /// Returns [`ResolveError`] for transport failures, invalid
    /// chains, and rejected certificates.
    pub(crate) fn run(&self) -> Result<(), ResolveError> {
        let hostname = DnsName::parse_display(&self.hostname)?;

        if let Some(store_path) = &self.store {
            return stateful_pass(
                self.resolver,
                store_path,
                &hostname,
                self.cert.as_deref(),
                &self.ingest,
            );
        }

        let now = UnixSeconds::from(now_seconds());
        let validator = Validator::iana();

        // The live zone: fetch → walk from the baked-in IANA anchors.
        let provider = crate::provider(self.resolver);
        let chain = crate::block_on(provider.fetch_chain(&hostname))??;

        say(&format!("chain: {} links fetched", chain.links().len()));

        if let Some(chain_out) = &self.chain_out {
            let mut framed = Vec::new();
            chain.write_framed(&mut framed);
            std::fs::write(chain_out, framed)?;
            say(&format!("chain written: {}", chain_out.display()));
        }

        let proof = validator.validate_detailed(&hostname, &chain)?;
        let grade = match proof.window.grade(now) {
            onomancy_core::freshness::Grade::Fresh => "fresh \u{2713}",
            onomancy_core::freshness::Grade::Stale => "stale \u{26a0}",
            onomancy_core::freshness::Grade::NotYetBegun => "not yet begun (deferred)",
        };
        say(&format!("DNSSEC: valid, window {grade}"));

        for record in &proof.records {
            say(&format!("zone says: {record}"));
        }

        // A certificate makes it a full graded verdict.
        let Some(cert_path) = &self.cert else {
            return Ok(());
        };
        let bytes = std::fs::read(cert_path)?;

        // Real authority (ADR-056): carriages replay into a Keyhive
        // delegation graph; doc-key-signed certificates pass by the
        // identity rule.
        let authority = KeyhiveAuthority;

        let verdict = verify::verify(&bytes, &hostname, now, &validator, &authority)?;

        let freshness = match verdict.freshness {
            Freshness::Fresh => "fresh \u{2713}",
            Freshness::Stale => "stale \u{26a0}",
        };
        let generation = match verdict.generation_check {
            verify::GenerationCheck::OnPath => "on delegation path",
            verify::GenerationCheck::Provisional => {
                "provisional ⚠ (stale evidence; re-checked when fresher evidence arrives)"
            }
        };

        say(&format!("verdict: {freshness}"));
        say(&format!("  document:   {}", verdict.document));
        say(&format!("  serial:     {}", verdict.serial));
        say(&format!("  generation: {generation}"));
        Ok(())
    }
}

/// One stateful pass: load the store, judge it, ingest live + gossiped
/// evidence, judge again, surface the difference, persist.
pub(crate) fn stateful_pass(
    resolver: Option<SocketAddr>,
    store_path: &Path,
    hostname: &DnsName,
    cert: Option<&Path>,
    ingest: &[PathBuf],
) -> Result<(), ResolveError> {
    let now = UnixSeconds::from(now_seconds());
    let validator = Validator::iana();
    let authority = KeyhiveAuthority;
    let pins: Map<DnsName, Vec<onomancy_core::name::doc::DocAnchor>> = Map::default();
    let decisions = Decisions::default();

    // What the evidence supported before this run's inputs.
    let mut store = store_dir::load(store_path)?;
    let before = VerifierState::compute(&store, now, &decisions, &pins, &validator, &authority);

    // New evidence: gossiped unit files, the live zone, an offered cert.
    let mut new_items: Vec<Item> = ingest
        .iter()
        .map(|path| decode_unit(path))
        .collect::<Result<_, _>>()?;

    let provider = crate::provider(resolver);
    match crate::block_on(provider.fetch_chain(hostname))? {
        Ok(chain) => {
            say(&format!("chain: {} links fetched", chain.links().len()));
            new_items.push(Item::ChainRefresh {
                hostname: hostname.clone(),
                chain,
            });
        }
        // In stateful mode a failed fetch is an event-free pass, not a
        // crash: held evidence still gets judged at `now`.
        Err(failure) => say(&format!(
            "chain: fetch failed ({failure}) — judging held evidence only"
        )),
    }

    if let Some(cert_path) = cert {
        new_items.push(Item::Record(Certificate::decode(&std::fs::read(
            cert_path,
        )?)?));
    }

    for item in new_items {
        if let Some(path) = store_dir::persist(store_path, &item)? {
            say(&format!("store: holding {}", path.display()));
        }
        store.insert(item);
    }

    // What the evidence supports now — and exactly what changed.
    let after = VerifierState::compute(&store, now, &decisions, &pins, &validator, &authority);
    let events = after.diff(&before);

    if events.is_empty() {
        say("no change: the evidence supports what it supported before");
    }
    for event in &events {
        say(&describe(event));
    }

    summarize(hostname, &after);
    Ok(())
}

/// Decode one gossiped unit file by extension.
fn decode_unit(path: &Path) -> Result<Item, ResolveError> {
    let bytes = std::fs::read(path)?;
    match path.extension().and_then(|e| e.to_str()) {
        Some("onc") => Ok(Item::Record(Certificate::decode(&bytes)?)),
        Some("onr") => Ok(Item::Rotation(RotationStatement::decode(&bytes)?)),
        Some("ons") => Ok(Item::Successor(SuccessorStatement::decode(&bytes)?)),
        _ => Err(ResolveError::UnknownUnit(path.to_path_buf())),
    }
}

/// One event, one line: `⚡` may prompt; `·` badges must not.
fn describe(event: &Event) -> String {
    let marker = if event.kind.may_prompt() { "⚡" } else { "·" };
    let hostname = &event.hostname;

    let change = match &event.kind {
        EventKind::BindingChanged { from, to } => format!(
            "binding changed: {} → {}",
            from.as_ref()
                .map_or_else(|| "none".into(), ToString::to_string),
            to.as_ref()
                .map_or_else(|| "none".into(), ToString::to_string),
        ),
        EventKind::ContestedCleared => "contested cleared".into(),
        EventKind::ContestedEntered => "CONTESTED: competing evidence of equal rank".into(),
        EventKind::DivergenceCleared(divergence) => format!("divergence cleared: {divergence:?}"),
        EventKind::DivergenceSurfaced(divergence) => format!("divergence: {divergence:?}"),
        EventKind::GradeChanged { from, to } => format!("grade: {from:?} → {to:?}"),
        EventKind::LineageForkSurfaced(fork) => format!("LINEAGE FORK (equivocation): {fork:?}"),
        EventKind::LosingAcceptanceCleared(document) => {
            format!("losing acceptance cleared: {document}")
        }
        EventKind::LosingAcceptanceSurfaced(document) => {
            format!("acceptance outranked by receipts: {document}")
        }
        EventKind::PendingCleared(document) => format!("pending cleared: {document}"),
        EventKind::PendingSurfaced(document) => format!("pending (stale challenger): {document}"),
        EventKind::RatchetReset { from, to } => format!("RATCHET RESET: serial {from} → {to}"),
        EventKind::SuccessionForkSurfaced(fork) => format!("SUCCESSION FORK: {fork:?}"),
    };

    format!("{marker} {hostname}: {change}")
}

/// The post-pass verdict line(s) for one hostname.
fn summarize(hostname: &DnsName, state: &VerifierState) {
    let Some(host) = state.hosts.get(hostname) else {
        say(&format!("{hostname}: no evidence held"));
        return;
    };

    match &host.accepted {
        Some(accepted) => say(&format!(
            "{hostname}: accepted → {} ({:?}, continuity {:?})",
            accepted.document, accepted.grade, accepted.continuity,
        )),
        None if host.contested => say(&format!("{hostname}: CONTESTED — no accepted binding")),
        None => say(&format!("{hostname}: no accepted binding")),
    }

    if !host.pending.is_empty() {
        say(&format!("  pending: {}", host.pending.len()));
    }
    if !host.forks.is_empty() || !host.succession_forks.is_empty() {
        say(&format!(
            "  forks: {} lineage, {} succession",
            host.forks.len(),
            host.succession_forks.len(),
        ));
    }
}

/// Seconds since the Unix epoch.
fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Resolution failed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ResolveError {
    /// The chain could not be fetched from live DNS.
    #[error(transparent)]
    Fetch(#[from] FetchChainError),

    /// The hostname did not parse.
    #[error("hostname: {0}")]
    Hostname(#[from] onomancy_core::name::dns::ParseDnsNameError),

    /// File or runtime IO failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// The certificate was rejected.
    #[error("certificate rejected: {0}")]
    Rejected(#[from] Rejection),

    /// An ingested `.onc` did not decode.
    #[error("certificate: {0}")]
    Certificate(#[from] onomancy_core::cert::DecodeCertificateError),

    /// An ingested `.onr` did not decode.
    #[error("rotation statement: {0}")]
    Rotation(#[from] onomancy_core::statement::rotation::DecodeRotationError),

    /// The store directory was unreadable or held corrupt units.
    #[error("store: {0}")]
    Store(#[from] StoreDirError),

    /// An ingested `.ons` did not decode.
    #[error("successor statement: {0}")]
    Successor(#[from] onomancy_core::statement::successor::DecodeSuccessorError),

    /// An ingested file had no unit extension.
    #[error("not a unit file (expected .onc/.onr/.ons): {0}")]
    UnknownUnit(PathBuf),

    /// The chain failed DNSSEC validation.
    #[error("chain invalid: {0}")]
    Walk(#[from] WalkError),
}
