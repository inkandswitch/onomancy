//! `onomancer name`: resolve a full onomancy name — anchor, then the
//! greedy walk across held documents.
//!
//! Held documents come from a directory of `<doc-anchor>.automerge`
//! files (filename = anchor: raw Automerge saves carry no intrinsic
//! ID until the substrate integration lands). A dev-tool bridge, not
//! the sync story.

use std::{cell::Cell, net::SocketAddr, path::PathBuf};

use clap::Args;
use onomancy_automerge::namestore::{DocumentNamestore, HeldDocuments};
use onomancy_core::{anchor::doc::DocAnchor, delegation_chain::DelegationChain};
use onomancy_dnssec::{
    supported_name::{ParseSupportedNameError, SupportedName},
    validator::{Validator, WalkError},
};
use onomancy_hickory::provider::FetchChainError;
use onomancy_keyhive::authority::KeyhiveAuthority;
use onomancy_protocol::resolve::{
    namestore::{Authority, Replicas, Vouched},
    resolution::{PartialReason, Resolution},
    resolve,
};

use crate::say;

/// Resolve a full onomancy name (`~/…`, `@host/…`, `automerge:…/…`)
/// through a directory of held documents.
#[derive(Debug, Args)]
pub(crate) struct NameWalk {
    /// The name to resolve.
    name: String,

    /// Directory of held documents (`<doc-anchor>.automerge` files).
    #[arg(long)]
    docs: PathBuf,

    /// Your own root document's anchor — required for `~` names.
    #[arg(long)]
    root: Option<String>,

    /// Recursive resolver (default: system resolvers, then 1.1.1.1).
    #[arg(long)]
    resolver: Option<SocketAddr>,
}

impl NameWalk {
    /// Anchor, walk, report.
    ///
    /// # Errors
    ///
    /// Returns [`NameError`] for unparsable inputs, anchor-resolution
    /// failures, and IO failures. A partial WALK is a report, not an
    /// error (the designed norm under partition).
    pub(crate) fn run(&self) -> Result<(), NameError> {
        let name = SupportedName::parse(&self.name)?;
        let root_anchor = self.anchor_of(&name)?;
        say(&format!("anchor: {root_anchor}"));

        let held = self.load_docs()?;
        let root = held
            .replica(&root_anchor)
            .ok_or_else(|| NameError::RootNotHeld(Box::new(root_anchor)))?;

        // Record each hop so the outcome names its documents.
        let tracking = Tracking {
            inner: &held,
            last: Cell::new(Some(root_anchor)),
        };

        match resolve(root, name.segments(), &tracking) {
            Resolution::Resolved { authority, .. } => {
                let target = tracking
                    .last
                    .get()
                    .map_or_else(|| "(untracked)".into(), |anchor| anchor.to_string());
                say(&format!("resolved \u{2713} \u{2192} automerge:{target}"));
                say(&format!(
                    "authority: {} \u{26a0} {}",
                    authority.label(),
                    match authority {
                        Authority::TrustedSubstrate => "nothing checked \u{2014} dev bridge",
                        Authority::CarriageVerified =>
                            "delegation graph verified; content authorship not yet checkable",
                    }
                ));
            }
            Resolution::Partial { consumed, reason } => {
                let why = match reason {
                    PartialReason::DanglingSegment => "no edge matches the next segment".into(),
                    PartialReason::UnsyncedTarget { target } => {
                        format!("next document not held: automerge:{target} (sync it, retry)")
                    }
                };
                say(&format!(
                    "partial: {consumed}/{} segments consumed \u{2014} {why}",
                    name.segments().len(),
                ));
            }
        }
        Ok(())
    }

    /// The root document anchor for the name's trust anchor.
    fn anchor_of(&self, name: &SupportedName) -> Result<DocAnchor, NameError> {
        match name {
            SupportedName::Doc(doc_name) => Ok(*doc_name.anchor()),
            SupportedName::Local(_) => match &self.root {
                Some(raw) => Ok(DocAnchor::parse(raw)?),
                None => Err(NameError::LocalNeedsRoot),
            },
            SupportedName::Dns(dns_name) => {
                let hostname = dns_name.anchor();
                // Live: the zone's word for this hostname's document.
                let provider = crate::provider(self.resolver);
                let chain = crate::block_on(provider.fetch_chain(hostname))??;
                let proof = Validator::iana().validate_detailed(hostname, &chain)?;

                proof
                    .records
                    .iter()
                    .max_by_key(|record| record.serial())
                    .map(|record| *record.document())
                    .ok_or(NameError::NoBinding)
            }
        }
    }

    /// Every `<doc-anchor>.automerge` in the docs directory, graded
    /// by its sibling `<doc-anchor>.carriage` when one exists.
    ///
    /// Fail-closed: a carriage that is present but does not vouch its
    /// anchor REFUSES the document — broken evidence is worse than
    /// none.
    fn load_docs(&self) -> Result<HeldDocuments, NameError> {
        let mut held = HeldDocuments::default();

        for entry in std::fs::read_dir(&self.docs)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("automerge") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };

            let anchor = DocAnchor::parse(stem).map_err(|source| NameError::BadDocFilename {
                path: path.clone(),
                source,
            })?;
            let doc = automerge::Automerge::load(&std::fs::read(&path)?)
                .map_err(|_| NameError::UnloadableDoc(path.clone()))?;

            let carriage_path = path.with_extension("carriage");
            let authority = if carriage_path.exists() {
                let carriage = DelegationChain::read_framed(&std::fs::read(&carriage_path)?)
                    .map_err(|_| NameError::UnloadableCarriage(carriage_path.clone()))?;

                if !KeyhiveAuthority.vouches_document(&anchor, &carriage) {
                    return Err(NameError::CarriageRefused(carriage_path));
                }
                Authority::CarriageVerified
            } else {
                Authority::TrustedSubstrate
            };

            held = held.with_vouched(anchor, doc, authority);
        }

        Ok(held)
    }
}

/// [`Replicas`] that remembers the last document fetched, so the
/// outcome can name where the walk landed.
struct Tracking<'a> {
    inner: &'a HeldDocuments,
    last: Cell<Option<DocAnchor>>,
}

impl Replicas for Tracking<'_> {
    type Namestore = DocumentNamestore;

    fn replica(&self, target: &DocAnchor) -> Option<Vouched<Self::Namestore>> {
        let replica = self.inner.replica(target);
        if replica.is_some() {
            self.last.set(Some(*target));
        }
        replica
    }
}

/// The name verb failed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum NameError {
    /// A docs-dir filename was not a document anchor.
    #[error("doc file {path}: {source}")]
    BadDocFilename {
        /// The offending file.
        path: PathBuf,
        /// Why its stem failed to parse.
        source: onomancy_core::anchor::doc::ParseDocAnchorError,
    },

    /// The live chain could not be fetched.
    #[error(transparent)]
    Fetch(#[from] FetchChainError),

    /// File or runtime IO failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// A `~` name arrived without `--root`.
    #[error("local (~) names resolve from YOUR root document: pass --root <doc-anchor>")]
    LocalNeedsRoot,

    /// The name did not parse.
    #[error("name: {0}")]
    Name(#[from] ParseSupportedNameError),

    /// The zone attests no binding record.
    #[error("the zone attests no binding for this hostname")]
    NoBinding,

    /// The `--root` argument was not a document anchor.
    #[error("root anchor: {0}")]
    Root(#[from] onomancy_core::anchor::doc::ParseDocAnchorError),

    /// The root document is not in the docs directory.
    #[error("root document not held: add {0}.automerge to --docs")]
    RootNotHeld(Box<DocAnchor>),

    /// A carriage file was present but did not vouch its document —
    /// refused rather than downgraded.
    #[error("carriage does not vouch its document (refusing the doc): {0}")]
    CarriageRefused(PathBuf),

    /// A carriage file did not parse.
    #[error("not a framed carriage: {0}")]
    UnloadableCarriage(PathBuf),

    /// A doc file did not load as Automerge.
    #[error("not an automerge document: {0}")]
    UnloadableDoc(PathBuf),

    /// The live chain failed DNSSEC validation.
    #[error("live chain invalid: {0}")]
    Walk(#[from] WalkError),
}
