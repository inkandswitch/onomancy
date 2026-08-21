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
use onomancy_core::name::{Name, anchor::Anchor, doc::DocAnchor};
use onomancy_dnssec::validator::{Validator, WalkError};
use onomancy_hickory::provider::FetchChainError;
use onomancy_protocol::resolve::{
    namestore::Replicas,
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
    /// Returns [`NameError`] for unparseable inputs, anchor-resolution
    /// failures, and IO failures. A partial WALK is a report, not an
    /// error (the designed norm under partition).
    pub(crate) fn run(&self) -> Result<(), NameError> {
        let name = Name::parse(&self.name)?;
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
            Resolution::Resolved(_) => {
                let target = tracking
                    .last
                    .get()
                    .map_or_else(|| "(untracked)".into(), |anchor| anchor.to_string());
                say(&format!("resolved \u{2713} \u{2192} automerge:{target}"));
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
    fn anchor_of(&self, name: &Name) -> Result<DocAnchor, NameError> {
        match name.anchor() {
            Anchor::Doc(anchor) => Ok(*anchor),
            Anchor::Local => match &self.root {
                Some(raw) => Ok(DocAnchor::parse(raw)?),
                None => Err(NameError::LocalNeedsRoot),
            },
            Anchor::Dns(hostname) => {
                // Live: the zone's word for this hostname's document.
                let provider = crate::provider(self.resolver);
                let chain = crate::block_on(provider.assemble(hostname))??;
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

    /// Every `<doc-anchor>.automerge` in the docs directory.
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

            held = held.with(anchor, doc);
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

    fn replica(&self, target: &DocAnchor) -> Option<Self::Namestore> {
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
        source: onomancy_core::name::doc::ParseDocAnchorError,
    },

    /// The live chain could not be assembled.
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
    Name(#[from] onomancy_core::name::ParseNameError),

    /// The zone attests no binding record.
    #[error("the zone attests no binding for this hostname")]
    NoBinding,

    /// The `--root` argument was not a document anchor.
    #[error("root anchor: {0}")]
    Root(#[from] onomancy_core::name::doc::ParseDocAnchorError),

    /// The root document is not in the docs directory.
    #[error("root document not held: add {0}.automerge to --docs")]
    RootNotHeld(Box<DocAnchor>),

    /// A doc file did not load as Automerge.
    #[error("not an automerge document: {0}")]
    UnloadableDoc(PathBuf),

    /// The live chain failed DNSSEC validation.
    #[error("live chain invalid: {0}")]
    Walk(#[from] WalkError),
}
