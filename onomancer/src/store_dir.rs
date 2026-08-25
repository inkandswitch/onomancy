//! The on-disk store: a directory of self-authenticating unit files.
//!
//! One file per unit, named by content hash with the unit's tag as
//! extension (`<hash>.onc` / `.onr` / `.ons`). Decoding IS the
//! verification witness, so loading re-verifies every signature — a
//! corrupt or tampered file is a loud error, never skipped evidence.
//!
//! Chain-refresh items are deliberately NOT persisted: they have no
//! self-describing unit encoding and are refetched live on every run.

use std::path::{Path, PathBuf};

use onomancy_dnssec::{
    certificate::Certificate,
    statement::{rotation::RotationStatement, successor::SuccessorStatement},
};
use onomancy_protocol::verifier::state::store::{Store, item::Item};

/// Load every unit file in `dir` into a store. Creates the directory
/// if missing (an empty store). Files with foreign extensions are
/// ignored; files with unit extensions MUST decode.
pub(crate) fn load(dir: &Path) -> Result<Store, StoreDirError> {
    std::fs::create_dir_all(dir)?;
    let mut store = Store::default();

    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let Some(extension) = path.extension().and_then(|e| e.to_str()) else {
            continue;
        };

        let item = match extension {
            "onc" => Item::Record(Certificate::decode(&std::fs::read(&path)?).map_err(
                |source| StoreDirError::Certificate {
                    path: path.clone(),
                    source,
                },
            )?),
            "onr" => Item::Rotation(RotationStatement::decode(&std::fs::read(&path)?).map_err(
                |source| StoreDirError::Rotation {
                    path: path.clone(),
                    source,
                },
            )?),
            "ons" => Item::Successor(SuccessorStatement::decode(&std::fs::read(&path)?).map_err(
                |source| StoreDirError::Successor {
                    path: path.clone(),
                    source,
                },
            )?),
            _ => continue,
        };

        store.insert(item);
    }

    Ok(store)
}

/// Persist one item as `<content-hash>.<tag>`. Idempotent (content
/// addressing: same item, same path, same bytes). Chain-refresh items
/// are ephemeral and return `None`.
pub(crate) fn persist(dir: &Path, item: &Item) -> Result<Option<PathBuf>, StoreDirError> {
    let (extension, bytes) = match item {
        Item::Record(certificate) => ("onc", certificate.encode()),
        Item::Rotation(statement) => ("onr", statement.encode()),
        Item::Successor(statement) => ("ons", statement.encode()),
        Item::ChainRefresh { .. } => return Ok(None),
    };

    let path = dir.join(format!("{}.{extension}", item.content_hash()));
    if !path.exists() {
        std::fs::write(&path, bytes)?;
    }
    Ok(Some(path))
}

/// A unit file could not be decoded into a store item.
#[derive(Debug, thiserror::Error)]
pub(crate) enum StoreDirError {
    /// A `.onc` file did not decode as a certificate.
    #[error("store file {path}: {source}")]
    Certificate {
        /// The offending file.
        path: PathBuf,
        /// Why it failed.
        source: onomancy_dnssec::certificate::DecodeCertificateError,
    },

    /// The directory could not be read or written.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// A `.onr` file did not decode as a rotation statement.
    #[error("store file {path}: {source}")]
    Rotation {
        /// The offending file.
        path: PathBuf,
        /// Why it failed.
        source: onomancy_dnssec::statement::rotation::DecodeRotationError,
    },

    /// A `.ons` file did not decode as a successor statement.
    #[error("store file {path}: {source}")]
    Successor {
        /// The offending file.
        path: PathBuf,
        /// Why it failed.
        source: onomancy_dnssec::statement::successor::DecodeSuccessorError,
    },
}
