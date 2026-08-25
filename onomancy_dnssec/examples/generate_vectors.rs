//! Regenerate the golden-vector files in `tests/vectors/` from the
//! catalog (`tests/vectors_catalog.rs` — the single source of truth).
//!
//! ```sh
//! cargo run -p onomancy_core --example generate_vectors
//! ```
//!
//! Byte drift in the regenerated files is a wire-format break: the
//! conformance test (`tests/golden_vectors.rs`) compares the checked-
//! in files against the catalog on every run.

// A regeneration tool, not a library: failing loudly is the point.
#![allow(clippy::expect_used)]

#[path = "../tests/support/vectors_catalog.rs"]
mod vectors_catalog;

use std::{fs, path::PathBuf};

fn main() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors");
    fs::create_dir_all(&dir).expect("create tests/vectors/");

    let vectors = vectors_catalog::vectors();
    let mut digests = String::new();

    for vector in &vectors {
        let path = dir.join(format!("{}.hex", vector.name));
        let mut contents = vectors_catalog::to_hex(&vector.bytes);
        contents.push('\n');
        fs::write(&path, contents).expect("write vector file");

        // Content-hash stability: record the digest of every unit
        // that decodes (hashes are over verbatim bytes).
        let digest = match vector.expect {
            vectors_catalog::Expect::Certificate => Some(
                onomancy_dnssec::certificate::Certificate::decode(&vector.bytes)
                    .expect("accept vector decodes")
                    .digest()
                    .to_string(),
            ),
            vectors_catalog::Expect::Rotation => Some(
                onomancy_dnssec::statement::rotation::RotationStatement::decode(&vector.bytes)
                    .expect("accept vector decodes")
                    .digest()
                    .to_string(),
            ),
            vectors_catalog::Expect::Successor => Some(
                onomancy_dnssec::statement::successor::SuccessorStatement::decode(&vector.bytes)
                    .expect("accept vector decodes")
                    .digest()
                    .to_string(),
            ),
            vectors_catalog::Expect::RejectCertificate => None,
        };

        if let Some(digest) = digest {
            digests.push_str(vector.name);
            digests.push(' ');
            digests.push_str(&digest);
            digests.push('\n');
        }

        println!("wrote {}", path.display());
    }

    fs::write(dir.join("digests.txt"), digests).expect("write digests.txt");
    println!("wrote {}", dir.join("digests.txt").display());
}
