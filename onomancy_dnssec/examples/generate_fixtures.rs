//! Regenerate the checked-in chain fixtures in `tests/fixtures/`.
//!
//! ```sh
//! cargo run -p onomancy_dnssec --example generate_fixtures \
//!     --features test_utils,std
//! ```
//!
//! Deterministic: zones are seeded, windows are constants, so output
//! is byte-identical across runs — regeneration only changes bytes
//! when the fixture DEFINITIONS change, and `tests/fixtures.rs` pins
//! the expected outcome of every file. See `tests/fixtures/README.md`.

use std::{fs, path::Path};

use onomancy_core::cert::chain::DnssecChain;
use onomancy_dnssec::test_utils::fixtures::all_fixtures;

fn main() -> std::io::Result<()> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    fs::create_dir_all(&dir)?;

    for (name, chain, _expectation) in all_fixtures() {
        let mut bytes = Vec::new();
        DnssecChain::write_framed(&chain, &mut bytes);
        let path = dir.join(format!("{name}.chain"));
        fs::write(&path, &bytes)?;
        println!("wrote {}", path.display());
    }

    Ok(())
}
