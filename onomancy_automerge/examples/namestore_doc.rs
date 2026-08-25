//! Generate a namestore document file: entries under the reserved
//! `onomancy` key, saved as raw Automerge bytes.
//!
//! ```text
//! cargo run -p onomancy_automerge --example namestore_doc -- \
//!   out.automerge --note="the gallery" \
//!   pics=automerge:VDTcix… "docs/current=automerge:8W3teP…"
//! ```

use automerge::{Automerge, ObjType, transaction::Transactable};
use onomancy_automerge::RESERVED_KEY;
use onomancy_core::anchor::doc::DocAnchor;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let out = args
        .next()
        .ok_or("usage: namestore_doc <out> [key=automerge:anchor]…")?;

    let mut doc = Automerge::new();
    doc.transact::<_, _, automerge::AutomergeError>(|tx| {
        let map = tx.put_object(automerge::ROOT, RESERVED_KEY, ObjType::Map)?;
        for entry in args {
            // A display note on the document root, not a name edge.
            if let Some(note) = entry.strip_prefix("--note=") {
                tx.put(automerge::ROOT, "note", note)?;
                continue;
            }

            let (key, value) = entry.split_once('=').unwrap_or((entry.as_str(), ""));
            // Only bare references belong in a namestore (E5): check
            // the spelling before writing anything.
            let anchor = value
                .strip_prefix("automerge:")
                .and_then(|raw| DocAnchor::parse(raw).ok());
            if anchor.is_none() {
                eprintln!("{entry:?}: value must be a bare automerge:<anchor> reference");
                std::process::exit(1);
            }
            tx.put(&map, key, value)?;
        }
        Ok(())
    })
    .map_err(|failure| failure.error)?;

    std::fs::write(&out, doc.save())?;
    eprintln!("wrote {out}");
    Ok(())
}
