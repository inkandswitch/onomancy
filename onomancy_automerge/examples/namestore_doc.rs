//! Generate a namestore document file: names as top-level keys,
//! saved as raw Automerge bytes.
//!
//! A namestore is the document's own map, so each name is a root key
//! and nothing is nested.
//!
//! ```text
//! cargo run -p onomancy_automerge --example namestore_doc -- \
//!   out.automerge \
//!   pics=automerge:VDTcix… "docs/current=automerge:8W3teP…"
//! ```

use automerge::{transaction::Transactable, Automerge};
use onomancy_core::anchor::doc::DocAnchor;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let out = args
        .next()
        .ok_or("usage: namestore_doc <out> [key=automerge:anchor]…")?;

    let mut doc = Automerge::new();
    doc.transact::<_, _, automerge::AutomergeError>(|tx| {
        for entry in args {
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
            tx.put(automerge::ROOT, key, value)?;
        }
        Ok(())
    })
    .map_err(|failure| failure.error)?;

    std::fs::write(&out, doc.save())?;
    eprintln!("wrote {out}");
    Ok(())
}
