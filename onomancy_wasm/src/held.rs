//! Held Automerge documents in the browser: mint, edit, and resolve
//! names across them.
//!
//! Documents live in JS memory, keyed by self-certifying anchors
//! (fresh ed25519 verifying keys, minted here). Namestore edges are
//! flat-map entries at the reserved location, exactly as the
//! resolution spec lays them out; the walk is the real
//! `onomancy_protocol::resolve` machine over the real
//! `onomancy_automerge` adapter — the demo drives production code,
//! not a mock.
//!
//! `@hostname/…` names anchor LIVE: the DNSSEC chain is fetched over
//! `DoH`, validated from the baked-in IANA anchors, and the zone's
//! attested document becomes the walk's root.

use std::cell::Cell;

use automerge::{Automerge, transaction::Transactable};
use ed25519_dalek::SigningKey;
use js_sys::{Array, Reflect};
use onomancy_automerge::namestore::{DocumentNamestore, HeldDocuments};
use onomancy_core::{
    anchor::doc::{self, DocAnchor},
    collections::Map,
    name::segment::Segment,
};
use onomancy_dnssec::supported_name::SupportedName;
use onomancy_protocol::resolve::{
    namestore::{Authority, Replicas, Vouched},
    resolution::{PartialReason, Resolution},
    resolve,
};
use wasm_bindgen::{JsCast as _, JsError, JsValue, prelude::wasm_bindgen};

use crate::{
    shapes::JsWalkOutcome,
    text::{self, Text},
};

/// The `WalkOutcome` literals: one home, so the Rust that emits them
/// and the TypeScript that declares them (`shapes.d.ts`) can be held
/// together by the drift test below rather than by habit.
///
/// These strings are API. A rewording here is a breaking change to
/// every `switch` downstream, whatever the `.d.ts` says.
pub mod walk {
    /// Every segment consumed; `document` names where the walk landed.
    pub const RESOLVED: &str = "resolved";

    /// The walk stopped short — the designed norm under partition.
    pub const PARTIAL: &str = "partial";

    /// A segment named no edge in the document it reached.
    pub const DANGLING_SEGMENT: &str = "dangling segment";

    /// The next hop's document is not held; `target` names it.
    pub const UNSYNCED_TARGET: &str = "unsynced target";

    /// A resolved walk whose root is the zone's word alone — the
    /// certificate direction was not checked.
    pub const ZONE_ONLY: &str = "zone-only";

    /// The published `WalkStatus` union, for the drift test.
    pub const STATUSES: &[&str] = &[RESOLVED, PARTIAL];

    /// The published `PartialWalkReason` union, for the drift test.
    pub const PARTIAL_REASONS: &[&str] = &[DANGLING_SEGMENT, UNSYNCED_TARGET];
}

/// A browser-held document set: the anchoring and replication
/// substrate a real agent would sync, reduced to in-memory documents
/// for the demo.
#[wasm_bindgen(js_name = HeldDocuments)]
#[derive(Debug, Default)]
pub struct JsHeldDocuments {
    docs: Map<DocAnchor, Automerge>,
}

#[wasm_bindgen(js_class = HeldDocuments)]
impl JsHeldDocuments {
    /// An empty document set.
    #[wasm_bindgen(constructor)]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint a fresh document under a fresh self-certifying anchor,
    /// returning the anchor (`automerge:…`).
    ///
    /// # Errors
    ///
    /// Throws when the host provides no entropy.
    #[wasm_bindgen(js_name = createDocument)]
    pub fn create_document(&mut self) -> Result<String, JsError> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|error| JsError::new(&error.to_string()))?;

        let anchor = DocAnchor::from(SigningKey::from_bytes(&seed).verifying_key());
        self.docs.insert(anchor, Automerge::new());
        Ok(anchor_string(&anchor))
    }

    /// Hold a fresh empty document AT a caller-supplied anchor — a
    /// stand-in replica for a document that lives elsewhere (the
    /// browser analogue of the CLI's filename-as-anchor dev bridge;
    /// real replication is the substrate's job). Held documents are
    /// never clobbered.
    ///
    /// # Errors
    ///
    /// Throws for malformed anchors.
    #[wasm_bindgen(js_name = holdAt)]
    pub fn hold_at(&mut self, anchor: &Text) -> Result<(), JsError> {
        let anchor = parse_anchor(&text::read(anchor, "a document anchor")?)?;
        self.docs.entry(anchor).or_default();
        Ok(())
    }

    /// Hold a REAL document's saved bytes at its anchor — replication
    /// by hand (file drop, HTTP fetch, `AirDrop`…). Replaces any
    /// stand-in already held there.
    ///
    /// # Errors
    ///
    /// Throws for malformed anchors and bytes that do not load as an
    /// Automerge document.
    pub fn hold(&mut self, anchor: &Text, bytes: &[u8]) -> Result<(), JsError> {
        let anchor = parse_anchor(&text::read(anchor, "a document anchor")?)?;
        let doc = Automerge::load(bytes)
            .map_err(|error| JsError::new(&format!("not an automerge document: {error}")))?;
        self.docs.insert(anchor, doc);
        Ok(())
    }

    /// A held document's saved bytes, for carrying elsewhere.
    ///
    /// # Errors
    ///
    /// Throws for unknown anchors.
    pub fn save(&self, anchor: &Text) -> Result<Vec<u8>, JsError> {
        Ok(self.held(&text::read(anchor, "a document anchor")?)?.save())
    }

    /// Every held anchor (`automerge:…`), sorted.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn anchors(&self) -> Vec<String> {
        let mut anchors: Vec<String> = self.docs.keys().map(anchor_string).collect();
        anchors.sort();
        anchors
    }

    /// Add a namestore edge: `path` (segments joined by `/`) names
    /// `target` from the `anchor` document.
    ///
    /// # Errors
    ///
    /// Throws for unknown anchors, malformed paths or targets, and
    /// write failures.
    pub fn bind(&mut self, anchor: &Text, path: &Text, target: &Text) -> Result<(), JsError> {
        let key = path_of(&text::read(path, "a path")?)?;
        let value = format!(
            "{}{}",
            doc::SCHEME_PREFIX,
            parse_anchor(&text::read(target, "a target anchor")?)?
        );

        let doc = self.held_mut(&text::read(anchor, "a document anchor")?)?;
        doc.transact::<_, _, automerge::AutomergeError>(|tx| {
            // A name is a root key: `foo` is `root["foo"]`. The store
            // is the document's own map, flat, shared with whatever
            // else the document holds.
            tx.put(automerge::ROOT, key.as_str(), value.as_str())?;
            Ok(())
        })
        .map_err(|failure| JsError::new(&failure.error.to_string()))?;
        Ok(())
    }

    /// A held document's namestore edges: `[{ path, target }]`.
    ///
    /// # Errors
    ///
    /// Throws for unknown anchors.
    pub fn edges(&self, anchor: &Text) -> Result<JsValue, JsError> {
        let namestore = DocumentNamestore::new(
            self.held(&text::read(anchor, "a document anchor")?)?
                .clone(),
        );

        let list = Array::new();
        for (path, target) in namestore.edges() {
            let edge = js_sys::Object::new();
            set(&edge, "path", &JsValue::from_str(&path));
            set(&edge, "target", &JsValue::from_str(&anchor_string(&target)));
            list.push(&edge.into());
        }
        Ok(list.into())
    }

    /// Resolve a full onomancy name (`automerge:…/…`, `~/…`, or
    /// `@hostname/…`) across the held documents.
    ///
    /// `~` names resolve from `root`; `@hostname` names anchor live
    /// over `DoH` (optionally at `doh_url`), validated from the
    /// baked-in IANA anchors inside the Wasm.
    ///
    /// **`@hostname` anchoring here is the zone's word only.** The
    /// DNSSEC walk proves what the zone published — one direction —
    /// and this method roots the walk on it without checking the
    /// certificate direction (`verifyBinding` is that check; neither
    /// direction alone is a binding). Such resolutions carry
    /// `anchorAuthority: "zone-only"` so a caller reading `status`
    /// cannot mistake a resolved walk for an authenticated binding.
    ///
    /// Returns `{ status: "resolved", document }` or
    /// `{ status: "partial", consumed, total, reason, target? }` — a
    /// partial walk is the designed norm under partition, not an
    /// error. An unheld ROOT is the same partial as any unsynced hop
    /// (`consumed: 0`, `target`: the root anchor): hold a replica for
    /// the target (`holdAt`) and retry.
    ///
    /// # Errors
    ///
    /// Throws for unparsable names, a missing `root` on `~` names,
    /// and live-anchoring failures.
    pub async fn resolve(
        &self,
        name: &Text,
        root: Option<Text>,
        doh_url: Option<Text>,
    ) -> Result<JsWalkOutcome, JsError> {
        let name = text::read(name, "a name")?;
        let name = SupportedName::parse(&name).map_err(|error| JsError::new(&error.to_string()))?;

        // `Option<Text>` rather than `Option<String>`: the latter
        // TRAPS inside the module on a non-string `Some` (`resolve(n,
        // 42, …)` was `RuntimeError: memory access out of bounds`)
        // and silently coerces `[]` to `""`.
        let root = root
            .map(|raw| text::read(&raw, "a root anchor"))
            .transpose()?;
        let doh_url = doh_url
            .map(|raw| text::read(&raw, "a DoH URL"))
            .transpose()?;

        // A DNS-anchored walk roots on the zone's word alone: the
        // certificate direction is verifyBinding's check, not this
        // method's, and the outcome says so explicitly below.
        let zone_anchored = matches!(name, SupportedName::Dns(_));
        let root_anchor = self.anchor_of(&name, root.as_deref(), doh_url).await?;

        let mut held = HeldDocuments::default();
        for (anchor, doc) in &self.docs {
            held = held.with(*anchor, doc.clone());
        }
        let Some(root_namestore) = held.replica(&root_anchor) else {
            // An unheld ROOT is the same partial as any unsynced hop.
            return Ok(unsynced_root(name.segments().len(), &root_anchor));
        };

        // Track hops so the outcome names where the walk landed.
        let tracking = Tracking {
            inner: &held,
            last: Cell::new(Some(root_anchor)),
        };

        let verdict = js_sys::Object::new();
        match resolve(root_namestore, name.segments(), &tracking) {
            Resolution::Resolved { authority, .. } => {
                set(&verdict, "status", &JsValue::from_str(walk::RESOLVED));
                set(&verdict, "authority", &JsValue::from_str(authority.label()));
                // The zone's word is one direction; the certificate
                // direction is verifyBinding's check. Said on the
                // OBJECT, not only in a doc comment: a caller reading
                // `status: "resolved"` must be able to see that the
                // anchor itself is unauthenticated.
                if zone_anchored {
                    set(
                        &verdict,
                        "anchorAuthority",
                        &JsValue::from_str(walk::ZONE_ONLY),
                    );
                }
                // The browser has no keyhive route yet: every grade
                // here is the dev bridge's, and says so.
                set(
                    &verdict,
                    "warning",
                    &JsValue::from_str(match authority {
                        Authority::TrustedSubstrate => "nothing checked \u{2014} dev bridge",
                        Authority::CarriageVerified => {
                            "delegation graph verified; content authorship not yet checkable"
                        }
                    }),
                );
                if let Some(landed) = tracking.last.get() {
                    set(
                        &verdict,
                        "document",
                        &JsValue::from_str(&anchor_string(&landed)),
                    );
                }
            }
            Resolution::Partial { consumed, reason } => {
                set(&verdict, "status", &JsValue::from_str(walk::PARTIAL));
                set(&verdict, "consumed", &JsValue::from_f64(cast_len(consumed)));
                set(
                    &verdict,
                    "total",
                    &JsValue::from_f64(cast_len(name.segments().len())),
                );
                match reason {
                    PartialReason::DanglingSegment => {
                        set(
                            &verdict,
                            "reason",
                            &JsValue::from_str(walk::DANGLING_SEGMENT),
                        );
                    }
                    PartialReason::UnsyncedTarget { target } => {
                        set(
                            &verdict,
                            "reason",
                            &JsValue::from_str(walk::UNSYNCED_TARGET),
                        );
                        set(
                            &verdict,
                            "target",
                            &JsValue::from_str(&anchor_string(&target)),
                        );
                    }
                }
            }
        }
        Ok(verdict.unchecked_into())
    }
}

impl JsHeldDocuments {
    /// Every held document, for readers outside this module that need
    /// the whole set rather than one lookup — certificate
    /// verification walks it to follow one hop of indirection.
    pub(crate) fn documents(&self) -> impl Iterator<Item = (&DocAnchor, &Automerge)> {
        self.docs.iter()
    }

    /// The held document at `anchor`.
    fn held(&self, anchor: &str) -> Result<&Automerge, JsError> {
        let anchor = parse_anchor(anchor)?;
        self.docs
            .get(&anchor)
            .ok_or_else(|| JsError::new(&format!("document not held: {}", anchor_string(&anchor))))
    }

    /// The held document at `anchor`, mutably.
    fn held_mut(&mut self, anchor: &str) -> Result<&mut Automerge, JsError> {
        let anchor = parse_anchor(anchor)?;
        self.docs
            .get_mut(&anchor)
            .ok_or_else(|| JsError::new(&format!("document not held: {}", anchor_string(&anchor))))
    }

    /// The root document anchor for the name's trust anchor.
    async fn anchor_of(
        &self,
        name: &SupportedName,
        root: Option<&str>,
        doh_url: Option<String>,
    ) -> Result<DocAnchor, JsError> {
        match name {
            SupportedName::Doc(doc_name) => Ok(*doc_name.anchor()),
            SupportedName::Local(_) => match root {
                Some(raw) => parse_anchor(raw),
                None => Err(JsError::new(
                    "local (~) names resolve from YOUR root document: pass a root anchor",
                )),
            },
            SupportedName::Dns(dns_name) => {
                let hostname = dns_name.anchor();
                #[cfg(feature = "doh")]
                {
                    use onomancy_dnssec::chain_provider::ChainProvider as _;

                    let provider = doh_url.map_or_else(
                        crate::doh::DohProvider::cloudflare,
                        crate::doh::DohProvider::new,
                    );
                    let chain = provider
                        .chain(hostname)
                        .await
                        .map_err(|error| JsError::new(&error.to_string()))?;
                    let proof = onomancy_dnssec::validator::Validator::iana()
                        .validate_detailed(hostname, &chain)
                        .map_err(|error| JsError::new(&error.to_string()))?;

                    // The zone's word: the highest-serial record. All
                    // records in one proof share one ∩-window, so the
                    // zone-state key reduces to the serial — but the
                    // maximum must be UNIQUE (dns-anchor, Comparing
                    // Records Offline): a serial tie across documents
                    // is zone equivocation, and RRset enumeration
                    // order must never resolve it.
                    let Some(best) = proof.records.iter().max_by_key(|record| record.serial())
                    else {
                        return Err(JsError::new(
                            "the zone attests no binding for this hostname",
                        ));
                    };

                    if proof.records.iter().any(|record| {
                        record.serial() == best.serial() && record.document() != best.document()
                    }) {
                        return Err(JsError::new(
                            "the zone equivocates: two documents share the highest \
                             serial — refusing to let RRset order decide",
                        ));
                    }

                    Ok(*best.document())
                }
                #[cfg(not(feature = "doh"))]
                {
                    let _ = (hostname, doh_url);
                    Err(JsError::new(
                        "@hostname names need the `doh` feature for live anchoring",
                    ))
                }
            }
        }
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

/// The partial outcome for an unheld root: `consumed: 0`, the root
/// anchor as the unsynced target.
fn unsynced_root(total: usize, root_anchor: &DocAnchor) -> JsWalkOutcome {
    let verdict = js_sys::Object::new();
    set(&verdict, "status", &JsValue::from_str(walk::PARTIAL));
    set(&verdict, "consumed", &JsValue::from_f64(0.0));
    set(&verdict, "total", &JsValue::from_f64(cast_len(total)));
    set(
        &verdict,
        "reason",
        &JsValue::from_str(walk::UNSYNCED_TARGET),
    );
    set(
        &verdict,
        "target",
        &JsValue::from_str(&anchor_string(root_anchor)),
    );
    verdict.unchecked_into()
}

/// An anchor in its printed `automerge:…` form.
fn anchor_string(anchor: &DocAnchor) -> String {
    format!("{}{anchor}", doc::SCHEME_PREFIX)
}

/// Parse an anchor with or without the `automerge:` prefix.
fn parse_anchor(raw: &str) -> Result<DocAnchor, JsError> {
    let bare = raw.strip_prefix(doc::SCHEME_PREFIX).unwrap_or(raw);
    DocAnchor::parse(bare).map_err(|error| JsError::new(&error.to_string()))
}

/// Validate a `/`-joined path and return its canonical flat-map key.
fn path_of(path: &str) -> Result<String, JsError> {
    let segments: Vec<Segment> = path
        .split('/')
        .map(|raw| Segment::parse(raw).map_err(|error| JsError::new(&error.to_string())))
        .collect::<Result<_, _>>()?;

    if segments.is_empty() {
        return Err(JsError::new("a path needs at least one segment"));
    }

    Ok(segments
        .iter()
        .map(Segment::as_str)
        .collect::<Vec<_>>()
        .join("/"))
}

/// Segment counts fit in a JS number.
#[allow(clippy::cast_precision_loss)] // paths are far below 2^52 segments
const fn cast_len(len: usize) -> f64 {
    len as f64
}

/// `Reflect::set` on a fresh plain object cannot fail.
fn set(object: &js_sys::Object, key: &str, value: &JsValue) {
    drop(Reflect::set(object, &JsValue::from_str(key), value));
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::walk;

    /// Every literal Rust emits must be declared to TypeScript, and
    /// every declared member must be one Rust emits — the same
    /// bidirectional drift test the refusal codes have, because these
    /// strings are the same kind of load-bearing API: `browser.rs`
    /// and the Playwright specs both `switch` on them.
    #[test]
    fn the_declared_walk_unions_match_the_emitted_literals() {
        for (name, emitted) in [
            ("WalkStatus", walk::STATUSES),
            ("PartialWalkReason", walk::PARTIAL_REASONS),
        ] {
            let declared = declared_union(name);

            for literal in emitted {
                assert!(
                    declared.contains(literal),
                    "`{literal}` is emitted by Rust but absent from {name}"
                );
            }

            for member in &declared {
                assert!(
                    emitted.contains(member),
                    "`{member}` is declared in {name} but no Rust path emits it"
                );
            }
        }
    }

    /// The `zone-only` marker is declared where it is emitted: on the
    /// resolved arm of `WalkOutcome`, verbatim.
    #[test]
    fn the_zone_only_marker_is_declared() {
        assert!(
            crate::shapes::TYPES.contains(&format!("\"{}\"", walk::ZONE_ONLY)),
            "`{}` is emitted but not declared in shapes.d.ts",
            walk::ZONE_ONLY
        );
    }

    /// The members of one published union, by quoted string only —
    /// same parser discipline as the refusal drift test: a substring
    /// search over the whole file would match OTHER unions.
    fn declared_union(name: &str) -> Vec<&'static str> {
        let after = crate::shapes::TYPES
            .split(&format!("export type {name} ="))
            .nth(1)
            .unwrap_or_else(|| panic!("{name} is declared"));

        after
            .split(';')
            .next()
            .expect("the union terminates")
            .split('|')
            .filter_map(|part| {
                let opening = part.find('"')?;
                let rest = part.get(opening + 1..)?;
                let closing = rest.find('"')?;

                rest.get(..closing)
            })
            .collect()
    }
}
