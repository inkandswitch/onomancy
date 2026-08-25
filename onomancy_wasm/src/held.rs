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

use automerge::{Automerge, ObjType, ReadDoc, ScalarValue, Value, transaction::Transactable};
use ed25519_dalek::SigningKey;
use js_sys::{Array, Reflect};
use onomancy_automerge::namestore::{DocumentNamestore, HeldDocuments, RESERVED_KEY};
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
use wasm_bindgen::{JsError, JsValue, prelude::wasm_bindgen};

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
    pub fn hold_at(&mut self, anchor: &str) -> Result<(), JsError> {
        let anchor = parse_anchor(anchor)?;
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
    pub fn hold(&mut self, anchor: &str, bytes: &[u8]) -> Result<(), JsError> {
        let anchor = parse_anchor(anchor)?;
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
    pub fn save(&self, anchor: &str) -> Result<Vec<u8>, JsError> {
        Ok(self.held(anchor)?.save())
    }

    /// Every held anchor (`automerge:…`), sorted.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn anchors(&self) -> Vec<String> {
        let mut anchors: Vec<String> = self.docs.keys().map(anchor_string).collect();
        anchors.sort();
        anchors
    }

    /// Set a display note on a held document.
    ///
    /// # Errors
    ///
    /// Throws for unknown anchors and write failures.
    #[wasm_bindgen(js_name = setNote)]
    pub fn set_note(&mut self, anchor: &str, note: &str) -> Result<(), JsError> {
        let doc = self.held_mut(anchor)?;
        doc.transact::<_, _, automerge::AutomergeError>(|tx| {
            tx.put(automerge::ROOT, "note", note)?;
            Ok(())
        })
        .map_err(|failure| JsError::new(&failure.error.to_string()))?;
        Ok(())
    }

    /// The display note on a held document, when set.
    ///
    /// # Errors
    ///
    /// Throws for unknown anchors.
    pub fn note(&self, anchor: &str) -> Result<Option<String>, JsError> {
        Ok(note_of(self.held(anchor)?))
    }

    /// Add a namestore edge: `path` (segments joined by `/`) names
    /// `target` from the `anchor` document.
    ///
    /// # Errors
    ///
    /// Throws for unknown anchors, malformed paths or targets, and
    /// write failures.
    pub fn bind(&mut self, anchor: &str, path: &str, target: &str) -> Result<(), JsError> {
        let key = path_of(path)?;
        let value = format!("{}{}", doc::SCHEME_PREFIX, parse_anchor(target)?);

        let doc = self.held_mut(anchor)?;
        doc.transact::<_, _, automerge::AutomergeError>(|tx| {
            let map = match tx.get(automerge::ROOT, RESERVED_KEY)? {
                Some((Value::Object(ObjType::Map), id)) => id,
                _ => tx.put_object(automerge::ROOT, RESERVED_KEY, ObjType::Map)?,
            };
            tx.put(&map, key.as_str(), value.as_str())?;
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
    pub fn edges(&self, anchor: &str) -> Result<JsValue, JsError> {
        let namestore = DocumentNamestore::new(self.held(anchor)?.clone());

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
    /// Returns `{ status: "resolved", document, note? }` or
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
        name: &str,
        root: Option<String>,
        doh_url: Option<String>,
    ) -> Result<JsValue, JsError> {
        let name = SupportedName::parse(name).map_err(|error| JsError::new(&error.to_string()))?;
        let root_anchor = self.anchor_of(&name, root.as_deref(), doh_url).await?;

        let mut held = HeldDocuments::default();
        for (anchor, doc) in &self.docs {
            held = held.with(*anchor, doc.clone());
        }
        let Some(root_namestore) = held.replica(&root_anchor) else {
            let verdict = js_sys::Object::new();
            set(&verdict, "status", &JsValue::from_str("partial"));
            set(&verdict, "consumed", &JsValue::from_f64(0.0));
            set(
                &verdict,
                "total",
                &JsValue::from_f64(cast_len(name.segments().len())),
            );
            set(&verdict, "reason", &JsValue::from_str("unsynced target"));
            set(
                &verdict,
                "target",
                &JsValue::from_str(&anchor_string(&root_anchor)),
            );
            return Ok(verdict.into());
        };

        // Track hops so the outcome names where the walk landed.
        let tracking = Tracking {
            inner: &held,
            last: Cell::new(Some(root_anchor)),
        };

        let verdict = js_sys::Object::new();
        match resolve(root_namestore, name.segments(), &tracking) {
            Resolution::Resolved { target, authority } => {
                set(&verdict, "status", &JsValue::from_str("resolved"));
                set(&verdict, "authority", &JsValue::from_str(authority.label()));
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
                if let Some(note) = note_of(target.document()) {
                    set(&verdict, "note", &JsValue::from_str(&note));
                }
            }
            Resolution::Partial { consumed, reason } => {
                set(&verdict, "status", &JsValue::from_str("partial"));
                set(&verdict, "consumed", &JsValue::from_f64(cast_len(consumed)));
                set(
                    &verdict,
                    "total",
                    &JsValue::from_f64(cast_len(name.segments().len())),
                );
                match reason {
                    PartialReason::DanglingSegment => {
                        set(&verdict, "reason", &JsValue::from_str("dangling segment"));
                    }
                    PartialReason::UnsyncedTarget { target } => {
                        set(&verdict, "reason", &JsValue::from_str("unsynced target"));
                        set(
                            &verdict,
                            "target",
                            &JsValue::from_str(&anchor_string(&target)),
                        );
                    }
                }
            }
        }
        Ok(verdict.into())
    }
}

impl JsHeldDocuments {
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

                    proof
                        .records
                        .iter()
                        .max_by_key(|record| record.serial())
                        .map(|record| *record.document())
                        .ok_or_else(|| {
                            JsError::new("the zone attests no binding for this hostname")
                        })
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

/// The `note` scalar on a document's root, when set.
fn note_of(doc: &Automerge) -> Option<String> {
    let (value, _) = doc.get(automerge::ROOT, "note").ok()??;
    let Value::Scalar(scalar) = value else {
        return None;
    };
    let ScalarValue::Str(text) = scalar.as_ref() else {
        return None;
    };
    Some(text.to_string())
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
