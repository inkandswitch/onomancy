//! Publisher ceremonies: [`Plan`](plan::Plan)s that verify by
//! construction.
//!
//! A ceremony (bind, refresh, rotate, migrate) turns intent into a
//! **Plan**: the DNS operations to apply, the artifacts to serve or
//! gossip, and the postconditions that hold once the zone reflects
//! the ops. Nothing here performs IO — applying a Plan is the
//! [`zone_editor::ZoneEditor`]'s job (a printing executor at minimum;
//! provider adapters are thin skins), and checking postconditions is
//! the verifier the workspace already ships.
//!
//! ```text
//! ceremony (intent + Signer)
//!    │ plan(now) — runs the REAL derivation against a
//!    │            simulated zone before emitting anything
//!    ▼
//! Plan { dns_ops · artifacts · postconditions }
//!    │ apply            │ serve/gossip        │ watch
//!    ▼                  ▼                     ▼
//! ZoneEditor        static files         verifier
//! ```
//!
//! **Verified by construction**: `plan()` simulates "the zone now
//! says what these ops publish" with the in-memory validator and runs
//! `VerifierState::compute` — the real 8-stage derivation — asserting
//! the accepted binding is exactly the ceremony's intent. A plan that
//! would fork your own lineage, regress your serial, or bind the
//! wrong generation fails at plan time, not in production. A `Plan`'s
//! existence is the witness (parse, don't validate).
//!
//! Delegation carriages are empty until `onomancy_keyhive` lands
//! (the simulation's authority seam is permissive, like the live
//! verifier's — the same loudly-documented gap).

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod ceremony;
pub mod plan;
pub mod signer;
pub mod zone_editor;
