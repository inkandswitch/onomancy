//! The Plan: a ceremony's output — neutral, inspectable, applyable.
//!
//! A Plan is NOT an API call: DNS-hosting interfaces are wildly
//! heterogeneous (dashboards, RFC 2136, provider APIs, zone files),
//! so the Plan is the boundary — one pure planner, N dumb executors.

use alloc::{string::String, vec::Vec};

use onomancy_core::{
    name::{dns::DnsName, doc::DocAnchor},
    txt::{generation_key::GenerationKey, record::TxtRecord, serial::Serial},
};

/// What a ceremony asks of the world: zone edits, bytes to serve,
/// and the facts that hold once the zone reflects the edits.
///
/// A `Plan` verifies by construction: the emitting ceremony already
/// ran the real derivation against a simulated zone stating exactly
/// what `dns_ops` publish — existence is the witness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Zone edits, in order.
    pub dns_ops: Vec<DnsOp>,

    /// Bytes to serve at the designated endpoint and/or gossip.
    pub artifacts: Vec<Artifact>,

    /// Checkable facts, once the zone reflects `dns_ops` (the
    /// verifier the workspace already ships is the checker — the
    /// agent's `watch`).
    pub postconditions: Vec<Postcondition>,
}

/// One zone edit. All records live at the `_onomancy.<hostname>`
/// owner name; the zone's own re-signing (managed DNSSEC or a manual
/// `dnssec-signzone`) is assumed — an unsigned edit produces a chain
/// that fails validation, which the postconditions will surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsOp {
    /// Publish this record (create, or replace the current one).
    PublishTxt {
        /// The bound hostname (owner name is `_onomancy.<hostname>`).
        hostname: DnsName,
        /// The record to publish.
        record: TxtRecord,
    },

    /// Keep an existing record in the `RRset` alongside newly
    /// published ones — the migration dual-publish window.
    RetainTxt {
        /// The bound hostname.
        hostname: DnsName,
        /// The record to retain.
        record: TxtRecord,
    },

    /// Remove a record once its window has served its purpose
    /// (post-migration cleanup). Advisory: leaving it costs only
    /// `RRset` bytes.
    RetireTxt {
        /// The bound hostname.
        hostname: DnsName,
        /// The record to retire.
        record: TxtRecord,
    },
}

impl DnsOp {
    /// The record the operation concerns.
    #[must_use]
    pub const fn record(&self) -> &TxtRecord {
        match self {
            Self::PublishTxt { record, .. }
            | Self::RetainTxt { record, .. }
            | Self::RetireTxt { record, .. } => record,
        }
    }

    /// The bound hostname the operation concerns.
    #[must_use]
    pub const fn hostname(&self) -> &DnsName {
        match self {
            Self::PublishTxt { hostname, .. }
            | Self::RetainTxt { hostname, .. }
            | Self::RetireTxt { hostname, .. } => hostname,
        }
    }
}

/// Bytes a ceremony produced: serve them, gossip them, or both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    /// A suggested filename (e.g. `example.com.onc`).
    pub name: String,
    /// What the bytes are.
    pub kind: ArtifactKind,
    /// The encoded unit, verbatim.
    pub bytes: Vec<u8>,
}

/// The unit an [`Artifact`] carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactKind {
    /// An `ONC\0` certificate.
    Certificate,
    /// An `ONR\0` rotation statement (also embedded in the
    /// certificate's lineage; standalone for gossip).
    RotationStatement,
    /// An `ONS\0` successor statement (also embedded as the
    /// certificate's predecessor proof; standalone for gossip).
    SuccessorStatement,
}

/// A fact that holds once the zone reflects the Plan's ops — the
/// contract `watch` checks with the ordinary verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Postcondition {
    /// Resolving the hostname verifies fresh ✓ with exactly this
    /// binding (boxed: anchors cache decompressed curve points).
    VerifiesFresh(alloc::boxed::Box<FreshBinding>),

    /// The effective serial is at least this (ratchet moved forward).
    EffectiveSerialAtLeast {
        /// The bound hostname.
        hostname: DnsName,
        /// The floor.
        serial: Serial,
    },
}

/// The binding a [`Postcondition::VerifiesFresh`] expects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreshBinding {
    /// The bound hostname.
    pub hostname: DnsName,
    /// The accepted document.
    pub document: DocAnchor,
    /// The attested generation.
    pub generation: GenerationKey,
}
