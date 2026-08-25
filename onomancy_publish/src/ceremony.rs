//! The ceremonies: intent in, verified-by-construction Plans out.
//!
//! Every ceremony's `plan()` ends the same way: [`simulate`] fakes a
//! zone that says exactly what the plan's ops publish, runs the REAL
//! 8-stage derivation (`VerifierState::compute`) over it, and refuses
//! to emit a Plan whose derived binding is not the ceremony's intent.
//! Lineage forks, serial regressions, wrong generations — all fail at
//! plan time.

pub mod bind;
pub mod migrate;
pub mod refresh;
pub mod rotate;

use alloc::boxed::Box;
use onomancy_core::{
    certificate::Certificate,
    collections::Map,
    freshness::ChainWindow,
    name::{dns::DnsName, doc::DocAnchor},
    time::UnixSeconds,
    txt::{generation_key::GenerationKey, record::TxtRecord, serial::Serial},
    wire::OversizeUnit,
};
use onomancy_protocol::verifier_state::{
    VerifierState,
    decisions::Decisions,
    memory::{MemoryAuthority, MemoryValidator},
    seam::ChainProof,
    store::{Store, item::Item},
};

/// The simulated chain window around `now`: comfortably fresh, zero
/// chance of straddling a grading boundary.
const SIMULATED_WINDOW_SLACK: u64 = 60 * 60;

/// The ceremony's intended outcome, asserted against the simulated
/// derivation.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Intent {
    pub(crate) document: DocAnchor,
    pub(crate) generation: GenerationKey,
    pub(crate) serial: Serial,
}

/// Run the real derivation against a zone that says exactly what the
/// plan publishes; error unless it accepts precisely the intent.
///
/// The authority seam is permissive here, matching the live verifier
/// until `onomancy_keyhive` lands — the same loudly-documented gap.
pub(crate) fn simulate(
    hostname: &DnsName,
    zone_records: &[TxtRecord],
    certificates: &[&Certificate],
    now: UnixSeconds,
    intent: &Intent,
) -> Result<(), CeremonyError> {
    let window = ChainWindow::new(
        UnixSeconds::from(u64::from(now).saturating_sub(SIMULATED_WINDOW_SLACK)),
        UnixSeconds::from(u64::from(now).saturating_add(SIMULATED_WINDOW_SLACK)),
    )
    .map_err(|_| CeremonyError::ClockOverflow)?;

    let proof = ChainProof {
        records: zone_records.to_vec(),
        window,
    };

    let mut validator = MemoryValidator::default();
    let mut store = Store::default();
    for certificate in certificates {
        validator = validator.with(hostname.clone(), certificate.dnssec_chain(), proof.clone());
        store.insert(Item::Record((*certificate).clone()));
    }

    let state = VerifierState::compute(
        &store,
        now,
        &Decisions::default(),
        &Map::default(),
        &validator,
        &MemoryAuthority::default(),
    );

    let Some(host) = state.hosts.get(hostname) else {
        return Err(CeremonyError::DerivesNothing);
    };

    if !host.forks.is_empty() || !host.succession_forks.is_empty() {
        return Err(CeremonyError::WouldFork);
    }
    if host.contested {
        return Err(CeremonyError::WouldContest);
    }

    let Some(accepted) = host.accepted else {
        return Err(CeremonyError::DerivesNothing);
    };

    if accepted.document != intent.document || accepted.generation != intent.generation {
        return Err(CeremonyError::WrongBinding(Box::new(BindingMismatch {
            intended: intent.document,
            derived: accepted.document,
        })));
    }

    if host.effective_serial != Some(intent.serial) {
        return Err(CeremonyError::WrongSerial {
            intended: intent.serial,
            derived: host.effective_serial,
        });
    }

    Ok(())
}

/// A ceremony refused to emit a Plan.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CeremonyError {
    /// The simulated window around `now` was unrepresentable.
    #[error("clock too close to the epoch or overflow for a simulated window")]
    ClockOverflow,

    /// The simulated derivation accepted nothing for the hostname.
    #[error("the planned zone state derives no accepted binding")]
    DerivesNothing,

    /// The successor generation already appears in the lineage:
    /// publishing would convert the lineage into a permanent
    /// surfaced fork (dns-anchor: publishers MUST NOT reuse
    /// generation keys).
    #[error("generation key reuse: the successor already appears in the lineage")]
    GenerationReuse,

    /// A unit exceeded the encoder cap.
    #[error(transparent)]
    Oversize(#[from] OversizeUnit),

    /// The simulated derivation lands contested.
    #[error("the planned zone state derives as contested")]
    WouldContest,

    /// The plan would surface a lineage or succession fork against
    /// itself.
    #[error("the plan forks its own lineage or succession")]
    WouldFork,

    /// The derivation accepted a different binding than intended
    /// (boxed: anchors cache decompressed curve points).
    #[error("planned zone state derives document {}, not {}", .0.derived, .0.intended)]
    WrongBinding(Box<BindingMismatch>),

    /// The derived effective serial is not the planned one.
    #[error("planned zone state derives serial {derived:?}, not {intended}")]
    WrongSerial {
        /// The planned serial.
        intended: Serial,
        /// What the derivation produced.
        derived: Option<Serial>,
    },
}

/// What [`CeremonyError::WrongBinding`] refused: intent vs derived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingMismatch {
    /// What the ceremony meant to bind.
    pub intended: DocAnchor,
    /// What the derivation accepted.
    pub derived: DocAnchor,
}
