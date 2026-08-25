//! The first-binding ceremony: a hostname gains an Onomancy binding.

use alloc::{format, vec};

use onomancy_core::{
    anchor::doc::{DocAnchor, Head},
    time::UnixSeconds,
};
use onomancy_dnssec::{
    certificate::{Certificate, CertificateParams, chain::DnssecChain},
    dns_name::DnsName,
    statement::rotation::RotationStatement,
    txt::{generation_key::GenerationKey, record::TxtRecord, serial::Serial},
};

use crate::{
    ceremony::{CeremonyError, Intent, simulate},
    plan::{Artifact, ArtifactKind, DnsOp, FreshBinding, Plan, Postcondition},
    signer::Signer,
};
use alloc::boxed::Box;

/// Bind `hostname` to `document`, attesting `generation`.
///
/// Build the intent keylessly; the signer surfaces only in
/// [`Bind::plan`].
#[derive(Debug, Clone)]
pub struct Bind {
    /// The hostname to bind (canonical A-label form).
    pub hostname: DnsName,

    /// The root document to bind it to.
    pub document: DocAnchor,

    /// The current generation key to attest in `g=`.
    pub generation: GenerationKey,

    /// Advisory heads to stamp into the certificate.
    pub heads: alloc::vec::Vec<Head>,

    /// Existing lineage to carry, oldest first (usually empty on a
    /// first binding).
    pub lineage: alloc::vec::Vec<RotationStatement>,

    /// The authority carriage to attach: delegation proof that
    /// `generation` lies on `document`'s path (D10). Opaque here —
    /// minted by `onomancy_keyhive::mint`, verified by the agent's
    /// authority.
    pub carriage: onomancy_core::delegation::DelegationChain,
}

impl Bind {
    /// Emit the verified Plan.
    ///
    /// `now_ms` is the clock in milliseconds (the serial-as-timestamp
    /// convention); `signer` signs the certificate (the document key
    /// itself until Keyhive delegation lands).
    ///
    /// # Errors
    ///
    /// Returns [`CeremonyError`] when a unit exceeds the encoder cap
    /// or the simulated derivation does not accept exactly this
    /// binding.
    pub fn plan(&self, now_ms: u64, signer: &Signer) -> Result<Plan, CeremonyError> {
        let serial = Serial::from(now_ms);
        let now = UnixSeconds::from(now_ms / 1000);

        let record = TxtRecord::new(serial, self.generation, self.document);

        // The chain is attached EMPTY here: the record is not in the
        // zone yet, so there is nothing true to attach. A refresh
        // ceremony re-attaches the live chain keylessly once the ops
        // have landed.
        let certificate = Certificate::sign(
            CertificateParams {
                root_doc: self.document,
                issued_at: now,
                hostname: self.hostname.clone(),
                heads: self.heads.clone(),
                predecessor: None,
                delegation_chain: self.carriage.clone(),
                lineage: self.lineage.clone(),
                chain: DnssecChain::default(),
            },
            signer.key(),
        )?;

        simulate(
            &self.hostname,
            &[record],
            &[&certificate],
            now,
            &Intent {
                document: self.document,
                generation: self.generation,
                serial,
            },
        )?;

        Ok(Plan {
            dns_ops: vec![DnsOp::PublishTxt {
                hostname: self.hostname.clone(),
                record,
            }],
            artifacts: vec![Artifact {
                name: format!("{}.onc", self.hostname),
                kind: ArtifactKind::Certificate,
                bytes: certificate.encode(),
            }],
            postconditions: vec![
                Postcondition::VerifiesFresh(Box::new(FreshBinding {
                    hostname: self.hostname.clone(),
                    document: self.document,
                    generation: self.generation,
                })),
                Postcondition::EffectiveSerialAtLeast {
                    hostname: self.hostname.clone(),
                    serial,
                },
            ],
        })
    }
}
