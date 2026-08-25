//! The migration ceremony: move a hostname to a successor document.
//!
//! Migration is per-name — the successor statement signs the
//! hostname precisely so one name's proof cannot be replayed under
//! another (dns-anchor, Succession). The predecessor's record stays
//! in the `RRset` through a dual-publish window so in-flight
//! verifiers converge via the proof, not a surprise.

use alloc::{format, vec, vec::Vec};

use onomancy_core::{anchor::doc::DocAnchor, delegation_chain::DelegationChain, time::UnixSeconds};
use onomancy_dnssec::{
    certificate::{Certificate, CertificateParams},
    chain::DnssecChain,
    dns_name::DnsName,
    statement::{rotation::RotationStatement, successor::SuccessorStatement},
    txt::{generation_key::GenerationKey, record::TxtRecord, serial::Serial},
};

use crate::{
    ceremony::{CeremonyError, Intent, simulate},
    plan::{Artifact, ArtifactKind, DnsOp, FreshBinding, Plan, Postcondition},
    signer::Signer,
};
use alloc::boxed::Box;

/// Migrate `hostname` from `predecessor` to `successor`.
#[derive(Debug, Clone)]
pub struct Migrate {
    /// The hostname migrating.
    pub hostname: DnsName,

    /// The document being left.
    pub predecessor: DocAnchor,

    /// The document being moved to.
    pub successor: DocAnchor,

    /// The currently published record (kept in the `RRset` through
    /// the dual-publish window).
    pub retained: TxtRecord,

    /// The successor document's current generation key.
    pub successor_generation: GenerationKey,

    /// The successor document's lineage, oldest first (usually
    /// empty for a fresh document).
    pub lineage: Vec<RotationStatement>,

    /// The successor document's authority carriage: D10 path proof
    /// for the new `g=`, attached to the successor certificate.
    /// Opaque here — minted by `onomancy_keyhive::mint`.
    pub carriage: onomancy_core::delegation_chain::DelegationChain,
}

impl Migrate {
    /// Emit the verified Plan. `predecessor_authority` signs the
    /// succession proof (it must speak for the PREDECESSOR document);
    /// `certificate_signer` signs the successor's certificate.
    ///
    /// # Errors
    ///
    /// Returns [`CeremonyError`] on cap overflows, or when the
    /// simulated dual-publish zone does not derive the successor as
    /// the accepted document (e.g. the proof does not connect the
    /// documents the records attest).
    pub fn plan(
        &self,
        now_ms: u64,
        predecessor_authority: &Signer,
        certificate_signer: &Signer,
    ) -> Result<Plan, CeremonyError> {
        let proof = SuccessorStatement::sign(
            &self.predecessor,
            &self.successor,
            &self.hostname,
            predecessor_authority.key(),
            DelegationChain::default(),
        )?;

        let serial = Serial::from(now_ms);
        let now = UnixSeconds::from(now_ms / 1000);
        let record = TxtRecord::new(serial, self.successor_generation, self.successor);

        let certificate = Certificate::sign(
            CertificateParams {
                root_doc: self.successor,
                issued_at: now,
                hostname: self.hostname.clone(),
                heads: vec![],
                predecessor: Some(proof.clone()),
                delegation_chain: self.carriage.clone(),
                lineage: self.lineage.clone(),
                chain: DnssecChain::default(),
            },
            certificate_signer.key(),
        )?;

        // The dual-publish zone: BOTH records in the RRset. The
        // derivation must pick the successor via the proof — rung 1
        // continuity, not zone-state luck — and mark nothing pending.
        simulate(
            &self.hostname,
            &[self.retained, record],
            &[&certificate],
            now,
            &Intent {
                document: self.successor,
                generation: self.successor_generation,
                serial,
            },
        )?;

        Ok(Plan {
            dns_ops: vec![
                DnsOp::RetainTxt {
                    hostname: self.hostname.clone(),
                    record: self.retained,
                },
                DnsOp::PublishTxt {
                    hostname: self.hostname.clone(),
                    record,
                },
            ],
            artifacts: vec![
                Artifact {
                    name: format!("{}.onc", self.hostname),
                    kind: ArtifactKind::Certificate,
                    bytes: certificate.encode(),
                },
                Artifact {
                    name: format!("{}-succession.ons", self.hostname),
                    kind: ArtifactKind::SuccessorStatement,
                    bytes: proof.encode(),
                },
            ],
            postconditions: vec![
                Postcondition::VerifiesFresh(Box::new(FreshBinding {
                    hostname: self.hostname.clone(),
                    document: self.successor,
                    generation: self.successor_generation,
                })),
                Postcondition::EffectiveSerialAtLeast {
                    hostname: self.hostname.clone(),
                    serial,
                },
            ],
        })
    }
}
