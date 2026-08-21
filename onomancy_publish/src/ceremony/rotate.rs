//! The rotation ceremony: retire generation Gₙ in favor of Gₙ₊₁.
//!
//! One ceremony heals every name bound to the document — the rotation
//! statement deliberately carries no hostname (dns-anchor,
//! Generation Key). The revoked generation's signers die against any
//! fresh chain the moment the new `g=` lands.

use alloc::{format, vec, vec::Vec};

use onomancy_core::{
    cert::{Certificate, CertificateParams, chain::DnssecChain},
    name::{dns::DnsName, doc::DocAnchor},
    statement::rotation::RotationStatement,
    time::UnixSeconds,
    txt::{generation_key::GenerationKey, record::TxtRecord, serial::Serial},
};

use crate::{
    ceremony::{CeremonyError, Intent, simulate},
    plan::{Artifact, ArtifactKind, DnsOp, FreshBinding, Plan, Postcondition},
    signer::Signer,
};
use alloc::boxed::Box;

/// Rotate `document`'s generation: `replaced` (Gₙ) out, the
/// successor signer's key (Gₙ₊₁) in.
#[derive(Debug, Clone)]
pub struct Rotate {
    /// A hostname bound to the document (each bound name needs its
    /// own TXT op; run one Rotate per name — the statement is shared).
    pub hostname: DnsName,

    /// The document whose generation rotates.
    pub document: DocAnchor,

    /// The generation being retired (Gₙ).
    pub replaced: GenerationKey,

    /// The document's accumulated lineage, oldest first (complete
    /// from the first rotation, per the spec's SHOULD).
    pub prior_lineage: Vec<RotationStatement>,
}

impl Rotate {
    /// Emit the verified Plan. The `successor` signer IS Gₙ₊₁ —
    /// rotation statements are signed by the incoming generation —
    /// and `certificate_signer` signs the refreshed certificate.
    ///
    /// # Errors
    ///
    /// Returns [`CeremonyError::GenerationReuse`] when Gₙ₊₁ already
    /// appears anywhere in the lineage (reuse converts the lineage
    /// into a permanent surfaced fork), and the usual cap/simulation
    /// failures otherwise.
    pub fn plan(
        &self,
        now_ms: u64,
        successor: &Signer,
        certificate_signer: &Signer,
    ) -> Result<Plan, CeremonyError> {
        let next_generation = GenerationKey::from(successor.verifying_key());

        // Publishers MUST NOT reuse generation keys: check against
        // every key the lineage has ever named (either side of any
        // statement), plus the one being replaced now.
        let reused = self.replaced == next_generation
            || self.prior_lineage.iter().any(|statement| {
                *statement.replaced() == next_generation
                    || *statement.successor() == next_generation
            });
        if reused {
            return Err(CeremonyError::GenerationReuse);
        }

        let statement =
            RotationStatement::sign(&self.document, &self.replaced, successor.key(), vec![])?;

        let mut lineage = self.prior_lineage.clone();
        lineage.push(statement.clone());

        let serial = Serial::from(now_ms);
        let now = UnixSeconds::from(now_ms / 1000);
        let record = TxtRecord::new(serial, next_generation, self.document);

        let certificate = Certificate::sign(
            CertificateParams {
                root_doc: self.document,
                issued_at: now,
                hostname: self.hostname.clone(),
                heads: vec![],
                predecessor: None,
                delegation_chain: vec![],
                lineage,
                chain: DnssecChain::default(),
            },
            certificate_signer.key(),
        )?;

        // The simulation is where set-wise lineage shape gets its
        // final word: a fork the reuse check above cannot see (e.g. a
        // double-replace hiding in prior_lineage) surfaces here.
        simulate(
            &self.hostname,
            &[record],
            &[&certificate],
            now,
            &Intent {
                document: self.document,
                generation: next_generation,
                serial,
            },
        )?;

        Ok(Plan {
            dns_ops: vec![DnsOp::PublishTxt {
                hostname: self.hostname.clone(),
                record,
            }],
            artifacts: vec![
                Artifact {
                    name: format!("{}.onc", self.hostname),
                    kind: ArtifactKind::Certificate,
                    bytes: certificate.encode(),
                },
                Artifact {
                    name: format!("{}-rotation.onr", self.hostname),
                    kind: ArtifactKind::RotationStatement,
                    bytes: statement.encode(),
                },
            ],
            postconditions: vec![
                Postcondition::VerifiesFresh(Box::new(FreshBinding {
                    hostname: self.hostname.clone(),
                    document: self.document,
                    generation: next_generation,
                })),
                Postcondition::EffectiveSerialAtLeast {
                    hostname: self.hostname.clone(),
                    serial,
                },
            ],
        })
    }
}
