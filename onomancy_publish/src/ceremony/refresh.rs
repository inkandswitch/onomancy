//! The refresh ceremony: keyless chain re-attachment.
//!
//! The operationally common ceremony, and the reason admin-only
//! signing is cheap: RRSIG windows lapse in days–weeks, and keeping a
//! certificate fresh needs NO key at all — the signed region is
//! untouched, only the attached region moves.

use alloc::{format, vec, vec::Vec};

use onomancy_core::time::UnixSeconds;
use onomancy_dnssec::{certificate::Certificate, chain::DnssecChain, txt::record::TxtRecord};
use onomancy_protocol::verifier::state::authority_verifier::AuthorityVerifier;

use crate::{
    ceremony::{CeremonyError, Intent, simulate},
    plan::{Artifact, ArtifactKind, FreshBinding, Plan, Postcondition},
};
use alloc::boxed::Box;

/// Re-attach a freshly fetched chain to an existing certificate.
#[derive(Debug, Clone)]
pub struct Refresh {
    /// The certificate to refresh (its signed region is reused
    /// verbatim — same certificate identity, new content hash).
    pub certificate: Certificate,

    /// The freshly fetched chain for the certificate's hostname.
    pub chain: DnssecChain,

    /// The binding records the chain proves (what the validator's
    /// walk of `chain` yielded).
    pub records: Vec<TxtRecord>,
}

impl Refresh {
    /// Emit the verified Plan: no DNS ops, no key — one refreshed
    /// artifact.
    ///
    /// # Errors
    ///
    /// Returns [`CeremonyError`] when the refreshed unit exceeds the
    /// encoder cap or the simulated derivation does not accept the
    /// certificate's own binding (e.g. the supplied chain proves a
    /// different document's records).
    pub fn plan<A: AuthorityVerifier>(
        &self,
        now: UnixSeconds,
        authority: &A,
    ) -> Result<Plan, CeremonyError> {
        let refreshed = self.certificate.with_attachments(
            self.certificate.delegation_chain().clone(),
            self.certificate.lineage().to_vec(),
            self.chain.clone(),
        )?;

        // The intended binding is whatever the zone's best record for
        // this document says — the record selection mirrors the
        // derivation's (highest serial among the proven records for
        // the certificate's document).
        let Some(best) = self
            .records
            .iter()
            .filter(|record| record.document() == refreshed.root_doc())
            .max_by_key(|record| record.serial())
        else {
            return Err(CeremonyError::DerivesNothing);
        };

        simulate(
            refreshed.hostname(),
            &self.records,
            &[&refreshed],
            now,
            &Intent {
                document: *refreshed.root_doc(),
                generation: *best.generation(),
                serial: best.serial(),
            },
            authority,
        )?;

        Ok(Plan {
            dns_ops: vec![],
            artifacts: vec![Artifact {
                name: format!("{}.onc", refreshed.hostname()),
                kind: ArtifactKind::Certificate,
                bytes: refreshed.encode(),
            }],
            postconditions: vec![Postcondition::VerifiesFresh(Box::new(FreshBinding {
                hostname: refreshed.hostname().clone(),
                document: *refreshed.root_doc(),
                generation: *best.generation(),
            }))],
        })
    }
}
