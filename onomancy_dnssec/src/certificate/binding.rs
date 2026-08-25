//! The certificate payload: the signed binding itself.

use alloc::{boxed::Box, vec::Vec};
use ed25519_dalek::VerifyingKey;

use onomancy_core::{
    anchor::doc::{DocAnchor, Head},
    signed::payload::Payload,
    time::UnixSeconds,
    wire::{self, Reader},
};

use crate::{dns_name::DnsName, statement::successor::SuccessorStatement};

use super::{DecodeCertificateError, FieldName, read_heads, read_key};

/// The signed fields: `hostname` is bound to `root_doc`, attested by
/// `signer` (a delegated admin key) at `issued_at`, optionally with
/// advisory `heads` and a succession proof from a `predecessor`
/// document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    root_doc: DocAnchor,
    signer: VerifyingKey,
    issued_at: UnixSeconds,
    hostname: DnsName,
    heads: Vec<Head>,
    predecessor: Option<Box<SuccessorStatement>>,
}

impl Binding {
    /// Assembles the payload verbatim; canonicalization (head
    /// sorting, dedup) is the caller's job before construction.
    #[must_use]
    pub fn new(
        root_doc: DocAnchor,
        signer: VerifyingKey,
        issued_at: UnixSeconds,
        hostname: DnsName,
        heads: Vec<Head>,
        predecessor: Option<SuccessorStatement>,
    ) -> Self {
        Self {
            root_doc,
            signer,
            issued_at,
            hostname,
            heads,
            predecessor: predecessor.map(Box::new),
        }
    }

    /// The signing key.
    #[must_use]
    pub const fn signer(&self) -> &VerifyingKey {
        &self.signer
    }

    /// The bound root document.
    #[must_use]
    pub const fn root_doc(&self) -> &DocAnchor {
        &self.root_doc
    }

    /// Signer-claimed issuance time.
    #[must_use]
    pub const fn issued_at(&self) -> UnixSeconds {
        self.issued_at
    }

    /// The bound hostname.
    #[must_use]
    pub const fn hostname(&self) -> &DnsName {
        &self.hostname
    }

    /// Advisory heads, canonical order.
    #[must_use]
    pub fn heads(&self) -> &[Head] {
        &self.heads
    }

    /// The succession proof, if any.
    #[must_use]
    pub fn predecessor(&self) -> Option<&SuccessorStatement> {
        self.predecessor.as_deref()
    }
}

impl Payload for Binding {
    const TAG: [u8; 4] = *b"ONC\x00";

    type Error = DecodeCertificateError;

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.root_doc.verifying_key().as_bytes());
        buf.extend_from_slice(self.signer.as_bytes());
        wire::put_varint(buf, self.issued_at.value());
        wire::put_varint(buf, self.hostname.as_str().len() as u64);
        buf.extend_from_slice(self.hostname.as_str().as_bytes());

        wire::put_varint(buf, self.heads.len() as u64);
        for head in &self.heads {
            buf.extend_from_slice(head.as_bytes());
        }

        match &self.predecessor {
            None => wire::put_varint(buf, 0),
            Some(statement) => {
                let unit = statement.encode();
                wire::put_varint(buf, unit.len() as u64);
                buf.extend_from_slice(&unit);
            }
        }
    }

    fn decode_fields(reader: &mut Reader<'_>) -> Result<Self, DecodeCertificateError> {
        let root_doc = DocAnchor::from(read_key(reader, FieldName::RootDoc)?);
        let signer = read_key(reader, FieldName::Signer)?;
        let issued_at = UnixSeconds::from(reader.varint()?);

        let hostname_len = reader.bounded_len(1)?;
        let hostname = DnsName::from_canonical(reader.take(hostname_len)?)?;

        let heads = read_heads(reader)?;

        let predecessor_len = reader.bounded_len(1)?;
        let predecessor = if predecessor_len == 0 {
            None
        } else {
            let unit = reader.take(predecessor_len)?;
            Some(Box::new(SuccessorStatement::decode(unit)?))
        };

        Ok(Self {
            root_doc,
            signer,
            issued_at,
            hostname,
            heads,
            predecessor,
        })
    }

    fn signer(&self) -> &VerifyingKey {
        self.signer()
    }
}
