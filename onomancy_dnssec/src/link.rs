//! The link model: one `RRset` and the RRSIG(s) that cover it.
//!
//! A chain link's bytes are a sequence of records in canonical wire
//! form: the data `RRset` (one owner, one type, class IN) followed by
//! at least one covering RRSIG. This module groups and cross-checks
//! that shape — signature *verification* is the walk's job; this is
//! the parse-don't-validate boundary in front of it.
//!
//! ```text
//! ChainLink bytes ──► [ data RR, data RR, …, RRSIG, RRSIG… ]
//!                        │ same owner/type/class │ covering that type,
//!                        ▼                        ▼ same owner
//!                     Link { rrset, signatures }
//! ```

use alloc::vec::Vec;

use onomancy_core::wire::Reader;

use crate::chain::ChainLink;

use crate::wire::{
    name::Name,
    record::{CLASS_IN, ParseRecordError, Record},
    rr_type::RrType,
    rrsig::{ParseRrsigError, Rrsig},
};

/// One parsed chain link: a data `RRset` with its covering signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    owner: Name,
    rrset: Vec<Record>,
    rtype: RrType,
    signatures: Vec<Rrsig>,
}

impl Link {
    /// Strictly parse one framed link.
    ///
    /// # Errors
    ///
    /// Returns [`ParseLinkError`] when any record fails to parse, the
    /// data records are not one `RRset` (one owner, one type, class
    /// IN), any RRSIG covers the wrong type or names a different
    /// owner, or either half is missing.
    pub fn parse(link: &ChainLink) -> Result<Self, ParseLinkError> {
        let bytes = link.as_bytes();
        let mut reader = Reader::new(bytes)?;

        let mut rrset: Vec<Record> = Vec::new();
        let mut signatures: Vec<(Record, Rrsig)> = Vec::new();

        while reader.remaining() > 0 {
            let record = Record::read(&mut reader)?;

            if record.class != CLASS_IN {
                return Err(ParseLinkError::WrongClass { got: record.class });
            }

            if record.rtype == RrType::RRSIG {
                let rrsig = Rrsig::parse(&record.rdata)?;
                signatures.push((record, rrsig));
            } else {
                rrset.push(record);
            }
        }

        let Some(first) = rrset.first() else {
            return Err(ParseLinkError::NoData);
        };
        let owner = first.owner.clone();
        let rtype = first.rtype;

        if rrset.iter().any(|r| r.owner != owner || r.rtype != rtype) {
            return Err(ParseLinkError::MixedRrset);
        }

        if signatures.is_empty() {
            return Err(ParseLinkError::NoSignatures);
        }

        for (record, rrsig) in &signatures {
            if record.owner != owner {
                return Err(ParseLinkError::SignatureOwnerMismatch);
            }
            if rrsig.type_covered() != rtype {
                return Err(ParseLinkError::SignatureCoversWrongType {
                    covered: rrsig.type_covered(),
                    data: rtype,
                });
            }
        }

        Ok(Self {
            owner,
            rrset,
            rtype,
            signatures: signatures.into_iter().map(|(_, rrsig)| rrsig).collect(),
        })
    }

    /// The `RRset`'s owner name.
    #[must_use]
    pub const fn owner(&self) -> &Name {
        &self.owner
    }

    /// The `RRset`'s record type.
    #[must_use]
    pub const fn rtype(&self) -> RrType {
        self.rtype
    }

    /// The data records, as carried.
    #[must_use]
    pub fn rrset(&self) -> &[Record] {
        &self.rrset
    }

    /// The covering signatures. Any ONE validating signature suffices
    /// (RFC 4035 §5.3.3); multiple are normal during key rollover.
    #[must_use]
    pub fn signatures(&self) -> &[Rrsig] {
        &self.signatures
    }
}

/// The bytes were not a canonical link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseLinkError {
    /// Data records with differing owners or types: not one `RRset`.
    #[error("link data records are not a single RRset")]
    MixedRrset,

    /// No data records at all.
    #[error("link carries no data records")]
    NoData,

    /// No covering RRSIG: unverifiable by construction.
    #[error("link carries no RRSIG")]
    NoSignatures,

    /// A record failed to parse.
    #[error("record: {0}")]
    Record(#[from] ParseRecordError),

    /// An RRSIG RDATA failed to parse.
    #[error("rrsig: {0}")]
    Rrsig(#[from] ParseRrsigError),

    /// An RRSIG covers a type other than the data type.
    #[error("RRSIG covers {covered}, data is {data}")]
    SignatureCoversWrongType {
        /// What the signature covers.
        covered: RrType,
        /// The data `RRset`'s type.
        data: RrType,
    },

    /// An RRSIG's owner differs from the data owner.
    #[error("RRSIG owner differs from the RRset owner")]
    SignatureOwnerMismatch,

    /// A record class other than IN.
    #[error("class {got}; Onomancy records exist only in IN")]
    WrongClass {
        /// The class found.
        got: u16,
    },

    /// Framing failure (truncation, size cap).
    #[error(transparent)]
    Wire(#[from] onomancy_core::wire::WireError),
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::wire::algorithm::Algorithm;
    use alloc::{vec, vec::Vec};

    fn owner() -> Name {
        "_onomancy.expede.wtf".parse().expect("parses")
    }

    fn txt_record(rdata: Vec<u8>) -> Record {
        Record {
            owner: owner(),
            rtype: RrType::TXT,
            class: CLASS_IN,
            ttl: 900,
            rdata,
        }
    }

    fn rrsig_record(covered: RrType, signer_owner: &Name) -> Record {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&covered.code().to_be_bytes());
        rdata.push(Algorithm::ED25519.code());
        rdata.push(3);
        rdata.extend_from_slice(&900u32.to_be_bytes());
        rdata.extend_from_slice(&1_755_600_000u32.to_be_bytes());
        rdata.extend_from_slice(&1_754_000_000u32.to_be_bytes());
        rdata.extend_from_slice(&12345u16.to_be_bytes());
        rdata.extend_from_slice(b"\x06expede\x03wtf\x00");
        rdata.extend_from_slice(&[0xEE; 64]);

        Record {
            owner: signer_owner.clone(),
            rtype: RrType::RRSIG,
            class: CLASS_IN,
            ttl: 900,
            rdata,
        }
    }

    fn frame(records: &[Record]) -> ChainLink {
        let mut bytes = Vec::new();
        for record in records {
            record.write(&mut bytes);
        }
        ChainLink::from(bytes)
    }

    #[test]
    fn groups_an_rrset_with_its_signatures() {
        let link = Link::parse(&frame(&[
            txt_record(vec![4, b't', b'e', b's', b't']),
            txt_record(vec![1, b'x']),
            rrsig_record(RrType::TXT, &owner()),
        ]))
        .expect("parses");

        assert_eq!(link.rtype(), RrType::TXT);
        assert_eq!(link.rrset().len(), 2);
        assert_eq!(link.signatures().len(), 1);
        assert_eq!(link.signatures()[0].algorithm(), Algorithm::ED25519);
    }

    #[test]
    fn missing_signatures_are_rejected() {
        assert!(matches!(
            Link::parse(&frame(&[txt_record(vec![1, b'x'])])),
            Err(ParseLinkError::NoSignatures)
        ));
    }

    #[test]
    fn signature_only_links_are_rejected() {
        assert!(matches!(
            Link::parse(&frame(&[rrsig_record(RrType::TXT, &owner())])),
            Err(ParseLinkError::NoData)
        ));
    }

    #[test]
    fn wrong_coverage_is_rejected() {
        assert!(matches!(
            Link::parse(&frame(&[
                txt_record(vec![1, b'x']),
                rrsig_record(RrType::DNSKEY, &owner()),
            ])),
            Err(ParseLinkError::SignatureCoversWrongType { .. })
        ));
    }

    #[test]
    fn mixed_rrsets_are_rejected() {
        let mut other = txt_record(vec![1, b'x']);
        other.rtype = RrType::CNAME;

        assert!(matches!(
            Link::parse(&frame(&[
                txt_record(vec![1, b'y']),
                other,
                rrsig_record(RrType::TXT, &owner()),
            ])),
            Err(ParseLinkError::MixedRrset)
        ));
    }
}
