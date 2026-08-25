//! One DNS question — what the assembler asks and a driver answers.

use hickory_proto::{
    op::{Edns, Message, MessageType, OpCode, Query as DnsQuery},
    rr::{Name, RecordType},
};

/// EDNS advertised payload size (the DNS-flag-day value).
pub const EDNS_PAYLOAD: u16 = 1232;

/// One DNS question to a recursive resolver.
///
/// Drivers answer with the answer-section records of `NoError` and
/// `NXDomain` responses (empty is meaningful: a suffix that is not a
/// zone cut probes exactly like this) and keep transport failure on
/// their own side of the seam.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// The owner name to query.
    pub name: Name,

    /// The record type sought.
    pub rtype: RecordType,
}

impl Question {
    /// A recursion-desired, checking-disabled, DNSSEC-OK query
    /// message for this question.
    ///
    /// `CD` is set because judging is not the upstream's job: the
    /// verifier wants the bytes even when the resolver's own
    /// validator calls them bogus. Pass `id: 0` for `DoH` (RFC
    /// 9250/8484 cache friendliness); socket transports use a
    /// per-query ID.
    #[must_use]
    pub fn message(&self, id: u16) -> Message {
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true);
        edns.set_max_payload(EDNS_PAYLOAD);
        edns.set_version(0);

        // `Message::new` rather than `Message::query()`: the latter is
        // std-gated (it mints a random ID), and the ID is ours to choose.
        let mut message = Message::new(id, MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = true;
        message.metadata.checking_disabled = true;
        message
            .add_query(DnsQuery::query(self.name.clone(), self.rtype))
            .set_edns(edns);
        message
    }
}
