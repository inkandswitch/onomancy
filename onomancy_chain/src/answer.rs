//! Accepting a DNS response: the answer section, or a refusal.

use hickory_proto::{
    op::{Message, ResponseCode},
    rr::Record,
};

/// The answer section of an accepted response: `NoError` and
/// `NXDomain` both count (empty answers are meaningful), anything
/// else is a refusal.
///
/// # Errors
///
/// Returns [`Refused`] for every other response code.
pub fn accepted(message: Message) -> Result<Vec<Record>, Refused> {
    #[allow(clippy::wildcard_enum_match_arm)] // every other rcode is a refusal
    match message.metadata.response_code {
        ResponseCode::NoError | ResponseCode::NXDomain => Ok(message.answers),
        code => Err(Refused { code }),
    }
}

/// The upstream refused the query (SERVFAIL, REFUSED, …).
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("upstream returned {code}")]
pub struct Refused {
    /// The response code.
    pub code: ResponseCode,
}
