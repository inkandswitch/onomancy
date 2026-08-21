//! A minimal stub resolver: one recursive upstream, UDP with TCP
//! fallback on truncation, `RD` + `CD` + EDNS `DO`.
//!
//! Deliberately no transport-level security: query IDs are weak, and
//! an off-path spoofer or lying resolver is IN the threat model — the
//! verifier's own DNSSEC validation is the trust boundary, so the
//! worst a forged response achieves is a chain that fails to
//! validate. `CD` is set because the verifier wants the bytes even
//! when the upstream's validator calls them bogus: judging is not the
//! resolver's job here.

use std::{net::SocketAddr, time::Duration};

use hickory_proto::{
    op::Message,
    rr::{Name, Record, RecordType},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};

use crate::chain_assembly::{self, Query, Refused};

/// UDP receive buffer: generous for signed `RRsets` under the payload cap.
const UDP_BUFFER: usize = 4096;

/// One recursive upstream, queried with the DNSSEC-OK bit.
#[derive(Debug, Clone, Copy)]
pub struct StubResolver {
    server: SocketAddr,
    timeout: Duration,
}

impl StubResolver {
    /// A stub against `server` (a recursive resolver, port included)
    /// with a 5-second per-query timeout.
    #[must_use]
    pub const fn new(server: SocketAddr) -> Self {
        Self {
            server,
            timeout: Duration::from_secs(5),
        }
    }

    /// Adjust the per-query timeout, builder-style.
    #[must_use]
    pub const fn with_timeout(self, timeout: Duration) -> Self {
        Self { timeout, ..self }
    }

    /// Query `name`/`rtype`, returning the answer-section records.
    ///
    /// `NXDOMAIN` and empty answers return `Ok(vec![])` — what they
    /// mean is the assembler's business (a suffix that is not a zone
    /// cut probes exactly like this).
    ///
    /// # Errors
    ///
    /// Returns [`QueryError`] for transport failures, timeouts,
    /// malformed responses, and non-`NoError`/`NXDomain` rcodes.
    pub async fn query(&self, name: &Name, rtype: RecordType) -> Result<Vec<Record>, QueryError> {
        let request = chain_assembly::build_query(name, rtype, weak_id());
        let id = request.metadata.id;
        let wire = request.to_vec().map_err(|_| QueryError::Encode)?;

        let response = match self.exchange_udp(&wire, id).await? {
            UdpOutcome::Complete(message) => message,
            UdpOutcome::Truncated => self.exchange_tcp(&wire, id).await?,
        };

        Ok(chain_assembly::accepted_answers(response)?)
    }

    async fn exchange_udp(&self, wire: &[u8], id: u16) -> Result<UdpOutcome, QueryError> {
        let socket = UdpSocket::bind(unspecified_for(self.server)).await?;
        socket.connect(self.server).await?;
        socket.send(wire).await?;

        let mut buffer = vec![0u8; UDP_BUFFER];
        let received = tokio::time::timeout(self.timeout, socket.recv(&mut buffer))
            .await
            .map_err(|_| QueryError::Timeout)??;

        let message = Message::from_vec(buffer.get(..received).unwrap_or_default())
            .map_err(|_| QueryError::MalformedResponse)?;

        if message.metadata.id != id {
            return Err(QueryError::IdMismatch);
        }

        if message.metadata.truncation {
            return Ok(UdpOutcome::Truncated);
        }

        Ok(UdpOutcome::Complete(message))
    }

    async fn exchange_tcp(&self, wire: &[u8], id: u16) -> Result<Message, QueryError> {
        let exchange = async {
            let mut stream = TcpStream::connect(self.server).await?;

            let length = u16::try_from(wire.len()).map_err(|_| QueryError::Encode)?;
            stream.write_all(&length.to_be_bytes()).await?;
            stream.write_all(wire).await?;

            let mut length = [0u8; 2];
            stream.read_exact(&mut length).await?;
            let mut buffer = vec![0u8; usize::from(u16::from_be_bytes(length))];
            stream.read_exact(&mut buffer).await?;

            Message::from_vec(&buffer).map_err(|_| QueryError::MalformedResponse)
        };

        let message = tokio::time::timeout(self.timeout, exchange)
            .await
            .map_err(|_| QueryError::Timeout)??;

        if message.metadata.id != id {
            return Err(QueryError::IdMismatch);
        }

        Ok(message)
    }
}

impl Query for StubResolver {
    type Error = QueryError;

    async fn answers(&self, name: &Name, rtype: RecordType) -> Result<Vec<Record>, QueryError> {
        self.query(name, rtype).await
    }
}

/// A weak query ID: fine here because transport is untrusted anyway —
/// DNSSEC validation downstream is the only trust boundary.
fn weak_id() -> u16 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.subsec_nanos())
        .unwrap_or(0);

    #[allow(clippy::cast_possible_truncation)] // deliberate folding
    let folded = (nanos ^ (nanos >> 16) ^ std::process::id()) as u16;
    folded
}

/// The local bind address family matching the upstream.
fn unspecified_for(server: SocketAddr) -> SocketAddr {
    match server {
        SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        SocketAddr::V6(_) => SocketAddr::from(([0u16; 8], 0)),
    }
}

enum UdpOutcome {
    Complete(Message),
    Truncated,
}

/// A query failed at the transport level — never a validity verdict.
#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    /// The request could not be encoded (oversized name, internal).
    #[error("query could not be encoded")]
    Encode,

    /// The response ID did not match the query.
    #[error("response ID mismatch")]
    IdMismatch,

    /// Socket-level failure.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// The response bytes did not parse as a DNS message.
    #[error("malformed DNS response")]
    MalformedResponse,

    /// The upstream refused the query (SERVFAIL, REFUSED, …).
    #[error(transparent)]
    Refused(#[from] Refused),

    /// No response within the configured timeout.
    #[error("query timed out")]
    Timeout,
}
