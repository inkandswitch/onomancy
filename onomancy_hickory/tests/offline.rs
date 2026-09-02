//! Offline transport tests: scripted local sockets, no network.
//!
//! The courier's contracts — failover order, whose error surfaces,
//! TCP fallback on truncation, ID-mismatch rejection, timeout mapping,
//! and resolv.conf parsing — are all observable against loopback
//! responders that misbehave on cue. The live test (`live.rs`) stays
//! the happy-path smoke; nothing here touches a real resolver.

#![allow(clippy::expect_used, clippy::panic)]

use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use onomancy_chain::{builder::ChainBuilder, question::Question};
use onomancy_dnssec::dns_name::DnsName;
use onomancy_hickory::{
    provider::{FALLBACK_UPSTREAM, FetchChainError, HickoryProvider, resolv_conf},
    stub::{QueryError, StubResolver},
};
use testresult::TestResult;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, UdpSocket},
};

/// How a scripted upstream answers.
#[derive(Debug, Clone, Copy)]
enum Script {
    /// Bytes that are not a DNS message.
    Garbage,
    /// A well-formed refusal.
    ServFail,
    /// A well-formed answer under the wrong ID.
    WrongId,
    /// A truncated answer (inviting the TCP retry).
    Truncated,
    /// A clean empty `NoError` answer.
    Empty,
}

/// The wire response a script produces for one request.
fn respond(script: Script, wire: &[u8]) -> Vec<u8> {
    if matches!(script, Script::Garbage) {
        return vec![0xFF; 8];
    }

    let request = Message::from_vec(wire).expect("requests are well-formed");
    let id = match script {
        Script::WrongId => request.metadata.id.wrapping_add(1),
        Script::Garbage | Script::ServFail | Script::Truncated | Script::Empty => {
            request.metadata.id
        }
    };

    let mut response = Message::new(id, MessageType::Response, OpCode::Query);
    response.metadata.response_code = match script {
        Script::ServFail => ResponseCode::ServFail,
        Script::Garbage | Script::WrongId | Script::Truncated | Script::Empty => {
            ResponseCode::NoError
        }
    };
    response.metadata.truncation = matches!(script, Script::Truncated);

    response.to_vec().expect("responses encode")
}

/// A loopback UDP upstream running `script`, logging each hit as
/// `tag` into the shared sequence.
async fn udp_upstream(
    script: Script,
    tag: char,
    log: Arc<Mutex<Vec<char>>>,
) -> TestResult<SocketAddr> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let addr = socket.local_addr()?;

    tokio::spawn(async move {
        let mut buffer = [0u8; 4096];
        while let Ok((received, peer)) = socket.recv_from(&mut buffer).await {
            log.lock().expect("uncontended").push(tag);
            let Some(datagram) = buffer.get(..received) else {
                break; // recv_from never overruns its buffer
            };
            let reply = respond(script, datagram);
            socket.send_to(&reply, peer).await.ok();
        }
    });

    Ok(addr)
}

/// The chain builder's first question (the root DNSKEY), which is all
/// a transport test needs: every scripted failure fires on query one.
fn first_question() -> Question {
    let hostname = DnsName::parse("example.com").expect("valid hostname");
    let (_, question) = ChainBuilder::start(&hostname).expect("representable name");
    question
}

/// Upstreams are tried strictly in order, and the LAST upstream's
/// error is what surfaces — the documented `fetch_chain` contract.
#[tokio::test(flavor = "current_thread")]
async fn failover_tries_upstreams_in_order_and_returns_the_last_error() -> TestResult {
    let log = Arc::new(Mutex::new(Vec::new()));
    let first = udp_upstream(Script::Garbage, 'a', Arc::clone(&log)).await?;
    let second = udp_upstream(Script::ServFail, 'b', Arc::clone(&log)).await?;

    let provider = HickoryProvider::new(first).or(second);
    let hostname = DnsName::parse("example.com")?;

    let outcome = provider.fetch_chain(&hostname).await;

    // The SECOND upstream's failure class, not the first's: garbage
    // is `Malformed`, a refusal is `Refused`, and last-error-wins is
    // only provable because they differ.
    match outcome {
        Err(FetchChainError::Transport(QueryError::Refused(refused))) => {
            assert_eq!(refused.code, ResponseCode::ServFail);
        }
        other => panic!("expected the last upstream's refusal, got {other:?}"),
    }

    assert_eq!(
        *log.lock().expect("uncontended"),
        vec!['a', 'b'],
        "one query each, first upstream first"
    );
    Ok(())
}

/// A single-upstream provider surfaces that upstream's error
/// unchanged — no fallback is invented.
#[tokio::test(flavor = "current_thread")]
async fn a_lone_upstreams_error_passes_through() -> TestResult {
    let log = Arc::new(Mutex::new(Vec::new()));
    let only = udp_upstream(Script::ServFail, 'x', Arc::clone(&log)).await?;

    let provider = HickoryProvider::new(only);
    let hostname = DnsName::parse("example.com")?;

    assert!(matches!(
        provider.fetch_chain(&hostname).await,
        Err(FetchChainError::Transport(QueryError::Refused(_)))
    ));
    assert_eq!(*log.lock().expect("uncontended"), vec!['x']);
    Ok(())
}

/// `system()`'s composition, testable without a filesystem:
/// discovered upstreams keep their order, the fallback rides last,
/// and an empty discovery uses the fallback alone.
#[test]
fn the_fallback_upstream_rides_last_or_alone() {
    let a: SocketAddr = "192.0.2.1:53".parse().expect("addr");
    let b: SocketAddr = "192.0.2.2:53".parse().expect("addr");

    assert_eq!(
        HickoryProvider::with_fallback(vec![a, b]).upstreams(),
        vec![a, b, FALLBACK_UPSTREAM]
    );
    assert_eq!(
        HickoryProvider::with_fallback(Vec::new()).upstreams(),
        vec![FALLBACK_UPSTREAM]
    );
}

/// `or()` appends after the existing upstreams.
#[test]
fn or_appends_upstreams_in_call_order() {
    let a: SocketAddr = "192.0.2.1:53".parse().expect("addr");
    let b: SocketAddr = "192.0.2.2:53".parse().expect("addr");
    let c: SocketAddr = "192.0.2.3:53".parse().expect("addr");

    assert_eq!(
        HickoryProvider::new(a).or(b).or(c).upstreams(),
        vec![a, b, c]
    );
}

/// resolv.conf parsing: `nameserver` entries in file order, junk and
/// unparsable entries skipped, never an error.
#[test]
fn resolv_conf_keeps_parsable_nameservers_in_file_order() {
    let text = "\
# a comment
search example.com
nameserver 192.0.2.1
nameserver\t2001:db8::1
options edns0
nameserver 192.0.2.2
";

    assert_eq!(
        resolv_conf(text),
        vec![
            "192.0.2.1:53".parse::<SocketAddr>().expect("addr"),
            "[2001:db8::1]:53".parse::<SocketAddr>().expect("addr"),
            "192.0.2.2:53".parse::<SocketAddr>().expect("addr"),
        ]
    );
}

/// The whitespace guard: `nameserverX` is not a `nameserver` entry,
/// and prefix-matching without it would invent an upstream from a
/// typo.
#[test]
fn resolv_conf_requires_whitespace_after_the_keyword() {
    assert_eq!(resolv_conf("nameserver192.0.2.1"), Vec::new());
    assert_eq!(resolv_conf("nameserverX 192.0.2.1"), Vec::new());
}

/// Scoped IPv6 (`fe80::1%eth0`) does not parse as a bare `IpAddr`;
/// discovery degrades by skipping it rather than erroring.
#[test]
fn resolv_conf_skips_scoped_ipv6_and_garbage() {
    let text = "\
nameserver fe80::1%eth0
nameserver not-an-address
nameserver 192.0.2.9
";

    assert_eq!(
        resolv_conf(text),
        vec!["192.0.2.9:53".parse::<SocketAddr>().expect("addr")]
    );
}

/// Truncation over UDP retries the same query over TCP and takes the
/// TCP answer — asserted by counting the TCP hit and getting the
/// clean empty answer only TCP serves.
#[tokio::test(flavor = "current_thread")]
async fn truncated_udp_answers_fall_back_to_tcp() -> TestResult {
    // Same port, both transports: bind TCP first (its port space is
    // separate from UDP's, so the pairing needs a retry loop).
    let (udp, tcp) = loop {
        let tcp = TcpListener::bind("127.0.0.1:0").await?;
        let port = tcp.local_addr()?.port();
        if let Ok(udp) = UdpSocket::bind(("127.0.0.1", port)).await {
            break (udp, tcp);
        }
    };
    let addr = udp.local_addr()?;

    // UDP: always truncated.
    tokio::spawn(async move {
        let mut buffer = [0u8; 4096];
        while let Ok((received, peer)) = udp.recv_from(&mut buffer).await {
            let Some(datagram) = buffer.get(..received) else {
                break; // recv_from never overruns its buffer
            };
            let reply = respond(Script::Truncated, datagram);
            udp.send_to(&reply, peer).await.ok();
        }
    });

    // TCP: the real (empty NoError) answer, length-prefixed.
    let tcp_hits = Arc::new(AtomicUsize::new(0));
    let hits = Arc::clone(&tcp_hits);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = tcp.accept().await {
            hits.fetch_add(1, Ordering::SeqCst);

            let mut length = [0u8; 2];
            if stream.read_exact(&mut length).await.is_err() {
                continue;
            }
            let mut wire = vec![0u8; usize::from(u16::from_be_bytes(length))];
            if stream.read_exact(&mut wire).await.is_err() {
                continue;
            }

            let reply = respond(Script::Empty, &wire);
            #[allow(clippy::cast_possible_truncation)] // responses are tiny
            let prefix = (reply.len() as u16).to_be_bytes();
            stream.write_all(&prefix).await.ok();
            stream.write_all(&reply).await.ok();
        }
    });

    let answers = StubResolver::new(addr).query(&first_question()).await?;

    assert!(answers.is_empty(), "the TCP answer is the empty NoError");
    assert_eq!(tcp_hits.load(Ordering::SeqCst), 1, "TCP was consulted");
    Ok(())
}

/// A response under the wrong ID is rejected, not accepted — weak IDs
/// are deliberate, but a mismatched one is still not this query's
/// answer.
#[tokio::test(flavor = "current_thread")]
async fn mismatched_response_ids_are_rejected() -> TestResult {
    let log = Arc::new(Mutex::new(Vec::new()));
    let addr = udp_upstream(Script::WrongId, 'w', log).await?;

    assert!(matches!(
        StubResolver::new(addr).query(&first_question()).await,
        Err(QueryError::IdMismatch)
    ));
    Ok(())
}

/// A silent upstream maps to `Timeout`, not a hang and not an `Io`
/// surprise.
#[tokio::test(flavor = "current_thread")]
async fn a_silent_upstream_times_out() -> TestResult {
    // Bound and never read: the query is sent and nothing returns.
    let silent = UdpSocket::bind("127.0.0.1:0").await?;
    let addr = silent.local_addr()?;

    let stub = StubResolver::new(addr).with_timeout(Duration::from_millis(100));

    assert!(matches!(
        stub.query(&first_question()).await,
        Err(QueryError::Timeout)
    ));
    drop(silent);
    Ok(())
}
