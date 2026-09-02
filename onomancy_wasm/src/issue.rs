//! Minting a certificate without holding a key.
//!
//! A Keyhive document's root signing key is destroyed at creation
//! (`EphemeralSigner`), so the only key able to sign a certificate for
//! such a document is an admin key held by whatever runtime owns it —
//! in a browser, that is Keyhive's own. Handing that key across this
//! boundary to save a round trip would trade the property worth having
//! for a convenience.
//!
//! So issuance is two calls with the signing in between, and the
//! signer is a capability (the published `Signing` shape), never key
//! material:
//!
//! ```js
//! const signing = { verifyingKey, sign }; // a `Signing`
//! const fields = [rootDoc, signing.verifyingKey, issuedAt, hostname];
//! const signature = await signing.sign(signableBytes(...fields));
//! const bytes = encodeCertificate(...fields, signature, carriage, chain);
//! ```
//!
//! The signer MUST sign the bytes verbatim. `encodeCertificate`
//! checks that the signature covers the signable region itself, so a
//! signer that frames its input (a length prefix, a domain tag, an
//! envelope) yields a signature over other bytes, and nothing the
//! caller prepends or appends can make it validate — framing signers
//! do not compose with this contract.
//!
//! This module never sees a signing key, which makes it a serializer
//! rather than a trusted party — the same posture `verifyCertificate`
//! has by taking bytes rather than a document set.
//!
//! Carriage entries are `bincode(StaticEvent)` blobs, the wire form
//! Keyhive already produces. Taking the wire form rather than a shape
//! mirroring any one extraction keeps this agnostic to who assembled
//! it: a hand-filtered bundle today, a scoped export later.

use js_sys::Uint8Array;
use onomancy_core::{anchor::doc::DocAnchor, delegation_chain::DelegationChain};
use onomancy_dnssec::{
    certificate::{Certificate, CertificateParams},
    chain::DnssecChain,
    dns_name::DnsName,
};
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};

use crate::{
    clock, refusal,
    text::{self, Text},
};

/// The bytes a signature must cover for this certificate.
///
/// Hand the result to whatever holds the admin key, then pass the
/// signature to `encodeCertificate` with the *same* fields. The two
/// calls must agree: a signature covers the bytes it was given, so
/// changing a field in between produces a certificate that verifies
/// nowhere.
///
/// `signer` is the verifying key that will sign — supplied rather than
/// derived, because there is no signing key here to derive it from.
///
/// # Errors
///
/// Rejects for a malformed hostname, anchor, or signer key.
#[wasm_bindgen(js_name = signableBytes)]
pub fn signable_bytes(
    root_doc: &Text,
    signer: &[u8],
    issued_at: f64,
    hostname: &Text,
) -> Result<Uint8Array, JsValue> {
    let (params, signer) = parts(root_doc, signer, issued_at, hostname)?;

    Ok(Uint8Array::from(
        Certificate::signable_bytes(&params, signer).as_slice(),
    ))
}

/// Assemble a certificate from fields, an outside signature, a
/// carriage, and a DNSSEC chain.
///
/// The fields must be **byte-identical** to those passed to
/// `signableBytes`, since the signature covers them.
///
/// `carriage` is a list of `bincode(StaticEvent)` blobs. `chain` is a
/// framed `DnssecChain` — `resolveHostname` returns one ready to pass
/// straight through.
///
/// Neither the carriage nor the chain is validated here. They are
/// unsigned evidence and the verifier judges them; a second judge at
/// assembly could only disagree with the first, and refusing at birth
/// for a reason the verifier would have accepted is worse than failing
/// where the judging happens.
///
/// # Errors
///
/// Rejects for malformed inputs, a signature that does not cover the
/// signed region under `signer`, and an assembled unit over the cap.
#[wasm_bindgen(js_name = encodeCertificate)]
// `Vec<Uint8Array>` rather than a slice: wasm-bindgen's ABI has no
// `RefFromWasmAbi` for `[Uint8Array]`, and the owned form is what
// publishes as `Uint8Array[]` in the `.d.ts`.
#[allow(clippy::needless_pass_by_value)]
pub fn encode_certificate(
    root_doc: &Text,
    signer: &[u8],
    issued_at: f64,
    hostname: &Text,
    signature: &[u8],
    carriage: Vec<Uint8Array>,
    chain: &[u8],
) -> Result<Uint8Array, JsValue> {
    let (mut params, signer) = parts(root_doc, signer, issued_at, hostname)?;

    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| IssueError::SignatureLength)
        .map_err(JsValue::from)?;

    params.delegation_chain = DelegationChain::from(
        carriage
            .iter()
            .map(|entry| entry.to_vec().into())
            .collect::<Vec<_>>(),
    );

    params.chain =
        DnssecChain::read_framed(chain).map_err(|error| JsValue::from(IssueError::Chain(error)))?;

    let certificate = Certificate::from_parts(params, signer, signature.into())
        .map_err(|error| JsValue::from(IssueError::Assemble(error)))?;

    Ok(Uint8Array::from(certificate.encode().as_slice()))
}

/// Why issuance refused its inputs.
///
/// A type so the reason code lives with the error's definition rather
/// than at every call site, and so `?` carries both the message and
/// the code across the JS boundary through the `From` impl below.
#[derive(Debug, thiserror::Error)]
enum IssueError {
    /// The document anchor did not parse.
    #[error("rootDoc: {0}")]
    Anchor(onomancy_core::anchor::doc::ParseDocAnchorError),

    /// The signer key is not 32 bytes.
    #[error("a signer key must be 32 bytes")]
    SignerKeyLength,

    /// The signer bytes are not a curve point.
    #[error("signer: not a valid ed25519 verifying key")]
    SignerKeyNotACurvePoint,

    /// The hostname is not a DNS name.
    #[error(transparent)]
    Hostname(onomancy_dnssec::dns_name::ParseDnsNameError),

    /// The timestamp cannot be epoch seconds.
    #[error(transparent)]
    Timestamp(#[from] crate::clock::ClockError),

    /// The signature is not 64 bytes.
    #[error("a signature must be 64 bytes")]
    SignatureLength,

    /// The chain bytes did not frame.
    #[error("chain: {0}")]
    Chain(onomancy_core::wire::WireError),

    /// Assembly refused: the signature does not cover the fields, or
    /// the unit is over the cap.
    #[error(transparent)]
    Assemble(#[from] onomancy_dnssec::certificate::AssembleError),
}

impl IssueError {
    /// The published code for this refusal.
    ///
    /// End-user-visible inputs (a hostname someone typed, a clock)
    /// keep their specific codes; developer wiring gets the one
    /// generic `invalid-argument`, with the message naming which
    /// argument — codes exist for remedies, and "fix the argument the
    /// message names" is one remedy, not five.
    const fn reason(&self) -> refusal::RefusalReason {
        use onomancy_dnssec::certificate::AssembleError;

        match self {
            Self::Hostname(_) => refusal::RefusalReason::InvalidHostname,
            Self::Timestamp(_) => refusal::RefusalReason::InvalidTimestamp,

            // The signature is well-formed and does not verify over
            // these fields: either the wrong bytes were signed or the
            // wrong key signed them, and both read as
            // `invalid-signature`.
            Self::Assemble(AssembleError::InvalidSignature) => {
                refusal::RefusalReason::InvalidSignature
            }

            Self::Anchor(_)
            | Self::SignerKeyLength
            | Self::SignerKeyNotACurvePoint
            | Self::SignatureLength
            | Self::Chain(_)
            | Self::Assemble(AssembleError::Oversize(_)) => refusal::RefusalReason::InvalidArgument,
        }
    }
}

impl From<IssueError> for JsValue {
    fn from(error: IssueError) -> Self {
        refusal::error(&error.to_string(), error.reason())
    }
}

/// The shared field parsing, so the two calls cannot disagree about
/// what they were given.
fn parts(
    root_doc: &Text,
    signer: &[u8],
    issued_at: f64,
    hostname: &Text,
) -> Result<(CertificateParams, ed25519_dalek::VerifyingKey), JsValue> {
    // Type errors stay reasonless — `"reason" in error` separates a
    // statement about the operation from "you passed the wrong kind
    // of thing" — so `text::read` bypasses `IssueError`.
    let root_doc = text::read(root_doc, "a document anchor").map_err(JsValue::from)?;
    let root_doc = DocAnchor::parse(
        root_doc
            .strip_prefix(onomancy_core::anchor::doc::SCHEME_PREFIX)
            .unwrap_or(&root_doc),
    )
    .map_err(|error| JsValue::from(IssueError::Anchor(error)))?;

    let signer: [u8; 32] = signer
        .try_into()
        .map_err(|_| IssueError::SignerKeyLength)
        .map_err(JsValue::from)?;

    let signer = ed25519_dalek::VerifyingKey::from_bytes(&signer)
        .map_err(|_| IssueError::SignerKeyNotACurvePoint)
        .map_err(JsValue::from)?;

    let hostname = text::read(hostname, "a hostname").map_err(JsValue::from)?;
    let hostname = DnsName::parse_display(&hostname)
        .map_err(|error| JsValue::from(IssueError::Hostname(error)))?;

    // Validated, not clamped: `Date.now()` here would date the
    // certificate in year 58000, and `NaN` would date it 1970. Both
    // silently, on the one field a verifier cannot cross-check.
    let issued_at = clock::seconds(issued_at, "issuedAt")
        .map_err(|error| JsValue::from(IssueError::Timestamp(error)))?;

    Ok((
        CertificateParams {
            root_doc,
            issued_at,
            hostname,
            heads: Vec::new(),
            predecessor: None,
            delegation_chain: DelegationChain::default(),
            lineage: Vec::new(),
            chain: DnssecChain::default(),
        },
        signer,
    ))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    /// The signing contract this module documents is declared to
    /// TypeScript under the names the docs use, so a consumer can
    /// import the type rather than reconstruct it from prose.
    #[test]
    fn the_signing_contract_is_declared() {
        for declaration in [
            "export type SignBytes = (bytes: Uint8Array) => Promise<Uint8Array>;",
            "export interface Signing {",
        ] {
            assert!(
                crate::shapes::TYPES.contains(declaration),
                "`{declaration}` is missing from shapes.d.ts"
            );
        }
    }
}
