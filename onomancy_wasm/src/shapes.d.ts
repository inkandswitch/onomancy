/**
 * Which build of this module is loaded.
 *
 * `version` is the package version and does not identify an artifact:
 * two builds can share one. `revision` is the source commit the
 * module was built from (short hash; `-dirty` when the tree had
 * uncommitted changes; `unknown` when the builder supplied none).
 */
export interface BuildInfo {
  version: string;
  revision: string;
}

/** Epoch seconds, as returned by this module. */
export type UnixSeconds = number;

/** The window during which a chain was zone-rooted. */
export interface ValidityWindow {
  inception: UnixSeconds;
  expiration: UnixSeconds;
}

/**
 * How a chain's validity window stands against the clock it was
 * graded at.
 *
 * `deferred` is not a failure: the evidence is proven and its window
 * has not opened, which is usually a clock difference and never a
 * forgery. Compare `window.inception` against `checkedAt` to tell
 * those apart rather than taking the label's word for it.
 */
export type Freshness = "fresh" | "stale" | "deferred";

/**
 * The standing of the delegation-path check for the zone-attested
 * generation key.
 *
 * There is deliberately no `"off-path"` member. A fresh chain whose
 * generation key is off-path is a *refusal*, not a grade — it is how
 * revocation becomes visible — so it is thrown, carrying
 * `reason: "generation-off-path"`. Reached only with a stale chain,
 * the same condition is `"provisional"`: surfaced, and re-checked
 * when fresher evidence arrives.
 *
 * `null` exactly when `freshness` is `"deferred"`, because deferral
 * precedes this check and so the check was never made — which a
 * missing property could not distinguish from an omission.
 */
export type GenerationCheck = "on-path" | "provisional" | null;

/** The verdict on one certificate's binding. */
export interface Verdict {
  hostname: string;
  /** The bound document, as an `automerge:` anchor. */
  document: string;
  /** Serial as a decimal string: the space is u64, which `number` cannot hold. */
  serial: string;
  freshness: Freshness;
  generation: GenerationCheck;
  /** The inputs to the freshness decision, returned so it can be checked. */
  window: ValidityWindow;
  /** The clock reading used. Compare against your own to detect skew. */
  checkedAt: UnixSeconds;
}

/**
 * Sign exactly the bytes given, returning the 64-byte ed25519
 * signature over them.
 *
 * Certificate assembly takes a signer, never key material: the
 * module computes `signableBytes`, the signer signs them, and
 * `encodeCertificate` checks the signature covers that region
 * verbatim. So the signer MUST sign the bytes as given. A signer that
 * frames its input first — a length prefix, a domain tag, a
 * serialization envelope — produces a signature over different bytes,
 * and no adjustment on the caller's side can make it validate:
 * framing signers do not compose with this contract.
 *
 * The handle shape is what survives non-extractable `CryptoKey`s,
 * hardware tokens, and runtimes that hold keys on the caller's
 * behalf.
 */
export type SignBytes = (bytes: Uint8Array) => Promise<Uint8Array>;

/** A signing capability: the verifying key, and a way to sign with its counterpart. */
export interface Signing {
  /** The 32-byte ed25519 verifying key. Passed as `signer` to `signableBytes`. */
  verifyingKey: Uint8Array;
  sign: SignBytes;
}

/** The result of a live DNSSEC walk. */
export interface Resolution {
  hostname: string;
  /**
   * The validated chain, framed as a certificate embeds it.
   *
   * A certificate must carry its own chain, and this call is the only
   * thing that fetched one — so minting from a browser needs these
   * bytes. Pass straight to `encodeCertificate`.
   */
  chain: Uint8Array;
  /** Links in the validated chain, root KSK to leaf. */
  links: number;
  /** The proven TXT records, as published. */
  records: string[];
  freshness: Freshness;
  window: ValidityWindow;
  checkedAt: UnixSeconds;
}

/** A binding as the zone states it, at the top serial of an `RRset`. */
export interface RecordCandidate {
  /** The bound document, as an `automerge:` anchor. */
  document: string;
  /** The attested generation key (`g=`), canonical base64. */
  generation: string;
  /** Serial as a decimal string: the space is u64, which `number` cannot hold. */
  serial: string;
}

/**
 * The result of `classifyRecords`: the `RRset` rules over one zone's
 * TXT strings at one instant.
 *
 * Every input lands in exactly one place: `selected` or `contested`,
 * or one of the four counts. `selected` and `contested` are mutually
 * exclusive; both are absent when no binding was considered.
 *
 * Contest is keyed on `(document, generation)`, not on the document
 * alone: two records for one document attesting different `g=` at one
 * serial disagree about which key is current, and are reported as a
 * contest rather than collapsed into a selection. A zone mid-rotation
 * can therefore read contested here where a document-keyed rule read
 * verified. This matches the verifier.
 *
 * This is the one-shot rule over one `RRset`. It is not the ratchet,
 * not generation lineage, and not the decisions logic — all of which
 * remember. A caller persisting state must not read `selected` as
 * "the binding"; it is the zone's current word, before any of that.
 */
export interface RecordClassification {
  /** The zone's word: the unique claim at the top serial. */
  selected?: RecordCandidate;
  /** Distinct claims tied at the top serial: equivocation, none picked. */
  contested?: RecordCandidate[];
  /** Bindings set aside: serial more than five minutes ahead of the clock. */
  deferred: number;
  /** Records that are not `v=ONO` at all (SPF, DKIM, anything else). */
  foreign: number;
  /** `v=ONO` records with a tag this software does not implement — a newer protocol version. */
  unknownVersion: number;
  /** `v=ONO0` records that failed the strict grammar. */
  malformed: number;
}

/** How far a resolution walk got. */
export type WalkStatus = "resolved" | "partial";

/**
 * Why a walk stopped short. A partial walk is the designed norm
 * under partition, not an error:
 *
 * - `"dangling segment"` — a segment named no edge in the document
 *   it reached. Retrying cannot help; the name goes nowhere from
 *   here.
 * - `"unsynced target"` — the next hop's document is not held.
 *   `target` names it: hold a replica (`holdAt`) and retry.
 */
export type PartialWalkReason = "dangling segment" | "unsynced target";

/**
 * The outcome of `HeldDocuments.resolve`.
 *
 * `anchorAuthority: "zone-only"` appears on resolved walks whose root
 * came from a live DNS anchor: the DNSSEC walk proves what the zone
 * published — one direction — and this walk roots on it without the
 * certificate direction (`verifyBinding` is that check). A caller
 * reading `status: "resolved"` must be able to see that the anchor
 * itself is unauthenticated.
 */
export type WalkOutcome =
  | {
      status: "resolved";
      /** The terminal document, as an `automerge:` anchor. */
      document: string;
      /** The weakest authority grade along the realized path. */
      authority: string;
      /** What the grade does NOT establish, in prose. */
      warning: string;
      anchorAuthority?: "zone-only";
    }
  | {
      status: "partial";
      /** Segments consumed before the walk stopped. */
      consumed: number;
      /** Segments in the name. */
      total: number;
      reason: PartialWalkReason;
      /** The unheld document, when the reason is an unsynced target. */
      target?: string;
    };

/**
 * Why an operation was refused.
 *
 * Present on every error that is a **statement about the operation**,
 * and absent only on **type errors** — an argument of the wrong
 * JavaScript type, which is a caller bug rather than a finding.
 *
 * So `"reason" in error` separates "this is what happened" from "you
 * passed the wrong kind of thing". The line is drawn at TYPE errors,
 * not argument errors: `invalid-hostname` is an argument error and
 * carries a reason, because a caller can act on it and a user can
 * see it.
 *
 * Grouped by the remedy, because that is the only distinction a UI
 * can act on — and the grouping below is the grouping, not a
 * commentary on one.
 *
 * Several of these are deliberately kept apart rather than merged,
 * because each distinction sends a caller somewhere different:
 *
 * - `malformed` vs `invalid-signature` — the bytes were never a
 *   certificate (a wiring bug), versus they are one and someone
 *   altered it.
 * - `chain-rejected` vs `signer-not-authorized` vs
 *   `document-not-attested` — the zone's DNSSEC failed; versus the
 *   zone is fine and the signing key is not delegated by that
 *   document; versus both are fine and the zone names a *different*
 *   document. Only the first is a reason to go and look at DNS.
 * - `broken-indirection` vs `malformed` — the document's certificate
 *   ENTRY does not lead to a list (a second hop, or a value that is
 *   neither list nor reference), versus certificate BYTES that were
 *   never a certificate. The first is grouped with the stable facts:
 *   nothing was forged, no certificate needs re-minting, and the fix
 *   is to the entry — repoint it or restore the list.
 */
export type RefusalReason =
  // Retrying may help. This one only.
  | "transport"
  // Stable facts. Retrying cannot change them, and absence of
  // evidence is never evidence against a binding.
  | "no-binding"
  | "no-certificate-held"
  | "broken-indirection"
  // The caller can see and fix these.
  | "invalid-hostname"
  | "invalid-resolver-url"
  | "invalid-timestamp"
  | "invalid-argument"
  | "malformed"
  // Security signals: evidence arrived and failed.
  | "invalid-signature"
  | "hostname-mismatch"
  | "chain-rejected"
  | "signer-not-authorized"
  | "document-not-attested"
  | "generation-off-path";

/** An error carrying why the evidence was refused. */
export interface RefusalError extends Error {
  reason: RefusalReason;
}
