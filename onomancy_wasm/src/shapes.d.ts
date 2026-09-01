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

/**
 * Why an operation was refused.
 *
 * Present on every error that is a **statement about the operation**,
 * and absent only on **type errors** — an argument of the wrong
 * JavaScript type, which is a caller bug rather than a finding.
 *
 * So `"reason" in error` separates "this is what happened" from "you
 * passed the wrong kind of thing". An earlier version of this comment
 * drew the line at argument errors instead, which was wrong:
 * `invalid-hostname` is an argument error and carries a reason,
 * because a caller can act on it and a user can see it.
 *
 * Grouped by the remedy, because that is the only distinction a UI
 * can act on — and the grouping below is the grouping, not a
 * commentary on one.
 *
 * Note `malformed` and `invalid-signature` are deliberately separate.
 * The first means the bytes were never a certificate, which is a
 * wiring bug; the second means they are one and someone altered it.
 * Reporting a mistyped buffer as a possible forgery, or a forgery as
 * a typo, are the two halves of the same mistake.
 */
export type RefusalReason =
  // Retrying may help. This one only.
  | "transport"
  // Stable facts. Retrying cannot change them, and absence of
  // evidence is never evidence against a binding.
  | "no-binding"
  | "no-certificate-held"
  // The caller can see and fix these.
  | "invalid-hostname"
  | "malformed"
  // Security signals: evidence arrived and failed.
  | "invalid-signature"
  | "hostname-mismatch"
  | "chain-rejected"
  | "generation-off-path";

/** An error carrying why the evidence was refused. */
export interface RefusalError extends Error {
  reason: RefusalReason;
}
