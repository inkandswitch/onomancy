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
 * Present on every error this module throws about *evidence*, and
 * absent on argument errors — so `"reason" in error` separates a
 * verdict about evidence from a failure to form one.
 *
 * Grouped by the remedy, because that is the only distinction a UI
 * can act on:
 *
 * - `transport` alone is worth retrying.
 * - `no-binding` and `invalid-hostname` are stable facts; retrying
 *   cannot change them, and telling a user to check their connection
 *   over an unbound name or a typo is the wrong-remedy bug this
 *   union exists to prevent.
 * - The rest are security signals about evidence that did arrive.
 */
export type RefusalReason =
  // Live walk (`resolveHostname`)
  | "transport"
  | "no-binding"
  | "invalid-hostname"
  // Certificate verification
  | "generation-off-path"
  | "hostname-mismatch"
  | "no-certificate-held"
  | "decode"
  // Either
  | "chain-rejected";

/** An error carrying why the evidence was refused. */
export interface RefusalError extends Error {
  reason: RefusalReason;
}
