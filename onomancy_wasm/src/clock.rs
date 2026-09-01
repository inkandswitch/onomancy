//! The clock, as a value.
//!
//! Grading is the only place time enters verification, and the caller
//! may supply it so a captured chain grades deterministically: chain
//! validation is pure over bytes and anchors, so one frozen fixture
//! can be graded at any instant.
//!
//! This lives in one module because it was briefly wrong in two. The
//! host clock is milliseconds and the parameter is seconds, so only
//! one of them converts; scaling both sent every caller-supplied
//! value to 1970, where it graded `Deferred` against any real window.

use js_sys::Date;
use onomancy_core::time::UnixSeconds;

/// Epoch seconds beyond which a value is certainly not seconds.
///
/// Year 5138. A caller passing milliseconds lands near 1.8e12, three
/// orders above anything a real clock produces, so the two ranges do
/// not overlap for any reachable input.
const IMPLAUSIBLE_SECONDS: f64 = 100_000_000_000.0;

/// Resolve the grading clock, defaulting to the host.
///
/// `now_seconds` is seconds since the epoch, as named. [`Date::now`]
/// is milliseconds, so the default converts and the supplied value
/// does not — a supplied clock round-trips into `checkedAt`
/// unchanged, which is what makes it checkable by a caller.
///
/// # Errors
///
/// Rejects a value that is not finite, is negative, or is too large to
/// be seconds.
///
/// This is refused rather than clamped because the failure is
/// **silent and unsafe in one direction**. `Date.now()` is the
/// obvious thing to reach for and is milliseconds; taken as seconds it
/// lands in the far future, where every chain is long expired and
/// therefore *stale* — and a stale chain downgrades an off-path
/// generation from a refusal to `provisional`. So a units slip turns
/// a revocation into an acceptance. Clamping to a bound would grade
/// against a fabricated instant and hide the same slip.
pub fn resolve(now_seconds: Option<f64>) -> Result<UnixSeconds, ClockError> {
    let Some(supplied) = now_seconds else {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // host clock fits
        return Ok(UnixSeconds::from((Date::now() / 1000.0) as u64));
    };

    seconds(supplied, "nowSeconds")
}

/// Read one epoch-seconds argument, or say what is wrong with it.
///
/// Shared with [`resolve`] rather than repeated: the original units
/// bug existed because this conversion lived in two places and only
/// one was fixed. `field` names the argument so a caller with several
/// timestamps knows which one to look at.
///
/// # Errors
///
/// Rejects non-finite, negative, and millisecond-scale values.
pub fn seconds(value: f64, field: &'static str) -> Result<UnixSeconds, ClockError> {
    if !value.is_finite() || value < 0.0 {
        return Err(ClockError::NotSeconds { field });
    }

    if value >= IMPLAUSIBLE_SECONDS {
        return Err(ClockError::LooksLikeMilliseconds { field });
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // bounded above
    Ok(UnixSeconds::from(value as u64))
}

/// A timestamp argument that cannot be seconds since the epoch.
///
/// A domain error rather than a `JsError` so the rule is testable on
/// the host: `JsError` can only be constructed under wasm, and a
/// validator whose failure path runs nowhere is exactly the shape
/// this review was about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClockError {
    /// Not a finite, non-negative number.
    #[error("{field} must be a finite, non-negative number of seconds since the epoch")]
    NotSeconds {
        /// The argument at fault, named so a caller with several
        /// timestamps knows which one to look at.
        field: &'static str,
    },

    /// Millisecond-scale, almost certainly `Date.now()`.
    #[error(
        "{field} is too large to be seconds since the epoch — it looks like \
         milliseconds. Date.now() returns milliseconds; divide by 1000. Using \
         the wrong instant can turn a refusal into an acceptance, so this is \
         refused rather than guessed at."
    )]
    LooksLikeMilliseconds {
        /// The argument at fault.
        field: &'static str,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::expect_used)]
    fn seconds(value: f64) -> u64 {
        u64::from(resolve(Some(value)).expect("a plausible clock is accepted"))
    }

    /// The property the original bug violated: seconds in, same
    /// seconds out, with no scaling in either direction.
    #[test]
    fn a_supplied_clock_round_trips() {
        assert_eq!(seconds(1_788_100_000.0), 1_788_100_000);
    }

    /// Milliseconds are REFUSED, not accepted and not clamped.
    ///
    /// This is the security case. Taken as seconds, `Date.now()`
    /// lands in the far future where every chain is expired, and a
    /// stale chain downgrades an off-path generation from a refusal
    /// to `provisional` — so the units slip turned a revoked key into
    /// an accepted one. Observed before this guard existed.
    #[test]
    fn milliseconds_are_refused_rather_than_silently_accepted() {
        assert!(resolve(Some(1_788_100_000_000.0)).is_err());
    }

    /// The boundary, both sides, so the bound cannot drift untested.
    #[test]
    fn the_plausibility_bound_is_where_it_claims_to_be() {
        assert!(resolve(Some(IMPLAUSIBLE_SECONDS - 1.0)).is_ok());
        assert!(resolve(Some(IMPLAUSIBLE_SECONDS)).is_err());
    }

    /// A negative clock is a caller bug and says so, rather than
    /// becoming 1970 and grading everything `Deferred`.
    #[test]
    fn a_negative_clock_is_refused() {
        assert!(resolve(Some(-1.0)).is_err());
    }

    /// `f64` admits values no integer conversion can represent; the
    /// cast would otherwise saturate and grade against nonsense.
    #[test]
    fn non_finite_clocks_are_refused() {
        assert!(resolve(Some(f64::NAN)).is_err());
        assert!(resolve(Some(f64::INFINITY)).is_err());
        assert!(resolve(Some(f64::NEG_INFINITY)).is_err());
    }
}
