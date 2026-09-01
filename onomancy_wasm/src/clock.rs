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

/// Resolve the grading clock, defaulting to the host.
///
/// `now_seconds` is seconds since the epoch, as named. [`Date::now`]
/// is milliseconds, so the default converts and the supplied value
/// does not — a supplied clock round-trips into `checkedAt`
/// unchanged, which is what makes it checkable by a caller.
#[must_use]
pub fn resolve(now_seconds: Option<f64>) -> UnixSeconds {
    let seconds = now_seconds.unwrap_or_else(|| Date::now() / 1000.0);

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // epoch seconds fit
    UnixSeconds::from(seconds.max(0.0) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property the bug violated: seconds in, same seconds out.
    #[test]
    fn a_supplied_clock_round_trips() {
        assert_eq!(u64::from(resolve(Some(1_788_100_000.0))), 1_788_100_000);
    }

    /// Guards the specific failure — a supplied value landing near
    /// the epoch, where every real window grades `Deferred`.
    #[test]
    fn a_supplied_clock_is_not_scaled_to_1970() {
        assert!(u64::from(resolve(Some(1_788_100_000.0))) > 1_700_000_000);
    }

    /// A negative clock is clamped rather than wrapping through the
    /// cast into an enormous positive one.
    #[test]
    fn a_negative_clock_clamps_to_the_epoch() {
        assert_eq!(u64::from(resolve(Some(-1.0))), 0);
    }
}
