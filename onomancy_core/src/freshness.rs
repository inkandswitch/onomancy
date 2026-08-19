//! Graded freshness vocabulary: chain windows and their standing at a
//! moment.
//!
//! DNSSEC verification proves a binding was zone-rooted *during its
//! RRSIG windows* — staleness is a risk signal, not a forgery signal.
//! Freshness is therefore a property of a **record** evaluated at a
//! clock reading, never a property of a connection: fresh chains travel
//! by gossip and courier like everything else.

use crate::time::UnixSeconds;

/// The intersection window of a chain's RRSIG validity intervals: the
/// span during which every link was simultaneously valid.
///
/// Empty intersections are unrepresentable: a chain whose windows never
/// jointly held is invalid ✗ (it never had joint validity), which
/// [`ChainWindow::new`] rejects at construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainWindow {
    inception: UnixSeconds,
    expiration: UnixSeconds,
}

impl ChainWindow {
    /// Construct a window, rejecting empty intersections.
    ///
    /// # Errors
    ///
    /// Returns [`EmptyWindow`] when `expiration < inception`.
    pub fn new(inception: UnixSeconds, expiration: UnixSeconds) -> Result<Self, EmptyWindow> {
        if expiration < inception {
            return Err(EmptyWindow {
                inception,
                expiration,
            });
        }

        Ok(Self {
            inception,
            expiration,
        })
    }

    /// When the window opens.
    #[must_use]
    pub const fn inception(&self) -> UnixSeconds {
        self.inception
    }

    /// When the window closes — the zone-state key's leading component.
    #[must_use]
    pub const fn expiration(&self) -> UnixSeconds {
        self.expiration
    }

    /// The window's standing at a clock reading.
    #[must_use]
    pub fn grade(&self, now: UnixSeconds) -> Grade {
        if now < self.inception {
            Grade::NotYetBegun
        } else if now <= self.expiration {
            Grade::Fresh
        } else {
            Grade::Stale
        }
    }
}

/// A chain window's standing at a moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Grade {
    /// The window covers `now`: fresh ✓.
    Fresh,

    /// The window has not opened yet: deferred — not considered until
    /// the clock reaches it, and never malformed (clock-skew failures
    /// are delays, not breaks).
    NotYetBegun,

    /// The window has lapsed: stale ⚠ — once-valid, a risk signal,
    /// never a forgery signal.
    Stale,
}

/// The freshness class of a considered record: [`Grade`] minus
/// deferral, which removes a record from consideration entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum Freshness {
    /// Chain window covers `now`: fresh ✓.
    Fresh,

    /// Chain window has lapsed: stale ⚠.
    Stale,
}

/// The RRSIG windows never jointly held: invalid ✗, not stale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("empty chain window: expires {expiration} before inception {inception}")]
pub struct EmptyWindow {
    /// The claimed opening.
    pub inception: UnixSeconds,
    /// The claimed close, before the opening.
    pub expiration: UnixSeconds,
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn grading_covers_all_three_standings() {
        let window = ChainWindow::new(UnixSeconds::from(100), UnixSeconds::from(200))
            .expect("non-empty window");

        assert_eq!(window.grade(UnixSeconds::from(50)), Grade::NotYetBegun);
        assert_eq!(window.grade(UnixSeconds::from(100)), Grade::Fresh);
        assert_eq!(window.grade(UnixSeconds::from(200)), Grade::Fresh);
        assert_eq!(window.grade(UnixSeconds::from(201)), Grade::Stale);
    }

    #[test]
    fn empty_windows_are_unrepresentable() {
        assert!(ChainWindow::new(UnixSeconds::from(2), UnixSeconds::from(1)).is_err());
        // Instantaneous joint validity is still a window.
        assert!(ChainWindow::new(UnixSeconds::from(2), UnixSeconds::from(2)).is_ok());
    }

    mod props {
        use super::*;

        /// Grading is monotone in `now`: `NotYetBegun`, then `Fresh`,
        /// then `Stale`, in that order, with no return.
        #[test]
        fn grade_is_monotone_in_now() {
            bolero::check!()
                .with_type::<(u64, u64, u64, u64)>()
                .for_each(|(a, b, t1, t2)| {
                    let (inception, expiration) = if a <= b { (*a, *b) } else { (*b, *a) };
                    let window = ChainWindow::new(
                        UnixSeconds::from(inception),
                        UnixSeconds::from(expiration),
                    )
                    .expect("ordered endpoints");

                    let (earlier, later) = if t1 <= t2 { (*t1, *t2) } else { (*t2, *t1) };
                    let rank = |grade: Grade| match grade {
                        Grade::NotYetBegun => 0,
                        Grade::Fresh => 1,
                        Grade::Stale => 2,
                    };

                    assert!(
                        rank(window.grade(UnixSeconds::from(earlier)))
                            <= rank(window.grade(UnixSeconds::from(later)))
                    );
                });
        }
    }
}
