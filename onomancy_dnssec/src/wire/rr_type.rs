//! The resource-record type code.
//!
//! The values are DNS's, not ours: the IANA RR TYPE registry.

use core::fmt;

/// A resource-record type code.
///
/// Only the types validation touches get names; everything else stays
/// a number (and, per the strictness doctrine, gets rejected where the
/// walk requires a specific type — never silently repurposed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RrType(u16);

impl RrType {
    /// Adopt a wire-carried code verbatim (the registry is open;
    /// unknown codes are representable and fail closed downstream).
    #[must_use]
    pub const fn new(code: u16) -> Self {
        Self(code)
    }

    /// The registry code, for wire encoding.
    #[must_use]
    pub const fn code(self) -> u16 {
        self.0
    }

    /// CNAME (5): indirection on the `_onomancy` owner name.
    pub const CNAME: Self = Self(5);
    /// DNSKEY (48): zone keys.
    pub const DNSKEY: Self = Self(48);
    /// DS (43): delegation signer digests at zone cuts.
    pub const DS: Self = Self(43);
    /// NSEC (47): authenticated denial of existence.
    pub const NSEC: Self = Self(47);
    /// NSEC3 (50): hashed authenticated denial.
    pub const NSEC3: Self = Self(50);
    /// RRSIG (46): the signatures themselves.
    pub const RRSIG: Self = Self(46);
    /// TXT (16): the binding record.
    pub const TXT: Self = Self(16);
}

impl fmt::Display for RrType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::CNAME => f.write_str("CNAME"),
            Self::DNSKEY => f.write_str("DNSKEY"),
            Self::DS => f.write_str("DS"),
            Self::NSEC => f.write_str("NSEC"),
            Self::NSEC3 => f.write_str("NSEC3"),
            Self::RRSIG => f.write_str("RRSIG"),
            Self::TXT => f.write_str("TXT"),
            Self(code) => write!(f, "TYPE{code}"),
        }
    }
}
