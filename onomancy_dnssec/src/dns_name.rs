//! DNS name anchors, normalized to lowercase A-label form.

use alloc::string::String;
use core::{fmt, str};

use onomancy_core::{
    anchor::Anchor,
    name::{Name, ParseSegmentsError, parse_segments, split_anchor},
};

/// A normalized DNS name: lowercase ASCII A-labels, at least two labels,
/// no trailing dot, no IP literals.
///
/// Onomancy specifies A-labels only: names are parsed, stored, and
/// compared as A-labels — the DNSSEC chain
/// never sees Unicode. Converting U-labels (`аррӏе.com`) to A-labels
/// (`xn--80ak6aa92e.com`) is an input-layer concern; raw Unicode here is a
/// parse error.
///
/// # Examples
///
/// ```
/// use onomancy_dnssec::dns_name::DnsName;
///
/// let dns = DnsName::parse("EXPEDE.WTF.").expect("valid, normalizes");
/// assert_eq!(dns.as_str(), "expede.wtf");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DnsName(String);

/// Maximum total length of a DNS name in its textual form.
pub const MAX_NAME_LEN: usize = 253;

/// Maximum length of a single DNS label.
pub const MAX_LABEL_LEN: usize = 63;

impl DnsName {
    /// Parse and normalize a DNS name: lowercase, strip one trailing dot.
    ///
    /// # Errors
    ///
    /// Returns [`ParseDnsNameError`] for non-ASCII input (A-labels only),
    /// dotless names (defined out of existence, per ICANN SAC053), names
    /// or labels exceeding DNS length limits, malformed LDH labels, and
    /// IP literals.
    pub fn parse(raw: &str) -> Result<Self, ParseDnsNameError> {
        if !raw.is_ascii() {
            return Err(ParseDnsNameError::NotALabel);
        }

        let trimmed = match raw.strip_suffix('.') {
            Some(stripped) => stripped,
            None => raw,
        };

        if trimmed.len() > MAX_NAME_LEN {
            return Err(ParseDnsNameError::NameTooLong);
        }

        let lowered = trimmed.to_ascii_lowercase();
        let mut labels = lowered.split('.');
        let tld = labels.next_back().ok_or(ParseDnsNameError::Dotless)?;

        validate_label(tld)?;

        // An all-digit rightmost label is what separates a hostname
        // from an IPv4 literal: `1.2.3.4` must not parse as a name.
        // Testing the TLD alone is sufficient and catches `host.123`
        // too, which is no IP literal but is equally unresolvable.
        if tld.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ParseDnsNameError::AllDigitTld);
        }

        let mut label_count = 1usize;

        for label in labels {
            validate_label(label)?;
            label_count += 1;
        }

        if label_count < 2 {
            return Err(ParseDnsNameError::Dotless);
        }

        Ok(Self(lowered))
    }

    /// Decode wire bytes that MUST already be canonical: lowercase
    /// A-labels, no trailing dot. Decoders reject rather than
    /// normalize — accept-then-canonicalize is the aliasing bug class
    /// the strict codecs exist to kill.
    ///
    /// # Errors
    ///
    /// Returns [`CanonicalDnsNameError`] when the bytes are not UTF-8
    /// (a fortiori not ASCII), do not parse as a DNS name, or parse
    /// but were not already in canonical form.
    pub fn from_canonical(raw: &[u8]) -> Result<Self, CanonicalDnsNameError> {
        let text = str::from_utf8(raw).map_err(|_| CanonicalDnsNameError::NotUtf8)?;
        let parsed = Self::parse(text)?;

        if parsed.as_str() == text {
            Ok(parsed)
        } else {
            Err(CanonicalDnsNameError::NotCanonical)
        }
    }

    /// Parse a display-form name: Unicode U-labels are converted to
    /// their Punycode A-labels (UTS-46 / [IDNA]), then handed to the
    /// strict A-label parser. The core stays A-label-only — U-labels
    /// exist purely at the display layer, which is where homograph
    /// defenses live (design/security.md).
    ///
    /// # Errors
    ///
    /// Returns [`ParseDnsNameError::NotIdnaConvertible`] when UTS-46
    /// processing rejects the input, or any [`ParseDnsNameError`] the
    /// A-label parser reports for the converted form.
    ///
    /// # Examples
    ///
    /// ```
    /// use onomancy_dnssec::dns_name::DnsName;
    ///
    /// let display = DnsName::parse_display("münchen.de")?;
    /// assert_eq!(display, DnsName::parse("xn--mnchen-3ya.de")?);
    /// # Ok::<(), onomancy_dnssec::dns_name::ParseDnsNameError>(())
    /// ```
    ///
    /// [IDNA]: https://www.rfc-editor.org/rfc/rfc5890
    #[cfg(feature = "idna")]
    pub fn parse_display(raw: &str) -> Result<Self, ParseDnsNameError> {
        let ascii =
            idna::domain_to_ascii(raw).map_err(|_| ParseDnsNameError::NotIdnaConvertible)?;
        Self::parse(&ascii)
    }

    /// View the normalized name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DnsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// LDH rule: letters, digits, hyphens; hyphens not at either end.
fn validate_label(label: &str) -> Result<(), ParseDnsNameError> {
    if label.is_empty() {
        return Err(ParseDnsNameError::EmptyLabel);
    }

    if label.len() > MAX_LABEL_LEN {
        return Err(ParseDnsNameError::LabelTooLong);
    }

    if label.starts_with('-') || label.ends_with('-') {
        return Err(ParseDnsNameError::HyphenAtLabelEdge);
    }

    if !label
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(ParseDnsNameError::NotALabel);
    }

    Ok(())
}

/// Wire bytes were not the canonical spelling of a DNS name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CanonicalDnsNameError {
    /// The bytes parse but are not in canonical form (uppercase,
    /// trailing dot, …). Decoders reject rather than normalize.
    #[error("not in canonical A-label form")]
    NotCanonical,

    /// The bytes were not UTF-8 text at all.
    #[error("not UTF-8 text")]
    NotUtf8,

    /// The bytes do not parse as a DNS name.
    #[error(transparent)]
    Parse(#[from] ParseDnsNameError),
}

/// The input was not a valid, normalizable DNS name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseDnsNameError {
    /// Dotless DNS names are defined out of existence (ICANN SAC053).
    #[error("DNS anchors need at least two labels (dotless domains do not exist)")]
    Dotless,

    /// A label was empty (leading dot or doubled dots).
    #[error("empty DNS label")]
    EmptyLabel,

    /// A label began or ended with a hyphen.
    #[error("DNS labels must not begin or end with a hyphen")]
    HyphenAtLabelEdge,

    /// The rightmost label was all digits.
    ///
    /// Stated as the rule rather than as one of its consequences:
    /// "IP literals are not DNS names" explains `1.2.3.4` but
    /// misdescribes `host.123`, which is no IP literal and is
    /// rejected by the same rule.
    #[error(
        "a top-level domain must not be all digits (the rule that keeps IP literals from being names)"
    )]
    AllDigitTld,

    /// A label exceeded 63 octets.
    #[error("DNS labels are limited to {MAX_LABEL_LEN} octets")]
    LabelTooLong,

    /// The whole name exceeded 253 octets.
    #[error("DNS names are limited to {MAX_NAME_LEN} octets")]
    NameTooLong,

    /// A label contained something other than lowercase ASCII LDH
    /// characters. U-label (Unicode) input must be IDNA-encoded to
    /// A-labels before parsing — [`DnsName::parse_display`] does so
    /// under the `idna` feature.
    #[error("DNS labels are ASCII letters, digits, and hyphens (A-label form)")]
    NotALabel,

    /// UTS-46 processing rejected the display-form input (the reasons
    /// are deliberately opaque upstream).
    #[cfg(feature = "idna")]
    #[error("display-form name is not convertible to A-labels")]
    NotIdnaConvertible,
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn normalizes_case_and_trailing_dot() {
        let dns = DnsName::parse("ExPeDe.WTF.").expect("valid");
        assert_eq!(dns.as_str(), "expede.wtf");
    }

    #[test]
    fn rejects_ipv4_literals() {
        assert_eq!(
            DnsName::parse("127.0.0.1"),
            Err(ParseDnsNameError::AllDigitTld)
        );
    }

    /// The same rule, on a name that is not an IP literal — the
    /// all-digit-TLD rejection covers more than IP literals, and this
    /// pins the wider half.
    #[test]
    fn rejects_an_all_digit_tld_that_is_not_an_ip_literal() {
        assert_eq!(
            DnsName::parse("host.123"),
            Err(ParseDnsNameError::AllDigitTld)
        );
    }

    /// A digit-leading TLD is fine as long as it is not *all* digits;
    /// the rule is about the whole label, not its first byte.
    #[test]
    fn accepts_a_tld_with_digits_and_letters() {
        assert_eq!(
            DnsName::parse("example.4d").expect("valid").as_str(),
            "example.4d"
        );
    }

    #[test]
    fn rejects_unicode_u_labels() {
        assert_eq!(
            DnsName::parse("аррӏе.com"),
            Err(ParseDnsNameError::NotALabel)
        );
    }

    #[test]
    fn accepts_punycode_a_labels() {
        assert_eq!(
            DnsName::parse("xn--80ak6aa92e.com")
                .expect("valid")
                .as_str(),
            "xn--80ak6aa92e.com"
        );
    }

    #[test]
    fn trailing_dot_only_strips_once() {
        assert_eq!(
            DnsName::parse("expede.wtf.."),
            Err(ParseDnsNameError::EmptyLabel)
        );
    }

    #[test]
    fn hyphens_at_label_edges_are_rejected() {
        assert_eq!(
            DnsName::parse("-foo.com"),
            Err(ParseDnsNameError::HyphenAtLabelEdge)
        );
        assert_eq!(
            DnsName::parse("foo-.com"),
            Err(ParseDnsNameError::HyphenAtLabelEdge)
        );
        assert_eq!(
            DnsName::parse("foo.-com"),
            Err(ParseDnsNameError::HyphenAtLabelEdge)
        );

        // Interior hyphens are ordinary LDH.
        assert!(DnsName::parse("fo-o.com").is_ok());
    }

    #[test]
    fn dotless_and_empty_names_do_not_exist() {
        assert_eq!(DnsName::parse("localhost"), Err(ParseDnsNameError::Dotless));
        assert_eq!(DnsName::parse(""), Err(ParseDnsNameError::EmptyLabel));
    }

    /// A name of exactly `target` octets: fill labels ahead of `com`.
    fn name_of_len(target: usize) -> String {
        let mut labels = alloc::vec![String::from("com")];
        let mut remaining = target - 3;

        while remaining > 0 {
            let label_len = MAX_LABEL_LEN.min(remaining - 1);
            labels.insert(0, "a".repeat(label_len));
            remaining -= label_len + 1;
        }

        let name = labels.join(".");
        assert_eq!(name.len(), target, "helper builds exact lengths");
        name
    }

    /// The 63/64 and 253/254 boundaries, both directions — classic
    /// `>` vs `>=` territory.
    #[test]
    fn length_limits_are_exact() {
        let max_label = alloc::format!("{}.com", "a".repeat(MAX_LABEL_LEN));
        assert!(DnsName::parse(&max_label).is_ok(), "63-octet label");
        assert_eq!(
            DnsName::parse(&alloc::format!("{}.com", "a".repeat(MAX_LABEL_LEN + 1))),
            Err(ParseDnsNameError::LabelTooLong)
        );

        assert!(DnsName::parse(&name_of_len(MAX_NAME_LEN)).is_ok(), "253");
        assert_eq!(
            DnsName::parse(&name_of_len(MAX_NAME_LEN + 1)),
            Err(ParseDnsNameError::NameTooLong)
        );

        // A 254-char INPUT whose trailing dot strips to 253 parses:
        // the limit applies after normalization.
        let dotted = alloc::format!("{}.", name_of_len(MAX_NAME_LEN));
        assert_eq!(
            DnsName::parse(&dotted)
                .expect("strips to the limit")
                .as_str()
                .len(),
            MAX_NAME_LEN
        );
    }

    /// `from_canonical` guards wire decode: it accepts exactly the
    /// canonical spelling and refuses to normalize.
    #[test]
    fn from_canonical_accepts_only_the_canonical_spelling() {
        let dns = DnsName::from_canonical(b"expede.wtf").expect("canonical");
        assert_eq!(dns.as_str(), "expede.wtf");

        assert_eq!(
            DnsName::from_canonical(b"ExPeDe.wtf"),
            Err(CanonicalDnsNameError::NotCanonical)
        );
        assert_eq!(
            DnsName::from_canonical(b"expede.wtf."),
            Err(CanonicalDnsNameError::NotCanonical)
        );
        assert_eq!(
            DnsName::from_canonical(&[0xFF, 0xFE]),
            Err(CanonicalDnsNameError::NotUtf8)
        );
        assert!(matches!(
            DnsName::from_canonical(b"localhost"),
            Err(CanonicalDnsNameError::Parse(ParseDnsNameError::Dotless))
        ));
    }

    /// The `@` spelling family: `Name<DnsName>` parses, roundtrips,
    /// and each `ParseDnsAnchoredNameError` variant has its input.
    mod anchored {
        use super::*;
        use onomancy_core::name::{Name, ParseSegmentsError};

        #[test]
        fn dns_anchored_names_parse_and_roundtrip() {
            let name = Name::<DnsName>::parse("@expede.wtf/pics/best").expect("valid");
            assert_eq!(name.anchor().as_str(), "expede.wtf");
            assert_eq!(name.segments().len(), 2);
            assert_eq!(name.to_string(), "@expede.wtf/pics/best");

            let bare = Name::<DnsName>::parse("@expede.wtf").expect("anchor-only");
            assert!(bare.segments().is_empty());
        }

        #[test]
        fn the_sigil_is_mandatory() {
            assert!(matches!(
                Name::<DnsName>::parse("expede.wtf/pics"),
                Err(ParseDnsAnchoredNameError::MissingSigil)
            ));
        }

        /// `@` means DNS and nothing else: a dotless `@` name is a
        /// flat parse error, never a petname fallback.
        #[test]
        fn dotless_at_names_are_flat_errors() {
            assert!(matches!(
                Name::<DnsName>::parse("@bob"),
                Err(ParseDnsAnchoredNameError::Anchor(
                    ParseDnsNameError::Dotless
                ))
            ));
        }

        #[test]
        fn malformed_paths_surface_as_segment_errors() {
            assert!(matches!(
                Name::<DnsName>::parse("@expede.wtf//x"),
                Err(ParseDnsAnchoredNameError::Segments(
                    ParseSegmentsError::Segment(_)
                ))
            ));
        }
    }

    #[cfg(feature = "idna")]
    mod display {
        use super::*;
        use testresult::TestResult;

        #[test]
        fn u_labels_convert_to_a_labels() -> TestResult {
            assert_eq!(
                DnsName::parse_display("münchen.de")?,
                DnsName::parse("xn--mnchen-3ya.de")?
            );
            Ok(())
        }

        #[test]
        fn homographs_map_to_their_punycode_form() -> TestResult {
            // Cyrillic а-р-р-ӏ-е: visually "apple", a different
            // name entirely — confusable detection is the display
            // layer's job, not the parser's.
            assert_eq!(
                DnsName::parse_display("аррӏе.com")?,
                DnsName::parse("xn--80ak6aa92e.com")?
            );
            Ok(())
        }

        #[test]
        fn ascii_input_passes_through_normalized() -> TestResult {
            assert_eq!(
                DnsName::parse_display("ExAmPlE.CoM.")?,
                DnsName::parse("example.com")?
            );
            Ok(())
        }

        #[test]
        fn unconvertible_display_input_errors() {
            // Invalid Punycode is rejected by UTS-46 itself…
            assert_eq!(
                DnsName::parse_display("xn--0.com"),
                Err(ParseDnsNameError::NotIdnaConvertible)
            );

            // …while characters UTS-46 merely passes through still
            // die in the strict A-label parser: two layers, no gap.
            assert_eq!(
                DnsName::parse_display("ex ample.com"),
                Err(ParseDnsNameError::NotALabel)
            );
        }
    }

    mod props {
        use super::*;

        #[test]
        fn parse_is_idempotent_on_normalized_output() {
            bolero::check!()
                .with_type::<alloc::string::String>()
                .for_each(|raw| {
                    if let Ok(dns) = DnsName::parse(raw) {
                        let renormalized =
                            DnsName::parse(dns.as_str()).expect("already normalized");
                        assert_eq!(dns, renormalized);
                        assert_eq!(dns.to_string(), renormalized.to_string());
                    }
                });
        }

        /// Structured traffic for the accept branch: arbitrary
        /// strings almost never form valid names, so this generator
        /// builds LDH labels from seeds — every built name must parse
        /// to itself.
        #[test]
        fn built_ldh_names_parse_verbatim() {
            bolero::check!()
                .with_type::<Vec<Vec<u8>>>()
                .for_each(|label_seeds| {
                    let labels: Vec<String> = label_seeds
                        .iter()
                        .take(4)
                        .map(|seed| {
                            seed.iter()
                                .take(8)
                                .map(|b| char::from(b'a' + (b % 26)))
                                .collect::<String>()
                        })
                        .filter(|l| !l.is_empty())
                        .collect();

                    if labels.len() < 2 {
                        return;
                    }

                    let raw = labels.join(".");
                    let parsed = DnsName::parse(&raw).expect("LDH names parse");
                    assert_eq!(parsed.as_str(), raw, "already canonical");
                });
        }

        /// `from_canonical` accepts exactly the fixed points of
        /// `parse`: the parser's output always re-enters, and inputs
        /// the parser had to normalize are refused.
        #[test]
        fn from_canonical_accepts_exactly_parse_fixed_points() {
            bolero::check!()
                .with_type::<alloc::string::String>()
                .for_each(|raw| {
                    let Ok(parsed) = DnsName::parse(raw) else {
                        return;
                    };

                    assert_eq!(
                        DnsName::from_canonical(parsed.as_str().as_bytes()),
                        Ok(parsed.clone()),
                        "parse output is canonical"
                    );

                    if raw != parsed.as_str() {
                        assert_eq!(
                            DnsName::from_canonical(raw.as_bytes()),
                            Err(CanonicalDnsNameError::NotCanonical),
                            "normalized inputs are not canonical spellings"
                        );
                    }
                });
        }
    }
}

impl Anchor for DnsName {
    type ParseError = ParseDnsAnchoredNameError;

    fn parse_name(raw: &str) -> Result<Name<Self>, ParseDnsAnchoredNameError> {
        let rest = raw
            .strip_prefix('@')
            .ok_or(ParseDnsAnchoredNameError::MissingSigil)?;
        let (anchor_raw, segments_raw) = split_anchor(rest);

        Ok(Name::from_parts(
            Self::parse(anchor_raw)?,
            parse_segments(segments_raw)?,
        ))
    }

    fn fmt_anchor(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "@{self}")
    }
}

/// The input could not be parsed as a DNS-anchored (`@`) name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseDnsAnchoredNameError {
    /// The DNS anchor was malformed (including dotless `@` names: `@`
    /// means DNS and nothing else).
    #[error(transparent)]
    Anchor(#[from] ParseDnsNameError),

    /// DNS-anchored names start with `@`.
    #[error("DNS-anchored names start with `@`")]
    MissingSigil,

    /// The path after the anchor was malformed.
    #[error(transparent)]
    Segments(#[from] ParseSegmentsError),
}
