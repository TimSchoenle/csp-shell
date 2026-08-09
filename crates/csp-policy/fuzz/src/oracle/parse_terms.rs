//! Every leaf parser the crate exposes, over the same arbitrary input.
//!
//! [`parse_source`](super::parse_source) covers the expression a consumer is most likely to build
//! from configuration. This one covers everything else that reaches a header from outside the
//! program — a reporting endpoint, a Trusted Types policy name, a sandbox token read from a
//! settings file — because each of those is a separate alphabet, and a hole in any one of them is
//! the same header injection.
//!
//! One property, applied uniformly: whatever a parser accepts must render inside the policy
//! alphabet, and must not render to nothing.

use csp_policy::{
    AncestorSource, DirectiveName, HashAlgorithm, HashSource, HostSource, NonceSource, ReportGroup,
    ReportUri, SandboxToken, Scheme, SourceDirective, TrustedTypePolicyName, TrustedTypeSink,
    Webrtc,
};

use crate::support;

/// Offer `data` to every leaf parser and assert the rendered form of whatever each accepts.
///
/// # Panics
///
/// If any parser accepts an input that renders to nothing, or outside the policy alphabet.
pub fn check(data: &[u8]) {
    let Some(text) = support::as_str(data) else {
        return;
    };

    renders("AncestorSource", AncestorSource::parse(text).ok());
    renders("HostSource", HostSource::parse(text).ok());
    renders("Scheme", Scheme::parse(text).ok());
    renders("NonceSource", NonceSource::parse(text).ok());
    renders("HashSource", HashSource::parse(text).ok());
    renders("HashAlgorithm", HashAlgorithm::parse(text).ok());
    renders("DirectiveName", DirectiveName::parse(text).ok());
    renders("SourceDirective", SourceDirective::parse(text).ok());
    renders("SandboxToken", SandboxToken::parse(text).ok());
    renders(
        "TrustedTypePolicyName",
        TrustedTypePolicyName::parse(text).ok(),
    );
    renders("TrustedTypeSink", TrustedTypeSink::parse(text).ok());
    renders("Webrtc", Webrtc::parse(text).ok());
    renders("ReportGroup", ReportGroup::parse(text).ok());
    renders("ReportUri", ReportUri::parse(text).ok());

    // A hash value is parsed separately from its algorithm, so it gets its own pass rather than
    // only being reached through the `'sha256-…'` framing.
    for &algorithm in HashAlgorithm::ALL {
        renders("HashSource::new", HashSource::new(algorithm, text).ok());
    }
}

/// Whatever this parser accepted must be renderable into a header.
fn renders<T>(term: &str, parsed: Option<T>)
where
    T: core::fmt::Display,
{
    let Some(value) = parsed else {
        return;
    };
    let rendered = value.to_string();

    assert!(
        !rendered.is_empty(),
        "{term} accepted an input that renders to nothing"
    );
    support::assert_term_alphabet(term, &rendered);
}
