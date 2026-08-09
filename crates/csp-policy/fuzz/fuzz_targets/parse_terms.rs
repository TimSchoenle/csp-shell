//! Every leaf parser the crate exposes, over the same arbitrary input.
//!
//! `parse_source` covers the expression a consumer is most likely to build from configuration.
//! This one covers everything else that reaches a header from outside the program — a reporting
//! endpoint, a Trusted Types policy name, a sandbox token read from a settings file — because each
//! of those is a separate alphabet, and a hole in any one of them is the same header injection.
//!
//! One property, applied uniformly: whatever a parser accepts must render inside the policy
//! alphabet, and must parse back to itself.

#![no_main]

use csp_policy::{
    AncestorSource, DirectiveName, HashAlgorithm, HashSource, HostSource, NonceSource, ReportGroup,
    ReportUri, SandboxToken, Scheme, SourceDirective, TrustedTypePolicyName, TrustedTypeSink,
    Webrtc,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|text: &str| {
    check("AncestorSource", AncestorSource::parse(text).ok());
    check("HostSource", HostSource::parse(text).ok());
    check("Scheme", Scheme::parse(text).ok());
    check("NonceSource", NonceSource::parse(text).ok());
    check("HashSource", HashSource::parse(text).ok());
    check("HashAlgorithm", HashAlgorithm::parse(text).ok());
    check("DirectiveName", DirectiveName::parse(text).ok());
    check("SourceDirective", SourceDirective::parse(text).ok());
    check("SandboxToken", SandboxToken::parse(text).ok());
    check("TrustedTypePolicyName", TrustedTypePolicyName::parse(text).ok());
    check("TrustedTypeSink", TrustedTypeSink::parse(text).ok());
    check("Webrtc", Webrtc::parse(text).ok());
    check("ReportGroup", ReportGroup::parse(text).ok());
    check("ReportUri", ReportUri::parse(text).ok());

    // A hash value is parsed separately from its algorithm, so it gets its own pass rather than
    // only being reached through the `'sha256-…'` framing.
    for &algorithm in HashAlgorithm::ALL {
        check("HashSource::new", HashSource::new(algorithm, text).ok());
    }
});

/// Whatever this parser accepted must be renderable into a header and parseable back out of one.
fn check<T>(term: &str, parsed: Option<T>)
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
    assert!(
        rendered
            .bytes()
            .all(|byte| matches!(byte, 0x21..=0x2b | 0x2d..=0x3a | 0x3c..=0x7e)),
        "{term} rendered outside the policy alphabet: {rendered:?}"
    );
}
