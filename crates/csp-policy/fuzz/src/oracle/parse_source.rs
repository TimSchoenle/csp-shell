//! One source expression, arbitrary text: nothing that parses may render something a header
//! cannot carry, and nothing that renders may parse back as something else.
//!
//! This is the narrowest oracle and the one that maps directly onto the threat. A consumer builds
//! a policy from configuration — a CDN origin, a tenant domain, a nonce forwarded from an edge —
//! and a source expression carrying `;` closes the directive and opens a new one. The resulting
//! header parses cleanly in every browser, which is what makes it a header injection rather than
//! a bug report.

use csp_policy::{Directive, Policy, Source, SourceDirective};

use crate::support;

/// Parse `data` as a source expression and assert every property its rendered form must have.
///
/// # Panics
///
/// If an accepted source expression renders outside the policy alphabet, fails to round-trip
/// through its own rendered form, or lets a separator reach the header.
pub fn check(data: &[u8]) {
    let Some(text) = support::as_str(data) else {
        return;
    };
    let Ok(source) = Source::parse(text) else {
        return;
    };

    let rendered = source.to_string();
    support::assert_term_alphabet("Source", &rendered);

    // Rendering is not allowed to lose or invent meaning: whatever came out must come back in.
    let reparsed = Source::parse(&rendered).expect("a rendered source must parse");
    assert_eq!(reparsed, source, "{text:?} rendered to {rendered:?}");
    assert_eq!(
        reparsed.to_string(),
        rendered,
        "rendering is not idempotent"
    );

    // A keyword is the only source expression that is entirely case-insensitive; a host source
    // carries a path, which is not. So the fold is asserted where it applies and nowhere else.
    if let Some(keyword) = source.as_keyword() {
        assert_eq!(rendered, keyword);
        assert_eq!(
            Source::parse(&rendered.to_ascii_uppercase()),
            Ok(source.clone()),
            "a keyword must parse in any case"
        );
    }

    // And the whole point: one directive holding it renders one directive.
    let policy = Policy::new().with(Directive::sources(SourceDirective::ImgSrc, [source]));
    let header = policy.to_header_value();
    assert!(!header.contains(';'), "directive separator in {header:?}");
    assert!(!header.contains(','), "policy separator in {header:?}");
    assert!(!header.contains("  "), "empty source in {header:?}");
    assert!(!header.ends_with(' '), "trailing space in {header:?}");
    assert_eq!(header, expected_header(&rendered));
}

/// The header a single `img-src` must render to, spelled out rather than derived, so the
/// assertion above compares against something independent of the renderer.
fn expected_header(source: &str) -> String {
    let mut expected = String::with_capacity("img-src ".len() + source.len());
    expected.push_str("img-src ");
    expected.push_str(source);
    expected
}
