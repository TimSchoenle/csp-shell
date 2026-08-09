//! One source expression, arbitrary text: nothing that parses may render something a header
//! cannot carry, and nothing that renders may parse back as something else.
//!
//! This is the narrowest target and the one that maps directly onto the threat. A consumer builds
//! a policy from configuration — a CDN origin, a tenant domain, a nonce forwarded from an edge —
//! and a source expression carrying `;` closes the directive and opens a new one. The resulting
//! header parses cleanly in every browser, which is what makes it a header injection rather than a
//! bug report.

#![no_main]

use csp_policy::{Directive, Policy, Source, SourceDirective};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|text: &str| {
    let Ok(source) = Source::parse(text) else {
        return;
    };

    let rendered = source.to_string();

    // A source expression is visible ASCII with no separators: `%x21-2B ∪ %x2D-3A ∪ %x3C-7E`.
    // A space would split one expression into two, a `;` would open a directive, a `,` would open
    // a policy — and all three would still parse in the browser.
    assert!(
        rendered
            .bytes()
            .all(|byte| matches!(byte, 0x21..=0x2b | 0x2d..=0x3a | 0x3c..=0x7e)),
        "{text:?} rendered outside the source alphabet: {rendered:?}"
    );

    // Rendering is not allowed to lose or invent meaning: whatever came out must come back in.
    let reparsed = Source::parse(&rendered).expect("a rendered source must parse");
    assert_eq!(reparsed, source, "{text:?} rendered to {rendered:?}");
    assert_eq!(reparsed.to_string(), rendered, "rendering is not idempotent");

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
    assert_eq!(header, alloc_expected(&rendered));
});

/// The header a single `img-src` must render to, spelled out rather than derived, so the assertion
/// above compares against something independent of the renderer.
fn alloc_expected(source: &str) -> String {
    let mut expected = String::with_capacity("img-src ".len() + source.len());
    expected.push_str("img-src ");
    expected.push_str(source);
    expected
}
