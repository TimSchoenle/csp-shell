//! One directive, arbitrary name and sources, through the path a consumer's configuration takes:
//! text is parsed into typed source expressions and those are handed to the builder.
//!
//! The parse itself is fuzzed by the typed crate. What this oracle covers is the layer above it —
//! that the builder adds no way for an accepted source expression to put a separator into the
//! rendered header, and that the routed source expressions are refused wherever the routing table
//! says they are.

use arbitrary::{Arbitrary, Unstructured};
use csp_shell::{Csp, CspError, Source, SourceDirective};

/// Decode `data` into a directive index and a list of source texts, then build with them.
///
/// The decode is `arbitrary_take_rest` over the raw bytes, which is exactly what
/// `libfuzzer_sys::fuzz_target!` does for a typed argument — so a corpus entry a campaign found
/// means the same thing here as it did under the fuzzer.
///
/// # Panics
///
/// See [`run`].
pub fn check(data: &[u8]) {
    let Ok((index, texts)) = <(u8, Vec<String>)>::arbitrary_take_rest(Unstructured::new(data))
    else {
        return;
    };
    run(index, &texts);
}

/// Parse `texts` as source expressions, set them on the directive `index` selects, and assert the
/// header that renders.
///
/// # Panics
///
/// If a separator reaches the header, if an empty source expression is admitted, or if a refusal
/// names a source that was never offered.
pub fn run(index: u8, texts: &[String]) {
    let directive = SourceDirective::ALL[usize::from(index) % SourceDirective::ALL.len()];

    let sources: Vec<Source> = texts
        .iter()
        .filter_map(|text| Source::parse(text).ok())
        .collect();
    let offered = sources.clone();

    let csp = match Csp::new().directive(directive, sources) {
        Ok(csp) => csp,
        Err(CspError::RoutedSourceExpression { source, .. }) => {
            // A refusal must name a source that was actually offered, or the error is pointing
            // the caller at a method for something they did not write.
            assert!(
                offered.contains(&source),
                "refused {source} which was not in {offered:?}"
            );
            return;
        }
        // `CspError` is non-exhaustive, so a variant added later reaches here rather than failing
        // to compile in a harness nobody rebuilds until it breaks.
        Err(other) => panic!("unexpected refusal: {other}"),
    };

    let policy = csp.build().headers().content_security_policy;

    // Exactly one directive was set, so the builder emitted no separator at all. Any `;` or `,`
    // in the result came from an input the parser should have rejected.
    assert!(!policy.contains(';'), "directive separator in {policy:?}");
    assert!(!policy.contains(','), "policy separator in {policy:?}");

    // A rendered policy is an HTTP field value: visible ASCII and spaces, nothing else. This
    // catches CR, LF, NUL, DEL and every non-ASCII byte in one assertion.
    assert!(
        policy.bytes().all(|byte| (0x20..=0x7e).contains(&byte)),
        "not a valid HTTP field value: {policy:?}"
    );

    // Sources are separated by exactly one space, so a doubled space or a trailing one means an
    // empty source expression was admitted and silently vanished.
    assert!(
        !policy.contains("  "),
        "empty source rendered as a space: {policy:?}"
    );
    assert!(!policy.ends_with(' '), "trailing space in {policy:?}");
    assert!(!policy.starts_with(' '), "leading space in {policy:?}");

    // The directive that was set is the directive that rendered, under its own name.
    assert!(
        policy.starts_with(directive.as_str()),
        "{policy:?} does not begin with {directive}"
    );
}
