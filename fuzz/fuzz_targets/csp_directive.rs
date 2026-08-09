//! One directive, arbitrary name and sources: no accepted input may put a separator into the
//! rendered header that the builder did not emit itself.
//!
//! This is the narrowest of the four targets and the one that maps directly onto the threat: a
//! consumer passing a CDN origin in from configuration. A source expression carrying `;` closes
//! the directive and opens a new one, and the resulting header parses cleanly — a
//! Content-Security-Policy header injection with an environment variable as the vector.

#![no_main]

use csp_shell::Csp;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (String, Vec<String>)| {
    let (name, sources) = input;

    let Ok(csp) = Csp::new().directive(&name, &sources) else {
        return;
    };
    let policy = csp.build().headers().content_security_policy;

    // Exactly one directive was set, so the builder emitted no separator at all. Any `;` or `,`
    // in the result came from an input the validator should have rejected.
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
    assert!(!policy.contains("  "), "empty source rendered as a space: {policy:?}");
    assert!(!policy.ends_with(' '), "trailing space in {policy:?}");
    assert!(!policy.starts_with(' '), "leading space in {policy:?}");
});
