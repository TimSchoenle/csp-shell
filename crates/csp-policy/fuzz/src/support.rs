//! Assertions shared by the oracles.
//!
//! Each one states a property of the *rendered* form, because rendering is where a policy stops
//! being a data structure and becomes a header a browser will parse. A value that never renders
//! cannot injure anyone; a value that renders a `;` is a header injection in every browser at
//! once.

/// The input as text, or `None` when it is not UTF-8.
///
/// The parsers take `&str`, so a non-UTF-8 input is not a rejected input — it is not an input at
/// all, and reporting it would be reporting on the encoding rather than on the parser.
pub fn as_str(data: &[u8]) -> Option<&str> {
    core::str::from_utf8(data).ok()
}

/// The alphabet a single policy term may render into: `%x21-2B ∪ %x2D-3A ∪ %x3C-7E`.
///
/// A space would split one expression into two, a `;` would open a directive and a `,` would open
/// a whole second policy — and all three would still parse cleanly in the browser, which is what
/// makes this a header injection rather than a bug report.
///
/// # Panics
///
/// If `rendered` carries a byte outside that alphabet.
pub fn assert_term_alphabet(term: &str, rendered: &str) {
    assert!(
        rendered
            .bytes()
            .all(|byte| matches!(byte, 0x21..=0x2b | 0x2d..=0x3a | 0x3c..=0x7e)),
        "{term} rendered outside the policy alphabet: {rendered:?}"
    );
}

/// The alphabet a whole rendered policy may use: visible ASCII and the spaces between tokens.
///
/// Catches CR, LF, NUL, DEL and every non-ASCII byte in one assertion. The `,` is excluded
/// separately because it is legal in an HTTP field value in general and fatal in this one: it
/// starts a second policy, and the strictest of the two is the one enforced.
///
/// # Panics
///
/// If `rendered` is not a single policy expressible as one HTTP field value.
pub fn assert_field_value(rendered: &str) {
    assert!(
        rendered.bytes().all(|byte| (0x20..=0x7e).contains(&byte)),
        "not a valid HTTP field value: {rendered:?}"
    );
    assert!(!rendered.contains(','), "policy separator in {rendered:?}");
}
