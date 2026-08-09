//! Assertions over a rendered policy, shared by the oracles.
//!
//! These are the properties a browser depends on without ever reporting: one directive per name,
//! one separator per boundary, nothing outside the field-value alphabet. A policy that breaks any
//! of them is not rejected — it is silently reinterpreted, which is the failure mode this whole
//! crate exists to remove.

/// The input as text, or `None` when it is not UTF-8.
///
/// The scanner takes `&str`, so a non-UTF-8 input is not a rejected document — it is not a
/// document at all, and reporting it would be reporting on the encoding rather than on the scan.
pub fn as_str(data: &[u8]) -> Option<&str> {
    core::str::from_utf8(data).ok()
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

/// Every structural property of a rendered policy that holds regardless of its content.
///
/// # Panics
///
/// If a directive is empty, repeated, misspelled, or padded with a separator the builder did not
/// write itself.
pub fn assert_structure(rendered: &str) {
    if rendered.is_empty() {
        return;
    }

    let mut names = Vec::new();
    for segment in rendered.split("; ") {
        assert!(!segment.is_empty(), "empty directive in {rendered:?}");
        assert!(!segment.contains(';'), "unseparated `;` in {rendered:?}");
        assert!(
            !segment.starts_with(' ') && !segment.ends_with(' '),
            "{rendered:?}"
        );
        assert!(!segment.contains("  "), "empty source in {rendered:?}");

        let mut tokens = segment.split(' ');
        let name = tokens.next().expect("split yields at least one token");
        assert!(
            name.starts_with(|c: char| c.is_ascii_lowercase())
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "malformed directive name {name:?} in {rendered:?}"
        );

        // A repeated directive is ignored by the browser with only a console warning, so the
        // builder must never emit one.
        assert!(
            !names.contains(&name),
            "duplicate directive {name:?} in {rendered:?}"
        );
        names.push(name);

        for token in tokens {
            assert!(!token.is_empty(), "empty source in {rendered:?}");
        }
    }
}

/// The `name …` segment of a rendered policy, if present.
pub fn directive_of<'a>(rendered: &'a str, name: &str) -> Option<&'a str> {
    rendered
        .split("; ")
        .find(|segment| *segment == name || segment.starts_with(&format!("{name} ")))
}

/// Every source expression in a rendered policy, with the directive names dropped.
pub fn source_expressions(rendered: &str) -> impl Iterator<Item = &str> {
    rendered
        .split("; ")
        .flat_map(|segment| segment.split(' ').skip(1))
}

/// The nonce sources of a rendered policy.
///
/// A nonce is a source expression, not a substring. A host source may carry a path, and a path
/// may contain `'nonce-`; only a token that *starts* with a quote can be a nonce to a browser, so
/// that is what this matches. Searching the raw text instead would report a nonce that is not
/// there — and, worse, would let a genuine one hide behind a path that also matches.
pub fn nonce_sources(rendered: &str) -> impl Iterator<Item = &str> {
    source_expressions(rendered).filter(|token| token.starts_with("'nonce-"))
}

/// The rendered policy with its nonce sources removed, so two renderings can be compared.
///
/// # Panics
///
/// Never in practice: splitting a segment yields at least one token, and the `expect` says so.
pub fn strip_nonce(rendered: &str) -> String {
    rendered
        .split("; ")
        .map(|segment| {
            let mut tokens = segment.split(' ');
            let name = tokens.next().expect("split yields at least one token");
            let kept: Vec<&str> = tokens
                .filter(|token| !token.starts_with("'nonce-"))
                .collect();
            if kept.is_empty() {
                name.to_owned()
            } else {
                format!("{name} {}", kept.join(" "))
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}
