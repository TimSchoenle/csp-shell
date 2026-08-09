//! Directive-name and source-expression validation.
//!
//! `Csp::directive(name, sources)` concatenates its arguments into a response header. The
//! consumer this crate was extracted from only ever passes literals, so nothing was exploitable
//! there — but the obvious second consumer passes a CDN origin in from configuration, and a
//! source expression containing `;` closes the directive and opens a new one:
//!
//! ```text
//! img-src 'self' https://evil.example; script-src 'unsafe-inline'
//! ```
//!
//! That is a Content-Security-Policy header injection with an environment variable as the vector,
//! and the resulting header parses cleanly. Validation lives in the builder so there is no path
//! from a `&str` to a rendered policy that skips it.

use alloc::string::{String, ToString};

use crate::error::CspError;

/// Source expressions that have a dedicated builder method, and the method that produces them.
///
/// Rejected as strings, not forbidden: all three are spec-valid and one of them is occasionally
/// correct. The point is that a method name is a stable token which cannot be assembled by
/// `format!`, `concat!` or a config value, so a downstream lint matching on it is exact.
///
/// The third field restricts the routing to one directive; `None` routes in every directive.
/// `'unsafe-inline'` in `style-src` is untouched — `Csp::spa_wasm` sets it.
const ROUTED_SOURCES: &[(&str, &str, Option<&str>)] = &[
    ("'unsafe-eval'", "allow_unsafe_eval", None), // csp-lint: allow — routing the token is what closes the string path to it
    (
        "'unsafe-inline'",
        "allow_unsafe_inline_script",
        Some("script-src"),
    ),
    ("'strict-dynamic'", "strict_dynamic", Some("script-src")),
];

/// Directive names this crate knows. Case-insensitive by construction: all entries are lowercase
/// and names are lowercased before lookup.
///
/// The list exists to catch typos, not to gate the spec: an unrecognised name is accepted in
/// release builds (see [`canonical_directive_name`]), so a directive added to CSP after this
/// crate's last release is usable without waiting for one.
const KNOWN_DIRECTIVES: &[&str] = &[
    // Fetch directives
    "child-src",
    "connect-src",
    "default-src",
    "fenced-frame-src",
    "font-src",
    "frame-src",
    "img-src",
    "manifest-src",
    "media-src",
    "object-src",
    "prefetch-src",
    "script-src",
    "script-src-attr",
    "script-src-elem",
    "style-src",
    "style-src-attr",
    "style-src-elem",
    "worker-src",
    // Document directives
    "base-uri",
    "sandbox",
    // Navigation directives
    "form-action",
    "frame-ancestors",
    // Reporting directives
    "report-to",
    "report-uri",
    // Other
    "block-all-mixed-content",
    "require-trusted-types-for",
    "trusted-types",
    "upgrade-insecure-requests",
    "webrtc",
];

/// Lowercase and validate a directive name.
///
/// # Errors
///
/// - [`CspError::InvalidDirectiveName`] if the name is not `[a-zA-Z][a-zA-Z0-9-]*`. A name outside
///   that grammar can carry the same injection a source expression can, and there is no directive
///   in any revision of CSP that needs a byte outside it.
/// - [`CspError::UnknownDirective`], **in debug builds only**, if the name is well-formed but not
///   in [`KNOWN_DIRECTIVES`]. The asymmetry is deliberate: a browser silently ignores a directive
///   it does not recognise, so `scrpit-src` is a restriction that is simply absent — worth a hard
///   error while developing, and not worth breaking a running deployment over when the crate's
///   table is merely older than the spec.
pub(crate) fn canonical_directive_name(name: &str) -> Result<String, CspError> {
    let mut bytes = name.bytes();
    let well_formed = match bytes.next() {
        Some(first) if first.is_ascii_alphabetic() => {
            bytes.all(|b| b.is_ascii_alphanumeric() || b == b'-')
        }
        _ => false,
    };
    if !well_formed {
        return Err(CspError::InvalidDirectiveName {
            name: name.to_string(),
        });
    }

    let lowered = name.to_ascii_lowercase();
    if cfg!(debug_assertions) && !KNOWN_DIRECTIVES.contains(&lowered.as_str()) {
        return Err(CspError::UnknownDirective { name: lowered });
    }
    Ok(lowered)
}

/// Validate one source expression for `directive`, which must already be canonical.
///
/// # Errors
///
/// - [`CspError::RoutedSourceExpression`] for the three routed sources above, checked first so the
///   caller gets the method name rather than a generic acceptance.
/// - [`CspError::EmptySource`] for the empty string, which renders as a stray space.
/// - [`CspError::InvalidSource`] for any byte outside `%x21-2B ∪ %x2D-3A ∪ %x3C-7E` — printable
///   ASCII less space, `,` and `;`. Whitespace is rejected rather than trimmed: a source with a
///   space in it would silently become two sources, which is a different policy that still parses.
pub(crate) fn validate_source(directive: &str, source: &str) -> Result<(), CspError> {
    for (routed, method, only_in) in ROUTED_SOURCES {
        let applies = only_in.is_none_or(|d| d == directive);
        if applies && source.eq_ignore_ascii_case(routed) {
            return Err(CspError::RoutedSourceExpression {
                source: source.to_string(),
                method,
            });
        }
    }

    if source.is_empty() {
        return Err(CspError::EmptySource {
            directive: directive.to_string(),
        });
    }

    if let Some((index, byte)) = source
        .bytes()
        .enumerate()
        .find(|&(_, b)| !is_source_byte(b))
    {
        return Err(CspError::InvalidSource {
            directive: directive.to_string(),
            source: source.to_string(),
            index,
            byte,
        });
    }

    Ok(())
}

/// `%x21-2B` ∪ `%x2D-3A` ∪ `%x3C-7E`.
///
/// Excludes SP (`%x20`), `,` (`%x2C`), `;` (`%x3B`), DEL, every C0 and C1 control byte, and every
/// non-ASCII byte. The three named exclusions are the separators of a source list, a policy list
/// and a directive list; the rest cannot appear in an HTTP field value without a smuggling risk.
#[inline]
const fn is_source_byte(b: u8) -> bool {
    matches!(b, 0x21..=0x2b | 0x2d..=0x3a | 0x3c..=0x7e)
}

#[cfg(test)]
mod tests {
    use super::{canonical_directive_name, validate_source};
    use crate::error::CspError;

    #[test]
    fn directive_names_are_lowercased() {
        assert_eq!(
            canonical_directive_name("Script-Src").unwrap(),
            "script-src"
        );
    }

    /// The injection this module exists for: a `;` in a config-derived origin opens a second directive.
    #[test]
    fn semicolon_in_a_source_is_rejected() {
        let err = validate_source("img-src", "https://evil.example;script-src")
            .expect_err("a source carrying a directive separator must not be accepted");
        assert!(matches!(err, CspError::InvalidSource { byte: b';', .. }));
    }

    /// A space would split one source into two without any parse error anywhere.
    #[test]
    fn whitespace_in_a_source_is_rejected() {
        for source in ["a b", "a\tb", "a\nb", " a", "a "] {
            assert!(
                validate_source("img-src", source).is_err(),
                "{source:?} must be rejected"
            );
        }
    }

    /// `,` separates two whole policies in one header.
    #[test]
    fn comma_in_a_source_is_rejected() {
        assert!(validate_source("img-src", "https://a.example,https://b.example").is_err());
    }

    #[test]
    fn the_source_expressions_a_real_policy_uses_are_accepted() {
        for source in [
            "'self'",
            "'none'",
            "'wasm-unsafe-eval'",
            "https:",
            "data:",
            "https://challenges.cloudflare.com",
            "'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='",
            "'nonce-cnJhbmRvbTEyMzQ1Ng=='",
            "*.example.com:8443/path",
        ] {
            validate_source("script-src", source).unwrap_or_else(|e| panic!("{source}: {e}"));
        }
    }

    /// Routed, and only in the directives the routing table names.
    #[test]
    fn routing_is_scoped_to_the_documented_directives() {
        assert!(matches!(
            validate_source("style-src", "'unsafe-inline'"),
            Ok(())
        ));
        assert!(matches!(
            validate_source("script-src", "'UNSAFE-INLINE'"),
            Err(CspError::RoutedSourceExpression {
                method: "allow_unsafe_inline_script",
                ..
            })
        ));
        assert!(matches!(
            validate_source("script-src", "'strict-dynamic'"),
            Err(CspError::RoutedSourceExpression {
                method: "strict_dynamic",
                ..
            })
        ));
        // Routed in every directive, not just script-src.
        for directive in ["script-src", "worker-src", "default-src"] {
            assert!(matches!(
                validate_source(directive, "'unsafe-eval'"), // csp-lint: allow — asserting the token is unreachable through the string API
                Err(CspError::RoutedSourceExpression {
                    method: "allow_unsafe_eval",
                    ..
                })
            ));
        }
        // `'wasm-unsafe-eval'` is a different source expression and is not routed.
        validate_source("script-src", "'wasm-unsafe-eval'").unwrap();
    }
}
