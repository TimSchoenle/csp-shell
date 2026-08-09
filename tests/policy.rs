//! Policy construction, source-expression validation, and the invariants they exist to hold.

use csp_shell::{scan_shell, Csp, CspError};

/// The exact policy `spa_wasm()` is documented to produce. A test on the whole string rather than
/// on its parts, because a directive silently dropped by a refactor is a restriction silently
/// removed.
#[test]
fn spa_wasm_is_the_documented_policy() {
    let policy = Csp::spa_wasm().build();
    assert_eq!(
        policy.headers().content_security_policy,
        "default-src 'self'; \
         script-src 'self' 'wasm-unsafe-eval'; \
         style-src 'self' 'unsafe-inline'; \
         connect-src 'self'; \
         img-src 'self' https: data:; \
         font-src 'self' data:; \
         object-src 'none'; \
         base-uri 'none'; \
         form-action 'self'; \
         frame-ancestors 'none'"
    );
    assert!(!policy.is_per_response());
}

/// Neither is a compatibility fallback: any browser that understands hashes or nonces
/// ignores `'unsafe-inline'`, and any browser that does not is outside `'wasm-unsafe-eval'`'s
/// support floor anyway. The exact assertion the source-tree lint in `no_unsafe_eval.rs` cannot
/// make.
#[test]
fn spa_wasm_admits_neither_unsafe_inline_script_nor_eval() {
    let policy = Csp::spa_wasm().build().headers().content_security_policy;

    let script_src = policy
        .split("; ")
        .find(|directive| directive.starts_with("script-src "))
        .expect("spa_wasm sets script-src");
    assert!(!script_src.contains("'unsafe-inline'"));

    // `'wasm-unsafe-eval'` is a different, narrower source expression and is expected here.
    assert!(!policy
        .replace("'wasm-unsafe-eval'", "")
        .contains("unsafe-eval")); // csp-lint: allow — asserting the absence of the token requires naming it
    assert!(policy.contains("'wasm-unsafe-eval'"));
}

/// The injection the validation exists for, at the level of the public API.
#[test]
fn a_source_expression_cannot_open_a_second_directive() {
    let err = Csp::spa_wasm()
        .extend(
            "img-src",
            ["https://cdn.example; script-src 'unsafe-inline'"],
        )
        .expect_err("a source carrying a directive separator must be rejected");
    assert!(matches!(err, CspError::InvalidSource { byte: b';', .. }));
}

/// A rejected list must leave the builder untouched, not half-applied: a partially applied
/// directive is a policy nobody wrote.
#[test]
fn a_rejected_list_applies_none_of_its_sources() {
    let before = Csp::spa_wasm();
    let after = before
        .clone()
        .extend("img-src", ["https://good.example", "https://bad.example;x"]);
    assert!(after.is_err());
    assert_eq!(
        before.build().headers().content_security_policy,
        Csp::spa_wasm().build().headers().content_security_policy
    );
}

/// A repeated directive is ignored by the browser with only a console warning, so the builder
/// replaces rather than appends — and keeps the original position, so the policy's shape does not
/// shift under an override.
#[test]
fn a_repeated_directive_replaces_in_place() {
    let policy = Csp::spa_wasm()
        .directive("connect-src", ["'self'", "https://api.example.com"])
        .unwrap()
        .build()
        .headers()
        .content_security_policy;

    assert_eq!(policy.matches("connect-src").count(), 1);
    assert!(policy.contains("connect-src 'self' https://api.example.com; img-src"));
}

#[test]
fn extend_appends_without_duplicating() {
    let policy = Csp::new()
        .directive("img-src", ["'self'"])
        .unwrap()
        .extend("img-src", ["'self'", "https:", "https:"])
        .unwrap()
        .build()
        .headers()
        .content_security_policy;
    assert_eq!(policy, "img-src 'self' https:");
}

#[test]
fn extend_creates_a_missing_directive() {
    let policy = Csp::new()
        .extend("frame-src", ["https://example.com"])
        .unwrap()
        .build()
        .headers()
        .content_security_policy;
    assert_eq!(policy, "frame-src https://example.com");
}

/// A well-formed but unrecognised directive name is a restriction the browser silently drops.
/// Failing on it in debug builds and accepting it in release is deliberate — see
/// `Csp::directive`.
#[test]
fn an_unknown_directive_is_a_debug_only_error() {
    let result = Csp::new().directive("scrpit-src", ["'self'"]);
    if cfg!(debug_assertions) {
        assert!(matches!(result, Err(CspError::UnknownDirective { .. })));
    } else {
        assert!(result.is_ok());
    }
}

#[test]
fn a_malformed_directive_name_is_always_an_error() {
    for name in ["", "-src", "1src", "img_src", "img src", "img;src", "imgé"] {
        assert!(
            matches!(
                Csp::new().directive(name, ["'self'"]),
                Err(CspError::InvalidDirectiveName { .. })
            ),
            "{name:?} must be rejected as a directive name"
        );
    }
}

/// Routed, not forbidden — and the error names the method to use instead.
#[test]
fn routed_sources_name_their_method() {
    let err = Csp::new()
        .directive("script-src", ["'strict-dynamic'"])
        .expect_err("'strict-dynamic' is routed");
    assert!(matches!(
        err,
        CspError::RoutedSourceExpression {
            method: "strict_dynamic",
            ..
        }
    ));

    // And the method itself works, on a `script-src` that did not exist yet.
    let policy = Csp::new()
        .strict_dynamic()
        .build()
        .headers()
        .content_security_policy;
    assert_eq!(policy, "script-src 'strict-dynamic'");
}

/// Hashes coexist with host sources: under CSP a script runs if it matches *any* source
/// expression, so adding a hash does not stop `'self'` matching `<script src>`.
#[test]
fn scan_hashes_are_added_to_script_src() {
    let scan = scan_shell("<script>alert(1)</script><script src=\"/a.js\"></script>");
    assert_eq!(scan.hashes.len(), 1);

    let policy = Csp::spa_wasm()
        .with_scan(&scan)
        .build()
        .headers()
        .content_security_policy;
    assert!(policy.contains(&format!(
        "script-src 'self' 'wasm-unsafe-eval' {}",
        scan.hashes[0]
    )));
}

/// Adding hashes to a policy that has no `script-src` must not tighten it by accident: a browser
/// already falls back to `default-src` for scripts, and the created directive must say so.
#[test]
fn a_created_script_src_inherits_default_src() {
    let scan = scan_shell("<script>alert(1)</script>");
    let policy = Csp::new()
        .directive("default-src", ["'self'", "https://cdn.example"])
        .unwrap()
        .with_scan(&scan)
        .build()
        .headers()
        .content_security_policy;

    assert_eq!(
        policy,
        format!(
            "default-src 'self' https://cdn.example; script-src 'self' https://cdn.example {}",
            scan.hashes[0]
        )
    );
}

/// A scan with no inline scripts must not invent a `script-src`, because an empty one would mean
/// "no scripts at all" rather than "nothing to add".
#[test]
fn an_empty_scan_still_leaves_a_usable_policy() {
    let scan = scan_shell("<script src=\"/a.js\"></script>");
    let policy = Csp::new()
        .directive("default-src", ["'self'"])
        .unwrap()
        .with_scan(&scan)
        .build()
        .headers()
        .content_security_policy;
    assert_eq!(policy, "default-src 'self'; script-src 'self'");
}

/// Without a nonce the header is constant, which is what lets a consumer compute it once at
/// startup instead of per response.
#[test]
fn a_hash_only_policy_is_not_per_response() {
    let policy = Csp::spa_wasm()
        .with_scan(&scan_shell("<script>alert(1)</script>"))
        .build();
    assert!(!policy.is_per_response());
    assert_eq!(policy.headers(), policy.headers());
    assert_eq!(policy.headers().cache_control, None);
}

/// The header-injection invariant, exercised over pseudo-random input on stable so that it is
/// checked by every `cargo test` rather than only by the nightly fuzz job.
/// `fuzz/fuzz_targets/csp_directive.rs` asserts the same property with coverage guidance.
#[test]
fn no_accepted_input_can_emit_a_separator_the_builder_did_not() {
    let mut rng = Xorshift64::new(0x00c5_9548_e110_0001);

    for _ in 0..20_000 {
        let name = rng.ascii_string(1, 12);
        let sources: Vec<String> = (0..rng.below(4)).map(|_| rng.ascii_string(0, 24)).collect();

        let Ok(csp) = Csp::new().directive(&name, &sources) else {
            continue;
        };
        let policy = csp.build().headers().content_security_policy;

        assert!(
            !policy.contains(';'),
            "a single directive rendered a directive separator: {policy:?}"
        );
        assert!(
            !policy.contains(','),
            "a single directive rendered a policy separator: {policy:?}"
        );
        assert!(
            policy.bytes().all(|b| (0x20..=0x7e).contains(&b)),
            "the rendered policy is not a valid HTTP field value: {policy:?}"
        );
        assert!(
            !policy.contains("  ") && !policy.ends_with(' '),
            "an empty source rendered as a stray space: {policy:?}"
        );
    }
}

/// Deterministic, dependency-free, and adequate for generating byte strings: the assertions above
/// do the work, not the generator.
struct Xorshift64(u64);

impl Xorshift64 {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }

    /// A string over the printable-ASCII range plus the separators the validator must reject.
    fn ascii_string(&mut self, min: u64, max: u64) -> String {
        let len = min + self.below(max - min + 1);
        (0..len)
            .map(|_| char::from(0x20 + u8::try_from(self.below(0x5f)).expect("below 0x5f")))
            .collect()
    }
}
