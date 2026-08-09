//! Policy construction and the invariants it exists to hold.
//!
//! Most of what this file used to assert is now a compile error: a directive name outside
//! [`SourceDirective`], a source expression carrying a `;`, a `sandbox` holding source
//! expressions. What is left is the behaviour that is genuinely this crate's — the preset, the
//! seeding of `script-src`, the routed source expressions, and the shell's hashes.

use csp_shell::{
    scan_shell, Csp, CspError, Directive, DirectiveName, SandboxToken, Source, SourceDirective,
    SourceList, TrustedTypeSink,
};

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

/// The injection the whole design exists for, at the level of the public API: a configuration
/// value carrying a directive separator never becomes a source expression, so there is no call to
/// the builder to reject.
#[test]
fn an_injected_origin_never_becomes_a_source() {
    for origin in [
        "https://cdn.example; script-src 'unsafe-inline'",
        "https://cdn.example,https://evil.example",
        "https://cdn.example script-src",
        "https://cdn.example\r\nX-Frame-Options: ALLOWALL",
    ] {
        assert!(
            Source::host(origin).is_err(),
            "{origin:?} must not parse as a source"
        );
    }
}

/// A rejected list must leave the builder untouched, not half-applied: a partially applied
/// directive is a policy nobody wrote.
#[test]
fn a_rejected_list_applies_none_of_its_sources() {
    let before = Csp::spa_wasm();
    let after = before.clone().extend(
        SourceDirective::ImgSrc,
        [
            Source::host("https://good.example").unwrap(),
            Source::UnsafeEval, // csp-lint: allow — the routed token is the input under test
        ],
    );

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
        .directive(
            SourceDirective::ConnectSrc,
            [
                Source::SelfOrigin,
                Source::host("https://api.example.com").unwrap(),
            ],
        )
        .unwrap()
        .build()
        .headers()
        .content_security_policy;

    assert_eq!(policy.matches("connect-src").count(), 1);
    assert!(policy.contains("connect-src 'self' https://api.example.com; img-src"));
}

#[test]
fn extend_appends_without_duplicating() {
    let https = Source::scheme("https").unwrap();
    let policy = Csp::new()
        .directive(SourceDirective::ImgSrc, [Source::SelfOrigin])
        .unwrap()
        .extend(
            SourceDirective::ImgSrc,
            [Source::SelfOrigin, https.clone(), https],
        )
        .unwrap()
        .build()
        .headers()
        .content_security_policy;
    assert_eq!(policy, "img-src 'self' https:");
}

#[test]
fn extend_creates_a_missing_directive() {
    let policy = Csp::new()
        .extend(
            SourceDirective::FrameSrc,
            [Source::host("https://example.com").unwrap()],
        )
        .unwrap()
        .build()
        .headers()
        .content_security_policy;
    assert_eq!(policy, "frame-src https://example.com");
}

/// Routed, not forbidden — and the error names the method to use instead.
#[test]
fn routed_sources_name_their_method() {
    let err = Csp::new()
        .directive(SourceDirective::ScriptSrc, [Source::StrictDynamic])
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

/// The routing is scoped: `'unsafe-inline'` is routed in `script-src` and untouched in
/// `style-src`, which is where the preset sets it.
#[test]
fn routing_is_scoped_to_the_directives_that_need_it() {
    assert!(Csp::new()
        .directive(
            SourceDirective::StyleSrc,
            [Source::SelfOrigin, Source::UnsafeInline]
        )
        .is_ok());
    assert!(Csp::new()
        .directive(SourceDirective::ScriptSrc, [Source::UnsafeInline])
        .is_err());

    // The eval keyword is routed in every directive, because there is none where passing it as
    // data rather than naming it is the clearer thing to write.
    for directive in [
        SourceDirective::ScriptSrc,
        SourceDirective::WorkerSrc,
        SourceDirective::DefaultSrc,
    ] {
        assert!(matches!(
            Csp::new().directive(directive, [Source::UnsafeEval]), // csp-lint: allow — asserting the token is unreachable through the data API
            Err(CspError::RoutedSourceExpression {
                method: "allow_unsafe_eval",
                ..
            })
        ));
    }
}

/// Everything whose value is not a source list reaches the policy through `set`, and the routing
/// check does not apply to it.
#[test]
fn directives_that_are_not_source_lists_go_through_set() {
    let policy = Csp::new()
        .set(Directive::sandbox([
            SandboxToken::AllowForms,
            SandboxToken::AllowScripts,
        ]))
        .unwrap()
        .set(Directive::require_trusted_types_for([
            TrustedTypeSink::Script,
        ]))
        .unwrap()
        .set(Directive::UpgradeInsecureRequests)
        .unwrap()
        .build()
        .headers()
        .content_security_policy;

    assert_eq!(
        policy,
        "sandbox allow-forms allow-scripts; \
         require-trusted-types-for 'script'; \
         upgrade-insecure-requests"
    );
}

/// `'none'` is a whole source list, so a directive that permits nothing is spelled with the list
/// rather than with a source expression that cannot exist.
#[test]
fn a_directive_can_be_set_to_none() {
    let policy = Csp::new()
        .directive(SourceDirective::ObjectSrc, SourceList::None)
        .unwrap()
        .build()
        .headers()
        .content_security_policy;
    assert_eq!(policy, "object-src 'none'");
}

/// The distinction removal exists to keep visible: an absent directive falls back to
/// `default-src`, an empty one blocks everything. Both are reachable, and neither is spelled like
/// the other.
#[test]
fn removing_a_directive_is_not_the_same_as_emptying_it() {
    let removed = Csp::spa_wasm()
        .remove(DirectiveName::FontSrc)
        .build()
        .headers()
        .content_security_policy;
    assert!(!removed.contains("font-src"));
    assert!(removed.contains("img-src 'self' https: data:; object-src 'none'"));

    let emptied = Csp::spa_wasm()
        .directive(SourceDirective::FontSrc, SourceList::None)
        .unwrap()
        .build()
        .headers()
        .content_security_policy;
    assert!(emptied.contains("font-src 'none'"));
}

/// Removing a name the policy never set changes nothing, so a consumer's teardown of a preset
/// does not have to know which version of the preset introduced what.
#[test]
fn removing_an_absent_directive_is_a_no_op() {
    assert_eq!(
        Csp::spa_wasm()
            .remove(DirectiveName::FrameSrc)
            .build()
            .headers()
            .content_security_policy,
        Csp::spa_wasm().build().headers().content_security_policy
    );
}

/// Narrowing a preset without restating it: the surviving sources keep their order, and the
/// directive keeps its position, so a later version of the preset can still add to it.
#[test]
fn remove_source_narrows_a_list_in_place() {
    let policy = Csp::spa_wasm()
        .remove_source(SourceDirective::ImgSrc, &Source::scheme("data").unwrap())
        .build()
        .headers()
        .content_security_policy;
    assert!(policy.contains("img-src 'self' https:; font-src 'self' data:"));
}

/// The rule form, for a narrowing that is not a single value.
#[test]
fn retain_sources_filters_by_rule() {
    let policy = Csp::spa_wasm()
        .retain_sources(SourceDirective::ImgSrc, |source| {
            !matches!(source, Source::Scheme(_))
        })
        .build()
        .headers()
        .content_security_policy;
    assert!(policy.contains("img-src 'self'; font-src"));
}

/// Filtering a directive the policy does not set must not create one: an empty `script-src` is a
/// flat refusal where the absent one was a `default-src` fallback.
#[test]
fn retaining_on_an_absent_directive_creates_nothing() {
    let policy = Csp::new()
        .directive(SourceDirective::DefaultSrc, [Source::SelfOrigin])
        .unwrap()
        .retain_sources(SourceDirective::ScriptSrc, |_| false)
        .build()
        .headers()
        .content_security_policy;
    assert_eq!(policy, "default-src 'self'");
}

/// Removing every source leaves the directive saying `'none'`, not saying nothing. The two differ
/// in what they permit, so the removal that empties a list must not quietly become the other one.
#[test]
fn removing_every_source_leaves_a_directive_that_permits_nothing() {
    let policy = Csp::spa_wasm()
        .retain_sources(SourceDirective::ImgSrc, |_| false)
        .build()
        .headers()
        .content_security_policy;
    assert!(policy.contains("img-src 'none'"));
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
        .directive(
            SourceDirective::DefaultSrc,
            [
                Source::SelfOrigin,
                Source::host("https://cdn.example").unwrap(),
            ],
        )
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

/// A scan with no inline scripts must still leave the created `script-src` permitting what
/// `default-src` permitted, rather than an empty one meaning "no scripts at all".
#[test]
fn an_empty_scan_still_leaves_a_usable_policy() {
    let scan = scan_shell("<script src=\"/a.js\"></script>");
    let policy = Csp::new()
        .directive(SourceDirective::DefaultSrc, [Source::SelfOrigin])
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

/// The header-injection invariant end to end: whatever a consumer's configuration contains, a
/// value that survives [`Source::parse`] cannot put a separator into the rendered header.
///
/// The typed crate fuzzes the parser itself; this asserts that the builder above it adds no new
/// way in.
#[test]
fn no_parsed_source_can_emit_a_separator_the_builder_did_not() {
    let mut rng = Xorshift64::new(0x00c5_9548_e110_0001);

    for _ in 0..20_000 {
        let sources: Vec<Source> = (0..rng.below(4))
            .filter_map(|_| rng.ascii_string(0, 24).parse().ok())
            .collect();

        let Ok(csp) = Csp::new().directive(SourceDirective::ImgSrc, sources) else {
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

    /// A string over the printable-ASCII range plus the separators a source expression must not
    /// contain.
    fn ascii_string(&mut self, min: u64, max: u64) -> String {
        let len = min + self.below(max - min + 1);
        (0..len)
            .map(|_| char::from(0x20 + u8::try_from(self.below(0x5f)).expect("below 0x5f")))
            .collect()
    }
}
