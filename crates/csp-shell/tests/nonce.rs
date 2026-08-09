//! The `nonce` feature: splicing, the cache obligation, and the hash/nonce coexistence that the
//! Cloudflare concession rests on.

#![cfg(feature = "nonce")]

use csp_shell::{
    scan_shell, Csp, DirectiveName, Nonce, Policy, Source, SourceDirective, SourceList,
};

/// The base64 value between `'nonce-` and the closing quote, from one rendered header.
fn minted_nonce_from(header: &str) -> String {
    let start = header.find("'nonce-").expect("a nonce slot was reserved") + "'nonce-".len();
    let end = start + header[start..].find('\'').expect("the nonce is quoted");
    header[start..end].to_owned()
}

/// The nonce this policy mints for one response.
fn minted_nonce(policy: &Policy) -> String {
    minted_nonce_from(&policy.headers().content_security_policy)
}

/// Without `no-cache` the minted nonce is shared by every reader served from cache, which
/// admits exactly the inline script the nonce exists to constrain. The obligation is returned
/// alongside the policy so that ignoring it is visible at the call site.
#[test]
fn a_per_response_policy_always_obliges_no_cache() {
    let policy = Csp::spa_wasm().per_response_nonce(true).build();
    assert!(policy.is_per_response());

    for _ in 0..8 {
        assert_eq!(policy.headers().cache_control, Some("no-cache"));
    }
}

/// A nonce that repeats is `'unsafe-inline'` with extra steps.
#[test]
fn successive_responses_carry_different_nonces() {
    let policy = Csp::spa_wasm().per_response_nonce(true).build();
    let first = minted_nonce(&policy);
    for _ in 0..64 {
        assert_ne!(minted_nonce(&policy), first);
    }
}

/// The head/tail splice must produce exactly the policy that would have been built with
/// that nonce as a literal source — the assertion that makes splicing safe to prefer over
/// rebuilding.
#[test]
fn splicing_round_trips_against_a_literal_nonce() {
    let scan = scan_shell("<script>alert(1)</script>");
    let spliced = Csp::spa_wasm()
        .with_scan(&scan)
        .per_response_nonce(true)
        .build();

    let header = spliced.headers().content_security_policy;
    let nonce = minted_nonce_from(&header);

    let rebuilt = Csp::spa_wasm()
        .with_scan(&scan)
        .extend(
            SourceDirective::ScriptSrc,
            [Source::nonce(&nonce).expect("a minted nonce must parse")],
        )
        .unwrap()
        .build()
        .headers()
        .content_security_policy;

    assert_eq!(header, rebuilt);
}

/// The load-bearing assumption behind the Cloudflare concession: under CSP3 a script executes if
/// it matches *any* source expression, so the shell's own inline scripts keep running by hash
/// while an edge-injected one runs by nonce. Both must therefore be present in one `script-src`.
#[test]
fn hashes_and_a_nonce_coexist_in_one_script_src() {
    let scan = scan_shell("<script>alert(1)</script><script>alert(2)</script>");
    assert_eq!(scan.hashes.len(), 2);

    let header = Csp::spa_wasm()
        .with_scan(&scan)
        .per_response_nonce(true)
        .build()
        .headers()
        .content_security_policy;

    let script_src = header
        .split("; ")
        .find(|directive| directive.starts_with("script-src "))
        .expect("script-src is present");

    for hash in &scan.hashes {
        assert!(
            script_src.contains(&hash.to_string()),
            "{hash} missing from {script_src}"
        );
    }
    assert!(script_src.contains("'nonce-"));
    assert_eq!(header.matches("'nonce-").count(), 1, "one slot, one nonce");
}

/// The nonce belongs to `script-src` and nowhere else; splicing it into the wrong directive would
/// widen the policy silently.
#[test]
fn the_nonce_lands_at_the_end_of_script_src() {
    let header = Csp::spa_wasm()
        .per_response_nonce(true)
        .build()
        .headers()
        .content_security_policy;
    assert!(header.contains("script-src 'self' 'wasm-unsafe-eval' 'nonce-"));
    assert!(header.contains("'; style-src 'self' 'unsafe-inline'"));
}

/// Reserving a slot on a policy with no `script-src` must not tighten it: the browser already
/// falls back to `default-src` for scripts, and the created directive says exactly that.
#[test]
fn a_created_script_src_inherits_default_src() {
    let header = Csp::new()
        .directive(
            SourceDirective::DefaultSrc,
            [
                Source::SelfOrigin,
                Source::host("https://cdn.example").unwrap(),
            ],
        )
        .unwrap()
        .per_response_nonce(true)
        .build()
        .headers()
        .content_security_policy;
    assert!(header.starts_with(
        "default-src 'self' https://cdn.example; script-src 'self' https://cdn.example 'nonce-"
    ));
}

/// The slot is filled when the policy is built, not when it is reserved, so the seeding sees the
/// `default-src` the policy ends up with rather than the one it had at that moment. Reserving
/// first and configuring afterwards is the order a consumer reaches for when the nonce comes from
/// a deployment flag and the sources come from configuration.
#[test]
fn reserving_the_slot_before_default_src_seeds_from_it_anyway() {
    let header = Csp::new()
        .per_response_nonce(true)
        .directive(SourceDirective::DefaultSrc, [Source::SelfOrigin])
        .unwrap()
        .build()
        .headers()
        .content_security_policy;
    assert!(header.starts_with("default-src 'self'; script-src 'self' 'nonce-"));
}

/// Removing `script-src` while a slot is reserved must not drop the nonce: the policy would still
/// render, the edge-injected script would still be refused, and nothing would say why.
#[test]
fn removing_script_src_does_not_silently_drop_the_nonce() {
    let policy = Csp::spa_wasm()
        .per_response_nonce(true)
        .remove(DirectiveName::ScriptSrc)
        .build();

    assert!(policy.is_per_response());
    let header = policy.headers().content_security_policy;
    assert!(header.contains("'nonce-"));
    // Re-created from `default-src`, and at the end rather than in the position it was removed
    // from — the removal is honoured for everything except the slot that was reserved.
    assert!(header.contains("script-src 'self' 'nonce-"));
}

/// `'none'` beside a nonce is a list this crate's types cannot spell and a browser reads as the
/// nonce alone. A `script-src` with nothing else in it renders as a bare name so that the header
/// says what is actually in force.
#[test]
fn an_otherwise_empty_script_src_renders_without_none() {
    for csp in [
        Csp::new().per_response_nonce(true),
        Csp::spa_wasm()
            .per_response_nonce(true)
            .retain_sources(SourceDirective::ScriptSrc, |_| false),
        Csp::spa_wasm()
            .per_response_nonce(true)
            .directive(SourceDirective::ScriptSrc, SourceList::None)
            .unwrap(),
    ] {
        let header = csp.build().headers().content_security_policy;
        assert!(
            header.contains("script-src 'nonce-"),
            "expected a bare script-src: {header}"
        );
        assert!(
            !header.contains("script-src 'none'"),
            "'none' rendered beside a nonce: {header}"
        );
    }
}

/// Reserving and then releasing a slot leaves a policy that is constant again, so a consumer's
/// `is_per_response` branch does not go stale.
#[test]
fn releasing_the_slot_makes_the_policy_constant_again() {
    let policy = Csp::spa_wasm()
        .per_response_nonce(true)
        .per_response_nonce(false)
        .build();
    assert!(!policy.is_per_response());
    assert_eq!(policy.headers().cache_control, None);
    assert!(!policy.headers().content_security_policy.contains("'nonce-"));
}

/// A minted nonce must be usable as a source expression in its own right, including through the
/// parser a consumer would reach for if it arrived as text.
#[test]
fn a_minted_nonce_is_a_valid_source_expression() {
    let nonce = Nonce::mint();
    assert_eq!(
        Source::nonce(nonce.as_str()).expect("a minted nonce must parse"),
        Source::Nonce(nonce.as_source().clone())
    );

    let csp = Csp::new()
        .directive(
            SourceDirective::ScriptSrc,
            [Source::Nonce(nonce.as_source().clone())],
        )
        .expect("a nonce is never routed");
    assert!(csp
        .build()
        .headers()
        .content_security_policy
        .contains(nonce.as_str()));
}
