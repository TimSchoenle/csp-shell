//! The `nonce` feature: splicing, the cache obligation, and the hash/nonce coexistence that the
//! Cloudflare concession rests on.

#![cfg(feature = "nonce")]

use csp_shell::{scan_shell, Csp, Nonce, Policy};

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
        .extend("script-src", [format!("'nonce-{nonce}'")])
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
            script_src.contains(hash.as_str()),
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
        .directive("default-src", ["'self'", "https://cdn.example"])
        .unwrap()
        .per_response_nonce(true)
        .build()
        .headers()
        .content_security_policy;
    assert!(header.starts_with(
        "default-src 'self' https://cdn.example; script-src 'self' https://cdn.example 'nonce-"
    ));
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

/// A minted nonce must be usable as a source expression in its own right, which is what
/// `getrandom` plus the crate's base64 alphabet guarantee.
#[test]
fn a_minted_nonce_is_a_valid_source_expression() {
    let nonce = Nonce::mint();
    let csp = Csp::new()
        .directive("script-src", [format!("'nonce-{nonce}'")])
        .expect("a minted nonce must pass source-expression validation");
    assert!(csp
        .build()
        .headers()
        .content_security_policy
        .contains(nonce.as_str()));
}
