//! The two concessions, and the properties their doc comments claim.

#![cfg(feature = "cloudflare")]

use csp_shell::{cloudflare, scan_shell, Csp};

/// The text `Policy::headers` splices a nonce in behind.
const SPLICE: &str = " 'nonce-";

/// The concession is the nonce; nothing is stamped into the shell, because Cloudflare reads
/// the response header and copies the nonce onto what it injects.
#[test]
fn script_nonce_reserves_a_slot_and_nothing_else() {
    let with = cloudflare::script_nonce(Csp::spa_wasm()).build();
    let without = Csp::spa_wasm().build();

    assert!(with.is_per_response());
    assert_eq!(with.headers().cache_control, Some("no-cache"));

    // The only difference is the nonce source; no directive is widened, added or dropped.
    let with_header = with.headers().content_security_policy;
    let start = with_header.find(SPLICE).expect("a nonce is spliced in");
    let closing_quote = start
        + SPLICE.len()
        + with_header[start + SPLICE.len()..]
            .find('\'')
            .expect("the nonce is quoted");
    let mut stripped = with_header.clone();
    stripped.replace_range(start..=closing_quote, "");
    assert_eq!(stripped, without.headers().content_security_policy);
}

/// The shell's own inline scripts keep running by hash either way — the coexistence that
/// makes the concession narrow rather than a return to `'unsafe-inline'`.
#[test]
fn the_shells_hashes_survive_the_concession() {
    let scan = scan_shell("<script>alert(1)</script>");
    let header = cloudflare::script_nonce(Csp::spa_wasm().with_scan(&scan))
        .build()
        .headers()
        .content_security_policy;

    assert!(header.contains(scan.hashes[0].as_str()));
    assert!(header.contains("'nonce-"));
}

/// One origin, two directives. Admitting the script without the frame renders an empty box.
#[test]
fn turnstile_admits_its_origin_in_both_directives() {
    let header = cloudflare::turnstile(Csp::spa_wasm())
        .expect("literal source expressions")
        .build()
        .headers()
        .content_security_policy;

    assert!(
        header.contains("script-src 'self' 'wasm-unsafe-eval' https://challenges.cloudflare.com")
    );
    assert!(header.contains("frame-src https://challenges.cloudflare.com"));
    assert_eq!(
        header.matches("https://challenges.cloudflare.com").count(),
        2
    );
}

/// Turnstile must not weaken anything else, and in particular must not touch `frame-ancestors`,
/// which controls who may frame *this* page rather than what this page may frame.
#[test]
fn turnstile_leaves_frame_ancestors_alone() {
    let header = cloudflare::turnstile(Csp::spa_wasm())
        .unwrap()
        .build()
        .headers()
        .content_security_policy;
    assert!(header.contains("frame-ancestors 'none'"));
}

/// The two concessions are independent and compose.
#[test]
fn both_concessions_compose() {
    let csp = cloudflare::turnstile(cloudflare::script_nonce(Csp::spa_wasm())).unwrap();
    let policy = csp.build();
    let header = policy.headers().content_security_policy;

    assert!(policy.is_per_response());
    assert!(header.contains("https://challenges.cloudflare.com"));
    // The nonce is spliced after every source `script-src` ended up with, Turnstile's included.
    assert!(header.contains("https://challenges.cloudflare.com 'nonce-"));
}
