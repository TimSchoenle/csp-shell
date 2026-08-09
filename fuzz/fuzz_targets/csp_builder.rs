//! An arbitrary sequence of builder operations, checked against the structural invariants a
//! rendered policy must satisfy however it was assembled.
//!
//! `csp_directive` covers one call in depth. This target covers the interactions between calls:
//! replacement keeping its position, `extend` creating a directive, the named escape hatches
//! reaching into `script-src`, and the nonce slot surviving every later mutation.

#![no_main]

use arbitrary::Arbitrary;
use csp_shell::{scan_shell, Csp};
use libfuzzer_sys::fuzz_target;

/// One call on the builder.
#[derive(Arbitrary, Debug)]
enum Operation {
    Directive { name: String, sources: Vec<String> },
    Extend { name: String, sources: Vec<String> },
    WithScan { shell: String },
    AllowUnsafeEval,
    AllowUnsafeInlineScript,
    StrictDynamic,
    PerResponseNonce { enabled: bool },
}

#[derive(Arbitrary, Debug)]
struct Session {
    /// Start from the documented preset rather than an empty policy half the time.
    from_preset: bool,
    operations: Vec<Operation>,
}

fuzz_target!(|session: Session| {
    let mut csp = if session.from_preset {
        Csp::spa_wasm()
    } else {
        Csp::new()
    };

    for operation in session.operations {
        csp = match operation {
            // A rejected call must leave the builder untouched, which is why the error path
            // restores the previous value rather than abandoning it.
            Operation::Directive { name, sources } => {
                csp.clone().directive(&name, &sources).unwrap_or(csp)
            }
            Operation::Extend { name, sources } => csp.clone().extend(&name, &sources).unwrap_or(csp),
            Operation::WithScan { shell } => csp.with_scan(&scan_shell(&shell)),
            Operation::AllowUnsafeEval => csp.allow_unsafe_eval(),
            Operation::AllowUnsafeInlineScript => csp.allow_unsafe_inline_script(),
            Operation::StrictDynamic => csp.strict_dynamic(),
            Operation::PerResponseNonce { enabled } => csp.per_response_nonce(enabled),
        };
    }

    let policy = csp.build();
    let headers = policy.headers();
    let rendered = &headers.content_security_policy;

    assert!(
        rendered.bytes().all(|byte| (0x20..=0x7e).contains(&byte)),
        "not a valid HTTP field value: {rendered:?}"
    );
    assert!(!rendered.contains(','), "policy separator in {rendered:?}");

    check_structure(rendered);

    if policy.is_per_response() {
        // The obligation is not optional: a cached shell pins one nonce across every reader for
        // the lifetime of the cache entry.
        assert_eq!(headers.cache_control, Some("no-cache"));
        assert_eq!(rendered.matches("'nonce-").count(), 1, "{rendered:?}");
        let script_src = directive_of(rendered, "script-src").expect("a nonce needs a script-src");
        assert!(script_src.contains("'nonce-"), "{rendered:?}");

        // Two responses differ only in the nonce; nothing else may vary between renderings.
        let other = policy.headers().content_security_policy;
        assert_eq!(strip_nonce(rendered), strip_nonce(&other));
    } else {
        assert_eq!(headers.cache_control, None);
        assert!(!rendered.contains("'nonce-"), "{rendered:?}");
        // A constant policy must be constant, or a consumer caching it at startup is wrong.
        assert_eq!(*rendered, policy.headers().content_security_policy);
    }
});

/// Every structural property of a rendered policy that holds regardless of its content.
fn check_structure(rendered: &str) {
    if rendered.is_empty() {
        return;
    }

    let mut names = Vec::new();
    for segment in rendered.split("; ") {
        assert!(!segment.is_empty(), "empty directive in {rendered:?}");
        assert!(!segment.contains(';'), "unseparated `;` in {rendered:?}");
        assert!(!segment.starts_with(' ') && !segment.ends_with(' '), "{rendered:?}");
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
        assert!(!names.contains(&name), "duplicate directive {name:?} in {rendered:?}");
        names.push(name);

        for token in tokens {
            assert!(!token.is_empty(), "empty source in {rendered:?}");
        }
    }
}

/// The `name …` segment of a rendered policy, if present.
fn directive_of<'a>(rendered: &'a str, name: &str) -> Option<&'a str> {
    rendered
        .split("; ")
        .find(|segment| segment == &name || segment.starts_with(&format!("{name} ")))
}

/// The rendered policy with its nonce source removed, so two renderings can be compared.
fn strip_nonce(rendered: &str) -> String {
    const SPLICE: &str = " 'nonce-";
    let Some(start) = rendered.find(SPLICE) else {
        return rendered.to_owned();
    };
    let Some(offset) = rendered[start + SPLICE.len()..].find('\'') else {
        return rendered.to_owned();
    };
    let mut stripped = rendered.to_owned();
    stripped.replace_range(start..=start + SPLICE.len() + offset, "");
    stripped
}
