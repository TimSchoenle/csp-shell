//! An arbitrary sequence of builder operations, checked against the structural invariants a
//! rendered policy must satisfy however it was assembled.
//!
//! `csp_directive` covers one call in depth. This target covers the interactions between calls:
//! replacement keeping its position, `extend` creating a directive, the named escape hatches
//! reaching into `script-src`, and the nonce slot surviving every later mutation.

#![no_main]

use arbitrary::Arbitrary;
use csp_shell::{scan_shell, Csp, Directive, SandboxToken, Source, SourceDirective, SourceList};
use libfuzzer_sys::fuzz_target;

/// One source expression, from whichever construction path the fuzzer picks.
#[derive(Arbitrary, Debug)]
enum SourceSpec {
    SelfOrigin,
    WasmUnsafeEval,
    Parsed(String),
    Host(String),
    Sha256([u8; 32]),
}

impl SourceSpec {
    fn build(self) -> Option<Source> {
        Some(match self {
            Self::SelfOrigin => Source::SelfOrigin,
            Self::WasmUnsafeEval => Source::WasmUnsafeEval,
            Self::Parsed(text) => Source::parse(&text).ok()?,
            Self::Host(text) => Source::host(&text).ok()?,
            Self::Sha256(digest) => Source::sha256(&digest),
        })
    }
}

/// One call on the builder.
#[derive(Arbitrary, Debug)]
enum Operation {
    Directive {
        directive: u8,
        sources: Vec<SourceSpec>,
    },
    Extend {
        directive: u8,
        sources: Vec<SourceSpec>,
    },
    Deny {
        directive: u8,
    },
    Sandbox(Vec<u8>),
    WithScan {
        shell: String,
    },
    AllowUnsafeEval,
    AllowUnsafeInlineScript,
    StrictDynamic,
    PerResponseNonce {
        enabled: bool,
    },
}

#[derive(Arbitrary, Debug)]
struct Session {
    /// Start from the documented preset rather than an empty policy half the time.
    from_preset: bool,
    operations: Vec<Operation>,
}

fn source_directive(index: u8) -> SourceDirective {
    SourceDirective::ALL[usize::from(index) % SourceDirective::ALL.len()]
}

fn build_sources(specs: Vec<SourceSpec>) -> Vec<Source> {
    specs.into_iter().filter_map(SourceSpec::build).collect()
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
            Operation::Directive { directive, sources } => csp
                .clone()
                .directive(source_directive(directive), build_sources(sources))
                .unwrap_or(csp),
            Operation::Extend { directive, sources } => csp
                .clone()
                .extend(source_directive(directive), build_sources(sources))
                .unwrap_or(csp),
            Operation::Deny { directive } => csp
                .clone()
                .directive(source_directive(directive), SourceList::None)
                .unwrap_or(csp),
            Operation::Sandbox(indices) => {
                let tokens = indices
                    .into_iter()
                    .map(|index| SandboxToken::ALL[usize::from(index) % SandboxToken::ALL.len()]);
                csp.clone().set(Directive::sandbox(tokens)).unwrap_or(csp)
            }
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
        assert_eq!(nonce_sources(rendered).count(), 1, "{rendered:?}");
        let script_src = directive_of(rendered, "script-src").expect("a nonce needs a script-src");
        assert!(script_src.contains("'nonce-"), "{rendered:?}");

        // Two responses differ only in the nonce; nothing else may vary between renderings.
        let other = policy.headers().content_security_policy;
        assert_eq!(strip_nonce(rendered), strip_nonce(&other));
    } else {
        assert_eq!(headers.cache_control, None);
        assert_eq!(nonce_sources(rendered).count(), 0, "{rendered:?}");
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
fn directive_of<'a>(rendered: &'a str, name: &str) -> Option<&'a str> {
    rendered
        .split("; ")
        .find(|segment| segment == &name || segment.starts_with(&format!("{name} ")))
}

/// The nonce sources of a rendered policy.
///
/// A nonce is a source expression, not a substring. A host-source may carry a path, and a path may
/// contain `'nonce-`; only a token that *starts* with a quote can be a nonce to a browser, so that
/// is what this matches. Searching the raw text instead would report a nonce that is not there —
/// and, worse, would let a genuine one hide behind a path that also matches.
fn nonce_sources(rendered: &str) -> impl Iterator<Item = &str> {
    source_expressions(rendered).filter(|token| token.starts_with("'nonce-"))
}

/// Every source expression in a rendered policy, with the directive names dropped.
fn source_expressions(rendered: &str) -> impl Iterator<Item = &str> {
    rendered
        .split("; ")
        .flat_map(|segment| segment.split(' ').skip(1))
}

/// The rendered policy with its nonce source removed, so two renderings can be compared.
fn strip_nonce(rendered: &str) -> String {
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
