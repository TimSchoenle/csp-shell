//! An arbitrary sequence of builder operations, checked against the structural invariants a
//! rendered policy must satisfy however it was assembled.
//!
//! [`csp_directive`](super::csp_directive) covers one call in depth. This oracle covers the
//! interactions between calls: replacement keeping its position, `extend` creating a directive,
//! the named escape hatches reaching into `script-src`, and the nonce slot surviving every later
//! mutation.

use arbitrary::{Arbitrary, Unstructured};
use csp_shell::{scan_shell, Csp, Directive, SandboxToken, Source, SourceDirective, SourceList};

use crate::support;

/// One source expression, from whichever construction path the fuzzer picks.
#[derive(Arbitrary, Debug)]
pub enum SourceSpec {
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
pub enum Operation {
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
pub struct Session {
    /// Start from the documented preset rather than an empty policy half the time.
    pub from_preset: bool,
    pub operations: Vec<Operation>,
}

fn source_directive(index: u8) -> SourceDirective {
    SourceDirective::ALL[usize::from(index) % SourceDirective::ALL.len()]
}

fn build_sources(specs: Vec<SourceSpec>) -> Vec<Source> {
    specs.into_iter().filter_map(SourceSpec::build).collect()
}

/// Decodes `data` into a builder session and runs it.
///
/// The decode is `arbitrary_take_rest` over the raw bytes, which is exactly what
/// `libfuzzer_sys::fuzz_target!` does for a typed argument — so a corpus entry a campaign found
/// means the same thing here as it did under the fuzzer.
///
/// # Panics
///
/// See [`run`].
pub fn check(data: &[u8]) {
    let Ok(session) = Session::arbitrary_take_rest(Unstructured::new(data)) else {
        return;
    };
    run(session);
}

/// Applies every operation in `session` and asserts the policy it renders to.
///
/// # Panics
///
/// If the rendered policy breaks its structural contract, or if the per-response nonce and the
/// cache obligation that must accompany it come apart.
pub fn run(session: Session) {
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

    support::assert_field_value(rendered);
    support::assert_structure(rendered);

    if policy.is_per_response() {
        // The obligation is not optional: a cached shell pins one nonce across every reader for
        // the lifetime of the cache entry.
        assert_eq!(headers.cache_control, Some("no-cache"));
        let script_src =
            support::directive_of(rendered, "script-src").expect("a nonce needs a script-src");
        assert!(
            support::nonce_sources(script_src).next().is_some(),
            "a per-response policy with no nonce in script-src: {rendered:?}"
        );

        // Two responses differ only in the nonce; nothing else may vary between renderings.
        let other = policy.headers().content_security_policy;
        assert_eq!(support::strip_nonce(rendered), support::strip_nonce(&other));
        // And they do differ. A "per-response" nonce that repeated across responses would be a
        // static one, which is precisely what the `no-cache` obligation exists to rule out.
        assert_ne!(
            *rendered, other,
            "the nonce did not change between responses"
        );
    } else {
        assert_eq!(headers.cache_control, None);
        // A constant policy must be constant, or a consumer caching it at startup is wrong.
        //
        // Constancy is the whole assertion, and deliberately so. A `'nonce-…'` present in the
        // rendered header is *not* disqualifying here: nonces are not routed source expressions,
        // so `directive` and `extend` accept one in any directive, and a caller who writes a
        // fixed nonce into `connect-src` gets a fixed nonce. What separates that from a minted
        // one is whether the header changes between renderings — which is what is checked.
        assert_eq!(*rendered, policy.headers().content_security_policy);
    }
}
