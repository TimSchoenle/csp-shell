//! An arbitrary sequence of builder operations, checked against the structural invariants a
//! rendered policy must satisfy however it was assembled.
//!
//! The parse targets cover one value in depth. This one covers the interactions between values:
//! a directive replaced in place, a list extended across calls, `'none'` displaced by a source,
//! and every value type sharing one header. The properties asserted here are the ones a browser
//! silently depends on — one directive per name, one separator per boundary, and nothing outside
//! the field-value alphabet — none of which any single type can guarantee alone.

#![no_main]

use arbitrary::Arbitrary;
use csp_policy::{
    AncestorSource, AncestorSourceList, Directive, DirectiveName, NonceSource, Policy, ReportGroup, ReportUri, SandboxToken, Source, SourceDirective, SourceList,
    TrustedTypePolicyName, TrustedTypeSink, TrustedTypes, Webrtc,
};
use libfuzzer_sys::fuzz_target;

/// The keyword sources, indexed by the fuzzer rather than named by it.
const KEYWORDS: &[Source] = &[
    Source::SelfOrigin,
    Source::UnsafeInline,
    Source::UnsafeEval, // csp-lint: allow — the target exists to reach every source expression
    Source::WasmUnsafeEval,
    Source::UnsafeHashes,
    Source::StrictDynamic,
    Source::ReportSample,
    Source::InlineSpeculationRules,
];

/// One source expression, from whichever construction path the fuzzer picks.
#[derive(Arbitrary, Debug)]
enum SourceSpec {
    Keyword(u8),
    Parsed(String),
    Host(String),
    Scheme(String),
    Sha256([u8; 32]),
    Nonce([u8; 16]),
}

impl SourceSpec {
    fn build(self) -> Option<Source> {
        Some(match self {
            Self::Keyword(index) => KEYWORDS[usize::from(index) % KEYWORDS.len()].clone(),
            Self::Parsed(text) => Source::parse(&text).ok()?,
            Self::Host(text) => Source::host(&text).ok()?,
            Self::Scheme(text) => Source::scheme(&text).ok()?,
            Self::Sha256(digest) => Source::sha256(&digest),
            Self::Nonce(entropy) => Source::Nonce(NonceSource::from_entropy(&entropy)),
        })
    }
}

#[derive(Arbitrary, Debug)]
enum ListSpec {
    None,
    Sources(Vec<SourceSpec>),
}

impl ListSpec {
    fn build(self) -> SourceList {
        match self {
            Self::None => SourceList::None,
            Self::Sources(specs) => SourceList::of(specs.into_iter().filter_map(SourceSpec::build)),
        }
    }
}

#[derive(Arbitrary, Debug)]
enum AncestorSpec {
    SelfOrigin,
    Parsed(String),
    Host(String),
}

impl AncestorSpec {
    fn build(self) -> Option<AncestorSource> {
        Some(match self {
            Self::SelfOrigin => AncestorSource::SelfOrigin,
            Self::Parsed(text) => AncestorSource::parse(&text).ok()?,
            Self::Host(text) => AncestorSource::host(&text).ok()?,
        })
    }
}

/// One call on the builder.
#[derive(Arbitrary, Debug)]
enum Operation {
    Set { directive: u8, list: ListSpec },
    Extend { directive: u8, sources: Vec<SourceSpec> },
    FrameAncestors(Vec<AncestorSpec>),
    Sandbox(Vec<u8>),
    ReportTo(String),
    ReportUri(Vec<String>),
    RequireTrustedTypesFor(bool),
    TrustedTypes { names: Vec<String>, wildcard: bool, allow_duplicates: bool },
    Webrtc(bool),
    UpgradeInsecureRequests,
    BlockAllMixedContent,
    Remove(u8),
}

/// The directive a fuzzer-chosen index refers to.
fn source_directive(index: u8) -> SourceDirective {
    SourceDirective::ALL[usize::from(index) % SourceDirective::ALL.len()]
}

fn directive_name(index: u8) -> DirectiveName {
    DirectiveName::ALL[usize::from(index) % DirectiveName::ALL.len()]
}

fuzz_target!(|operations: Vec<Operation>| {
    let mut policy = Policy::new();

    for operation in operations {
        match operation {
            Operation::Set { directive, list } => {
                policy.set(Directive::Sources(source_directive(directive), list.build()));
            }
            Operation::Extend { directive, sources } => {
                policy.extend_sources(
                    source_directive(directive),
                    sources.into_iter().filter_map(SourceSpec::build),
                );
            }
            Operation::FrameAncestors(specs) => {
                policy.set(Directive::FrameAncestors(AncestorSourceList::of(
                    specs.into_iter().filter_map(AncestorSpec::build),
                )));
            }
            Operation::Sandbox(indices) => {
                policy.set(Directive::sandbox(indices.into_iter().map(|index| {
                    SandboxToken::ALL[usize::from(index) % SandboxToken::ALL.len()]
                })));
            }
            Operation::ReportTo(group) => {
                if let Ok(group) = ReportGroup::parse(&group) {
                    policy.set(Directive::ReportTo(group));
                }
            }
            Operation::ReportUri(endpoints) => {
                policy.set(Directive::report_uri(
                    endpoints
                        .iter()
                        .filter_map(|endpoint| ReportUri::parse(endpoint).ok()),
                ));
            }
            Operation::RequireTrustedTypesFor(present) => {
                let sinks = if present {
                    vec![TrustedTypeSink::Script]
                } else {
                    Vec::new()
                };
                policy.set(Directive::require_trusted_types_for(sinks));
            }
            Operation::TrustedTypes {
                names,
                wildcard,
                allow_duplicates,
            } => {
                let value = TrustedTypes::Policies {
                    names: names
                        .iter()
                        .filter_map(|name| TrustedTypePolicyName::parse(name).ok())
                        .collect(),
                    wildcard,
                    allow_duplicates,
                };
                policy.set(Directive::TrustedTypes(value));
            }
            Operation::Webrtc(block) => {
                policy.set(Directive::Webrtc(if block {
                    Webrtc::Block
                } else {
                    Webrtc::Allow
                }));
            }
            Operation::UpgradeInsecureRequests => {
                policy.set(Directive::UpgradeInsecureRequests);
            }
            Operation::BlockAllMixedContent => {
                policy.set(Directive::BlockAllMixedContent);
            }
            Operation::Remove(index) => {
                policy.remove(directive_name(index));
            }
        }
    }

    let rendered = policy.to_header_value();
    check_structure(&policy, &rendered);

    // Rendering is a pure function of the policy, which is what lets a consumer compute the header
    // once at startup and reuse it for the life of the process.
    assert_eq!(rendered, policy.to_header_value());
    assert_eq!(rendered, policy.to_string());
});

/// Every structural property of a rendered policy that holds regardless of its content.
fn check_structure(policy: &Policy, rendered: &str) {
    assert!(
        rendered.bytes().all(|byte| (0x20..=0x7e).contains(&byte)),
        "not a valid HTTP field value: {rendered:?}"
    );
    assert!(!rendered.contains(','), "policy separator in {rendered:?}");

    if policy.is_empty() {
        assert!(rendered.is_empty());
        return;
    }

    let segments: Vec<&str> = rendered.split("; ").collect();
    assert_eq!(
        segments.len(),
        policy.len(),
        "one segment per directive: {rendered:?}"
    );

    let mut names = Vec::new();
    for (segment, directive) in segments.iter().zip(policy) {
        assert!(!segment.is_empty(), "empty directive in {rendered:?}");
        assert!(!segment.contains(';'), "unseparated `;` in {rendered:?}");
        assert!(
            !segment.starts_with(' ') && !segment.ends_with(' '),
            "{rendered:?}"
        );
        assert!(!segment.contains("  "), "empty value in {rendered:?}");

        let name = segment.split(' ').next().expect("split yields one token");
        assert_eq!(
            name,
            directive.name().as_str(),
            "a directive rendered under a name it does not report: {rendered:?}"
        );
        assert_eq!(DirectiveName::parse(name), Ok(directive.name()));

        // A repeated directive is ignored by the browser with only a console warning, so the
        // builder must never emit one.
        assert!(
            !names.contains(&name),
            "duplicate directive {name:?} in {rendered:?}"
        );
        names.push(name);
    }
}
