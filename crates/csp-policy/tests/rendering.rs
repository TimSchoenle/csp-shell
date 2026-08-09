//! What a rendered policy may and may not contain, across the whole vocabulary at once.
//!
//! The unit tests in each module check one type against its own grammar. This file checks the
//! property that only holds of the crate as a whole: whatever a caller assembles, the result is an
//! HTTP field value carrying exactly the directives that were set, separated only by the
//! separators the renderer wrote itself.

use csp_policy::{
    AncestorSource, AncestorSourceList, Directive, DirectiveName, Grammar, HashAlgorithm,
    HashSource, HostSource, NonceSource, Policy, ReportGroup, ReportUri, SandboxToken, Scheme,
    Source, SourceDirective, SourceList, TrustedTypePolicyName, TrustedTypeSink, TrustedTypes,
    Webrtc,
};

/// One directive of every shape the crate knows, so a change to any value type is exercised here
/// as well as in its own module.
fn every_shape() -> Vec<Directive> {
    vec![
        Directive::sources(SourceDirective::DefaultSrc, [Source::SelfOrigin]),
        Directive::sources(
            SourceDirective::ScriptSrc,
            [
                Source::SelfOrigin,
                Source::WasmUnsafeEval,
                Source::StrictDynamic,
                Source::UnsafeHashes,
                Source::ReportSample,
                Source::InlineSpeculationRules,
                Source::Scheme(Scheme::Https),
                Source::Host(HostSource::parse("https://*.cdn.example:8443/a/").unwrap()),
                Source::Nonce(NonceSource::from_entropy(&[0x11; 16])),
                Source::Hash(HashSource::from_digest(HashAlgorithm::Sha384, &[0x22; 48]).unwrap()),
            ],
        ),
        Directive::sources(SourceDirective::StyleSrc, [Source::UnsafeInline]),
        Directive::sources(SourceDirective::ObjectSrc, SourceList::None),
        Directive::frame_ancestors([
            AncestorSource::SelfOrigin,
            AncestorSource::Scheme(Scheme::Https),
            AncestorSource::host("https://parent.example").unwrap(),
        ]),
        Directive::sandbox([
            SandboxToken::AllowForms,
            SandboxToken::AllowSameOrigin,
            SandboxToken::AllowTopNavigationToCustomProtocols,
        ]),
        Directive::ReportTo(ReportGroup::parse("csp-endpoint").unwrap()),
        Directive::report_uri([
            ReportUri::parse("https://reports.example/csp?project=web").unwrap(),
            ReportUri::parse("/csp").unwrap(),
        ]),
        Directive::require_trusted_types_for([TrustedTypeSink::Script]),
        Directive::TrustedTypes(
            TrustedTypes::policies([TrustedTypePolicyName::parse("dompurify").unwrap()])
                .allowing_duplicates(),
        ),
        Directive::Webrtc(Webrtc::Block),
        Directive::UpgradeInsecureRequests,
        Directive::BlockAllMixedContent,
    ]
}

#[test]
fn the_whole_vocabulary_renders_to_one_valid_header_value() {
    let policy: Policy = every_shape().into_iter().collect();
    let rendered = policy.to_header_value();

    assert!(
        rendered.bytes().all(|byte| (0x20..=0x7e).contains(&byte)),
        "not a valid HTTP field value: {rendered:?}"
    );
    assert!(!rendered.contains(','), "policy separator in {rendered:?}");
    assert_eq!(
        rendered.matches("; ").count(),
        policy.len() - 1,
        "one separator per directive boundary and no more: {rendered:?}"
    );
    assert!(!rendered.contains("  "), "empty value in {rendered:?}");
    assert!(!rendered.starts_with(' ') && !rendered.ends_with(' '));
}

/// A directive rendering under a name other than the one it reports would break the policy's own
/// replace-by-name bookkeeping without changing a single test on either side of it.
#[test]
fn every_directive_renders_under_the_name_it_reports() {
    let policy: Policy = every_shape().into_iter().collect();
    let rendered = policy.to_header_value();

    let segments: Vec<&str> = rendered.split("; ").collect();
    assert_eq!(segments.len(), policy.len());

    for (segment, directive) in segments.iter().zip(&policy) {
        let name = directive.name();
        assert_eq!(
            segment.split(' ').next(),
            Some(name.as_str()),
            "{segment:?} does not begin with {name}"
        );
        assert_eq!(DirectiveName::parse(name.as_str()), Ok(name));
    }
}

/// A value of the wrong shape for its name is unrepresentable, and the grammar table is what says
/// which shape that is. If the two ever disagree, a directive is being built that the table calls
/// something else.
#[test]
fn each_directive_matches_the_grammar_its_name_declares() {
    for directive in every_shape() {
        let grammar = directive.name().grammar();
        let matches = match &directive {
            Directive::Sources(..) => grammar == Grammar::SourceList,
            Directive::FrameAncestors(_) => grammar == Grammar::AncestorSourceList,
            Directive::Sandbox(_) => grammar == Grammar::SandboxTokens,
            Directive::ReportTo(_) => grammar == Grammar::ReportGroup,
            Directive::ReportUri(_) => grammar == Grammar::ReportUris,
            Directive::RequireTrustedTypesFor(_) => grammar == Grammar::TrustedTypeSinks,
            Directive::TrustedTypes(_) => grammar == Grammar::TrustedTypes,
            Directive::Webrtc(_) => grammar == Grammar::Webrtc,
            Directive::UpgradeInsecureRequests | Directive::BlockAllMixedContent => {
                grammar == Grammar::Empty
            }
            _ => false,
        };
        assert!(matches, "{} declares {grammar:?}", directive.name());
    }
}

/// A directive that permits nothing must say so out loud. An empty list and `'none'` mean the same
/// thing to a browser, and rendering the bare name would leave a reader guessing which was meant.
#[test]
fn a_directive_that_permits_nothing_renders_none() {
    for list in [SourceList::None, SourceList::of([]), SourceList::from([])] {
        let policy = Policy::new().with(Directive::sources(SourceDirective::ScriptSrc, list));
        assert_eq!(policy.to_header_value(), "script-src 'none'");
    }
    let policy = Policy::new().with(Directive::frame_ancestors(AncestorSourceList::None));
    assert_eq!(policy.to_header_value(), "frame-ancestors 'none'");

    // `sandbox` is the exception, and it is the exception in the other direction: no tokens means
    // every restriction applies, so the bare name is the restrictive form rather than the empty
    // one.
    let policy = Policy::new().with(Directive::sandbox([]));
    assert_eq!(policy.to_header_value(), "sandbox");
}

/// Rendering is the crate's only output, so it must not depend on how a policy was assembled.
#[test]
fn assembly_order_is_render_order_and_nothing_else_is() {
    let forwards: Policy = every_shape().into_iter().collect();

    let mut rebuilt = Policy::new();
    for directive in every_shape() {
        rebuilt.set(directive);
    }
    assert_eq!(forwards.to_header_value(), rebuilt.to_header_value());

    // Setting a directive again keeps its position, so a late override does not reshuffle the
    // policy around it.
    let mut overridden = forwards.clone();
    overridden.set(Directive::sources(
        SourceDirective::DefaultSrc,
        [Source::Scheme(Scheme::Https)],
    ));
    assert!(overridden
        .to_header_value()
        .starts_with("default-src https:;"));
    assert_eq!(overridden.len(), forwards.len());
}

/// The dedup is not cosmetic: a repeated source lengthens every response for the lifetime of the
/// deployment without changing what the policy permits.
#[test]
fn repeats_are_dropped_everywhere_a_list_is_built() {
    let https = Source::Scheme(Scheme::Https);
    let list = SourceList::of([https.clone(), Source::SelfOrigin, https]);
    assert_eq!(list.sources().len(), 2);

    let mut policy = Policy::new();
    policy.extend_sources(SourceDirective::ImgSrc, [Source::SelfOrigin]);
    policy.extend_sources(SourceDirective::ImgSrc, [Source::SelfOrigin]);
    assert_eq!(policy.to_header_value(), "img-src 'self'");

    assert_eq!(
        Directive::sandbox([SandboxToken::AllowForms, SandboxToken::AllowForms]).to_string(),
        "sandbox allow-forms"
    );
}
