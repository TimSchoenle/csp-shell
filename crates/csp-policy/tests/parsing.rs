//! Every leaf parser, against the one property they all have to share: an input that is accepted
//! renders back to something a header can carry, and an input that would need a separator to
//! render is refused.
//!
//! This is the crate's security boundary. A consumer builds a policy from configuration — a CDN
//! origin, a reporting endpoint, a Trusted Types policy name — and every one of those values
//! arrives as a string from outside the program.

use csp_policy::{
    AncestorSource, DirectiveName, HashAlgorithm, HashSource, HostSource, NonceSource, ParseError,
    ReportGroup, ReportUri, SandboxToken, Scheme, Source, SourceDirective, TrustedTypePolicyName,
    TrustedTypeSink, Webrtc,
};

/// Payloads that turn one directive into two, one policy into two, or one header into two.
const INJECTIONS: &[&str] = &[
    "https://cdn.example; script-src 'unsafe-inline'",
    "https://cdn.example,https://evil.example",
    "https://cdn.example script-src",
    "https://cdn.example\r\nX-Frame-Options: ALLOWALL",
    "https://cdn.example\nscript-src *",
    "https://cdn.example\0",
    "https://cdn.example\u{7f}",
    "https://cdn.exämple",
    " https://cdn.example",
    "https://cdn.example ",
    ";",
    ",",
    " ",
];

/// One parser, erased down to what every parser in the crate has in common: text in, either a
/// rendered value or a refusal out.
type Parser = fn(&str) -> Result<String, ParseError>;

/// Every parser in the crate, as a name and the function that either accepts a string or does not.
///
/// Collected in one table so that a parser added later is one line away from being covered by the
/// property below, rather than being covered only if someone remembers.
fn parsers() -> Vec<(&'static str, Parser)> {
    vec![
        ("Source", |text| Source::parse(text).map(rendered)),
        ("AncestorSource", |text| {
            AncestorSource::parse(text).map(rendered)
        }),
        ("HostSource", |text| HostSource::parse(text).map(rendered)),
        ("Scheme", |text| Scheme::parse(text).map(rendered)),
        ("NonceSource", |text| NonceSource::parse(text).map(rendered)),
        ("HashSource", |text| HashSource::parse(text).map(rendered)),
        ("HashAlgorithm", |text| {
            HashAlgorithm::parse(text).map(rendered)
        }),
        ("DirectiveName", |text| {
            DirectiveName::parse(text).map(rendered)
        }),
        ("SourceDirective", |text| {
            SourceDirective::parse(text).map(rendered)
        }),
        ("SandboxToken", |text| {
            SandboxToken::parse(text).map(rendered)
        }),
        ("TrustedTypePolicyName", |text| {
            TrustedTypePolicyName::parse(text).map(rendered)
        }),
        ("TrustedTypeSink", |text| {
            TrustedTypeSink::parse(text).map(rendered)
        }),
        ("Webrtc", |text| Webrtc::parse(text).map(rendered)),
        ("ReportGroup", |text| ReportGroup::parse(text).map(rendered)),
        ("ReportUri", |text| ReportUri::parse(text).map(rendered)),
    ]
}

fn rendered<T: std::fmt::Display>(value: T) -> String {
    value.to_string()
}

/// No parser in the crate may accept a value that renders a separator, a control byte or a
/// non-ASCII byte.
#[test]
fn nothing_that_parses_can_render_a_separator() {
    for (name, parse) in parsers() {
        for injection in INJECTIONS {
            let Ok(text) = parse(injection) else {
                continue;
            };
            assert!(
                text.bytes().all(|byte| (0x21..=0x7e).contains(&byte)),
                "{name} accepted {injection:?} and rendered {text:?}"
            );
            assert!(
                !text.contains(';') && !text.contains(','),
                "{name} accepted {injection:?} and rendered {text:?}"
            );
        }
    }
}

/// The same property over pseudo-random input, so the coverage does not stop at the payloads
/// someone thought of. The fuzz targets do this with coverage guidance; this runs on every
/// `cargo test`.
#[test]
fn no_parsed_value_renders_outside_the_policy_alphabet() {
    let mut rng = Xorshift64::new(0x00c5_9548_e110_0001);

    for _ in 0..20_000 {
        let input = rng.ascii_string(0, 32);
        for (name, parse) in parsers() {
            let Ok(text) = parse(&input) else {
                continue;
            };
            assert!(
                text.bytes().all(|byte| (0x21..=0x7e).contains(&byte)),
                "{name} accepted {input:?} and rendered {text:?}"
            );
            assert!(
                !text.contains(';') && !text.contains(','),
                "{name} accepted {input:?} and rendered {text:?}"
            );
        }
    }
}

/// Anything that parses must render to something that parses back to the same value. A parser that
/// normalises more than it renders is a parser that quietly changes a policy.
#[test]
fn accepted_sources_round_trip_through_their_rendered_form() {
    let mut rng = Xorshift64::new(0x0000_4d2a_7b13_0001);
    let mut accepted = 0_usize;

    for _ in 0..40_000 {
        let input = rng.source_shaped_string();
        let Ok(source) = Source::parse(&input) else {
            continue;
        };
        accepted += 1;

        let text = source.to_string();
        assert_eq!(
            Source::parse(&text),
            Ok(source),
            "{input:?} rendered to {text:?}, which parses differently"
        );
    }

    assert!(
        accepted > 500,
        "only {accepted} inputs were accepted; the generator is not producing source expressions"
    );
}

/// Case folding is part of the round-trip: a host and a scheme are case-insensitive, and a policy
/// that renders them as typed would compare unequal to the same policy typed differently.
#[test]
fn case_is_folded_where_the_grammar_says_it_is_insignificant() {
    assert_eq!(
        Source::parse("HTTPS://API.Example.COM:8443/Path").map(|s| s.to_string()),
        Ok(String::from("https://api.example.com:8443/Path"))
    );
    assert_eq!(
        DirectiveName::parse("SCRIPT-SRC"),
        Ok(DirectiveName::ScriptSrc)
    );
    assert_eq!(
        SandboxToken::parse("ALLOW-FORMS"),
        Ok(SandboxToken::AllowForms)
    );
    assert_eq!(HashAlgorithm::parse("SHA256"), Ok(HashAlgorithm::Sha256));
}

/// Deterministic, dependency-free, and adequate: the assertions do the work, not the generator.
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

    /// A string over printable ASCII, including every separator a parser must reject.
    fn ascii_string(&mut self, min: u64, max: u64) -> String {
        let len = min + self.below(max - min + 1);
        (0..len)
            .map(|_| char::from(0x20 + u8::try_from(self.below(0x5f)).expect("below 0x5f")))
            .collect()
    }

    /// A string drawn from the alphabet source expressions actually use, so that a useful share of
    /// them parse rather than failing on the first byte.
    fn source_shaped_string(&mut self) -> String {
        const ALPHABET: &[u8] = b"abcdeABCDE019-.:/*'+=_ ;,%@#";
        let len = self.below(28);
        (0..len)
            .map(|_| {
                let index = usize::try_from(self.below(ALPHABET.len() as u64)).expect("in range");
                char::from(ALPHABET[index])
            })
            .collect()
    }
}
