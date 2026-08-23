//! Source expressions and the two kinds of list they appear in.

use alloc::string::ToString;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use crate::error::{ParseError, Term};
use crate::hash::{HashAlgorithm, HashSource, NonceSource};
use crate::host::{HostSource, Scheme};
use crate::util::push_unique;

/// `'none'`, which is a whole source list rather than a source expression.
const NONE: &str = "'none'";

/// One source expression.
///
/// Under CSP a fetch is allowed if it matches *any* expression in the list, so adding one never
/// narrows a directive. The two that do narrow it are [`Source::UnsafeInline`], which stops
/// applying the moment a hash or a nonce is present, and [`Source::StrictDynamic`], which disables
/// every host expression in the same list.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Source {
    /// `'self'` — the origin of the protected document, scheme and port included.
    SelfOrigin,
    /// `'unsafe-inline'` — inline script or style. Ignored by any browser that also sees a hash or
    /// a nonce in the same directive, which is why it is not a usable compatibility fallback.
    UnsafeInline,
    /// `'unsafe-eval'` — `eval`, `new Function`, and string timers. <!-- csp-lint: allow — the
    /// variant that models this source expression cannot be documented without naming it -->
    UnsafeEval,
    /// `'wasm-unsafe-eval'` — WebAssembly compilation without the rest of the broader keyword.
    WasmUnsafeEval,
    /// `'unsafe-hashes'` — lets a hash cover an event-handler attribute, not just a `<script>`.
    UnsafeHashes,
    /// `'strict-dynamic'` — trust propagates from an already-trusted script to what it loads, and
    /// every host expression in the same directive stops applying.
    StrictDynamic,
    /// `'report-sample'` — include a prefix of the offending content in violation reports.
    ReportSample,
    /// `'inline-speculation-rules'` — allow inline `<script type="speculationrules">`.
    InlineSpeculationRules,
    /// A scheme, such as `https:` or `data:`.
    Scheme(Scheme),
    /// A host, optionally with a scheme, port and path.
    Host(HostSource),
    /// A per-response nonce.
    Nonce(NonceSource),
    /// The digest of an inline script or style.
    Hash(HashSource),
}

/// Every keyword source, as it is written in a header.
///
/// `'none'` is deliberately absent: it is a source *list*, and admitting it here would let a
/// caller write a list containing `'none'` and something else, which a browser resolves by
/// ignoring the `'none'` entirely.
const KEYWORDS: &[&str] = &[
    "'self'",
    "'unsafe-inline'",
    "'unsafe-eval'", // csp-lint: allow — the keyword table is the definition of the token
    "'wasm-unsafe-eval'",
    "'unsafe-hashes'",
    "'strict-dynamic'",
    "'report-sample'",
    "'inline-speculation-rules'",
];

impl Source {
    /// A host source.
    ///
    /// # Errors
    ///
    /// As [`HostSource::parse`].
    pub fn host(host: &str) -> Result<Self, ParseError> {
        HostSource::parse(host).map(Self::Host)
    }

    /// A scheme source.
    ///
    /// # Errors
    ///
    /// As [`Scheme::parse`].
    pub fn scheme(scheme: &str) -> Result<Self, ParseError> {
        Scheme::parse(scheme).map(Self::Scheme)
    }

    /// A nonce source from an existing base64 value.
    ///
    /// # Errors
    ///
    /// As [`NonceSource::parse`].
    pub fn nonce(value: &str) -> Result<Self, ParseError> {
        NonceSource::parse(value).map(Self::Nonce)
    }

    /// A hash source from an existing base64 digest.
    ///
    /// # Errors
    ///
    /// As [`HashSource::new`].
    pub fn hash(algorithm: HashAlgorithm, value: &str) -> Result<Self, ParseError> {
        HashSource::new(algorithm, value).map(Self::Hash)
    }

    /// A `'sha256-…'` source from a digest.
    #[must_use]
    pub fn sha256(digest: &[u8; 32]) -> Self {
        Self::Hash(HashSource::sha256(digest))
    }

    /// The keyword this source is, if it is one.
    ///
    /// The quoted form is included, because the quotes are part of the expression rather than
    /// punctuation around it.
    #[must_use]
    pub const fn as_keyword(&self) -> Option<&'static str> {
        Some(match self {
            Self::SelfOrigin => "'self'",
            Self::UnsafeInline => "'unsafe-inline'",
            Self::UnsafeEval => "'unsafe-eval'", // csp-lint: allow — rendering the variant is naming it
            Self::WasmUnsafeEval => "'wasm-unsafe-eval'",
            Self::UnsafeHashes => "'unsafe-hashes'",
            Self::StrictDynamic => "'strict-dynamic'",
            Self::ReportSample => "'report-sample'",
            Self::InlineSpeculationRules => "'inline-speculation-rules'",
            Self::Scheme(_) | Self::Host(_) | Self::Nonce(_) | Self::Hash(_) => return None,
        })
    }

    /// Parses a source expression.
    ///
    /// # Errors
    ///
    /// [`ParseError::NoneIsNotASource`] for `'none'`, [`ParseError::Unrecognised`] for a quoted
    /// value that is neither a known keyword nor a nonce or hash, and whatever the host and scheme
    /// grammars reject for everything else.
    pub fn parse(source: &str) -> Result<Self, ParseError> {
        if source.is_empty() {
            return Err(ParseError::Empty { term: Term::Source });
        }

        if source.starts_with('\'') && source.ends_with('\'') && source.len() >= 2 {
            return Self::parse_quoted(source);
        }

        // `scheme:` is a scheme source; anything else with a host in it is a host source. The `/`
        // test is what keeps `https://example.com` out of the scheme branch.
        if source.ends_with(':') && !source.contains('/') {
            return Self::scheme(source);
        }
        Self::host(source)
    }

    /// The `'…'` half of [`Source::parse`].
    fn parse_quoted(source: &str) -> Result<Self, ParseError> {
        for keyword in KEYWORDS {
            if source.eq_ignore_ascii_case(keyword) {
                // The keyword table and the rendered form are the same strings, so parsing the
                // rendered form is the only construction path that has to agree with itself.
                return Self::from_keyword(keyword);
            }
        }

        let body = &source[1..source.len() - 1];
        if body.eq_ignore_ascii_case("none") {
            return Err(ParseError::NoneIsNotASource {
                input: source.to_string(),
            });
        }
        if body
            .get(..6)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("nonce-"))
        {
            return NonceSource::parse(source).map(Self::Nonce);
        }
        if let Some((algorithm, _)) = body.split_once('-') {
            if HashAlgorithm::parse(algorithm).is_ok() {
                return HashSource::parse(source).map(Self::Hash);
            }
        }

        Err(ParseError::Unrecognised {
            term: Term::Source,
            input: source.to_string(),
        })
    }

    /// The inverse of [`Source::as_keyword`], over the entries of `KEYWORDS`.
    fn from_keyword(keyword: &str) -> Result<Self, ParseError> {
        Ok(match keyword {
            "'self'" => Self::SelfOrigin,
            "'unsafe-inline'" => Self::UnsafeInline,
            "'unsafe-eval'" => Self::UnsafeEval, // csp-lint: allow — parsing the variant is naming it
            "'wasm-unsafe-eval'" => Self::WasmUnsafeEval,
            "'unsafe-hashes'" => Self::UnsafeHashes,
            "'strict-dynamic'" => Self::StrictDynamic,
            "'report-sample'" => Self::ReportSample,
            "'inline-speculation-rules'" => Self::InlineSpeculationRules,
            _ => {
                return Err(ParseError::Unrecognised {
                    term: Term::Source,
                    input: keyword.to_string(),
                })
            }
        })
    }
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(keyword) = self.as_keyword() {
            return f.write_str(keyword);
        }
        match self {
            Self::Scheme(scheme) => write!(f, "{scheme}:"),
            Self::Host(host) => host.fmt(f),
            Self::Nonce(nonce) => nonce.fmt(f),
            Self::Hash(hash) => hash.fmt(f),
            _ => unreachable!("every keyword source is handled by as_keyword"),
        }
    }
}

impl FromStr for Source {
    type Err = ParseError;

    fn from_str(source: &str) -> Result<Self, Self::Err> {
        Self::parse(source)
    }
}

impl From<HostSource> for Source {
    fn from(host: HostSource) -> Self {
        Self::Host(host)
    }
}

impl From<Scheme> for Source {
    fn from(scheme: Scheme) -> Self {
        Self::Scheme(scheme)
    }
}

impl From<NonceSource> for Source {
    fn from(nonce: NonceSource) -> Self {
        Self::Nonce(nonce)
    }
}

impl From<HashSource> for Source {
    fn from(hash: HashSource) -> Self {
        Self::Hash(hash)
    }
}

/// The value of a source-list directive.
///
/// `'none'` is a variant rather than a source expression because that is what the grammar says:
/// a list is either `'none'` or one or more expressions. A list holding `'none'` next to anything
/// else is a policy a browser silently reads as the anything-else, and this type has no way to
/// spell it.
///
/// An empty list renders as `'none'`. A directive with no sources already means "match nothing" in
/// every browser, so rendering the shorter, ambiguous form would only hide that.
///
/// # Examples
///
/// ```
/// use csp_policy::{Source, SourceList};
///
/// assert_eq!(SourceList::from([Source::SelfOrigin]).to_string(), "'self'");
/// assert_eq!(SourceList::None.to_string(), "'none'");
/// assert_eq!(SourceList::from([]).to_string(), "'none'");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SourceList {
    /// `'none'` — nothing matches.
    #[default]
    None,
    /// The expressions that match, in the order they were added.
    Sources(Vec<Source>),
}

impl SourceList {
    /// A list of source expressions, in order, with duplicates dropped.
    ///
    /// A repeated expression lengthens every response without changing what the policy permits.
    #[must_use]
    pub fn of(sources: impl IntoIterator<Item = Source>) -> Self {
        let mut list = Vec::new();
        for source in sources {
            push_unique(&mut list, source);
        }
        Self::Sources(list)
    }

    /// Whether this list matches nothing — either `'none'` or no expressions at all.
    #[must_use]
    pub fn matches_nothing(&self) -> bool {
        self.sources().is_empty()
    }

    /// The expressions, empty for `'none'`.
    #[must_use]
    pub fn sources(&self) -> &[Source] {
        match self {
            Self::None => &[],
            Self::Sources(sources) => sources,
        }
    }

    /// Whether `source` is already in the list.
    #[must_use]
    pub fn contains(&self, source: &Source) -> bool {
        self.sources().contains(source)
    }

    /// Adds an expression unless it is already present.
    ///
    /// Adding to `'none'` replaces it: a list cannot hold `'none'` alongside anything else, and
    /// the caller's intent in adding a source to a directive that currently permits nothing is to
    /// permit that source.
    pub fn push(&mut self, source: Source) {
        match self {
            Self::None => *self = Self::Sources(alloc::vec![source]),
            Self::Sources(sources) => push_unique(sources, source),
        }
    }

    /// Keeps only the expressions `keep` accepts.
    ///
    /// A list emptied this way still matches nothing and still renders as `'none'`, which is the
    /// same policy an empty list always described. Removing the last source expression from a
    /// directive is not the same as removing the directive, and neither is silently turned into
    /// the other.
    pub fn retain(&mut self, keep: impl FnMut(&Source) -> bool) {
        if let Self::Sources(sources) = self {
            sources.retain(keep);
        }
    }

    /// Removes one expression, reporting whether it was there.
    ///
    /// The counterpart to [`SourceList::push`], for narrowing a list that was handed over rather
    /// than assembled — dropping one scheme from a preset without restating the rest of it.
    pub fn remove(&mut self, source: &Source) -> bool {
        let removed = self.contains(source);
        self.retain(|existing| existing != source);
        removed
    }

    /// The expressions, consuming the list. Empty for `'none'`.
    #[must_use]
    pub fn into_sources(self) -> Vec<Source> {
        match self {
            Self::None => Vec::new(),
            Self::Sources(sources) => sources,
        }
    }
}

impl fmt::Display for SourceList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sources = self.sources();
        if sources.is_empty() {
            return f.write_str(NONE);
        }
        for (index, source) in sources.iter().enumerate() {
            if index > 0 {
                f.write_str(" ")?;
            }
            source.fmt(f)?;
        }
        Ok(())
    }
}

impl<const N: usize> From<[Source; N]> for SourceList {
    fn from(sources: [Source; N]) -> Self {
        Self::of(sources)
    }
}

impl From<Vec<Source>> for SourceList {
    fn from(sources: Vec<Source>) -> Self {
        Self::of(sources)
    }
}

impl FromIterator<Source> for SourceList {
    fn from_iter<I: IntoIterator<Item = Source>>(sources: I) -> Self {
        Self::of(sources)
    }
}

/// One expression in a `frame-ancestors` list.
///
/// A narrower grammar than [`Source`]: `frame-ancestors` is matched against the URL of an
/// embedding document, so a nonce, a hash and every keyword but `'self'` are meaningless there.
/// Browsers ignore them, which turns a mistake into a framing restriction that is quietly weaker
/// than it reads.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AncestorSource {
    /// `'self'` — only the protected document's own origin may frame it.
    SelfOrigin,
    /// A scheme.
    Scheme(Scheme),
    /// A host, optionally with a scheme, port and path.
    Host(HostSource),
}

impl AncestorSource {
    /// An ancestor host source.
    ///
    /// # Errors
    ///
    /// As [`HostSource::parse`].
    pub fn host(host: &str) -> Result<Self, ParseError> {
        HostSource::parse(host).map(Self::Host)
    }

    /// Parses an ancestor source expression.
    ///
    /// # Errors
    ///
    /// [`ParseError::Unrecognised`] for a keyword other than `'self'`, plus whatever the host and
    /// scheme grammars reject.
    pub fn parse(source: &str) -> Result<Self, ParseError> {
        match Source::parse(source)? {
            Source::SelfOrigin => Ok(Self::SelfOrigin),
            Source::Scheme(scheme) => Ok(Self::Scheme(scheme)),
            Source::Host(host) => Ok(Self::Host(host)),
            _ => Err(ParseError::Unrecognised {
                term: Term::Source,
                input: source.to_string(),
            }),
        }
    }
}

impl fmt::Display for AncestorSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SelfOrigin => f.write_str("'self'"),
            Self::Scheme(scheme) => write!(f, "{scheme}:"),
            Self::Host(host) => host.fmt(f),
        }
    }
}

impl From<AncestorSource> for Source {
    fn from(source: AncestorSource) -> Self {
        match source {
            AncestorSource::SelfOrigin => Self::SelfOrigin,
            AncestorSource::Scheme(scheme) => Self::Scheme(scheme),
            AncestorSource::Host(host) => Self::Host(host),
        }
    }
}

/// The value of `frame-ancestors`.
///
/// `'none'` here is the setting most policies want and the one `X-Frame-Options: DENY` used to
/// spell.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum AncestorSourceList {
    /// `'none'` — nothing may frame this document.
    #[default]
    None,
    /// The documents that may frame this one.
    Sources(Vec<AncestorSource>),
}

impl AncestorSourceList {
    /// A list of ancestor sources, in order, with duplicates dropped.
    #[must_use]
    pub fn of(sources: impl IntoIterator<Item = AncestorSource>) -> Self {
        let mut list = Vec::new();
        for source in sources {
            push_unique(&mut list, source);
        }
        Self::Sources(list)
    }

    /// The expressions, empty for `'none'`.
    #[must_use]
    pub fn sources(&self) -> &[AncestorSource] {
        match self {
            Self::None => &[],
            Self::Sources(sources) => sources,
        }
    }

    /// Adds an expression unless it is already present. Adding to `'none'` replaces it.
    pub fn push(&mut self, source: AncestorSource) {
        match self {
            Self::None => *self = Self::Sources(alloc::vec![source]),
            Self::Sources(sources) => push_unique(sources, source),
        }
    }
}

impl fmt::Display for AncestorSourceList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sources = self.sources();
        if sources.is_empty() {
            return f.write_str(NONE);
        }
        for (index, source) in sources.iter().enumerate() {
            if index > 0 {
                f.write_str(" ")?;
            }
            source.fmt(f)?;
        }
        Ok(())
    }
}

impl<const N: usize> From<[AncestorSource; N]> for AncestorSourceList {
    fn from(sources: [AncestorSource; N]) -> Self {
        Self::of(sources)
    }
}

impl From<Vec<AncestorSource>> for AncestorSourceList {
    fn from(sources: Vec<AncestorSource>) -> Self {
        Self::of(sources)
    }
}

impl FromIterator<AncestorSource> for AncestorSourceList {
    fn from_iter<I: IntoIterator<Item = AncestorSource>>(sources: I) -> Self {
        Self::of(sources)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::{AncestorSource, Source, SourceList, KEYWORDS};
    use crate::error::ParseError;

    /// The parse and the render are two tables that have to agree; nothing but a test says so.
    #[test]
    fn every_keyword_round_trips_through_both_tables() {
        for keyword in KEYWORDS {
            let source = Source::parse(keyword)
                .unwrap_or_else(|error| panic!("{keyword} must parse: {error}"));
            assert_eq!(source.as_keyword(), Some(*keyword));
            assert_eq!(source.to_string(), *keyword);
            assert_eq!(
                Source::parse(&keyword.to_ascii_uppercase()),
                Ok(source),
                "{keyword} must parse case-insensitively"
            );
        }
    }

    #[test]
    fn the_source_expressions_a_real_policy_uses_round_trip() {
        for source in [
            "'self'",
            "'wasm-unsafe-eval'",
            "https:",
            "data:",
            "https://challenges.cloudflare.com",
            "'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='",
            "'nonce-cmFuZG9tLW5vbmNlLTE2Yg=='",
            "*.example.com:8443/path",
            "*",
        ] {
            let parsed = Source::parse(source).unwrap_or_else(|error| panic!("{source}: {error}"));
            assert_eq!(parsed.to_string(), source, "{source} did not round-trip");
        }
    }

    /// `'none'` is a list, and a list holding it next to anything else is a policy the browser
    /// reads as the anything-else.
    #[test]
    fn none_is_not_a_source_expression() {
        assert!(matches!(
            Source::parse("'none'"),
            Err(ParseError::NoneIsNotASource { .. })
        ));
        assert!(matches!(
            Source::parse("'NONE'"),
            Err(ParseError::NoneIsNotASource { .. })
        ));
        assert_eq!(SourceList::None.to_string(), "'none'");
        assert_eq!(SourceList::of([]).to_string(), "'none'");
    }

    #[test]
    fn a_list_deduplicates_and_keeps_its_order() {
        let list = SourceList::of([
            Source::SelfOrigin,
            Source::WasmUnsafeEval,
            Source::SelfOrigin,
        ]);
        assert_eq!(list.to_string(), "'self' 'wasm-unsafe-eval'");
    }

    #[test]
    fn adding_a_source_to_none_replaces_it() {
        let mut list = SourceList::None;
        list.push(Source::SelfOrigin);
        list.push(Source::SelfOrigin);
        assert_eq!(list.to_string(), "'self'");
    }

    #[test]
    fn removing_reports_what_it_removed_and_keeps_the_order_of_the_rest() {
        let mut list = SourceList::of([
            Source::SelfOrigin,
            Source::WasmUnsafeEval,
            Source::UnsafeInline,
        ]);

        assert!(list.remove(&Source::WasmUnsafeEval));
        assert!(!list.remove(&Source::WasmUnsafeEval));
        assert_eq!(list.to_string(), "'self' 'unsafe-inline'"); // csp-lint: allow — the removal has to be asserted against the sources it left behind

        list.retain(|source| source == &Source::SelfOrigin);
        assert_eq!(list.to_string(), "'self'");
    }

    /// A list emptied by removal describes the same policy an empty list always did. Turning it
    /// back into `'none'` would be indistinguishable, and turning it into "no directive" would be
    /// a different policy entirely — so it does neither.
    #[test]
    fn emptying_a_list_by_removal_still_matches_nothing() {
        let mut list = SourceList::of([Source::SelfOrigin]);
        assert!(list.remove(&Source::SelfOrigin));
        assert!(list.matches_nothing());
        assert_eq!(list.to_string(), "'none'");
    }

    /// `'none'` holds no expressions, so there is nothing to take out of it.
    #[test]
    fn removing_from_none_is_a_no_op() {
        let mut list = SourceList::None;
        assert!(!list.remove(&Source::SelfOrigin));
        list.retain(|_| false);
        assert_eq!(list, SourceList::None);
    }

    /// Everything a browser would drop from `frame-ancestors` is refused instead.
    #[test]
    fn ancestor_sources_admit_only_what_a_browser_matches() {
        assert_eq!(
            AncestorSource::parse("'self'"),
            Ok(AncestorSource::SelfOrigin)
        );
        assert!(AncestorSource::parse("https://example.com").is_ok());
        assert!(AncestorSource::parse("https:").is_ok());
        for source in [
            "'unsafe-inline'",
            "'strict-dynamic'",
            "'nonce-cmFuZG9tLW5vbmNlLTE2Yg=='",
            "'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='",
        ] {
            assert!(
                AncestorSource::parse(source).is_err(),
                "{source} must be refused"
            );
        }
    }

    #[test]
    fn unparseable_sources_are_refused_rather_than_rendered() {
        for source in [
            "",
            "'unknown'",
            "'sha256-tooshort'",
            "'nonce-'",
            "https://evil.example; script-src *",
            "a b",
        ] {
            assert!(Source::parse(source).is_err(), "{source:?} must be refused");
        }
    }
}
