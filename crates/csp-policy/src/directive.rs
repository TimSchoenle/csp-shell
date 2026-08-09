//! A directive: a name and a value of the shape that name requires.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use crate::error::{ParseError, Term};
use crate::name::{DirectiveName, SourceDirective};
use crate::report::{ReportGroup, ReportUri};
use crate::sandbox::SandboxToken;
use crate::source::{AncestorSourceList, Source, SourceList};
use crate::trusted_types::{TrustedTypeSink, TrustedTypes};
use crate::util::push_unique;

/// The value of the `webrtc` directive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Webrtc {
    /// `'allow'` — RTC connections are permitted.
    Allow,
    /// `'block'` — RTC connections are refused. Unlike a fetch directive this is not scoped by
    /// origin: there is no middle setting.
    Block,
}

impl Webrtc {
    /// Both values.
    pub const ALL: &'static [Self] = &[Self::Allow, Self::Block];

    /// The value as it is written in a header, quotes included.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "'allow'",
            Self::Block => "'block'",
        }
    }

    /// Parse a value, with or without quotes, case-insensitively.
    ///
    /// # Errors
    ///
    /// [`ParseError::Unrecognised`] for anything but `'allow'` and `'block'`.
    pub fn parse(value: &str) -> Result<Self, ParseError> {
        let bare = value.trim_matches('\'');
        Self::ALL
            .iter()
            .copied()
            .find(|candidate| {
                candidate
                    .as_str()
                    .trim_matches('\'')
                    .eq_ignore_ascii_case(bare)
            })
            .ok_or_else(|| ParseError::Unrecognised {
                term: Term::Webrtc,
                input: value.to_string(),
            })
    }
}

impl fmt::Display for Webrtc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Webrtc {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// One directive, carrying a value of the shape its name requires.
///
/// The pairing is the point. A `sandbox` holding source expressions, or a `webrtc` holding a host,
/// is a header a browser parses without complaint and then ignores — and nothing in the response
/// says so. Here it does not exist as a value.
///
/// # Examples
///
/// ```
/// use csp_policy::{Directive, SandboxToken, Source, SourceDirective};
///
/// let scripts = Directive::sources(SourceDirective::ScriptSrc, [Source::SelfOrigin]);
/// assert_eq!(scripts.to_string(), "script-src 'self'");
///
/// let sandbox = Directive::sandbox([SandboxToken::AllowForms]);
/// assert_eq!(sandbox.to_string(), "sandbox allow-forms");
///
/// assert_eq!(Directive::UpgradeInsecureRequests.to_string(), "upgrade-insecure-requests");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Directive {
    /// A source-list directive.
    Sources(SourceDirective, SourceList),
    /// `frame-ancestors`, whose list has its own narrower grammar.
    FrameAncestors(AncestorSourceList),
    /// `sandbox`. An empty token list applies every restriction.
    Sandbox(Vec<SandboxToken>),
    /// `report-to`.
    ReportTo(ReportGroup),
    /// `report-uri`.
    ReportUri(Vec<ReportUri>),
    /// `require-trusted-types-for`.
    RequireTrustedTypesFor(Vec<TrustedTypeSink>),
    /// `trusted-types`.
    TrustedTypes(TrustedTypes),
    /// `webrtc`.
    Webrtc(Webrtc),
    /// `upgrade-insecure-requests`.
    UpgradeInsecureRequests,
    /// `block-all-mixed-content`, deprecated in favour of `upgrade-insecure-requests`.
    BlockAllMixedContent,
}

impl Directive {
    /// A source-list directive.
    #[must_use]
    pub fn sources(directive: SourceDirective, sources: impl Into<SourceList>) -> Self {
        Self::Sources(directive, sources.into())
    }

    /// `frame-ancestors`.
    #[must_use]
    pub fn frame_ancestors(sources: impl Into<AncestorSourceList>) -> Self {
        Self::FrameAncestors(sources.into())
    }

    /// `sandbox`, with duplicates dropped.
    #[must_use]
    pub fn sandbox(tokens: impl IntoIterator<Item = SandboxToken>) -> Self {
        Self::Sandbox(deduplicated(tokens))
    }

    /// `report-uri`, with duplicates dropped.
    #[must_use]
    pub fn report_uri(endpoints: impl IntoIterator<Item = ReportUri>) -> Self {
        Self::ReportUri(deduplicated(endpoints))
    }

    /// `require-trusted-types-for`, with duplicates dropped.
    #[must_use]
    pub fn require_trusted_types_for(sinks: impl IntoIterator<Item = TrustedTypeSink>) -> Self {
        Self::RequireTrustedTypesFor(deduplicated(sinks))
    }

    /// The name this directive renders under.
    #[must_use]
    pub const fn name(&self) -> DirectiveName {
        match self {
            Self::Sources(directive, _) => directive.name(),
            Self::FrameAncestors(_) => DirectiveName::FrameAncestors,
            Self::Sandbox(_) => DirectiveName::Sandbox,
            Self::ReportTo(_) => DirectiveName::ReportTo,
            Self::ReportUri(_) => DirectiveName::ReportUri,
            Self::RequireTrustedTypesFor(_) => DirectiveName::RequireTrustedTypesFor,
            Self::TrustedTypes(_) => DirectiveName::TrustedTypes,
            Self::Webrtc(_) => DirectiveName::Webrtc,
            Self::UpgradeInsecureRequests => DirectiveName::UpgradeInsecureRequests,
            Self::BlockAllMixedContent => DirectiveName::BlockAllMixedContent,
        }
    }

    /// The source list, if this is a source-list directive.
    #[must_use]
    pub const fn source_list(&self) -> Option<&SourceList> {
        match self {
            Self::Sources(_, list) => Some(list),
            _ => None,
        }
    }

    /// The source list, if this is a source-list directive.
    #[must_use]
    pub fn source_list_mut(&mut self) -> Option<&mut SourceList> {
        match self {
            Self::Sources(_, list) => Some(list),
            _ => None,
        }
    }

    /// Add a source expression, if this is a source-list directive that does not already have it.
    ///
    /// Returns whether the directive takes source expressions at all, so a caller that reached
    /// here from a parsed name learns that `sandbox` is not one rather than silently doing
    /// nothing.
    pub fn push_source(&mut self, source: Source) -> bool {
        match self.source_list_mut() {
            Some(list) => {
                list.push(source);
                true
            }
            None => false,
        }
    }

    /// Append this directive's rendered form to `out`.
    ///
    /// Rendering cannot fail and cannot emit a separator: every component was validated when it
    /// was built, and the only bytes this method writes itself are the single spaces between a
    /// name and its value.
    pub fn render_into(&self, out: &mut String) {
        use fmt::Write as _;

        // Writing to a `String` is infallible, so the only error this could observe is one a
        // `Display` implementation invented — and none of this crate's do.
        let _ = write!(out, "{self}");
    }
}

impl fmt::Display for Directive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name().as_str())?;
        match self {
            Self::Sources(_, list) => write!(f, " {list}"),
            Self::FrameAncestors(list) => write!(f, " {list}"),
            Self::Sandbox(tokens) => write_space_separated(f, tokens),
            Self::ReportTo(group) => write!(f, " {group}"),
            Self::ReportUri(endpoints) => write_space_separated(f, endpoints),
            Self::RequireTrustedTypesFor(sinks) => write_space_separated(f, sinks),
            Self::TrustedTypes(value) => write!(f, " {value}"),
            Self::Webrtc(value) => write!(f, " {value}"),
            Self::UpgradeInsecureRequests | Self::BlockAllMixedContent => Ok(()),
        }
    }
}

/// Each value preceded by a space, which is also the empty-list rendering: `sandbox` alone is a
/// valid directive and the most restrictive one there is.
fn write_space_separated<T: fmt::Display>(f: &mut fmt::Formatter<'_>, values: &[T]) -> fmt::Result {
    for value in values {
        write!(f, " {value}")?;
    }
    Ok(())
}

/// Collect in order, dropping repeats.
fn deduplicated<T: PartialEq>(values: impl IntoIterator<Item = T>) -> Vec<T> {
    let mut collected = Vec::new();
    for value in values {
        push_unique(&mut collected, value);
    }
    collected
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::{Directive, Webrtc};
    use crate::name::{DirectiveName, SourceDirective};
    use crate::report::ReportUri;
    use crate::sandbox::SandboxToken;
    use crate::source::{AncestorSourceList, Source, SourceList};
    use crate::trusted_types::{TrustedTypeSink, TrustedTypes};

    #[test]
    fn every_shape_renders_under_its_own_name() {
        let cases = [
            (
                Directive::sources(SourceDirective::ScriptSrc, [Source::SelfOrigin]),
                "script-src 'self'",
            ),
            (
                Directive::sources(SourceDirective::ObjectSrc, SourceList::None),
                "object-src 'none'",
            ),
            (
                Directive::frame_ancestors(AncestorSourceList::None),
                "frame-ancestors 'none'",
            ),
            (Directive::sandbox([]), "sandbox"),
            (
                Directive::sandbox([SandboxToken::AllowForms, SandboxToken::AllowForms]),
                "sandbox allow-forms",
            ),
            (
                Directive::report_uri([ReportUri::parse("/csp").unwrap()]),
                "report-uri /csp",
            ),
            (
                Directive::require_trusted_types_for([TrustedTypeSink::Script]),
                "require-trusted-types-for 'script'",
            ),
            (
                Directive::TrustedTypes(TrustedTypes::None),
                "trusted-types 'none'",
            ),
            (Directive::Webrtc(Webrtc::Block), "webrtc 'block'"),
            (
                Directive::UpgradeInsecureRequests,
                "upgrade-insecure-requests",
            ),
            (Directive::BlockAllMixedContent, "block-all-mixed-content"),
        ];

        for (directive, expected) in cases {
            assert_eq!(directive.to_string(), expected);
            assert!(expected.starts_with(directive.name().as_str()));
        }
    }

    /// The name a directive reports must be the name it renders under, for every variant, or the
    /// policy's own replace-by-name bookkeeping is wrong.
    #[test]
    fn the_reported_name_is_the_rendered_name() {
        for &directive in SourceDirective::ALL {
            let rendered = Directive::sources(directive, SourceList::None);
            assert_eq!(rendered.name(), DirectiveName::from(directive));
            assert!(rendered.to_string().starts_with(directive.as_str()));
        }
    }

    #[test]
    fn pushing_a_source_reports_whether_the_directive_takes_one() {
        let mut scripts = Directive::sources(SourceDirective::ScriptSrc, SourceList::None);
        assert!(scripts.push_source(Source::SelfOrigin));
        assert!(scripts.push_source(Source::SelfOrigin));
        assert_eq!(scripts.to_string(), "script-src 'self'");

        let mut sandbox = Directive::sandbox([]);
        assert!(!sandbox.push_source(Source::SelfOrigin));
        assert_eq!(sandbox.to_string(), "sandbox");
    }

    #[test]
    fn webrtc_parses_with_or_without_quotes() {
        assert_eq!(Webrtc::parse("'block'"), Ok(Webrtc::Block));
        assert_eq!(Webrtc::parse("ALLOW"), Ok(Webrtc::Allow));
        assert!(Webrtc::parse("'maybe'").is_err());
    }
}
