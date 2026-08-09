//! Directive names, and the grammar each one's value follows.

use alloc::string::ToString;
use core::fmt;
use core::str::FromStr;

use crate::error::{ParseError, Term};

/// The shape of a directive's value.
///
/// Directives do not share one value grammar. `sandbox` takes flags, `webrtc` takes one of two
/// keywords, `upgrade-insecure-requests` takes nothing at all, and treating them as source lists
/// produces a header a browser accepts and ignores. [`Directive`](crate::Directive) carries a
/// value of the right shape for its name by construction; this enum is how a caller working from
/// a name alone can find out which shape that is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Grammar {
    /// A serialised source list: `'none'`, or one or more source expressions.
    SourceList,
    /// An ancestor source list — a source list without keywords, nonces or hashes.
    AncestorSourceList,
    /// Zero or more `sandbox` tokens. Zero means every restriction applies.
    SandboxTokens,
    /// One reporting group name.
    ReportGroup,
    /// One or more reporting endpoints.
    ReportUris,
    /// One or more sinks that require a Trusted Type.
    TrustedTypeSinks,
    /// A `trusted-types` policy-name list, or `'none'`.
    TrustedTypes,
    /// `'allow'` or `'block'`.
    Webrtc,
    /// No value: the directive's presence is the whole of its meaning.
    Empty,
}

/// Every directive name this crate knows.
///
/// A name is not a restriction on its own — a browser silently ignores a directive it cannot
/// parse — so the value of an enum here is that `scrpit-src` does not compile. New directives keep
/// appearing, which is why this is `#[non_exhaustive]`: adding one is not a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum DirectiveName {
    // Fetch directives.
    /// `child-src`
    ChildSrc,
    /// `connect-src`
    ConnectSrc,
    /// `default-src`
    DefaultSrc,
    /// `fenced-frame-src`
    FencedFrameSrc,
    /// `font-src`
    FontSrc,
    /// `frame-src`
    FrameSrc,
    /// `img-src`
    ImgSrc,
    /// `manifest-src`
    ManifestSrc,
    /// `media-src`
    MediaSrc,
    /// `object-src`
    ObjectSrc,
    /// `prefetch-src`
    PrefetchSrc,
    /// `script-src`
    ScriptSrc,
    /// `script-src-attr`
    ScriptSrcAttr,
    /// `script-src-elem`
    ScriptSrcElem,
    /// `style-src`
    StyleSrc,
    /// `style-src-attr`
    StyleSrcAttr,
    /// `style-src-elem`
    StyleSrcElem,
    /// `worker-src`
    WorkerSrc,

    // Document directives.
    /// `base-uri`
    BaseUri,
    /// `sandbox`
    Sandbox,

    // Navigation directives.
    /// `form-action`
    FormAction,
    /// `frame-ancestors`
    FrameAncestors,

    // Reporting directives.
    /// `report-to`
    ReportTo,
    /// `report-uri`, deprecated in favour of `report-to` and still the only one some browsers
    /// implement.
    ReportUri,

    // Everything else.
    /// `block-all-mixed-content`, deprecated in favour of `upgrade-insecure-requests`.
    BlockAllMixedContent,
    /// `require-trusted-types-for`
    RequireTrustedTypesFor,
    /// `trusted-types`
    TrustedTypes,
    /// `upgrade-insecure-requests`
    UpgradeInsecureRequests,
    /// `webrtc`
    Webrtc,
}

impl DirectiveName {
    /// Every name, in the order this crate documents them.
    pub const ALL: &'static [Self] = &[
        Self::ChildSrc,
        Self::ConnectSrc,
        Self::DefaultSrc,
        Self::FencedFrameSrc,
        Self::FontSrc,
        Self::FrameSrc,
        Self::ImgSrc,
        Self::ManifestSrc,
        Self::MediaSrc,
        Self::ObjectSrc,
        Self::PrefetchSrc,
        Self::ScriptSrc,
        Self::ScriptSrcAttr,
        Self::ScriptSrcElem,
        Self::StyleSrc,
        Self::StyleSrcAttr,
        Self::StyleSrcElem,
        Self::WorkerSrc,
        Self::BaseUri,
        Self::Sandbox,
        Self::FormAction,
        Self::FrameAncestors,
        Self::ReportTo,
        Self::ReportUri,
        Self::BlockAllMixedContent,
        Self::RequireTrustedTypesFor,
        Self::TrustedTypes,
        Self::UpgradeInsecureRequests,
        Self::Webrtc,
    ];

    /// The name as it is written in a header.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ChildSrc => "child-src",
            Self::ConnectSrc => "connect-src",
            Self::DefaultSrc => "default-src",
            Self::FencedFrameSrc => "fenced-frame-src",
            Self::FontSrc => "font-src",
            Self::FrameSrc => "frame-src",
            Self::ImgSrc => "img-src",
            Self::ManifestSrc => "manifest-src",
            Self::MediaSrc => "media-src",
            Self::ObjectSrc => "object-src",
            Self::PrefetchSrc => "prefetch-src",
            Self::ScriptSrc => "script-src",
            Self::ScriptSrcAttr => "script-src-attr",
            Self::ScriptSrcElem => "script-src-elem",
            Self::StyleSrc => "style-src",
            Self::StyleSrcAttr => "style-src-attr",
            Self::StyleSrcElem => "style-src-elem",
            Self::WorkerSrc => "worker-src",
            Self::BaseUri => "base-uri",
            Self::Sandbox => "sandbox",
            Self::FormAction => "form-action",
            Self::FrameAncestors => "frame-ancestors",
            Self::ReportTo => "report-to",
            Self::ReportUri => "report-uri",
            Self::BlockAllMixedContent => "block-all-mixed-content",
            Self::RequireTrustedTypesFor => "require-trusted-types-for",
            Self::TrustedTypes => "trusted-types",
            Self::UpgradeInsecureRequests => "upgrade-insecure-requests",
            Self::Webrtc => "webrtc",
        }
    }

    /// The shape of this directive's value.
    #[must_use]
    pub const fn grammar(self) -> Grammar {
        match self {
            Self::ChildSrc
            | Self::ConnectSrc
            | Self::DefaultSrc
            | Self::FencedFrameSrc
            | Self::FontSrc
            | Self::FrameSrc
            | Self::ImgSrc
            | Self::ManifestSrc
            | Self::MediaSrc
            | Self::ObjectSrc
            | Self::PrefetchSrc
            | Self::ScriptSrc
            | Self::ScriptSrcAttr
            | Self::ScriptSrcElem
            | Self::StyleSrc
            | Self::StyleSrcAttr
            | Self::StyleSrcElem
            | Self::WorkerSrc
            | Self::BaseUri
            | Self::FormAction => Grammar::SourceList,
            Self::FrameAncestors => Grammar::AncestorSourceList,
            Self::Sandbox => Grammar::SandboxTokens,
            Self::ReportTo => Grammar::ReportGroup,
            Self::ReportUri => Grammar::ReportUris,
            Self::RequireTrustedTypesFor => Grammar::TrustedTypeSinks,
            Self::TrustedTypes => Grammar::TrustedTypes,
            Self::Webrtc => Grammar::Webrtc,
            Self::BlockAllMixedContent | Self::UpgradeInsecureRequests => Grammar::Empty,
        }
    }

    /// This name as a [`SourceDirective`], if its value is a source list.
    ///
    /// The route from a name parsed at runtime — a configuration key, a policy read back off a
    /// response — to the typed builder API.
    #[must_use]
    pub const fn as_source_directive(self) -> Option<SourceDirective> {
        Some(match self {
            Self::ChildSrc => SourceDirective::ChildSrc,
            Self::ConnectSrc => SourceDirective::ConnectSrc,
            Self::DefaultSrc => SourceDirective::DefaultSrc,
            Self::FencedFrameSrc => SourceDirective::FencedFrameSrc,
            Self::FontSrc => SourceDirective::FontSrc,
            Self::FrameSrc => SourceDirective::FrameSrc,
            Self::ImgSrc => SourceDirective::ImgSrc,
            Self::ManifestSrc => SourceDirective::ManifestSrc,
            Self::MediaSrc => SourceDirective::MediaSrc,
            Self::ObjectSrc => SourceDirective::ObjectSrc,
            Self::PrefetchSrc => SourceDirective::PrefetchSrc,
            Self::ScriptSrc => SourceDirective::ScriptSrc,
            Self::ScriptSrcAttr => SourceDirective::ScriptSrcAttr,
            Self::ScriptSrcElem => SourceDirective::ScriptSrcElem,
            Self::StyleSrc => SourceDirective::StyleSrc,
            Self::StyleSrcAttr => SourceDirective::StyleSrcAttr,
            Self::StyleSrcElem => SourceDirective::StyleSrcElem,
            Self::WorkerSrc => SourceDirective::WorkerSrc,
            Self::BaseUri => SourceDirective::BaseUri,
            Self::FormAction => SourceDirective::FormAction,
            _ => return None,
        })
    }

    /// Parse a directive name, case-insensitively.
    ///
    /// # Errors
    ///
    /// [`ParseError::Unrecognised`] for a name this crate does not know. Unlike a browser, which
    /// ignores what it cannot parse, refusing here turns a typo into a compile-time-adjacent
    /// failure rather than a restriction that is silently absent from every response.
    pub fn parse(name: &str) -> Result<Self, ParseError> {
        Self::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.as_str().eq_ignore_ascii_case(name))
            .ok_or_else(|| ParseError::Unrecognised {
                term: Term::DirectiveName,
                input: name.to_string(),
            })
    }
}

impl fmt::Display for DirectiveName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for DirectiveName {
    type Err = ParseError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Self::parse(name)
    }
}

/// A directive whose value is a source list.
///
/// Separate from [`DirectiveName`] so that the builder's source-list methods cannot be handed
/// `sandbox`. The alternative — one method taking any name and returning an error for the twelve
/// that do not fit — moves a fact the compiler already knows into a runtime branch every caller
/// has to handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum SourceDirective {
    /// `child-src`
    ChildSrc,
    /// `connect-src`
    ConnectSrc,
    /// `default-src`
    DefaultSrc,
    /// `fenced-frame-src`
    FencedFrameSrc,
    /// `font-src`
    FontSrc,
    /// `frame-src`
    FrameSrc,
    /// `img-src`
    ImgSrc,
    /// `manifest-src`
    ManifestSrc,
    /// `media-src`
    MediaSrc,
    /// `object-src`
    ObjectSrc,
    /// `prefetch-src`
    PrefetchSrc,
    /// `script-src`
    ScriptSrc,
    /// `script-src-attr`
    ScriptSrcAttr,
    /// `script-src-elem`
    ScriptSrcElem,
    /// `style-src`
    StyleSrc,
    /// `style-src-attr`
    StyleSrcAttr,
    /// `style-src-elem`
    StyleSrcElem,
    /// `worker-src`
    WorkerSrc,
    /// `base-uri`
    BaseUri,
    /// `form-action`
    FormAction,
}

impl SourceDirective {
    /// Every source-list directive.
    pub const ALL: &'static [Self] = &[
        Self::ChildSrc,
        Self::ConnectSrc,
        Self::DefaultSrc,
        Self::FencedFrameSrc,
        Self::FontSrc,
        Self::FrameSrc,
        Self::ImgSrc,
        Self::ManifestSrc,
        Self::MediaSrc,
        Self::ObjectSrc,
        Self::PrefetchSrc,
        Self::ScriptSrc,
        Self::ScriptSrcAttr,
        Self::ScriptSrcElem,
        Self::StyleSrc,
        Self::StyleSrcAttr,
        Self::StyleSrcElem,
        Self::WorkerSrc,
        Self::BaseUri,
        Self::FormAction,
    ];

    /// The corresponding [`DirectiveName`].
    #[must_use]
    pub const fn name(self) -> DirectiveName {
        match self {
            Self::ChildSrc => DirectiveName::ChildSrc,
            Self::ConnectSrc => DirectiveName::ConnectSrc,
            Self::DefaultSrc => DirectiveName::DefaultSrc,
            Self::FencedFrameSrc => DirectiveName::FencedFrameSrc,
            Self::FontSrc => DirectiveName::FontSrc,
            Self::FrameSrc => DirectiveName::FrameSrc,
            Self::ImgSrc => DirectiveName::ImgSrc,
            Self::ManifestSrc => DirectiveName::ManifestSrc,
            Self::MediaSrc => DirectiveName::MediaSrc,
            Self::ObjectSrc => DirectiveName::ObjectSrc,
            Self::PrefetchSrc => DirectiveName::PrefetchSrc,
            Self::ScriptSrc => DirectiveName::ScriptSrc,
            Self::ScriptSrcAttr => DirectiveName::ScriptSrcAttr,
            Self::ScriptSrcElem => DirectiveName::ScriptSrcElem,
            Self::StyleSrc => DirectiveName::StyleSrc,
            Self::StyleSrcAttr => DirectiveName::StyleSrcAttr,
            Self::StyleSrcElem => DirectiveName::StyleSrcElem,
            Self::WorkerSrc => DirectiveName::WorkerSrc,
            Self::BaseUri => DirectiveName::BaseUri,
            Self::FormAction => DirectiveName::FormAction,
        }
    }

    /// The name as it is written in a header.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.name().as_str()
    }

    /// Parse a source-list directive name, case-insensitively.
    ///
    /// # Errors
    ///
    /// [`ParseError::Unrecognised`] for a name that is unknown, and
    /// [`ParseError::Malformed`] for a known name whose value is not a source list.
    pub fn parse(name: &str) -> Result<Self, ParseError> {
        DirectiveName::parse(name)?
            .as_source_directive()
            .ok_or_else(|| ParseError::Malformed {
                term: Term::DirectiveName,
                input: name.to_string(),
                reason: "this directive's value is not a source list",
            })
    }
}

impl From<SourceDirective> for DirectiveName {
    fn from(directive: SourceDirective) -> Self {
        directive.name()
    }
}

impl fmt::Display for SourceDirective {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SourceDirective {
    type Err = ParseError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Self::parse(name)
    }
}

#[cfg(test)]
mod tests {
    use super::{DirectiveName, Grammar, SourceDirective};

    /// Two enums describing one set of names drift the moment someone adds a directive to only
    /// one of them. The compiler cannot catch that; this can.
    #[test]
    fn the_source_directives_are_exactly_the_source_list_names() {
        for &name in DirectiveName::ALL {
            assert_eq!(
                name.grammar() == Grammar::SourceList,
                name.as_source_directive().is_some(),
                "{name} disagrees about whether its value is a source list"
            );
        }
        assert_eq!(
            SourceDirective::ALL.len(),
            DirectiveName::ALL
                .iter()
                .filter(|name| name.grammar() == Grammar::SourceList)
                .count()
        );
        for &directive in SourceDirective::ALL {
            assert_eq!(directive.name().as_source_directive(), Some(directive));
        }
    }

    /// A duplicate or a typo in the name table renders a policy no browser enforces as written.
    #[test]
    fn every_name_is_distinct_and_well_formed() {
        for (index, &name) in DirectiveName::ALL.iter().enumerate() {
            let text = name.as_str();
            assert!(!text.is_empty());
            assert!(
                text.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
                    && text.starts_with(|c: char| c.is_ascii_lowercase()),
                "{text:?} is not a well-formed directive name"
            );
            assert!(
                !DirectiveName::ALL[..index]
                    .iter()
                    .any(|earlier| earlier.as_str() == text),
                "duplicate directive name {text:?}"
            );
        }
    }

    #[test]
    fn names_parse_case_insensitively_and_round_trip() {
        for &name in DirectiveName::ALL {
            assert_eq!(DirectiveName::parse(name.as_str()), Ok(name));
            assert_eq!(
                DirectiveName::parse(&name.as_str().to_ascii_uppercase()),
                Ok(name)
            );
        }
        assert!(DirectiveName::parse("scrpit-src").is_err());
        assert!(SourceDirective::parse("sandbox").is_err());
        assert_eq!(
            SourceDirective::parse("Script-Src"),
            Ok(SourceDirective::ScriptSrc)
        );
    }
}
