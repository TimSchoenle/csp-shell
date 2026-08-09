//! `trusted-types` and `require-trusted-types-for`.
//!
//! These two are the only directives in CSP that change what JavaScript may do rather than what it
//! may load. `require-trusted-types-for 'script'` turns every assignment to a DOM sink into a
//! `TypeError` unless the value came from a policy, and `trusted-types` names which policies may
//! exist. Neither has anything to do with source expressions, which is why neither takes one.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use crate::error::{ParseError, Term};
use crate::util::push_unique;

/// The name of a Trusted Types policy, as passed to `trustedTypes.createPolicy`.
///
/// Opaque and constructible only by parsing: the name reaches a response header, so its alphabet
/// is checked rather than assumed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrustedTypePolicyName(String);

impl TrustedTypePolicyName {
    /// Parse a policy name.
    ///
    /// # Errors
    ///
    /// [`ParseError::Empty`] for the empty string, and [`ParseError::InvalidByte`] for a byte
    /// outside `ALPHA / DIGIT / "-" / "#" / "=" / "_" / "/" / "@" / "." / "%"`.
    pub fn parse(name: &str) -> Result<Self, ParseError> {
        if name.is_empty() {
            return Err(ParseError::Empty {
                term: Term::TrustedTypePolicyName,
            });
        }
        if let Some((index, byte)) = name.bytes().enumerate().find(|&(_, b)| !is_name_byte(b)) {
            return Err(ParseError::InvalidByte {
                term: Term::TrustedTypePolicyName,
                input: name.to_string(),
                index,
                byte,
            });
        }
        Ok(Self(name.to_string()))
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// `ALPHA / DIGIT / "-" / "#" / "=" / "_" / "/" / "@" / "." / "%"`.
///
/// Notably excludes `*` and `'`, which is what keeps a policy name from being mistaken for the
/// wildcard or for `'allow-duplicates'`.
#[inline]
const fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(byte, b'-' | b'#' | b'=' | b'_' | b'/' | b'@' | b'.' | b'%')
}

impl fmt::Display for TrustedTypePolicyName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for TrustedTypePolicyName {
    type Err = ParseError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Self::parse(name)
    }
}

/// The value of `trusted-types`.
///
/// # Examples
///
/// ```
/// use csp_policy::{TrustedTypePolicyName, TrustedTypes};
///
/// assert_eq!(TrustedTypes::None.to_string(), "'none'");
///
/// let value = TrustedTypes::policies([TrustedTypePolicyName::parse("dompurify")?])
///     .allowing_duplicates();
/// assert_eq!(value.to_string(), "dompurify 'allow-duplicates'");
/// # Ok::<(), csp_policy::ParseError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum TrustedTypes {
    /// `'none'` — no policy may be created at all.
    #[default]
    None,
    /// The policies that may be created.
    Policies {
        /// Named policies, in the order they were added.
        names: Vec<TrustedTypePolicyName>,
        /// `*` — any policy name.
        wildcard: bool,
        /// `'allow-duplicates'` — a name may be registered more than once. Without it, a second
        /// `createPolicy` with the same name throws, which is the point.
        allow_duplicates: bool,
    },
}

impl TrustedTypes {
    /// Named policies, with duplicates dropped.
    #[must_use]
    pub fn policies(names: impl IntoIterator<Item = TrustedTypePolicyName>) -> Self {
        let mut list = Vec::new();
        for name in names {
            push_unique(&mut list, name);
        }
        Self::Policies {
            names: list,
            wildcard: false,
            allow_duplicates: false,
        }
    }

    /// Any policy name. Equivalent to not deploying Trusted Types' allow-list at all, and useful
    /// only as a first step in a rollout.
    #[must_use]
    pub fn any() -> Self {
        Self::Policies {
            names: Vec::new(),
            wildcard: true,
            allow_duplicates: false,
        }
    }

    /// The same value, with `'allow-duplicates'`. A no-op on [`TrustedTypes::None`].
    #[must_use]
    pub fn allowing_duplicates(self) -> Self {
        match self {
            Self::None => Self::None,
            Self::Policies {
                names, wildcard, ..
            } => Self::Policies {
                names,
                wildcard,
                allow_duplicates: true,
            },
        }
    }
}

impl fmt::Display for TrustedTypes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self::Policies {
            names,
            wildcard,
            allow_duplicates,
        } = self
        else {
            return f.write_str("'none'");
        };
        if names.is_empty() && !wildcard && !allow_duplicates {
            return f.write_str("'none'");
        }

        let mut separator = "";
        if *wildcard {
            f.write_str("*")?;
            separator = " ";
        }
        for name in names {
            write!(f, "{separator}{name}")?;
            separator = " ";
        }
        if *allow_duplicates {
            write!(f, "{separator}'allow-duplicates'")?;
        }
        Ok(())
    }
}

/// A sink category that `require-trusted-types-for` can protect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum TrustedTypeSink {
    /// `'script'` — every DOM sink that compiles or executes script.
    Script,
}

impl TrustedTypeSink {
    /// Every sink category.
    pub const ALL: &'static [Self] = &[Self::Script];

    /// The sink as it is written in a header, quotes included.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Script => "'script'",
        }
    }

    /// Parse a sink category, with or without quotes, case-insensitively.
    ///
    /// # Errors
    ///
    /// [`ParseError::Unrecognised`] for anything but `'script'`.
    pub fn parse(sink: &str) -> Result<Self, ParseError> {
        let bare = sink
            .strip_prefix('\'')
            .and_then(|rest| rest.strip_suffix('\''))
            .unwrap_or(sink);
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
                term: Term::TrustedTypeSink,
                input: sink.to_string(),
            })
    }
}

impl fmt::Display for TrustedTypeSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TrustedTypeSink {
    type Err = ParseError;

    fn from_str(sink: &str) -> Result<Self, Self::Err> {
        Self::parse(sink)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::{TrustedTypePolicyName, TrustedTypeSink, TrustedTypes};

    fn name(text: &str) -> TrustedTypePolicyName {
        TrustedTypePolicyName::parse(text).unwrap()
    }

    #[test]
    fn a_policy_name_is_checked_against_its_own_alphabet() {
        for text in ["dompurify", "my-policy#1", "a/b@c.d%20", "="] {
            assert!(TrustedTypePolicyName::parse(text).is_ok(), "{text}");
        }
        for text in ["", "*", "'allow-duplicates'", "a b", "a;b", "a,b"] {
            assert!(TrustedTypePolicyName::parse(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn the_rendered_value_matches_what_the_directive_means() {
        assert_eq!(TrustedTypes::None.to_string(), "'none'");
        assert_eq!(TrustedTypes::policies([]).to_string(), "'none'");
        assert_eq!(TrustedTypes::any().to_string(), "*");
        assert_eq!(
            TrustedTypes::policies([name("a"), name("b"), name("a")]).to_string(),
            "a b"
        );
        assert_eq!(
            TrustedTypes::any().allowing_duplicates().to_string(),
            "* 'allow-duplicates'"
        );
        assert_eq!(
            TrustedTypes::None.allowing_duplicates().to_string(),
            "'none'"
        );
    }

    #[test]
    fn sinks_parse_with_or_without_quotes() {
        assert_eq!(
            TrustedTypeSink::parse("'script'"),
            Ok(TrustedTypeSink::Script)
        );
        assert_eq!(
            TrustedTypeSink::parse("SCRIPT"),
            Ok(TrustedTypeSink::Script)
        );
        assert!(TrustedTypeSink::parse("'style'").is_err());
    }
}
