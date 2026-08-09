//! The `sandbox` directive's tokens.

use alloc::string::ToString;
use core::fmt;
use core::str::FromStr;

use crate::error::{ParseError, Term};

/// One `sandbox` token: a restriction lifted from the document.
///
/// `sandbox` inverts the polarity of the rest of a policy. Every other directive names what is
/// allowed; this one applies every restriction there is and each token gives one back. A `sandbox`
/// with no tokens is the most restrictive form, not the least.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum SandboxToken {
    /// `allow-downloads`
    AllowDownloads,
    /// `allow-downloads-without-user-activation`
    AllowDownloadsWithoutUserActivation,
    /// `allow-forms`
    AllowForms,
    /// `allow-modals`
    AllowModals,
    /// `allow-orientation-lock`
    AllowOrientationLock,
    /// `allow-pointer-lock`
    AllowPointerLock,
    /// `allow-popups`
    AllowPopups,
    /// `allow-popups-to-escape-sandbox`
    AllowPopupsToEscapeSandbox,
    /// `allow-presentation`
    AllowPresentation,
    /// `allow-same-origin`. Granting this together with `allow-scripts` to a document from the
    /// same origin lets that document remove its own sandbox attribute, which is the one
    /// combination worth reading twice.
    AllowSameOrigin,
    /// `allow-scripts`
    AllowScripts,
    /// `allow-storage-access-by-user-activation`
    AllowStorageAccessByUserActivation,
    /// `allow-top-navigation`
    AllowTopNavigation,
    /// `allow-top-navigation-by-user-activation`
    AllowTopNavigationByUserActivation,
    /// `allow-top-navigation-to-custom-protocols`
    AllowTopNavigationToCustomProtocols,
}

impl SandboxToken {
    /// Every token.
    pub const ALL: &'static [Self] = &[
        Self::AllowDownloads,
        Self::AllowDownloadsWithoutUserActivation,
        Self::AllowForms,
        Self::AllowModals,
        Self::AllowOrientationLock,
        Self::AllowPointerLock,
        Self::AllowPopups,
        Self::AllowPopupsToEscapeSandbox,
        Self::AllowPresentation,
        Self::AllowSameOrigin,
        Self::AllowScripts,
        Self::AllowStorageAccessByUserActivation,
        Self::AllowTopNavigation,
        Self::AllowTopNavigationByUserActivation,
        Self::AllowTopNavigationToCustomProtocols,
    ];

    /// The token as it is written in a header.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AllowDownloads => "allow-downloads",
            Self::AllowDownloadsWithoutUserActivation => "allow-downloads-without-user-activation",
            Self::AllowForms => "allow-forms",
            Self::AllowModals => "allow-modals",
            Self::AllowOrientationLock => "allow-orientation-lock",
            Self::AllowPointerLock => "allow-pointer-lock",
            Self::AllowPopups => "allow-popups",
            Self::AllowPopupsToEscapeSandbox => "allow-popups-to-escape-sandbox",
            Self::AllowPresentation => "allow-presentation",
            Self::AllowSameOrigin => "allow-same-origin",
            Self::AllowScripts => "allow-scripts",
            Self::AllowStorageAccessByUserActivation => "allow-storage-access-by-user-activation",
            Self::AllowTopNavigation => "allow-top-navigation",
            Self::AllowTopNavigationByUserActivation => "allow-top-navigation-by-user-activation",
            Self::AllowTopNavigationToCustomProtocols => "allow-top-navigation-to-custom-protocols",
        }
    }

    /// Parse a token, case-insensitively.
    ///
    /// # Errors
    ///
    /// [`ParseError::Unrecognised`] for anything else. A browser drops a token it does not know,
    /// leaving a restriction in place that the policy says was lifted — a broken page rather than
    /// a hole, but broken with no message that names the cause.
    pub fn parse(token: &str) -> Result<Self, ParseError> {
        Self::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.as_str().eq_ignore_ascii_case(token))
            .ok_or_else(|| ParseError::Unrecognised {
                term: Term::SandboxToken,
                input: token.to_string(),
            })
    }
}

impl fmt::Display for SandboxToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SandboxToken {
    type Err = ParseError;

    fn from_str(token: &str) -> Result<Self, Self::Err> {
        Self::parse(token)
    }
}

#[cfg(test)]
mod tests {
    use super::SandboxToken;

    #[test]
    fn every_token_is_distinct_and_round_trips() {
        for (index, &token) in SandboxToken::ALL.iter().enumerate() {
            assert_eq!(SandboxToken::parse(token.as_str()), Ok(token));
            assert_eq!(
                SandboxToken::parse(&token.as_str().to_ascii_uppercase()),
                Ok(token)
            );
            assert!(
                !SandboxToken::ALL[..index]
                    .iter()
                    .any(|earlier| earlier.as_str() == token.as_str()),
                "duplicate token {token}"
            );
            assert!(token.as_str().starts_with("allow-"));
        }
        assert!(SandboxToken::parse("allow-everything").is_err());
    }
}
