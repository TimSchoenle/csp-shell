//! Where violation reports go.

use alloc::string::{String, ToString};
use core::fmt;
use core::str::FromStr;

use crate::error::{ParseError, Term};
use crate::util::is_policy_byte;

/// A reporting group name, as declared in a `Reporting-Endpoints` header.
///
/// `report-to` names a group rather than a URL, which is what lets one endpoint serve several
/// policies. A group that was never declared is not an error anywhere: reports are not sent,
/// and the only symptom is a reporting pipeline that stays empty.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReportGroup(String);

impl ReportGroup {
    /// Parses a group name.
    ///
    /// # Errors
    ///
    /// [`ParseError::Empty`] for the empty string, and [`ParseError::InvalidByte`] for a byte that
    /// cannot appear in a policy.
    pub fn parse(group: &str) -> Result<Self, ParseError> {
        validate(group, Term::ReportGroup)?;
        Ok(Self(group.to_string()))
    }

    /// The group name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ReportGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for ReportGroup {
    type Err = ParseError;

    fn from_str(group: &str) -> Result<Self, Self::Err> {
        Self::parse(group)
    }
}

/// A `report-uri` endpoint.
///
/// Deprecated in favour of `report-to`, and still the only one some browsers implement, so a
/// policy that wants reports from all of them sets both.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReportUri(String);

impl ReportUri {
    /// Parses an endpoint.
    ///
    /// # Errors
    ///
    /// [`ParseError::Empty`] for the empty string, and [`ParseError::InvalidByte`] for a byte that
    /// cannot appear in a policy — which is what stops a configured endpoint from carrying a
    /// directive separator into the header.
    pub fn parse(uri: &str) -> Result<Self, ParseError> {
        validate(uri, Term::ReportUri)?;
        Ok(Self(uri.to_string()))
    }

    /// The endpoint.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ReportUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for ReportUri {
    type Err = ParseError;

    fn from_str(uri: &str) -> Result<Self, Self::Err> {
        Self::parse(uri)
    }
}

/// Non-empty, and every byte one a policy may carry.
fn validate(value: &str, term: Term) -> Result<(), ParseError> {
    if value.is_empty() {
        return Err(ParseError::Empty { term });
    }
    if let Some((index, byte)) = value.bytes().enumerate().find(|&(_, b)| !is_policy_byte(b)) {
        return Err(ParseError::InvalidByte {
            term,
            input: value.to_string(),
            index,
            byte,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::{ReportGroup, ReportUri};

    #[test]
    fn endpoints_keep_what_they_are_given() {
        let uri = ReportUri::parse("https://reports.example.com/csp?project=web").unwrap();
        assert_eq!(
            uri.to_string(),
            "https://reports.example.com/csp?project=web"
        );
        assert_eq!(
            ReportGroup::parse("csp-endpoint").unwrap().to_string(),
            "csp-endpoint"
        );
    }

    #[test]
    fn a_separator_in_a_configured_endpoint_is_refused() {
        for value in [
            "",
            "https://a.example; script-src *",
            "https://a.example,b",
            "a b",
        ] {
            assert!(ReportUri::parse(value).is_err(), "{value:?}");
            assert!(ReportGroup::parse(value).is_err(), "{value:?}");
        }
    }
}
