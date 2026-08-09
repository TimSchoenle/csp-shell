//! Error types.
//!
//! Hand-written rather than derived: two shapes do not justify a proc-macro dependency in a crate
//! whose entire default build is two dependencies.

use core::fmt;

use csp_policy::Source;

/// A source expression the [`Csp`](crate::Csp) builder refuses to take as data.
///
/// Everything that used to be an error here — an unknown directive name, a malformed origin, a
/// source expression carrying a `;` — is now a value that cannot be constructed. What remains is
/// the one refusal that is a policy of this crate rather than a rule of the grammar.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CspError {
    /// A source expression that has a dedicated method on the builder was passed as data.
    ///
    /// Not a prohibition: all three are spec-valid and one of them is occasionally correct. The
    /// named method is a token a downstream lint can match exactly, and a method name cannot be
    /// assembled by `format!`, `concat!` or a configuration value the way a list of sources
    /// built at runtime can.
    RoutedSourceExpression {
        /// The source expression as supplied.
        source: Source,
        /// The method to call instead, as a bare identifier.
        method: &'static str,
    },
}

impl fmt::Display for CspError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RoutedSourceExpression { source, method } => write!(
                f,
                "source expression {source} is not accepted as data; call Csp::{method}() instead"
            ),
        }
    }
}

impl core::error::Error for CspError {}

/// A shell that could not be read or decoded.
///
/// The caller decides whether this is fatal. For a shell whose inline scripts are a progressive
/// enhancement, serving a hashless policy and logging is right; for a shell that is entirely
/// inline-scripted the degraded outcome is a blank page, which is the failure this crate exists
/// to prevent. The crate does not pick.
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
#[derive(Debug)]
pub struct ScanError {
    path: std::path::PathBuf,
    source: std::io::Error,
}

#[cfg(feature = "std")]
impl ScanError {
    pub(crate) fn new(path: std::path::PathBuf, source: std::io::Error) -> Self {
        Self { path, source }
    }

    /// The path that could not be read.
    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

#[cfg(feature = "std")]
impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "could not read shell at {}", self.path.display())
    }
}

#[cfg(feature = "std")]
impl core::error::Error for ScanError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.source)
    }
}
