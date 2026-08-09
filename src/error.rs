//! Error types.
//!
//! Hand-written rather than derived: three shapes do not justify a proc-macro dependency in a
//! crate whose entire default build is one dependency.

use alloc::string::String;
use core::fmt;

/// A rejected input to the [`Csp`](crate::Csp) builder.
///
/// Every variant describes a policy that would have been silently wrong — a header the browser
/// parses cleanly while meaning something other than what the caller wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CspError {
    /// The directive name is not `[a-zA-Z][a-zA-Z0-9-]*`.
    InvalidDirectiveName {
        /// The name as supplied.
        name: String,
    },

    /// The directive name is well-formed but is not a directive this crate knows about.
    ///
    /// Only produced in debug builds — see [`Csp::directive`](crate::Csp::directive) for why the
    /// two build profiles differ here.
    UnknownDirective {
        /// The name as supplied, lowercased.
        name: String,
    },

    /// A source expression was the empty string, which would render as a stray space and shift
    /// the meaning of the directive around it.
    EmptySource {
        /// The directive the source was being added to.
        directive: String,
    },

    /// A source expression contained a byte outside the permitted set.
    ///
    /// The permitted set is printable ASCII excluding space, `,` and `;` — the three bytes that
    /// end a source, end a policy and end a directive respectively. A source carrying any of them
    /// is a Content-Security-Policy header injection.
    InvalidSource {
        /// The directive the source was being added to.
        directive: String,
        /// The source expression as supplied.
        source: String,
        /// Byte offset of the first offending byte within `source`.
        index: usize,
        /// The offending byte.
        byte: u8,
    },

    /// A source expression that has a dedicated method on the builder was passed as a string.
    ///
    /// Not a prohibition: all three are spec-valid and one of them is occasionally correct. The
    /// named method is a token a downstream lint can match exactly, where a lint matching the
    /// source expression inside an arbitrary string literal is a heuristic.
    RoutedSourceExpression {
        /// The source expression as supplied.
        source: String,
        /// The method to call instead, as a bare identifier.
        method: &'static str,
    },
}

impl fmt::Display for CspError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDirectiveName { name } => write!(
                f,
                "invalid CSP directive name {name:?}: expected [a-zA-Z][a-zA-Z0-9-]*"
            ),
            Self::UnknownDirective { name } => write!(
                f,
                "unknown CSP directive {name:?}; a browser ignores a directive it does not \
                 recognise, so a typo here is a silently absent restriction"
            ),
            Self::EmptySource { directive } => {
                write!(f, "empty source expression in directive {directive:?}")
            }
            Self::InvalidSource {
                directive,
                source,
                index,
                byte,
            } => write!(
                f,
                "invalid byte {byte:#04x} at offset {index} in source expression {source:?} of \
                 directive {directive:?}: a source expression may contain only printable ASCII \
                 excluding space, ',' and ';'"
            ),
            Self::RoutedSourceExpression { source, method } => write!(
                f,
                "source expression {source} is not accepted as a string; call Csp::{method}() \
                 instead"
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
