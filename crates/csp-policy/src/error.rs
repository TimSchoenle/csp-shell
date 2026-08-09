//! The one error every parse in this crate returns.
//!
//! Hand-written rather than derived: a crate whose whole point is to sit under a security header
//! with no dependencies does not acquire a proc-macro for six variants.

use alloc::string::String;
use core::fmt;

use crate::hash::HashAlgorithm;

/// What was being parsed when the input was rejected.
///
/// Carried by every [`ParseError`] so a message names the grammar that refused the input rather
/// than only the input itself — the difference between "invalid" and "invalid as a port".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Term {
    /// A directive name, such as `script-src`.
    DirectiveName,
    /// A whole source expression.
    Source,
    /// The scheme of a scheme-source or the scheme part of a host-source.
    Scheme,
    /// A host-source: optional scheme, host, optional port, optional path.
    HostSource,
    /// The host part of a host-source.
    Host,
    /// The port part of a host-source.
    Port,
    /// The path part of a host-source.
    Path,
    /// The base64 value of a `'nonce-…'` source.
    Nonce,
    /// The base64 value of a `'sha256-…'` source.
    Hash,
    /// A hash algorithm name.
    HashAlgorithm,
    /// A `sandbox` token.
    SandboxToken,
    /// A `trusted-types` policy name.
    TrustedTypePolicyName,
    /// A `require-trusted-types-for` sink.
    TrustedTypeSink,
    /// The value of the `webrtc` directive.
    Webrtc,
    /// A reporting group name.
    ReportGroup,
    /// A `report-uri` endpoint.
    ReportUri,
}

impl Term {
    /// The term as it appears in an error message.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DirectiveName => "directive name",
            Self::Source => "source expression",
            Self::Scheme => "scheme",
            Self::HostSource => "host source",
            Self::Host => "host",
            Self::Port => "port",
            Self::Path => "path",
            Self::Nonce => "nonce",
            Self::Hash => "hash",
            Self::HashAlgorithm => "hash algorithm",
            Self::SandboxToken => "sandbox token",
            Self::TrustedTypePolicyName => "trusted-types policy name",
            Self::TrustedTypeSink => "trusted-types sink",
            Self::Webrtc => "webrtc value",
            Self::ReportGroup => "reporting group name",
            Self::ReportUri => "report-uri endpoint",
        }
    }
}

impl fmt::Display for Term {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An input that does not parse as the CSP term it was offered as.
///
/// Every variant describes a policy that would have been silently wrong. A browser does not
/// report a malformed source expression to the origin that served it: it drops the expression,
/// keeps the rest of the directive, and enforces something narrower or wider than what was
/// written. That is the failure this type exists to move forward in time.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// The input was empty where the grammar requires at least one character.
    Empty {
        /// The term the empty input was offered as.
        term: Term,
    },

    /// The input contained a byte the grammar does not allow in that position.
    ///
    /// This is the variant that stops a Content-Security-Policy header injection: a `;` inside a
    /// configuration-supplied origin closes the directive and opens a new one, and the resulting
    /// header parses cleanly in every browser.
    InvalidByte {
        /// The term being parsed.
        term: Term,
        /// The input as supplied.
        input: String,
        /// Byte offset of the first offending byte within `input`.
        index: usize,
        /// The offending byte.
        byte: u8,
    },

    /// The input is well-formed but is not one of the values this term admits.
    Unrecognised {
        /// The term being parsed.
        term: Term,
        /// The input as supplied.
        input: String,
    },

    /// The input's bytes are all allowed but its shape is not.
    Malformed {
        /// The term being parsed.
        term: Term,
        /// The input as supplied.
        input: String,
        /// What the grammar required instead.
        reason: &'static str,
    },

    /// A hash value that cannot be a digest of the algorithm it was labelled with.
    ///
    /// Checked because the length is the only property of a hash a reader can verify, and a
    /// truncated one is a script that silently never runs.
    HashLength {
        /// The algorithm the value was labelled with.
        algorithm: HashAlgorithm,
        /// The base64 value as supplied.
        input: String,
    },

    /// `'none'` was offered as a source expression.
    ///
    /// It is not one: the grammar admits it only as an entire source list, because a list
    /// containing `'none'` alongside anything else means the `'none'` is ignored. Keeping that
    /// unrepresentable is the whole reason [`SourceList`](crate::SourceList) is an enum.
    NoneIsNotASource {
        /// The input as supplied, which may differ from `'none'` in case.
        input: String,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty { term } => write!(f, "empty {term}"),
            Self::InvalidByte {
                term,
                input,
                index,
                byte,
            } => write!(
                f,
                "invalid byte {byte:#04x} at offset {index} in {term} {input:?}"
            ),
            Self::Unrecognised { term, input } => write!(f, "unrecognised {term} {input:?}"),
            Self::Malformed {
                term,
                input,
                reason,
            } => write!(f, "malformed {term} {input:?}: {reason}"),
            Self::HashLength { algorithm, input } => write!(
                f,
                "{input:?} is not a {algorithm} digest: {} produces {} bytes, which is {} base64 \
                 characters ({} with padding), and this value has {}",
                algorithm,
                algorithm.digest_len(),
                algorithm.unpadded_len(),
                algorithm.padded_len(),
                input.len()
            ),
            Self::NoneIsNotASource { input } => write!(
                f,
                "{input:?} is a whole source list, not a source expression; use SourceList::None"
            ),
        }
    }
}

impl core::error::Error for ParseError {}
