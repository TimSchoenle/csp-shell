//! Schemes and host sources: the two source expressions that carry data from outside the program.
//!
//! Everything else in a policy is a keyword, a digest or a nonce this crate produced. A host
//! source is the one part a consumer routinely assembles from configuration — a CDN origin, an API
//! base URL, a tenant's domain — which makes it the only place a `;` can arrive from an
//! environment variable and close the directive it was supposed to extend.
//!
//! So a host source is parsed into its parts rather than accepted as a string. The parts are
//! private and rendering rebuilds the expression from them, which means the rendered form is
//! reachable only through a successful parse.

use alloc::string::{String, ToString};
use core::fmt;
use core::str::FromStr;

use crate::error::{ParseError, Term};

/// A scheme whose name this crate does not have a variant for.
///
/// Opaque and constructible only by parsing, so [`Scheme::Other`] cannot be handed a string
/// carrying a directive separator.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SchemeName(String);

impl SchemeName {
    /// Parse and lowercase a scheme name.
    ///
    /// # Errors
    ///
    /// [`ParseError::Empty`] for the empty string, and [`ParseError::InvalidByte`] for anything
    /// outside `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`.
    pub fn parse(name: &str) -> Result<Self, ParseError> {
        let name = name.strip_suffix(':').unwrap_or(name);
        let mut bytes = name.bytes().enumerate();

        match bytes.next() {
            None => return Err(ParseError::Empty { term: Term::Scheme }),
            Some((_, first)) if !first.is_ascii_alphabetic() => {
                return Err(ParseError::InvalidByte {
                    term: Term::Scheme,
                    input: name.to_string(),
                    index: 0,
                    byte: first,
                })
            }
            Some(_) => {}
        }

        for (index, byte) in bytes {
            if !(byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')) {
                return Err(ParseError::InvalidByte {
                    term: Term::Scheme,
                    input: name.to_string(),
                    index,
                    byte,
                });
            }
        }

        Ok(Self(name.to_ascii_lowercase()))
    }

    /// The scheme without its trailing colon.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SchemeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A URL scheme, as a scheme-source or as the scheme part of a host-source.
///
/// The named variants are the schemes a web policy actually mentions; anything else — an extension
/// scheme, a custom protocol handler — goes through [`Scheme::Other`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Scheme {
    /// `http`
    Http,
    /// `https`
    Https,
    /// `ws`
    Ws,
    /// `wss`
    Wss,
    /// `data`. As a scheme-source in `script-src` this is equivalent to `'unsafe-inline'`, and in
    /// `img-src` it is routine; the difference is the directive, not the scheme.
    Data,
    /// `blob`
    Blob,
    /// `filesystem`
    FileSystem,
    /// `mediastream`
    MediaStream,
    /// `file`
    File,
    /// Any other scheme.
    Other(SchemeName),
}

impl Scheme {
    /// The scheme without its trailing colon.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
            Self::Ws => "ws",
            Self::Wss => "wss",
            Self::Data => "data",
            Self::Blob => "blob",
            Self::FileSystem => "filesystem",
            Self::MediaStream => "mediastream",
            Self::File => "file",
            Self::Other(name) => name.as_str(),
        }
    }

    /// Parse a scheme, with or without its trailing colon, case-insensitively.
    ///
    /// # Errors
    ///
    /// As [`SchemeName::parse`].
    pub fn parse(scheme: &str) -> Result<Self, ParseError> {
        let name = SchemeName::parse(scheme)?;
        Ok(match name.as_str() {
            "http" => Self::Http,
            "https" => Self::Https,
            "ws" => Self::Ws,
            "wss" => Self::Wss,
            "data" => Self::Data,
            "blob" => Self::Blob,
            "filesystem" => Self::FileSystem,
            "mediastream" => Self::MediaStream,
            "file" => Self::File,
            _ => Self::Other(name),
        })
    }
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Scheme {
    type Err = ParseError;

    fn from_str(scheme: &str) -> Result<Self, Self::Err> {
        Self::parse(scheme)
    }
}

/// A host name: dot-separated labels of `ALPHA / DIGIT / "-"`, optionally ending in a dot.
///
/// Opaque and constructible only by parsing, for the same reason as [`SchemeName`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostName(String);

impl HostName {
    /// Parse and lowercase a host name.
    ///
    /// # Errors
    ///
    /// [`ParseError::Empty`] for the empty string, [`ParseError::InvalidByte`] for a byte outside
    /// the label alphabet, and [`ParseError::Malformed`] for an empty label — `a..b`, or a leading
    /// dot.
    pub fn parse(host: &str) -> Result<Self, ParseError> {
        if host.is_empty() {
            return Err(ParseError::Empty { term: Term::Host });
        }
        if let Some((index, byte)) = host
            .bytes()
            .enumerate()
            .find(|&(_, b)| !(b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.')))
        {
            return Err(ParseError::InvalidByte {
                term: Term::Host,
                input: host.to_string(),
                index,
                byte,
            });
        }

        // A single trailing dot is the root label and is allowed; every other label must have
        // content, so `a..b`, `.a` and `..` are all rejected.
        let labels = host.strip_suffix('.').unwrap_or(host);
        if labels.is_empty() || labels.split('.').any(str::is_empty) {
            return Err(ParseError::Malformed {
                term: Term::Host,
                input: host.to_string(),
                reason: "every label between dots must be non-empty",
            });
        }

        Ok(Self(host.to_ascii_lowercase()))
    }

    /// The host name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HostName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The host part of a host source.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HostPattern {
    /// `*` — any host.
    Any,
    /// `*.example.com` — any subdomain, but not `example.com` itself. That exclusion is the one
    /// most policies get wrong; a wildcard host does not match its own parent.
    Subdomains(HostName),
    /// `example.com` — exactly this host.
    Exact(HostName),
}

impl fmt::Display for HostPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => f.write_str("*"),
            Self::Subdomains(host) => write!(f, "*.{host}"),
            Self::Exact(host) => host.fmt(f),
        }
    }
}

/// The port part of a host source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PortPattern {
    /// `*` — any port.
    Any,
    /// A single port.
    Number(u16),
}

impl fmt::Display for PortPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => f.write_str("*"),
            Self::Number(port) => port.fmt(f),
        }
    }
}

/// The path part of a host source.
///
/// Opaque and constructible only by parsing. A path is the one component with a genuinely wide
/// alphabet, so it is also the one where accepting a string wholesale would matter most.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathPart(String);

impl PathPart {
    /// Parse an absolute path.
    ///
    /// # Errors
    ///
    /// [`ParseError::Malformed`] if the path does not begin with `/`, and
    /// [`ParseError::InvalidByte`] for a byte outside the policy alphabet or for `?` or `#`, which
    /// end a path and begin a query or a fragment — neither of which a host source may carry.
    pub fn parse(path: &str) -> Result<Self, ParseError> {
        if !path.starts_with('/') {
            return Err(ParseError::Malformed {
                term: Term::Path,
                input: path.to_string(),
                reason: "a path source must begin with '/'",
            });
        }
        if let Some((index, byte)) = path
            .bytes()
            .enumerate()
            .find(|&(_, b)| !crate::util::is_policy_byte(b) || matches!(b, b'?' | b'#'))
        {
            return Err(ParseError::InvalidByte {
                term: Term::Path,
                input: path.to_string(),
                index,
                byte,
            });
        }
        Ok(Self(path.to_string()))
    }

    /// The path, including its leading `/`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PathPart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A host source: `[ scheme "://" ] host [ ":" port ] [ path ]`.
///
/// # Examples
///
/// ```
/// use csp_policy::{HostPattern, HostSource, PortPattern, Scheme};
///
/// let source = HostSource::parse("https://*.example.com:8443/assets/")?;
/// assert_eq!(source.scheme(), Some(&Scheme::Https));
/// assert_eq!(source.port(), Some(PortPattern::Number(8443)));
/// assert_eq!(source.to_string(), "https://*.example.com:8443/assets/");
///
/// // The injection this type exists for.
/// assert!(HostSource::parse("https://evil.example; script-src *").is_err());
/// # Ok::<(), csp_policy::ParseError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostSource {
    scheme: Option<Scheme>,
    host: HostPattern,
    port: Option<PortPattern>,
    path: Option<PathPart>,
}

impl HostSource {
    /// A host source for exactly this host, with no scheme, port or path.
    ///
    /// # Errors
    ///
    /// As [`HostName::parse`].
    pub fn host(host: &str) -> Result<Self, ParseError> {
        Ok(Self {
            scheme: None,
            host: HostPattern::Exact(HostName::parse(host)?),
            port: None,
            path: None,
        })
    }

    /// `*`: any scheme, host, port and path. The widest source expression there is.
    #[must_use]
    pub const fn any() -> Self {
        Self {
            scheme: None,
            host: HostPattern::Any,
            port: None,
            path: None,
        }
    }

    /// Parse a host source.
    ///
    /// # Errors
    ///
    /// Whichever of [`ParseError`]'s variants the offending component produces. A source
    /// expression that is not a host source at all — a keyword, a bare scheme — is
    /// [`ParseError::Malformed`] or an invalid byte, depending on where it first departs from the
    /// grammar.
    pub fn parse(source: &str) -> Result<Self, ParseError> {
        if source.is_empty() {
            return Err(ParseError::Empty {
                term: Term::HostSource,
            });
        }

        let (scheme, rest) = match source.split_once("://") {
            Some((scheme, rest)) => (Some(Scheme::parse(scheme)?), rest),
            None => (None, source),
        };

        // The path starts at the first `/`; everything before it is the authority. Splitting here
        // first keeps a `:` inside a path from being read as a port separator.
        let (authority, path) = match rest.find('/') {
            Some(index) => (&rest[..index], Some(PathPart::parse(&rest[index..])?)),
            None => (rest, None),
        };

        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(parse_port(port)?)),
            None => (authority, None),
        };

        Ok(Self {
            scheme,
            host: parse_host_pattern(host)?,
            port,
            path,
        })
    }

    /// The scheme, if the source names one.
    #[must_use]
    pub fn scheme(&self) -> Option<&Scheme> {
        self.scheme.as_ref()
    }

    /// The host pattern.
    #[must_use]
    pub const fn host_pattern(&self) -> &HostPattern {
        &self.host
    }

    /// The port, if the source names one.
    #[must_use]
    pub const fn port(&self) -> Option<PortPattern> {
        self.port
    }

    /// The path, if the source names one.
    #[must_use]
    pub fn path(&self) -> Option<&str> {
        self.path.as_ref().map(PathPart::as_str)
    }
}

impl fmt::Display for HostSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(scheme) = &self.scheme {
            write!(f, "{scheme}://")?;
        }
        self.host.fmt(f)?;
        if let Some(port) = self.port {
            write!(f, ":{port}")?;
        }
        if let Some(path) = &self.path {
            path.fmt(f)?;
        }
        Ok(())
    }
}

impl FromStr for HostSource {
    type Err = ParseError;

    fn from_str(source: &str) -> Result<Self, Self::Err> {
        Self::parse(source)
    }
}

/// `"*" / [ "*." ] host-name`.
fn parse_host_pattern(host: &str) -> Result<HostPattern, ParseError> {
    if host == "*" {
        return Ok(HostPattern::Any);
    }
    match host.strip_prefix("*.") {
        Some(rest) => Ok(HostPattern::Subdomains(HostName::parse(rest)?)),
        None => Ok(HostPattern::Exact(HostName::parse(host)?)),
    }
}

/// `1*DIGIT / "*"`.
fn parse_port(port: &str) -> Result<PortPattern, ParseError> {
    if port == "*" {
        return Ok(PortPattern::Any);
    }
    if port.is_empty() {
        return Err(ParseError::Empty { term: Term::Port });
    }
    if let Some((index, byte)) = port.bytes().enumerate().find(|&(_, b)| !b.is_ascii_digit()) {
        return Err(ParseError::InvalidByte {
            term: Term::Port,
            input: port.to_string(),
            index,
            byte,
        });
    }
    port.parse()
        .map(PortPattern::Number)
        .map_err(|_| ParseError::Malformed {
            term: Term::Port,
            input: port.to_string(),
            reason: "a port must fit in 16 bits",
        })
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::{HostPattern, HostSource, PortPattern, Scheme};

    #[test]
    fn the_shapes_a_real_policy_uses_round_trip() {
        for source in [
            "*",
            "example.com",
            "*.example.com",
            "example.com.",
            "https://example.com",
            "https://*.example.com:8443/assets/",
            "http://localhost:3000",
            "example.com:*",
            "https://challenges.cloudflare.com",
            "wss://api.example.com/socket",
        ] {
            let parsed = HostSource::parse(source)
                .unwrap_or_else(|error| panic!("{source} must parse: {error}"));
            assert_eq!(parsed.to_string(), source, "{source} did not round-trip");
        }
    }

    #[test]
    fn schemes_hosts_and_ports_are_case_folded() {
        let parsed = HostSource::parse("HTTPS://API.Example.COM:443").unwrap();
        assert_eq!(parsed.to_string(), "https://api.example.com:443");
        assert_eq!(parsed.scheme(), Some(&Scheme::Https));
        assert_eq!(parsed.port(), Some(PortPattern::Number(443)));
    }

    /// The vector this module exists for: a separator inside a configuration-supplied origin.
    #[test]
    fn separators_and_whitespace_are_refused() {
        for source in [
            "https://evil.example; script-src *",
            "https://a.example,https://b.example",
            "https://a.example b.example",
            "https://a.example\nscript-src",
            "https://a.example/pa th",
            "https://a.example/path?q=1",
            "https://a.example/path#f",
        ] {
            assert!(
                HostSource::parse(source).is_err(),
                "{source:?} must be refused"
            );
        }
    }

    #[test]
    fn malformed_authorities_are_refused() {
        for source in [
            "",
            "https://",
            "https://:443",
            "example.com:",
            "example.com:65536",
            "example.com:-1",
            ".example.com",
            "a..b",
            "*.*",
            "*example.com",
        ] {
            assert!(
                HostSource::parse(source).is_err(),
                "{source:?} must be refused"
            );
        }
    }

    #[test]
    fn a_colon_inside_a_path_is_not_a_port() {
        let parsed = HostSource::parse("https://example.com/a:b").unwrap();
        assert_eq!(parsed.port(), None);
        assert_eq!(parsed.path(), Some("/a:b"));
    }

    #[test]
    fn wildcards_keep_their_two_distinct_meanings() {
        assert_eq!(
            HostSource::parse("*").unwrap().host_pattern(),
            &HostPattern::Any
        );
        let subdomains = HostSource::parse("*.example.com").unwrap();
        assert!(matches!(
            subdomains.host_pattern(),
            HostPattern::Subdomains(host) if host.as_str() == "example.com"
        ));
    }
}
