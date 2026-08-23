//! Hash and nonce sources — the two source expressions that admit an inline script by identity
//! rather than by origin.
//!
//! Both are base64 values, and both fail silently when they are wrong: a browser given a hash that
//! does not match, or a nonce it cannot parse, refuses the script and reports nothing to the
//! origin. The page is blank and the only evidence is in a console nobody is watching. So both
//! types check what can be checked at construction — the alphabet, the padding, and for a hash the
//! length the algorithm implies.

use alloc::string::{String, ToString};
use core::fmt;
use core::str::FromStr;

use crate::base64;
use crate::error::{ParseError, Term};

/// A hash algorithm CSP admits for an integrity source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum HashAlgorithm {
    /// SHA-256, and the only one worth defaulting to: it is the shortest of the three and no
    /// weakness relevant to this use is known.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl HashAlgorithm {
    /// Every algorithm, weakest first.
    pub const ALL: &'static [Self] = &[Self::Sha256, Self::Sha384, Self::Sha512];

    /// The prefix as it is written in a source expression, without the trailing `-`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }

    /// Length of a digest in bytes.
    #[must_use]
    pub const fn digest_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// Length of a base64 digest written without padding.
    #[must_use]
    pub const fn unpadded_len(self) -> usize {
        (self.digest_len() * 4).div_ceil(3)
    }

    /// Length of a base64 digest written with padding.
    #[must_use]
    pub const fn padded_len(self) -> usize {
        self.digest_len().div_ceil(3) * 4
    }

    /// Parses an algorithm name, case-insensitively.
    ///
    /// # Errors
    ///
    /// [`ParseError::Unrecognised`] for anything but the three names above. A policy naming an
    /// algorithm the browser does not implement has a source expression that matches nothing.
    pub fn parse(name: &str) -> Result<Self, ParseError> {
        Self::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.as_str().eq_ignore_ascii_case(name))
            .ok_or_else(|| ParseError::Unrecognised {
                term: Term::HashAlgorithm,
                input: name.to_string(),
            })
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for HashAlgorithm {
    type Err = ParseError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Self::parse(name)
    }
}

/// A `'sha256-…'` source: an inline script or style admitted by the digest of its content.
///
/// # Examples
///
/// ```
/// use csp_policy::{HashAlgorithm, HashSource};
///
/// let empty = HashSource::from_digest(HashAlgorithm::Sha256, &[0u8; 32])?;
/// assert_eq!(
///     empty.to_string(),
///     "'sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='"
/// );
///
/// // A digest of the wrong length for the algorithm it claims cannot be built.
/// assert!(HashSource::new(HashAlgorithm::Sha256, "deadbeef").is_err());
/// # Ok::<(), csp_policy::ParseError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HashSource {
    algorithm: HashAlgorithm,
    value: String,
}

impl HashSource {
    /// A hash source from an already-encoded base64 digest.
    ///
    /// # Errors
    ///
    /// [`ParseError::InvalidByte`] for a value outside `base64-value`, and
    /// [`ParseError::HashLength`] for a value that cannot be a digest of `algorithm`.
    pub fn new(algorithm: HashAlgorithm, value: &str) -> Result<Self, ParseError> {
        if let Some((index, byte)) = base64::first_invalid_base64_byte(value) {
            return Err(ParseError::InvalidByte {
                term: Term::Hash,
                input: value.to_string(),
                index,
                byte,
            });
        }
        if value.len() != algorithm.unpadded_len() && value.len() != algorithm.padded_len() {
            return Err(ParseError::HashLength {
                algorithm,
                input: value.to_string(),
            });
        }
        Ok(Self {
            algorithm,
            value: value.to_string(),
        })
    }

    /// A `'sha256-…'` source from a SHA-256 digest.
    ///
    /// Infallible where [`HashSource::from_digest`] is not: the array's length is the algorithm's
    /// digest length, so the only way this can be wrong is to hash the wrong bytes.
    #[must_use]
    pub fn sha256(digest: &[u8; 32]) -> Self {
        Self {
            algorithm: HashAlgorithm::Sha256,
            value: base64::encode(digest),
        }
    }

    /// A hash source from a raw digest.
    ///
    /// # Errors
    ///
    /// [`ParseError::HashLength`] if `digest` is not [`HashAlgorithm::digest_len`] bytes long.
    pub fn from_digest(algorithm: HashAlgorithm, digest: &[u8]) -> Result<Self, ParseError> {
        let value = base64::encode(digest);
        if digest.len() != algorithm.digest_len() {
            return Err(ParseError::HashLength {
                algorithm,
                input: value,
            });
        }
        Ok(Self { algorithm, value })
    }

    /// Parses a hash source, with or without its surrounding quotes.
    ///
    /// # Errors
    ///
    /// [`ParseError::Malformed`] if there is no `-` separating an algorithm from a value, plus
    /// whatever [`HashAlgorithm::parse`] and [`HashSource::new`] reject.
    pub fn parse(source: &str) -> Result<Self, ParseError> {
        let body = unquote(source);
        let (algorithm, value) = body.split_once('-').ok_or_else(|| ParseError::Malformed {
            term: Term::Hash,
            input: source.to_string(),
            reason: "expected an algorithm, '-', then a base64 digest",
        })?;
        Self::new(HashAlgorithm::parse(algorithm)?, value)
    }

    /// The algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    /// The base64 digest, without the algorithm prefix or the surrounding quotes.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Display for HashSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "'{}-{}'", self.algorithm, self.value)
    }
}

impl FromStr for HashSource {
    type Err = ParseError;

    fn from_str(source: &str) -> Result<Self, Self::Err> {
        Self::parse(source)
    }
}

/// Base64 characters carrying 128 bits, which is the entropy floor CSP puts on a nonce.
///
/// Six bits per character, rounded up. A shorter nonce is guessable in a way the header gives no
/// hint of, which is the failure mode this crate exists to make loud.
const MIN_NONCE_CHARS: usize = 128_usize.div_ceil(6);

/// A `'nonce-…'` source: an inline script admitted by a value the server minted for this response.
///
/// A nonce is only a restriction if it is unpredictable *and* used once. This type can enforce the
/// first — 128 bits, checked — and nothing in a type can enforce the second: serving one response
/// from cache pins its nonce across every reader for the lifetime of the cache entry, which is
/// `'unsafe-inline'` with extra steps.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NonceSource(String);

impl NonceSource {
    /// A nonce from at least 128 bits of entropy, base64-encoded.
    ///
    /// The bound is on the array's length, so a caller who tries to mint a nonce from eight bytes
    /// does not compile. The bytes must come from a CSPRNG; that part is the caller's.
    #[must_use]
    pub fn from_entropy<const N: usize>(bytes: &[u8; N]) -> Self {
        const { assert!(N * 8 >= 128, "a nonce needs at least 128 bits of entropy") }
        Self(base64::encode(bytes))
    }

    /// Parses a nonce, with or without its `nonce-` prefix and surrounding quotes.
    ///
    /// # Errors
    ///
    /// [`ParseError::InvalidByte`] for a value outside `base64-value`, and
    /// [`ParseError::Malformed`] for one carrying less than 128 bits.
    pub fn parse(source: &str) -> Result<Self, ParseError> {
        let body = unquote(source);
        let value = body.strip_prefix("nonce-").unwrap_or(body);

        if let Some((index, byte)) = base64::first_invalid_base64_byte(value) {
            return Err(ParseError::InvalidByte {
                term: Term::Nonce,
                input: value.to_string(),
                index,
                byte,
            });
        }
        if value.trim_end_matches('=').len() < MIN_NONCE_CHARS {
            return Err(ParseError::Malformed {
                term: Term::Nonce,
                input: value.to_string(),
                reason: "a nonce must carry at least 128 bits, which is 22 base64 characters",
            });
        }
        Ok(Self(value.to_string()))
    }

    /// The base64 value, without the `nonce-` prefix or the surrounding quotes.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NonceSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "'nonce-{}'", self.0)
    }
}

impl FromStr for NonceSource {
    type Err = ParseError;

    fn from_str(source: &str) -> Result<Self, Self::Err> {
        Self::parse(source)
    }
}

/// Strips one layer of `'…'`, so a parser accepts a source expression as it appears in a header
/// as well as the bare value inside it.
fn unquote(source: &str) -> &str {
    source
        .strip_prefix('\'')
        .and_then(|rest| rest.strip_suffix('\''))
        .unwrap_or(source)
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::{HashAlgorithm, HashSource, NonceSource};

    /// The encoded lengths are arithmetic, and arithmetic in a `const fn` is exactly the kind of
    /// thing that is wrong by one and never noticed.
    #[test]
    fn encoded_lengths_match_the_encoder() {
        for &algorithm in HashAlgorithm::ALL {
            let digest = alloc::vec![0u8; algorithm.digest_len()];
            let source = HashSource::from_digest(algorithm, &digest).unwrap();
            assert_eq!(source.value().len(), algorithm.padded_len(), "{algorithm}");
            assert_eq!(
                source.value().trim_end_matches('=').len(),
                algorithm.unpadded_len(),
                "{algorithm}"
            );
        }
    }

    #[test]
    fn a_hash_round_trips_through_its_rendered_form() {
        let source = HashSource::from_digest(HashAlgorithm::Sha256, &[0xab; 32]).unwrap();
        assert_eq!(HashSource::parse(&source.to_string()), Ok(source));
    }

    #[test]
    fn both_base64_alphabets_and_both_paddings_are_accepted() {
        // 43 characters unpadded, 44 padded: a browser console produces either.
        let padded = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
        let unpadded = padded.trim_end_matches('=');
        assert!(HashSource::new(HashAlgorithm::Sha256, padded).is_ok());
        assert!(HashSource::new(HashAlgorithm::Sha256, unpadded).is_ok());
        assert!(HashSource::new(HashAlgorithm::Sha256, &padded.replace('+', "-")).is_ok());
    }

    #[test]
    fn a_value_that_cannot_be_a_digest_is_refused() {
        for (algorithm, value) in [
            (HashAlgorithm::Sha256, ""),
            (HashAlgorithm::Sha256, "deadbeef"),
            (
                HashAlgorithm::Sha512,
                "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
            ),
            (
                HashAlgorithm::Sha256,
                "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuF!=",
            ),
        ] {
            assert!(
                HashSource::new(algorithm, value).is_err(),
                "{algorithm} {value:?} must be refused"
            );
        }
        assert!(HashSource::from_digest(HashAlgorithm::Sha256, &[0u8; 31]).is_err());
        assert!(HashSource::parse("'sha1-deadbeef'").is_err());
        assert!(HashSource::parse("'sha256'").is_err());
    }

    #[test]
    fn a_nonce_round_trips_and_keeps_its_entropy_floor() {
        let nonce = NonceSource::from_entropy(&[0x5a; 16]);
        assert_eq!(nonce.value().len(), 24);
        assert_eq!(NonceSource::parse(&nonce.to_string()), Ok(nonce));

        assert!(NonceSource::parse("'nonce-cmFuZG9tLW5vbmNlLTE2Yg=='").is_ok());
        assert!(NonceSource::parse("'nonce-cmFuZG9tLW5vbmNlLTE2Yg;='").is_err());

        // 15 bytes is 120 bits: a nonce a browser accepts and an attacker has 256 times fewer
        // guesses to make than the specification's floor allows for.
        assert!(NonceSource::parse("'nonce-cnJhbmRvbTEyMzQ1Ng=='").is_err());
        assert!(NonceSource::parse("'nonce-tooshort'").is_err());
    }
}
