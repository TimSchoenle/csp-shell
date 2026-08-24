//! Per-response nonces (`nonce` feature).

use core::fmt;

use csp_policy::NonceSource;

/// Bytes of entropy behind one nonce. CSP requires at least 128 bits, and there is no argument
/// for more: the value is single-use and lives for one response.
const ENTROPY_BYTES: usize = 16;

/// A per-response nonce: 128 CSPRNG bits, base64-encoded.
///
/// Generic rather than Cloudflare-specific. Anything that injects inline script downstream of the
/// origin — an edge worker, a CDN's RUM beacon, an SSR template — needs one; Cloudflare is merely
/// the motivating case.
///
/// A nonce is only a restriction if it is unpredictable *and* used once. Serving one from cache
/// pins it across every reader for the lifetime of the cache entry, which is `'unsafe-inline'`
/// with extra steps — which is why [`Policy::headers`](crate::Policy::headers) hands back a
/// `Cache-Control` alongside the policy rather than leaving the obligation implicit.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(docsrs, doc(cfg(feature = "nonce")))]
pub struct Nonce {
    source: NonceSource,
}

impl Nonce {
    /// Mints a fresh nonce, drawing 128 bits from the operating system's CSPRNG.
    ///
    /// # Panics
    ///
    /// If the operating system's CSPRNG is unavailable. There is no correct fallback: every
    /// alternative source is one an attacker could predict, and a predictable nonce is a policy
    /// that admits arbitrary inline script while appearing to restrict it. Failing loudly at the
    /// point of failure is the only outcome that is not silently insecure.
    #[must_use]
    pub fn mint() -> Self {
        let mut bytes = [0u8; ENTROPY_BYTES];
        getrandom::fill(&mut bytes).expect("the operating system CSPRNG must be available");

        // `from_entropy` takes a fixed-size array so that the 128-bit floor is checked where the
        // array is declared rather than where the nonce is used.
        Self {
            source: NonceSource::from_entropy(&bytes),
        }
    }

    /// The base64 value, without the `'nonce-'` prefix or the surrounding quotes.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.source.value()
    }

    /// The nonce as a source expression, which is how it reaches a policy.
    #[must_use]
    pub const fn as_source(&self) -> &NonceSource {
        &self.source
    }

    /// The nonce as a source expression, consuming it.
    #[must_use]
    pub fn into_source(self) -> NonceSource {
        self.source
    }
}

impl fmt::Display for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::Nonce;

    /// Base64 of 16 bytes: six groups of four characters, the last carrying two `=` of padding.
    const ENCODED_LEN: usize = 24;

    #[test]
    fn a_nonce_is_128_bits_of_base64() {
        let nonce = Nonce::mint();
        assert_eq!(nonce.as_str().len(), ENCODED_LEN);
        assert!(nonce.as_str().ends_with("=="));
        assert!(nonce
            .as_str()
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')));
    }

    /// The source expression is what reaches the header, so its framing is asserted here rather
    /// than only where a policy is rendered.
    #[test]
    fn the_source_expression_carries_the_value() {
        let nonce = Nonce::mint();
        assert_eq!(
            nonce.as_source().to_string(),
            alloc::format!("'nonce-{}'", nonce.as_str())
        );
    }

    /// A nonce reused across responses is `'unsafe-inline'` with extra steps. This does not prove
    /// the CSPRNG is sound; it proves the crate is not caching the value by accident.
    #[test]
    fn successive_nonces_differ() {
        let first = Nonce::mint();
        for _ in 0..64 {
            assert_ne!(first, Nonce::mint());
        }
    }
}
