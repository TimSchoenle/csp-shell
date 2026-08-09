//! Per-response nonces (`nonce` feature).

use core::fmt;

use crate::base64;

/// Bytes of entropy behind one nonce. CSP requires at least 128 bits, and there is no argument
/// for more: the value is single-use and lives for one response.
const ENTROPY_BYTES: usize = 16;

/// Base64 of 16 bytes: six groups of four characters, the last carrying one `=` of padding.
const ENCODED_LEN: usize = 24;

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
    /// ASCII base64. Fixed length, so no allocation and no `String`.
    encoded: [u8; ENCODED_LEN],
}

impl Nonce {
    /// 128 CSPRNG bits.
    ///
    /// # Panics
    ///
    /// If the operating system's CSPRNG is unavailable. There is no correct fallback: every
    /// alternative source is one an attacker could predict, and a predictable nonce is a policy
    /// that admits arbitrary inline script while appearing to restrict it. Failing loudly at the
    /// point of failure is the only outcome that is not silently insecure.
    #[must_use]
    #[allow(clippy::missing_panics_doc)] // documented above, in the terms that matter
    pub fn mint() -> Self {
        let mut bytes = [0u8; ENTROPY_BYTES];
        getrandom::fill(&mut bytes).expect("the operating system CSPRNG must be available");

        let encoded = base64::encode(&bytes);
        debug_assert_eq!(encoded.len(), ENCODED_LEN);
        let mut buffer = [0u8; ENCODED_LEN];
        buffer.copy_from_slice(encoded.as_bytes());
        Self { encoded: buffer }
    }

    /// The base64 value, without the `'nonce-'` prefix or the surrounding quotes.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // The buffer was filled from a `String` produced by the crate's own encoder, whose output
        // alphabet is ASCII, so this cannot fail; `unwrap_or` keeps the guarantee without an
        // `unsafe` block the crate forbids anyway.
        core::str::from_utf8(&self.encoded).unwrap_or("")
    }
}

impl fmt::Display for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::{Nonce, ENCODED_LEN};

    #[test]
    fn a_nonce_is_128_bits_of_base64() {
        let nonce = Nonce::mint();
        assert_eq!(nonce.as_str().len(), ENCODED_LEN);
        assert!(nonce.as_str().ends_with('='));
        assert!(nonce
            .as_str()
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')));
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
