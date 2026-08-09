//! The hand-rolled encoder is pinned to a reference implementation rather than to a reading of
//! RFC 4648.
//!
//! `base64` is a dev-dependency for exactly this: correctness is asserted against it, and the
//! runtime cost — a dependency in every consumer's tree for twenty-five lines of encode-only code
//! — is not paid.
//!
//! The encoder is not public, so the test reaches it the way the crate does: through the two
//! values that carry base64 into a header. That also covers the framing — the algorithm prefix,
//! the `nonce-` prefix and the quotes — rather than only the alphabet.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use csp_policy::{HashAlgorithm, HashSource, NonceSource};

/// Deterministic byte generator; the reference implementation does the judging.
struct Xorshift64(u64);

impl Xorshift64 {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// Truncation is the point: the generator produces bytes, and the reference implementation
    /// judges whatever comes out.
    fn fill(&mut self, bytes: &mut [u8]) {
        for byte in bytes {
            *byte = u8::try_from(self.next() & 0xff).expect("masked to one byte");
        }
    }
}

/// The three digest lengths are 32, 48 and 64 bytes, whose remainders mod 3 are 2, 0 and 1 — so
/// this covers both padding classes and the unpadded one without contriving an input.
#[test]
fn every_hash_agrees_with_the_reference_encoder() {
    let mut rng = Xorshift64(0x0000_c5b6_4e11_0001);

    for &algorithm in HashAlgorithm::ALL {
        for round in 0..64 {
            let mut digest = vec![0u8; algorithm.digest_len()];
            rng.fill(&mut digest);

            let source = HashSource::from_digest(algorithm, &digest)
                .expect("a digest of the algorithm's own length must be accepted");
            let expected = STANDARD.encode(&digest);

            assert_eq!(
                source.value(),
                expected,
                "{algorithm} disagreed on round {round}"
            );
            assert_eq!(source.to_string(), format!("'{algorithm}-{expected}'"));
            assert_eq!(
                STANDARD
                    .decode(source.value())
                    .expect("the reference decoder must accept what the crate encodes"),
                digest
            );
        }
    }
}

/// An all-zero and an all-ones digest are the two inputs where an off-by-one in the sextet masking
/// would still produce plausible-looking output.
#[test]
fn the_extremes_agree_too() {
    for byte in [0x00, 0xff] {
        let digest = [byte; 32];
        let source = HashSource::sha256(&digest);
        assert_eq!(source.value(), STANDARD.encode(digest));
    }
}

/// Nonce lengths of 16, 17 and 18 bytes cover the three padding classes from the other direction.
#[test]
fn every_nonce_agrees_with_the_reference_encoder() {
    let mut rng = Xorshift64(0x0000_7f3a_2c90_0001);

    macro_rules! check {
        ($length:literal) => {{
            let mut bytes = [0u8; $length];
            rng.fill(&mut bytes);

            let nonce = NonceSource::from_entropy(&bytes);
            let expected = STANDARD.encode(bytes);
            assert_eq!(nonce.value(), expected, "{} bytes", $length);
            assert_eq!(nonce.to_string(), format!("'nonce-{expected}'"));
            assert_eq!(
                NonceSource::parse(&nonce.to_string()).as_ref(),
                Ok(&nonce),
                "a minted nonce must parse back"
            );
        }};
    }

    check!(16);
    check!(17);
    check!(18);
    check!(32);
    check!(64);
}
