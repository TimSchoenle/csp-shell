//! The hand-rolled encoder is pinned to a reference implementation rather than to a reading
//! of RFC 4648.
//!
//! `base64` is a dev-dependency for exactly this: correctness is asserted against it over random
//! inputs of every length class, and the runtime edge — a dependency in every consumer's tree for
//! twenty-five lines of encode-only code — is not paid.
//!
//! The encoder is not public, so the test reaches it the way the crate does: through the
//! `'sha256-…'` source expressions the scanner produces, and through the nonce when that feature
//! is on. That also makes the test cover the framing — the `'sha256-'` prefix and the quotes —
//! rather than only the alphabet.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use csp_shell::scan_shell;
use sha2::{Digest, Sha256};

/// Deterministic byte-string generator; the reference implementation does the judging.
struct Xorshift64(u64);

impl Xorshift64 {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

#[test]
fn every_scanned_hash_agrees_with_the_reference_encoder() {
    let mut rng = Xorshift64(0x0000_c5b6_4e11_0001);

    for length in 0..256_usize {
        // Script text of every length class, over the whole byte range that survives UTF-8.
        let script: String = (0..length)
            .map(|_| char::from(u8::try_from(rng.next() % 0x60).expect("below 0x60") + 0x20))
            .collect();

        let scan = scan_shell(&format!("<script>{script}</script>"));
        let expected = STANDARD.encode(Sha256::digest(script.as_bytes()));

        assert_eq!(
            scan.hashes,
            vec![format!("'sha256-{expected}'")],
            "disagreement for script of length {length}"
        );
    }
}

/// The empty script is the only input whose base64 has two padding characters at the digest
/// length this crate uses, and it is also the input a bundler is most likely to emit by accident.
#[test]
fn the_empty_script_agrees_too() {
    let scan = scan_shell("<script></script>");
    let expected = STANDARD.encode(Sha256::digest(b""));
    assert_eq!(scan.hashes, vec![format!("'sha256-{expected}'")]);
    assert!(
        scan.hashes[0].ends_with("='"),
        "32 bytes always pad with one '='"
    );
}

/// The nonce takes the other padding class: 16 bytes encode to 24 characters with one `=`.
#[cfg(feature = "nonce")]
#[test]
fn a_minted_nonce_decodes_to_128_bits() {
    let nonce = csp_shell::Nonce::mint();
    let decoded = STANDARD
        .decode(nonce.as_str())
        .expect("the reference decoder must accept what the crate encodes");
    assert_eq!(decoded.len(), 16);
    assert_eq!(STANDARD.encode(&decoded), nonce.as_str());
}
