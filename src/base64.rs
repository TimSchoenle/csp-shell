//! Encode-only base64, standard alphabet, with padding (RFC 4648, section 4).
//!
//! The crate needs base64 in exactly two places — a 32-byte SHA-256 digest and a 16-byte nonce —
//! and needs no decoder at all. Twenty-five lines against a dependency that pulls its own SIMD
//! backends and `no_std` feature plumbing is not a close call.
//!
//! Correctness is not left to inspection: `base64` is a dev-dependency and
//! `tests/base64_differential.rs` asserts agreement with it over random inputs of every length
//! class, so this implementation is pinned to a reference rather than to a reading of the RFC.

use alloc::string::String;

/// Standard alphabet. Index is the 6-bit group value.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode `input` as standard base64 with `=` padding.
///
/// The output is ASCII, so it is always a valid HTTP field value and a valid CSP `base64-value`.
pub(crate) fn encode(input: &[u8]) -> String {
    // Four output characters per three input bytes, rounded up to a whole group.
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);

    let mut chunks = input.chunks_exact(3);
    for chunk in &mut chunks {
        let group = (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]);
        push_sextet(&mut out, group >> 18);
        push_sextet(&mut out, group >> 12);
        push_sextet(&mut out, group >> 6);
        push_sextet(&mut out, group);
    }

    match chunks.remainder() {
        [a] => {
            let group = u32::from(*a) << 16;
            push_sextet(&mut out, group >> 18);
            push_sextet(&mut out, group >> 12);
            out.push_str("==");
        }
        [a, b] => {
            let group = (u32::from(*a) << 16) | (u32::from(*b) << 8);
            push_sextet(&mut out, group >> 18);
            push_sextet(&mut out, group >> 12);
            push_sextet(&mut out, group >> 6);
            out.push('=');
        }
        _ => {}
    }

    out
}

/// Append the alphabet character for the low six bits of `bits`.
#[inline]
fn push_sextet(out: &mut String, bits: u32) {
    // Masking to six bits makes the index unconditionally in range, so this cannot panic and
    // needs no bounds-check reasoning at the call sites.
    out.push(ALPHABET[(bits & 0x3f) as usize] as char);
}

#[cfg(test)]
mod tests {
    use super::encode;

    /// RFC 4648 section 10 test vectors, covering all three padding classes.
    #[test]
    fn rfc4648_vectors() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg==");
        assert_eq!(encode(b"fo"), "Zm8=");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(b"foob"), "Zm9vYg==");
        assert_eq!(encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
    }

    /// Every 6-bit value must map to a distinct alphabet character; a typo in the table would
    /// otherwise only surface as a wrong hash somewhere far away.
    #[test]
    fn alphabet_is_the_standard_one() {
        assert_eq!(encode(&[0xff, 0xff, 0xff]), "////");
        assert_eq!(encode(&[0xfb, 0xff, 0xff]), "+///");
        assert_eq!(encode(&[0x00, 0x00, 0x00]), "AAAA");
    }
}
