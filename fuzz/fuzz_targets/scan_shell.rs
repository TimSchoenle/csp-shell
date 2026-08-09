//! Arbitrary documents through the scanner: it must not panic, and the parser-equivalence
//! properties it exists to provide must hold on every input, not only on well-formed HTML.
//!
//! The scanner is a byte scan over attacker-adjacent input — a bundler's output, a mounted
//! volume, a development directory — and it does index arithmetic on offsets it computes itself.
//! An unterminated tag once produced a reversed range; that is the class of bug this target
//! exists to keep from coming back.

#![no_main]

use csp_shell::{scan_shell, Csp};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|html: &str| {
    let scan = scan_shell(html);

    // Determinism: the same document must always produce the same policy input.
    assert_eq!(scan, scan_shell(html));

    for hash in &scan.hashes {
        // Every hash is a well-formed source expression of a fixed shape: `'sha256-` plus 44
        // base64 characters plus a closing quote.
        assert!(hash.starts_with("'sha256-"), "{hash:?}");
        assert!(hash.ends_with('\''), "{hash:?}");
        assert_eq!(hash.len(), "'sha256-".len() + 44 + 1, "{hash:?}");

        let encoded = &hash["'sha256-".len()..hash.len() - 1];
        assert!(
            encoded
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')),
            "{hash:?}"
        );

        // A hash the builder would reject is a hash that can never reach a header.
        Csp::new()
            .directive("script-src", [hash])
            .expect("a scanned hash must be a valid source expression");
    }

    // Hashes are deduplicated, so the same source expression never appears twice.
    for (index, hash) in scan.hashes.iter().enumerate() {
        assert!(!scan.hashes[..index].contains(hash), "duplicate {hash:?}");
    }
    for (index, warning) in scan.warnings.iter().enumerate() {
        assert!(!scan.warnings[..index].contains(warning), "duplicate {warning:?}");
    }

    // Newline normalisation: a CSP hash covers the script's text content as the HTML parser
    // produces it, and the parser folds CRLF and lone CR to LF before that text exists. A
    // checkout's line endings must therefore be invisible to the hashes.
    let normalised = html.replace("\r\n", "\n").replace('\r', "\n");
    assert_eq!(
        scan.hashes,
        scan_shell(&normalised).hashes,
        "line endings changed the hashes"
    );
    let crlf = normalised.replace('\n', "\r\n");
    assert_eq!(
        scan.hashes,
        scan_shell(&crlf).hashes,
        "a CRLF checkout would be refused by the browser"
    );

    // A leading byte order mark is discarded by the parser before the document exists, so
    // prefixing one cannot change a single hash.
    let with_bom = alloc_with_bom(html);
    assert_eq!(scan.hashes, scan_shell(&with_bom).hashes, "the BOM leaked into a hash");

    // The digest identifies the bytes that were read, which is what makes a replaced bundle
    // detectable. It must therefore be sensitive to exactly the changes the hashes ignore.
    assert_ne!(
        scan.digest,
        scan_shell(&with_bom).digest,
        "the digest failed to distinguish two different files"
    );
});

/// `format!` with a byte order mark in front, kept out of the assertions for readability.
fn alloc_with_bom(html: &str) -> String {
    let mut with_bom = String::with_capacity(html.len() + 3);
    with_bom.push('\u{feff}');
    with_bom.push_str(html);
    with_bom
}
