//! The scanner against a whole shell, including the line-endings case that motivates the crate.
//!
//! The CRLF fixture is **generated here rather than committed**. A committed CRLF file is at
//! the mercy of `.gitattributes`, `core.autocrlf` and every contributor's checkout — the exact
//! normalisation this test exists to detect would be silently applied to the test's own input, and
//! the test would pass while proving nothing.

use csp_shell::{scan_shell, Csp, HashAlgorithm, ScanWarning};

/// A shell shaped like the one this crate was extracted from: an external bundle, a theme-flash
/// guard, a keyboard-shortcut registration, and a module script.
const SHELL_LF: &str = "\
<!doctype html>
<html lang=\"en\">
  <head>
    <meta charset=\"utf-8\" />
    <title>Shell</title>
    <script>
      (function () {
        var stored = localStorage.getItem('theme');
        document.documentElement.dataset.theme = stored || 'system';
      })();
    </script>
    <link rel=\"stylesheet\" href=\"/assets/app.css\" />
  </head>
  <body>
    <div id=\"root\"></div>
    <script type=\"module\" src=\"/assets/app.js\"></script>
    <script>
      document.addEventListener('keydown', function (event) {
        if (event.key === '/' && event.target === document.body) {
          event.preventDefault();
        }
      });
    </script>
  </body>
</html>
";

#[test]
fn a_realistic_shell_yields_one_hash_per_inline_script() {
    let scan = scan_shell(SHELL_LF);
    assert_eq!(
        scan.hashes.len(),
        2,
        "the external module script has no hash"
    );
    assert!(scan
        .hashes
        .iter()
        .all(|hash| hash.algorithm() == HashAlgorithm::Sha256
            && hash.value().len() == HashAlgorithm::Sha256.padded_len()));
    assert!(scan.warnings.is_empty(), "{:?}", scan.warnings);
}

/// The whole reason this crate exists in a repository developed on Windows.
///
/// A CSP hash covers the script element's text content as the HTML parser produces it, and input
/// stream preprocessing turns `\r\n` into `\n` before that text exists. Hashing the wire bytes
/// computes a hash no browser ever computes: the header looks correct, the inline scripts are
/// refused, and the page is blank.
#[test]
fn a_crlf_checkout_produces_the_same_hashes_as_an_lf_one() {
    let shell_crlf = SHELL_LF.replace('\n', "\r\n");
    assert!(
        shell_crlf.contains("\r\n"),
        "the fixture must actually differ"
    );

    let lf = scan_shell(SHELL_LF);
    let crlf = scan_shell(&shell_crlf);

    assert_eq!(lf.hashes, crlf.hashes);
    // The digest identifies the file, so the two checkouts are still distinguishable — which is
    // what makes a replaced bundle detectable without confusing it with a re-checkout.
    assert_ne!(lf.digest, crlf.digest);
}

/// A lone `\r`, which the same preprocessing step also folds to `\n`. Old-Mac line endings are
/// not a live concern; a text-transforming build step emitting one is.
#[test]
fn a_lone_cr_normalises_too() {
    let shell_cr = SHELL_LF.replace('\n', "\r");
    assert_eq!(scan_shell(SHELL_LF).hashes, scan_shell(&shell_cr).hashes);
}

/// The end-to-end shape a consumer sees: the shell's hashes land in `script-src` next to
/// `'self'`, which continues to cover the external bundle.
#[test]
fn the_policy_built_from_the_shell_carries_both_hashes() {
    let scan = scan_shell(SHELL_LF);
    let policy = Csp::spa_wasm()
        .with_scan(&scan)
        .build()
        .headers()
        .content_security_policy;

    for hash in &scan.hashes {
        assert!(
            policy.contains(&hash.to_string()),
            "{hash} missing from {policy}"
        );
    }
    assert!(policy.contains("script-src 'self' 'wasm-unsafe-eval' 'sha256-"));
}

/// The scanner's accepted limits are observable at runtime rather than only in the documentation,
/// so a mysterious blank page has something to attribute itself to.
#[test]
fn accepted_limits_are_reported_rather_than_hidden() {
    let scan = scan_shell(r#"<script data-title="a > b">alert(1)</script>"#);
    assert_eq!(scan.warnings, vec![ScanWarning::AmbiguousTagBoundary]);
}

/// The `std` reader is a thin wrapper, and its error is the caller's decision to make.
#[cfg(feature = "std")]
#[test]
fn scan_shell_at_reads_a_file_and_reports_a_missing_one() {
    use std::io::Write;

    let path = std::env::temp_dir().join(format!(
        "csp-shell-test-{}-{}.html",
        std::process::id(),
        line!()
    ));
    let mut file = std::fs::File::create(&path).expect("temp file");
    file.write_all(SHELL_LF.as_bytes()).expect("write fixture");
    drop(file);

    let from_file = csp_shell::scan_shell_at(&path).expect("the fixture is readable");
    assert_eq!(from_file.hashes, scan_shell(SHELL_LF).hashes);
    std::fs::remove_file(&path).expect("cleanup");

    let err = csp_shell::scan_shell_at(&path).expect_err("the fixture is gone");
    assert_eq!(err.path(), path);
    assert!(std::error::Error::source(&err).is_some());
}
