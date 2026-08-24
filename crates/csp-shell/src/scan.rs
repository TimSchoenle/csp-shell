//! Scanning a shell for inline scripts.
//!
//! Every failure mode below produces a **correct-looking header and a blank page**: the policy
//! parses, the browser refuses the scripts, and the only evidence is in a console nobody is
//! watching. That is why the scan is here rather than in a `const` list of hashes maintained by
//! hand — a hand-maintained list drifts the moment anyone edits the shell, and the symptom is
//! identical.

use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use csp_policy::HashSource;
use sha2::{Digest, Sha256};

use crate::util::push_unique;

/// A documented limit of the scanner that this scan actually hit.
///
/// The scanner is deliberately not an HTML parser. Its accepted limits are observable at
/// runtime rather than only in the documentation, so a mysterious blank page has something to
/// attribute itself to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ScanWarning {
    /// Script data contained U+0000.
    ///
    /// The HTML tokenizer replaces it with U+FFFD, so the hash computed here is one no browser
    /// will compute. Not compensated for — a NUL in a generated shell means something upstream is
    /// already broken — but reported so the failure is attributable.
    NulInScriptData,

    /// An opening `<script>` tag carried a `>` inside a quoted attribute value.
    ///
    /// The tag was split at that `>`, so the attribute region and the script's text content are
    /// both wrong. Accepted rather than parsed around: the input is one bundler-generated file.
    AmbiguousTagBoundary,

    /// An opening `<script` tag was never closed by a `>` before the end of the document, or
    /// `</script` appeared before it. The scan stopped there; any inline script after that point
    /// has no hash.
    UnterminatedTag,

    /// A `<script>` element was never closed by `</script>`. The scan stopped there.
    UnterminatedScriptElement,
}

impl fmt::Display for ScanWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::NulInScriptData => {
                "script data contains U+0000, which the HTML tokenizer replaces with U+FFFD; the \
                 computed hash will not match the one the browser computes"
            }
            Self::AmbiguousTagBoundary => {
                "a '>' inside a quoted attribute value split a <script> tag in the wrong place"
            }
            Self::UnterminatedTag => "an opening <script tag was never closed by '>'",
            Self::UnterminatedScriptElement => "a <script> element was never closed by </script>",
        };
        f.write_str(text)
    }
}

/// The result of scanning a shell.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct ScanResult {
    /// `'sha256-…'` sources, in document order.
    ///
    /// Deduplicated: two identical inline scripts hash identically, and repeating the source
    /// expression lengthens every response for no change in what the policy permits.
    pub hashes: Vec<HashSource>,

    /// SHA-256 of the shell's raw bytes — the identity of the input this policy was derived
    /// from. Compare it to detect a policy gone stale against a replaced bundle.
    ///
    /// Computed over the bytes as they were read, *before* BOM stripping and newline
    /// normalisation, because its job is to identify the file rather than the parse.
    pub digest: [u8; 32],

    /// Documented scanner limits hit during this scan. Empty in the normal case.
    ///
    /// Deduplicated: fifty NULs in one file are one problem.
    pub warnings: Vec<ScanWarning>,
}

/// Scans a shell's source for inline scripts.
///
/// Returns a `'sha256-…'` source expression for every `<script>` element that has no `src`
/// attribute, in document order.
///
/// Newlines are normalised and a leading byte order mark is stripped before hashing, because a
/// CSP hash covers the script element's text content **as the HTML parser produces it**, not the
/// file's wire bytes — see the module documentation.
///
/// # Examples
///
/// ```
/// use csp_shell::HashAlgorithm;
///
/// let scan = csp_shell::scan_shell("<script>console.log(1)</script>");
/// assert_eq!(scan.hashes.len(), 1);
/// assert_eq!(scan.hashes[0].algorithm(), HashAlgorithm::Sha256);
///
/// // An external script needs no hash; `'self'` already covers it.
/// assert!(csp_shell::scan_shell(r#"<script src="/app.js"></script>"#).hashes.is_empty());
/// ```
#[must_use]
pub fn scan_shell(html: &str) -> ScanResult {
    let digest: [u8; 32] = Sha256::digest(html.as_bytes()).into();

    // Input-stream preprocessing, in the order the HTML spec performs it: the byte order mark is
    // discarded, then CRLF and lone CR both become LF.
    let without_bom = html.strip_prefix('\u{feff}').unwrap_or(html);
    let normalised = normalize_newlines(without_bom);

    let mut result = ScanResult {
        digest,
        ..ScanResult::default()
    };
    scan_normalised(&normalised, &mut result);
    result
}

/// Reads a shell from disk and scans it.
///
/// # Errors
///
/// Returns the I/O error, including the `InvalidData` error `read_to_string` produces for a file
/// that is not valid UTF-8. The caller decides whether an unreadable shell is fatal.
///
/// # Examples
///
/// The fail-open posture, which is a decision for the caller and not for this crate:
///
/// ```no_run
/// # use std::path::Path;
/// let scan = match csp_shell::scan_shell_at(Path::new("dist/index.html")) {
///     Ok(scan) => Some(scan),
///     Err(err) => {
///         eprintln!("shell unreadable ({err}); serving a policy without inline-script hashes");
///         None
///     }
/// };
/// ```
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub fn scan_shell_at(path: &std::path::Path) -> Result<ScanResult, crate::ScanError> {
    let html = std::fs::read_to_string(path)
        .map_err(|err| crate::ScanError::new(path.to_path_buf(), err))?;
    Ok(scan_shell(&html))
}

/// Replaces `\r\n` and lone `\r` with `\n`, borrowing when there is nothing to replace.
///
/// This is the single most load-bearing line in the crate. A hash over the file's wire bytes is a
/// hash **no browser ever computes**, so a checkout with CRLF line endings has its inline scripts
/// refused under a header that looks entirely correct. On Windows — where this crate is developed
/// — that is not hypothetical, which is why the CI matrix has both platforms and the CRLF fixture
/// is generated in-test rather than committed.
fn normalize_newlines(src: &str) -> Cow<'_, str> {
    if !src.contains('\r') {
        return Cow::Borrowed(src);
    }

    let mut out = String::with_capacity(src.len());
    let mut rest = src;
    while let Some(cr) = rest.find('\r') {
        out.push_str(&rest[..cr]);
        out.push('\n');
        // `\r` is ASCII, so `cr + 1` is a character boundary regardless of what follows.
        rest = &rest[cr + 1..];
        if let Some(after_lf) = rest.strip_prefix('\n') {
            rest = after_lf;
        }
    }
    out.push_str(rest);
    Cow::Owned(out)
}

/// Walks the preprocessed document, hashing the text content of every inline `<script>`.
fn scan_normalised(html: &str, result: &mut ScanResult) {
    let mut cursor = 0;
    while let Some(tag_start) = find_ascii_ci(html, b"<script", cursor) {
        let after_name = tag_start + b"<script".len();

        // `<scriptfoo>` is not a `<script>`: the tokenizer only leaves the tag-name state on a
        // whitespace, `/` or `>`. Resuming at `after_name` rather than `tag_start + 1` is safe
        // because `<script` cannot overlap itself.
        match html.as_bytes().get(after_name) {
            None => {
                push_unique(&mut result.warnings, ScanWarning::UnterminatedTag);
                return;
            }
            Some(&byte) if !is_tag_name_boundary(byte) => {
                cursor = after_name;
                continue;
            }
            Some(_) => {}
        }

        let Some(tag_end) = html[after_name..].find('>').map(|rel| after_name + rel) else {
            push_unique(&mut result.warnings, ScanWarning::UnterminatedTag);
            return;
        };

        // An opening tag whose `>` is missing looks, to the byte scan, like a tag that extends
        // past its own closing tag. Stopping here is what keeps the content range from being
        // reversed further down.
        if let Some(close) = find_close_tag(html, after_name) {
            if close < tag_end {
                push_unique(&mut result.warnings, ScanWarning::UnterminatedTag);
                return;
            }
        }

        let attributes = &html[after_name..tag_end];
        if has_src_attribute(attributes) {
            // An element carrying `src` is an external script; `'self'` already covers it.
            cursor = tag_end + 1;
            continue;
        }
        if ends_inside_quotes(attributes) {
            push_unique(&mut result.warnings, ScanWarning::AmbiguousTagBoundary);
        }

        let content_start = tag_end + 1;
        let Some(content_end) = find_close_tag(html, content_start) else {
            push_unique(&mut result.warnings, ScanWarning::UnterminatedScriptElement);
            return;
        };

        let content = &html[content_start..content_end];
        if content.contains('\0') {
            push_unique(&mut result.warnings, ScanWarning::NulInScriptData);
        }
        push_unique(&mut result.hashes, sha256_source(content));

        cursor = content_end + b"</script".len();
    }
}

/// Finds the next `</script` that a tokenizer would treat as an end tag, from `from`.
///
/// The name must be followed by a boundary, so `</scriptfoo>` is character data inside the script
/// rather than the end of it — the same rule as the opening tag, in the direction that matters
/// more: getting it wrong truncates the hashed text and produces a hash for a script that does
/// not exist.
fn find_close_tag(html: &str, from: usize) -> Option<usize> {
    let mut at = from;
    loop {
        let found = find_ascii_ci(html, b"</script", at)?;
        let after_name = found + b"</script".len();
        match html.as_bytes().get(after_name) {
            // A document ending exactly at `</script` has no `>`; treat it as the end tag it is
            // plainly meant to be rather than scanning past the end of the document.
            None => return Some(found),
            Some(&byte) if is_tag_name_boundary(byte) => return Some(found),
            Some(_) => at = after_name,
        }
    }
}

/// Whether the opening tag's attribute region declares a `src` attribute.
///
/// Three conditions, each of which has a test: the match must start at an attribute boundary so
/// `srcsrc=` does not match; it must be followed by `=` after optional whitespace so a `srcset`
/// or a bare `src` does not match; and it must not be inside a quoted attribute value, so
/// `data-x="src=1"` does not cause the element's inline script to be skipped — which would drop a
/// hash silently, the crate's own failure mode.
fn has_src_attribute(attributes: &str) -> bool {
    let bytes = attributes.as_bytes();
    let mut quote: Option<u8> = None;
    let mut index = 0;

    while index < bytes.len() {
        let byte = bytes[index];
        match quote {
            Some(open) => {
                if byte == open {
                    quote = None;
                }
                index += 1;
                continue;
            }
            None if byte == b'"' || byte == b'\'' => {
                quote = Some(byte);
                index += 1;
                continue;
            }
            None => {}
        }

        let at_boundary = index == 0 || is_attribute_boundary(bytes[index - 1]);
        if at_boundary
            && bytes[index..].len() >= 3
            && bytes[index..index + 3].eq_ignore_ascii_case(b"src")
        {
            let mut after = index + 3;
            while matches!(bytes.get(after), Some(b) if b.is_ascii_whitespace()) {
                after += 1;
            }
            if bytes.get(after) == Some(&b'=') {
                return true;
            }
        }
        index += 1;
    }

    false
}

/// Whether a quoted attribute value was left open at the end of `attributes`, which means the `>`
/// used to end the tag was inside that value.
fn ends_inside_quotes(attributes: &str) -> bool {
    let mut quote: Option<u8> = None;
    for &byte in attributes.as_bytes() {
        match quote {
            Some(open) if byte == open => quote = None,
            None if byte == b'"' || byte == b'\'' => quote = Some(byte),
            _ => {}
        }
    }
    quote.is_some()
}

/// The `'sha256-…'` source for one script's text content.
fn sha256_source(content: &str) -> HashSource {
    let digest: [u8; 32] = Sha256::digest(content.as_bytes()).into();
    HashSource::sha256(&digest)
}

/// Byte offset of the next case-insensitive occurrence of the ASCII `needle`, at or after `from`.
///
/// `needle` must be ASCII: every returned offset is then a UTF-8 character boundary, because an
/// ASCII byte never occurs inside a multi-byte sequence.
fn find_ascii_ci(haystack: &str, needle: &[u8], from: usize) -> Option<usize> {
    debug_assert!(needle.is_ascii() && !needle.is_empty());
    let bytes = haystack.as_bytes();
    let last_start = bytes.len().checked_sub(needle.len())?;
    (from..=last_start)
        .find(|&start| bytes[start..start + needle.len()].eq_ignore_ascii_case(needle))
}

/// The bytes that end a tag name: HTML whitespace, `/` and `>`.
///
/// `\r` is absent because newline normalisation has already removed it.
#[inline]
const fn is_tag_name_boundary(byte: u8) -> bool {
    matches!(byte, b'\t' | b'\n' | b'\x0c' | b' ' | b'/' | b'>')
}

/// The bytes that may precede an attribute name.
#[inline]
const fn is_attribute_boundary(byte: u8) -> bool {
    matches!(byte, b'\t' | b'\n' | b'\x0c' | b' ' | b'/')
}

#[cfg(test)]
mod tests {
    use super::{has_src_attribute, normalize_newlines, Digest, ScanWarning, Sha256};
    use crate::scan_shell;
    use alloc::borrow::Cow;

    /// Hashing the wire bytes computes a hash no browser computes, and the page is blank
    /// under a header that looks entirely correct.
    #[test]
    fn crlf_and_lone_cr_normalise_to_lf() {
        assert!(matches!(normalize_newlines("a\nb"), Cow::Borrowed("a\nb")));
        assert_eq!(normalize_newlines("a\r\nb"), "a\nb");
        assert_eq!(normalize_newlines("a\rb"), "a\nb");
        assert_eq!(normalize_newlines("a\r\r\nb"), "a\n\nb");
        assert_eq!(normalize_newlines("a\n\rb"), "a\n\nb");
        assert_eq!(normalize_newlines("\r"), "\n");
    }

    /// The parser discards a leading BOM before the document exists, so it is not part of any
    /// script's text content — and it is not part of the first script's hash either.
    #[test]
    fn a_leading_bom_is_stripped() {
        let with_bom = scan_shell("\u{feff}<script>x</script>");
        let without = scan_shell("<script>x</script>");
        assert_eq!(with_bom.hashes, without.hashes);
        // The digest identifies the file, so it does differ.
        assert_ne!(with_bom.digest, without.digest);
    }

    /// A BOM anywhere but the start is ordinary character data.
    #[test]
    fn a_bom_inside_a_script_is_not_stripped() {
        assert_ne!(
            scan_shell("<script>\u{feff}x</script>").hashes,
            scan_shell("<script>x</script>").hashes
        );
    }

    /// Only a name or attribute boundary may follow the tag name.
    #[test]
    fn scriptfoo_is_not_a_script() {
        assert!(scan_shell("<scriptfoo>x</scriptfoo>").hashes.is_empty());
        assert_eq!(
            scan_shell("<scriptfoo>x</scriptfoo><script>y</script>")
                .hashes
                .len(),
            1
        );
    }

    /// `srcsrc=` is not `src=`, and `srcset=` is not `src=`.
    #[test]
    fn src_detection_requires_a_boundary_and_an_equals() {
        assert!(has_src_attribute(" src=\"/a.js\""));
        assert!(has_src_attribute(" SRC = '/a.js'"));
        assert!(has_src_attribute(" defer src=/a.js"));
        assert!(!has_src_attribute(" srcsrc=\"/a.js\""));
        assert!(!has_src_attribute(" srcset=\"/a.js\""));
        assert!(!has_src_attribute(" nosrc=\"/a.js\""));
        assert!(!has_src_attribute(" src"));
        assert!(!has_src_attribute(" data-src=\"/a.js\""));
    }

    /// A `src=` inside a quoted attribute value must not cause the element to be skipped: the
    /// element is inline, and skipping it drops its hash with no error anywhere.
    #[test]
    fn src_inside_a_quoted_value_does_not_count() {
        assert!(!has_src_attribute(r#" data-x="src=1""#));
        assert_eq!(
            scan_shell(r#"<script data-x="src=1">alert(1)</script>"#)
                .hashes
                .len(),
            1
        );
    }

    /// A reversed range would panic; stopping is the documented behaviour.
    #[test]
    fn an_unterminated_opening_tag_stops_the_scan() {
        let scan = scan_shell("<script foo=</script>");
        assert!(scan.hashes.is_empty());
        assert!(scan.warnings.contains(&ScanWarning::UnterminatedTag));

        let scan = scan_shell("<script>ok</script><script foo=");
        assert_eq!(scan.hashes.len(), 1);
        assert!(scan.warnings.contains(&ScanWarning::UnterminatedTag));
    }

    #[test]
    fn an_unclosed_script_element_stops_the_scan() {
        let scan = scan_shell("<script>alert(1)");
        assert!(scan.hashes.is_empty());
        assert!(scan
            .warnings
            .contains(&ScanWarning::UnterminatedScriptElement));
    }

    /// Accepted, documented, reported — and not worth a parser for a file the bundler
    /// validated.
    #[test]
    fn a_gt_inside_an_attribute_value_is_reported() {
        let scan = scan_shell(r#"<script data-x="a>b">alert(1)</script>"#);
        assert!(scan.warnings.contains(&ScanWarning::AmbiguousTagBoundary));
    }

    /// Not compensated for, but attributable.
    #[test]
    fn a_nul_in_script_data_is_reported() {
        let scan = scan_shell("<script>a\0b</script>");
        assert_eq!(scan.hashes.len(), 1);
        assert!(scan.warnings.contains(&ScanWarning::NulInScriptData));
        // One problem, reported once.
        let many = scan_shell("<script>a\0b</script><script>c\0d</script>");
        assert_eq!(
            many.warnings
                .iter()
                .filter(|w| **w == ScanWarning::NulInScriptData)
                .count(),
            1
        );
    }

    /// `</scriptfoo>` is character data inside the script, not the end of it. Treating it as the
    /// end tag would hash a prefix of the real script — a hash for a script that does not exist,
    /// under a header that parses cleanly.
    #[test]
    fn a_close_tag_name_needs_a_boundary_too() {
        let whole = scan_shell("<script>a</scriptfoo>b</script>");
        assert_eq!(whole.hashes.len(), 1);
        assert_eq!(
            whole.hashes,
            scan_shell("<script>a</scriptfoo>b</script>").hashes
        );
        // Not the hash of the truncated text a boundary-blind scan would have produced.
        assert_ne!(whole.hashes, scan_shell("<script>a</script>").hashes);
    }

    #[test]
    fn identical_scripts_hash_once() {
        let scan = scan_shell("<script>x</script><script>x</script>");
        assert_eq!(scan.hashes.len(), 1);
    }

    #[test]
    fn hashes_are_in_document_order() {
        let scan = scan_shell("<script>a</script><script>b</script>");
        let first = scan_shell("<script>a</script>").hashes;
        let second = scan_shell("<script>b</script>").hashes;
        assert_eq!(scan.hashes, [first[0].clone(), second[0].clone()]);
    }

    #[test]
    fn tag_names_are_case_insensitive() {
        assert_eq!(
            scan_shell("<SCRIPT>x</SCRIPT>").hashes,
            scan_shell("<script>x</script>").hashes
        );
    }

    /// The digest identifies the input, which is what makes a stale policy detectable.
    #[test]
    fn the_digest_covers_the_raw_bytes() {
        // Two documents whose scripts hash identically still have different identities.
        assert_ne!(
            scan_shell("<script>x</script>").digest,
            scan_shell("<script>x</script>\n").digest
        );
        // The empty document's digest is SHA-256 of no bytes, not of anything the scanner made up.
        assert_eq!(scan_shell("").digest, <[u8; 32]>::from(Sha256::digest(b"")));
    }

    /// The two hash inputs must not be confused: the digest is over the wire bytes, the source
    /// expressions are over the parsed text. A CRLF document has a different digest and the same
    /// hashes as its LF twin — which is the entire point of the newline normalisation.
    #[test]
    fn crlf_changes_the_digest_and_not_the_hashes() {
        let lf = "<script>\nconsole.log(1)\n</script>";
        let crlf = lf.replace('\n', "\r\n");
        assert_eq!(scan_shell(lf).hashes, scan_shell(&crlf).hashes);
        assert_ne!(scan_shell(lf).digest, scan_shell(&crlf).digest);
    }
}
