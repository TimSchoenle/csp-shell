//! `TankoVault`'s `csp-no-unsafe-eval` repo-lint rule, ported to the tree the code now lives
//! in.
//!
//! Walks every `.rs` and `.md` in the workspace and rejects the token outside a line
//! carrying a `csp-lint: allow — <reason>` marker. The marker is not gold-plating: `spa_wasm()`'s
//! doc comment and the rationale for its absence both have to name the token in order to explain
//! that absence, so an unmarked grep fails on the first commit.
//!
//! This does not substitute for `policy.rs`'s `spa_wasm` assertion and that assertion does not
//! substitute for this: the unit test covers one constructor precisely, the tree walk covers
//! everything else approximately. What the walk buys over a reviewer's attention is that a method
//! name cannot be split across a `format!`, built from a config value, or hidden in a `concat!`.

#![cfg(feature = "std")]

use std::fs;
use std::path::{Path, PathBuf};

/// Assembled at runtime so that this file's own source does not contain the token it searches
/// for; otherwise the lint would need a marker to permit its own definition, and a marker on the
/// definition line is indistinguishable from a marker that disables the rule.
fn token() -> String {
    format!("{}-{}", "unsafe", "eval")
}

/// A line may name the token if it says why, in the form `csp-lint: allow — <reason>`.
const MARKER: &str = "csp-lint: allow — ";

/// Directories that are build output or version-control metadata rather than source.
const SKIPPED_DIRECTORIES: &[&str] = &["target", ".git", ".idea", ".serena", "corpus", "artifacts"];

/// `Design.md` is the frozen record of the decision that produced this rule. Its tables and
/// rationale name the token a dozen times *because* the rule exists, and rewriting those lines to
/// carry markers would edit the record to satisfy the thing the record specifies. Excluded as a
/// whole file, deliberately and visibly, rather than by weakening the marker requirement for
/// every other document.
const EXCLUDED_FILES: &[&str] = &["Design.md"];

#[test]
fn the_token_appears_only_on_lines_that_justify_it() {
    let root = workspace_root();
    let token = token();
    let mut findings = Vec::new();
    let mut files_walked = 0_usize;

    walk(&root, &mut |path| {
        files_walked += 1;
        let relative = path.strip_prefix(&root).unwrap_or(path).to_owned();
        let contents = fs::read_to_string(path).expect("source files are UTF-8");

        for (number, line) in contents.lines().enumerate() {
            if !names_the_token(line, &token) {
                continue;
            }
            if let Some(reason) = line.split(MARKER).nth(1) {
                assert!(
                    !reason.trim().trim_end_matches("-->").trim().is_empty(),
                    "{}:{}: the marker needs a reason",
                    relative.display(),
                    number + 1
                );
                continue;
            }
            findings.push(format!(
                "{}:{}: {}",
                relative.display(),
                number + 1,
                line.trim()
            ));
        }
    });

    assert!(
        files_walked > 5,
        "the walk found only {files_walked} files; it is not looking where it thinks it is"
    );
    assert!(
        findings.is_empty(),
        "unjustified occurrences of the token:\n{}",
        findings.join("\n")
    );
}

/// The marker must not be usable as a blanket suppression: a line carrying it and nothing else is
/// a rule that has been switched off rather than an exception that has been justified.
#[test]
fn the_lint_recognises_what_it_is_looking_for() {
    let token = token();

    assert!(names_the_token(&format!("let x = \"'{token}'\";"), &token));
    assert!(names_the_token(
        &format!("// mentions {token} in prose"),
        &token
    ));

    // `'wasm-unsafe-eval'` is a different, narrower source expression: it permits WebAssembly
    // compilation and nothing else. Flagging it would make the rule noise, and `spa_wasm()` sets
    // it deliberately.
    assert!(!names_the_token(&format!("'wasm-{token}'"), &token));
    // Method names use an underscore and are the escape hatch this rule points at.
    assert!(!names_the_token("csp.allow_unsafe_eval()", &token));
}

/// Whether `line` names the CSP source expression, as opposed to something that merely contains
/// its characters.
///
/// The preceding-character check is what separates it from `'wasm-unsafe-eval'`. Without it the
/// rule fires on every policy this crate is designed to produce, and a rule that always fires is
/// a rule that gets deleted.
fn names_the_token(line: &str, token: &str) -> bool {
    let mut from = 0;
    while let Some(offset) = line[from..].find(token) {
        let at = from + offset;
        let preceded_by_identifier = line[..at]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_alphanumeric() || c == '-' || c == '_');
        if !preceded_by_identifier {
            return true;
        }
        from = at + token.len();
    }
    false
}

/// The workspace root rather than this crate's directory.
///
/// The typed crate is in scope too: the source expression this rule keeps out of a data path is a
/// variant of that crate's source enum, and a rule that stopped at the crate boundary would be
/// silently narrower than the one it replaced.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("this crate lives two directories below the workspace root")
        .to_owned()
}

/// Depth-first walk over `.rs` and `.md` files, skipping build output.
fn walk(directory: &Path, visit: &mut impl FnMut(&Path)) {
    let entries = fs::read_dir(directory).expect("the manifest directory is readable");
    for entry in entries {
        let path = entry.expect("directory entries are readable").path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned();

        if path.is_dir() {
            if !SKIPPED_DIRECTORIES.contains(&name.as_str()) {
                walk(&path, visit);
            }
            continue;
        }

        let is_source = matches!(
            path.extension().and_then(|ext| ext.to_str()),
            Some("rs" | "md")
        );
        if is_source && !EXCLUDED_FILES.contains(&name.as_str()) {
            visit(&path);
        }
    }
}
