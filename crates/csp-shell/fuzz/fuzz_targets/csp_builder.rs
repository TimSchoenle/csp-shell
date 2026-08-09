//! Shim over [`csp_shell_fuzz::oracle::csp_builder`], where the oracle and its documentation
//! live. See `scan_shell.rs` for why the body is in the library and why this is `cfg`-gated.
//!
//! The argument is `&[u8]` rather than the `Session` the oracle works on: the decode belongs next
//! to the type it produces, and doing it there is what lets the replay suite read the same corpus
//! entries off disk.

#![cfg_attr(fuzzing, no_main)]

#[cfg(fuzzing)]
libfuzzer_sys::fuzz_target!(|data: &[u8]| csp_shell_fuzz::oracle::csp_builder::check(data));

#[cfg(not(fuzzing))]
fn main() {
    eprintln!(
        "built without --cfg fuzzing; run this through `cargo +nightly fuzz run csp_builder` \
         or replay the corpus with `cargo test`"
    );
}
