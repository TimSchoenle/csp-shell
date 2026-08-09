//! Shim over [`csp_shell_fuzz::oracle::csp_directive`], where the oracle and its documentation
//! live. See `scan_shell.rs` for why the body is in the library and why this is `cfg`-gated.

#![cfg_attr(fuzzing, no_main)]

#[cfg(fuzzing)]
libfuzzer_sys::fuzz_target!(|data: &[u8]| csp_shell_fuzz::oracle::csp_directive::check(data));

#[cfg(not(fuzzing))]
fn main() {
    eprintln!(
        "built without --cfg fuzzing; run this through `cargo +nightly fuzz run csp_directive` \
         or replay the corpus with `cargo test`"
    );
}
