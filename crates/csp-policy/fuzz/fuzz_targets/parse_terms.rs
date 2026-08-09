//! Shim over [`csp_policy_fuzz::oracle::parse_terms`], where the oracle and its documentation
//! live. See `parse_source.rs` for why the body is in the library and why this is `cfg`-gated.

#![cfg_attr(fuzzing, no_main)]

#[cfg(fuzzing)]
libfuzzer_sys::fuzz_target!(|data: &[u8]| csp_policy_fuzz::oracle::parse_terms::check(data));

#[cfg(not(fuzzing))]
fn main() {
    eprintln!(
        "built without --cfg fuzzing; run this through `cargo +nightly fuzz run parse_terms` \
         or replay the corpus with `cargo test`"
    );
}
