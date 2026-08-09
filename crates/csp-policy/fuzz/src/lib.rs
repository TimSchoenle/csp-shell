//! The fuzz oracles, as an ordinary library.
//!
//! Each `fuzz_targets/*.rs` binary is a shim over one function in [`oracle`]. The bodies live
//! here rather than in the targets so they can be **replayed without libFuzzer** — see
//! `tests/seeds.rs`, which runs every committed seed through the matching oracle on a plain
//! `cargo test`.
//!
//! That split is not only a convenience. `cargo fuzz` needs `-Z sanitizer=address`, which is
//! nightly-only and, on Windows, needs an `AddressSanitizer` runtime that ships with Visual
//! Studio rather than with rustup. An oracle that can only run under that toolchain is an oracle
//! nobody checks. Here, the seeds are a regression suite that runs anywhere, and the fuzzer is
//! what discovers new inputs to add to it.
//!
//! Every oracle takes `&[u8]` rather than the typed input it works on, so that one replay loop
//! can drive all of them from a file on disk. The targets that want a structured value decode it
//! with [`arbitrary`] exactly as `libfuzzer-sys` would, which is what keeps a corpus produced by
//! a campaign readable by the replay suite.

pub mod oracle;
pub mod support;
