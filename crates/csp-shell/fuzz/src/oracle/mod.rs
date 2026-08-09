//! One module per fuzz target, each exposing a `check(&[u8])` and a typed `run`.
//!
//! The four widen in steps. [`scan_shell`] covers the scanner alone, over the least trusted input
//! in the chain. [`csp_directive`] covers one builder call in depth, along the path a consumer's
//! configuration takes. [`csp_builder`] covers the interactions *between* calls. [`shell_to_header`]
//! is the one that matches a deployment end to end: a document is scanned, its hashes go into a
//! preset, and the result is a response header.

pub mod csp_builder;
pub mod csp_directive;
pub mod scan_shell;
pub mod shell_to_header;
