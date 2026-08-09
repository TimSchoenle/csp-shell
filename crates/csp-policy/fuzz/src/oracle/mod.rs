//! One module per fuzz target, each exposing a `check(&[u8])`.
//!
//! The three sit at different widths on purpose. [`parse_source`] is the narrowest and maps
//! directly onto the threat — a source expression built from configuration. [`parse_terms`]
//! widens that to every other leaf parser, because each is a separate alphabet and a hole in any
//! one of them is the same injection. [`build_policy`] covers what no single value can promise:
//! the properties that only hold across a whole assembled policy.

pub mod build_policy;
pub mod parse_source;
pub mod parse_terms;
