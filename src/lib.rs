//! Build a Content-Security-Policy from the app shell you actually serve.
//!
//! There is exactly one mechanism in this crate:
//!
//! > A Content-Security-Policy assembled from the document about to be served, by hashing that
//! > document's inline scripts, with the newline normalisation the HTML parser performs applied
//! > first — plus the per-response nonce that lets an edge-injected script run alongside them.
//!
//! Everything around that — static file serving, SPA fallback, a reverse proxy, baseline security
//! headers, a `tower::Layer` to attach the header — is ordinary and belongs to the consumer. This
//! crate does not depend on a web framework and never will: a breaking change to a feature-gated
//! public API is still a breaking change, and `axum` is pre-1.0.
//!
//! # Why this is a crate at all
//!
//! Every failure mode here is **silent**. The header looks correct, the browser refuses the
//! scripts, the page is blank, and the only evidence is in a console nobody is watching. A
//! hand-maintained list of `sha256-…` values drifts the moment anyone edits the shell, with the
//! same symptom. That is the class of bug worth encoding once, testing once, and documenting
//! once.
//!
//! # Usage
//!
//! The example reads a file, so it is compiled only when the `std` feature is on. Without it,
//! hand [`scan_shell`] the document's text yourself.
//!
#![cfg_attr(feature = "std", doc = "```no_run")]
#![cfg_attr(not(feature = "std"), doc = "```ignore")]
//! use csp_shell::{scan_shell_at, Csp};
//! use std::path::Path;
//!
//! // Fail-open or fail-closed is the caller's decision, not this crate's.
//! let scan = scan_shell_at(Path::new("dist/index.html")).expect("shell must be readable");
//! let policy = Csp::spa_wasm().with_scan(&scan).build();
//!
//! let headers = policy.headers();
//! // `content_security_policy` is the header value; `cache_control` is an obligation, not a
//! // suggestion. Ignoring it on a per-response policy shares one nonce with every reader.
//! assert_eq!(headers.cache_control, None); // no nonce reserved
//! ```
//!
//! # Features
//!
//! | Feature | Default | Adds | New dependency |
//! |---|---|---|---|
//! | *(core)* | always | [`Csp`], [`Policy`], [`ScanResult`], [`scan_shell`], SHA-256 hashing | `sha2` |
//! | `std` | **on** | `scan_shell_at`, `ScanError` | — |
//! | `nonce` | off | `Nonce`, `Csp::per_response_nonce`, nonce splicing in [`Policy::headers`] | `getrandom` |
//! | `cloudflare` | off | `cloudflare::script_nonce`, `cloudflare::turnstile` | — |
//!
//! `std` is on by default because it adds no dependency and its absence is a compile error for
//! the obvious first call. `default-features = false` gives a `no_std + alloc` core usable from a
//! build script, a bundler, or a bare-metal target, where the caller supplies the shell's text
//! itself.
//!
//! # Reloading: the shell is a configuration input
//!
//! [`ScanResult::digest`] exists so that a consumer can detect a shell replaced under a running
//! process — a volume-mounted bundle, a `ConfigMap`, a development directory — without a second
//! read of the file. The crate deliberately does not own the watching: comparing the digest
//! against the one the running policy was built from is three lines wherever the consumer's
//! configuration already reloads. The README carries the pattern, including the Kubernetes
//! caveats that make a naive `inotify` watch on `index.html` never fire.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![deny(missing_docs, missing_debug_implementations)]

extern crate alloc;

mod base64;
mod csp;
mod error;
mod scan;
mod util;
mod validate;

#[cfg(feature = "cloudflare")]
#[cfg_attr(docsrs, doc(cfg(feature = "cloudflare")))]
pub mod cloudflare;

#[cfg(feature = "nonce")]
mod nonce;

pub use crate::csp::{Csp, Headers, Policy};
pub use crate::error::CspError;
pub use crate::scan::{scan_shell, ScanResult, ScanWarning};

#[cfg(feature = "std")]
pub use crate::error::ScanError;
#[cfg(feature = "std")]
pub use crate::scan::scan_shell_at;

#[cfg(feature = "nonce")]
pub use crate::nonce::Nonce;
