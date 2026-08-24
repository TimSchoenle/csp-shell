//! Builds a Content-Security-Policy from the app shell you serve.
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
//! # What a policy is made of
//!
//! Everything about *what a Content-Security-Policy can say* lives in [`csp_policy`], and this
//! crate re-exports the whole vocabulary so that building one needs a single dependency. A
//! directive name is a [`SourceDirective`], a source expression is a [`Source`], and a value that
//! does not parse is not a value — so the header injection that a configuration-supplied origin
//! used to be is refused at the point the origin is read rather than at the point the policy is
//! rendered.
//!
//! What is left here is the part that depends on the document being served: the hashes, the
//! per-response nonce, and the two or three source expressions worth naming rather than passing
//! as data.
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
//! | *(core)* | always | [`Csp`], [`Policy`], [`ScanResult`], [`scan_shell`], the typed vocabulary, SHA-256 hashing | `csp-policy`, `sha2` |
//! | `std` | **on** | `scan_shell_at`, `ScanError` | — |
//! | `nonce` | off | `Nonce`, `Csp::per_response_nonce`, `Headers::nonce`, nonce splicing in [`Policy::headers`] | `getrandom` |
//! | `presets` | off | `presets` — the origins third-party services load from, in the directives they belong in | — |
//! | `cloudflare` | off | `presets` and `nonce` together, under the name the Cloudflare concessions were first published as | — |
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

extern crate alloc;

mod csp;
mod error;
mod scan;
mod util;

#[cfg(feature = "presets")]
#[cfg_attr(docsrs, doc(cfg(feature = "presets")))]
pub mod presets;

#[cfg(feature = "nonce")]
mod nonce;

pub use crate::csp::{Csp, Headers, Policy};
pub use crate::error::CspError;
pub use crate::scan::{scan_shell, ScanResult, ScanWarning};

/// The typed policy vocabulary, re-exported so that building a policy needs one dependency
/// rather than two.
///
/// [`csp_policy::Policy`] is deliberately not re-exported: [`Csp`] is this crate's builder and
/// [`Policy`] its rendered result, and two types called `Policy` in one namespace would be a
/// worse trade than the one qualified path a consumer needs to reach the untyped builder.
pub use csp_policy::{
    AncestorSource, AncestorSourceList, Directive, DirectiveName, Grammar, HashAlgorithm,
    HashSource, HostName, HostPattern, HostSource, NonceSource, ParseError, PathPart, PortPattern,
    ReportGroup, ReportUri, SandboxToken, Scheme, SchemeName, Source, SourceDirective, SourceList,
    Term, TrustedTypePolicyName, TrustedTypeSink, TrustedTypes, Webrtc,
};

/// The typed policy crate itself, for a consumer that wants
/// [`csp_policy::Policy`] or the rest of the vocabulary without adding a second
/// dependency.
pub use ::csp_policy;

#[cfg(feature = "std")]
pub use crate::error::ScanError;
#[cfg(feature = "std")]
pub use crate::scan::scan_shell_at;

#[cfg(feature = "nonce")]
pub use crate::nonce::Nonce;
