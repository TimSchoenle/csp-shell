//! A Content-Security-Policy as data: every directive, source expression and token is a type, and
//! the header value is what those types render to.
//!
//! # Why a type per term
//!
//! A CSP fails silently in both directions. A browser given a directive it cannot parse drops the
//! directive; given a source expression it cannot parse it drops the expression and keeps the
//! rest. Either way the response looks correct, the header is present, and the restriction the
//! author wrote is not in force — or is in force more tightly than intended and the page is
//! blank. Nothing is reported to the origin.
//!
//! So the mistakes worth catching are the ones a string API cannot see:
//!
//! - `scrpit-src` is a missing restriction, not an error. [`DirectiveName`] has no such variant.
//! - `sandbox 'self'` parses and does nothing. A [`Directive`] carries a value of the shape its
//!   name requires, so it does not exist.
//! - `frame-ancestors 'unsafe-inline'` is dropped by the browser. [`AncestorSource`] has no
//!   keywords beyond `'self'`.
//! - `script-src 'none' 'self'` means `'self'`. [`SourceList`] is `'none'` *or* a list, never both.
//! - A `'sha256-…'` of the wrong length matches nothing. [`HashSource`] checks the length the
//!   algorithm implies.
//! - An origin arriving from configuration as `https://cdn.example; script-src *` is a header
//!   injection that parses cleanly. [`HostSource`] parses into components and renders from them.
//!
//! # Rendering is infallible on purpose
//!
//! Every leaf type validates its bytes at construction, and every one of them is opaque or an
//! enum. There is therefore no value in this crate whose rendered form can contain a `;`, a `,`,
//! a space or a control byte that the renderer did not write itself — so
//! [`Policy::to_header_value`] returns a `String` rather than a `Result`, and the check lives
//! where a caller can act on it instead of where they can only unwrap.
//!
//! # Usage
//!
//! ```
//! use csp_policy::{Directive, Policy, Source, SourceDirective, SourceList};
//!
//! let policy = Policy::new()
//!     .with(Directive::sources(SourceDirective::DefaultSrc, [Source::SelfOrigin]))
//!     .with(Directive::sources(
//!         SourceDirective::ScriptSrc,
//!         [Source::SelfOrigin, Source::WasmUnsafeEval],
//!     ))
//!     .with(Directive::sources(
//!         SourceDirective::ConnectSrc,
//!         [Source::SelfOrigin, Source::host("https://api.example.com")?],
//!     ))
//!     .with(Directive::sources(SourceDirective::ObjectSrc, SourceList::None))
//!     .with(Directive::frame_ancestors([]));
//!
//! assert_eq!(
//!     policy.to_header_value(),
//!     "default-src 'self'; \
//!      script-src 'self' 'wasm-unsafe-eval'; \
//!      connect-src 'self' https://api.example.com; \
//!      object-src 'none'; \
//!      frame-ancestors 'none'"
//! );
//! # Ok::<(), csp_policy::ParseError>(())
//! ```
//!
//! # Scope
//!
//! Building and rendering, not parsing a policy back out of a response and not enforcing one. Each
//! term parses from its own textual form — [`Source::parse`], [`HostSource::parse`] and the rest —
//! which is what a consumer reading origins out of configuration needs; reassembling a whole
//! header into a [`Policy`] is not offered, because the only honest result of parsing a policy a
//! browser would partly ignore is a value that says which parts those were.
//!
//! The crate is `no_std + alloc` and has no dependencies.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]

extern crate alloc;

mod base64;
mod directive;
mod error;
mod hash;
mod host;
mod name;
mod policy;
mod report;
mod sandbox;
mod source;
mod trusted_types;
mod util;

pub use crate::directive::{Directive, Webrtc};
pub use crate::error::{ParseError, Term};
pub use crate::hash::{HashAlgorithm, HashSource, NonceSource};
pub use crate::host::{
    HostName, HostPattern, HostSource, PathPart, PortPattern, Scheme, SchemeName,
};
pub use crate::name::{DirectiveName, Grammar, SourceDirective};
pub use crate::policy::Policy;
pub use crate::report::{ReportGroup, ReportUri};
pub use crate::sandbox::SandboxToken;
pub use crate::source::{AncestorSource, AncestorSourceList, Source, SourceList};
pub use crate::trusted_types::{TrustedTypePolicyName, TrustedTypeSink, TrustedTypes};
