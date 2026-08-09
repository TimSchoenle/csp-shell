//! The Cloudflare concessions (`cloudflare` feature).
//!
//! Two behaviours, both off by default even when the feature is on. The doc comment on each is
//! the deliverable: the point of a security concession is that whoever enables it understood what
//! it costs.
//!
//! # Why this is not a generic "edge provider" abstraction
//!
//! Both behaviours are specific to how Cloudflare works — that it reads the CSP response header
//! and copies the nonce onto what it injects, and that Turnstile lives on exactly one host. An
//! `EdgeConfig` trait with Cloudflare as its only implementation would be generality invented
//! rather than observed, and the first non-Cloudflare CDN would not fit it. The generic half —
//! minting a nonce at all — is already factored out as the [`nonce`](crate::Nonce) feature.

use crate::{Csp, CspError};

/// The one host Turnstile serves both its script and its widget from.
const TURNSTILE_ORIGIN: &str = "https://challenges.cloudflare.com";

/// [`Csp::per_response_nonce(true)`](Csp::per_response_nonce), named for why you would want it.
///
/// Cloudflare's bot products — Bot Fight Mode, JavaScript Detections, the challenge platform —
/// inject an inline `<script>` into the served HTML **at the edge**, after this crate has hashed
/// the shell. `script-src` refuses it and the detection silently never runs: bot management
/// appears enabled and does nothing.
///
/// Cloudflare's documented answer is a nonce. It parses the `Content-Security-Policy` **response
/// header** and copies the nonce onto what it injects. That is why nothing is stamped into the
/// shell — the header is the entire contract, and the shell's own inline scripts keep running by
/// hash either way, because under CSP3 a script executes if it matches *any* source expression.
///
/// # The concession
///
/// Real but narrow. An injected script that can already run could read the header back off a
/// same-origin fetch and admit further inline script. It cannot forge one ahead of time — 128
/// CSPRNG bits, minted per response — and it still cannot reach `'unsafe-eval'` or an off-origin <!-- csp-lint: allow — stating the bound of the concession requires naming what stays out of reach -->
/// host.
///
/// # Two load-bearing conditions, as obligations on the caller
///
/// 1. **The shell must be served `Cache-Control: no-cache`.**
///    [`Policy::headers`](crate::Policy::headers) returns it in
///    [`Headers::cache_control`](crate::Headers::cache_control) for a per-response policy;
///    ignoring that field is the failure.
/// 2. **No Cloudflare Cache Rule may cache the shell.** A "Cache Everything" rule overrides the
///    origin `Cache-Control`, satisfying condition 1 at the origin and violating it at the edge.
///    Not detectable from inside the process; it belongs in the deployment checklist.
#[must_use]
#[cfg_attr(docsrs, doc(cfg(feature = "cloudflare")))]
pub fn script_nonce(csp: Csp) -> Csp {
    csp.per_response_nonce(true)
}

/// Admit `https://challenges.cloudflare.com` in `script-src` **and** `frame-src`.
///
/// One origin, two directives, because Turnstile loads `api.js` and then frames the widget from
/// the same host — admitting the script without the frame renders an empty box, which is a
/// support ticket rather than a security event, but an avoidable one.
///
/// Only for a widget rendered *in* a page served by the caller. A managed-challenge interstitial
/// is a Cloudflare-served document carrying its own policy and needs nothing here.
///
/// # Errors
///
/// Cannot fail in practice — the origin is a literal that validation accepts, and both
/// directive names are known — but [`Csp::extend`] is fallible and this function does not paper
/// over that with a panic on the caller's behalf.
#[cfg_attr(docsrs, doc(cfg(feature = "cloudflare")))]
pub fn turnstile(csp: Csp) -> Result<Csp, CspError> {
    csp.extend("script-src", [TURNSTILE_ORIGIN])?
        .extend("frame-src", [TURNSTILE_ORIGIN])
}
