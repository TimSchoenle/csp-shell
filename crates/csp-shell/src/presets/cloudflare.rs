//! Cloudflare.
//!
//! `script_nonce`, behind the `nonce` feature, is the one preset in this module tree whose
//! contract is carried entirely by the response header: Cloudflare parses the
//! `Content-Security-Policy` it serves and copies the nonce onto what it injects, so nothing has
//! to be stamped into the shell.
//! Every other nonce preset here needs the value in the document as well.

use csp_policy::SourceDirective::{ConnectSrc, FrameSrc, ScriptSrc};

use crate::presets::{admit, Origins};
use crate::Csp;

/// The one host Turnstile serves both its script and its widget from.
pub(crate) const TURNSTILE: Origins = &[
    (ScriptSrc, &["https://challenges.cloudflare.com"]),
    (FrameSrc, &["https://challenges.cloudflare.com"]),
];

/// The beacon script and the endpoint it reports to. Two different hosts, and the `static.`
/// prefix on only one of them is the detail a hand-written policy gets wrong.
pub(crate) const WEB_ANALYTICS: Origins = &[
    (ScriptSrc, &["https://static.cloudflareinsights.com"]),
    (ConnectSrc, &["https://cloudflareinsights.com"]),
];

/// Reserves the per-response nonce slot, for the inline script Cloudflare injects at the edge.
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
#[cfg(feature = "nonce")]
#[cfg_attr(docsrs, doc(cfg(all(feature = "presets", feature = "nonce"))))]
pub fn script_nonce(csp: Csp) -> Csp {
    csp.per_response_nonce(true)
}

/// Admits `https://challenges.cloudflare.com` in `script-src` **and** `frame-src`.
///
/// One origin, two directives, because Turnstile loads `api.js` and then frames the widget from
/// the same host — admitting the script without the frame renders an empty box, which is a
/// support ticket rather than a security event, but an avoidable one.
///
/// Only for a widget rendered *in* a page served by the caller. A managed-challenge interstitial
/// is a Cloudflare-served document carrying its own policy and needs nothing here.
///
/// `frame-ancestors` is untouched: it governs who may frame *this* page, which Turnstile has no
/// opinion about.
///
/// # Examples
///
/// ```
/// use csp_shell::{presets::cloudflare, Csp};
///
/// let header = cloudflare::turnstile(Csp::spa_wasm())
///     .build()
///     .headers()
///     .content_security_policy;
/// assert!(header.contains("frame-src 'self' https://challenges.cloudflare.com"));
/// ```
#[must_use]
pub fn turnstile(csp: Csp) -> Csp {
    admit(csp, TURNSTILE)
}

/// Admits Cloudflare Web Analytics: the beacon script, and the endpoint it reports to.
///
/// Only for the manual snippet.
/// The automatic injection Cloudflare performs at the edge is an inline `<script>` this crate
/// never saw, so it needs `script_nonce`, behind the `nonce` feature, rather than these two
/// origins — which is the whole difference between the two kinds of preset in one product.
#[must_use]
pub fn web_analytics(csp: Csp) -> Csp {
    admit(csp, WEB_ANALYTICS)
}
