//! Sentry error monitoring, Session Replay and the CDN loader.
//!
//! Sentry has no fixed ingest host: it is derived from the DSN, which is per-organisation and
//! per-region. [`ingest`] therefore takes the origin rather than inventing one, and what the
//! preset still owns is the part that is not deployment-specific — that the origin belongs in
//! `connect-src` and nowhere else.

use csp_policy::Scheme;
use csp_policy::SourceDirective::{ConnectSrc, ScriptSrc, WorkerSrc};
use csp_policy::{ParseError, Source};

use crate::presets::{admit, admit_origin, Origins};
use crate::Csp;

/// The two hosts Sentry serves its CDN bundles from.
pub(crate) const LOADER: Origins = &[(
    ScriptSrc,
    &[
        "https://browser.sentry-cdn.com",
        "https://js.sentry-cdn.com",
    ],
)];

/// Admit the DSN's ingest origin in `connect-src`.
///
/// Pass the origin, not the DSN: `https://o123456.ingest.us.sentry.io`, not the
/// `https://<key>@o123456.ingest.us.sentry.io/1` string from the dashboard. The key is a
/// credential and has no place in a response header every visitor reads.
///
/// A wildcard such as `https://*.ingest.sentry.io` would spare the caller this argument and admit
/// every other organisation's ingest endpoint along with theirs. Since the exact origin is known
/// wherever the DSN is configured, the wildcard buys nothing but reach.
///
/// # Tunnelling
///
/// A deployment using Sentry's `tunnel` option posts to its own origin instead, which
/// `default-src 'self'` already covers — that configuration needs this preset not at all.
///
/// # Errors
///
/// [`ParseError`] if `origin` is not a host source, which is where a DSN pasted whole is caught.
///
/// # Examples
///
/// ```
/// use csp_shell::{presets::sentry, Csp};
///
/// let csp = sentry::ingest(Csp::spa_wasm(), "https://o123456.ingest.us.sentry.io")?;
/// assert!(csp
///     .build()
///     .headers()
///     .content_security_policy
///     .contains("connect-src 'self' https://o123456.ingest.us.sentry.io"));
/// # Ok::<(), csp_shell::ParseError>(())
/// ```
pub fn ingest(csp: Csp, origin: &str) -> Result<Csp, ParseError> {
    admit_origin(csp, origin, &[ConnectSrc])
}

/// Admit the CDN loader script.
///
/// Only for the loader snippet or a CDN-hosted bundle. An SDK installed from npm and bundled into
/// the application is served from the caller's own origin and needs nothing here.
#[must_use]
pub fn loader(csp: Csp) -> Csp {
    admit(csp, LOADER)
}

/// Admit `blob:` in `worker-src`, which Session Replay needs.
///
/// Replay compresses events in a Web Worker it constructs from a `Blob` rather than from a URL,
/// so no host allowance covers it — the source is the `blob:` scheme itself.
///
/// The seeding rule this module tree follows matters here more than anywhere else: on a policy
/// with `default-src 'self'` and no `worker-src`, creating `worker-src blob:` alone would revoke
/// every same-origin worker the application already ran. This preset seeds `worker-src` from the
/// directive it was falling back to first, so the result is `worker-src 'self' blob:` and the
/// only change is the addition.
///
/// `blob:` in `worker-src` admits worker code the page constructed itself. That is a real
/// widening and a narrow one: it reaches no network origin, and a page that can build a `Blob`
/// worker is a page already running the caller's own script.
#[must_use]
pub fn session_replay(csp: Csp) -> Csp {
    csp.extend_unrouted(WorkerSrc, [Source::Scheme(Scheme::Blob)])
}
