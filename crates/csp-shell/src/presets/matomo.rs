//! Matomo Analytics.
//!
//! Matomo has no fixed host in either form — self-hosted is the caller's own server, and Matomo
//! Cloud is a per-account subdomain — so there is no origins table here, only the knowledge of
//! which directives the origin belongs in.

use csp_policy::ParseError;
use csp_policy::SourceDirective::{ConnectSrc, ImgSrc, ScriptSrc};

use crate::presets::admit_origin;
use crate::Csp;

/// `matomo.js` is a script, `matomo.php` receives the tracking request, and the `<noscript>`
/// fallback requests the same endpoint as an image.
const DIRECTIVES: &[csp_policy::SourceDirective] = &[ScriptSrc, ConnectSrc, ImgSrc];

/// Admit a Matomo instance: `https://analytics.example.com`, or the Matomo Cloud subdomain.
///
/// `img-src` is included for the `<noscript>` fallback, which is a plain `<img>` request to the
/// tracking endpoint. Omitting it is invisible in every browser that runs script, which is every
/// browser anyone tests in.
///
/// A Matomo served from the same origin as the application — the reverse-proxy setup Matomo
/// documents for surviving blockers — needs no preset: `default-src 'self'` covers it.
///
/// # Errors
///
/// [`ParseError`] if `origin` is not a host source.
///
/// # Examples
///
/// ```
/// use csp_shell::{presets::matomo, Csp};
///
/// let header = matomo::instance(Csp::spa_wasm(), "https://analytics.example.com")?
///     .build()
///     .headers()
///     .content_security_policy;
/// assert!(header.contains("connect-src 'self' https://analytics.example.com"));
/// # Ok::<(), csp_shell::ParseError>(())
/// ```
pub fn instance(csp: Csp, origin: &str) -> Result<Csp, ParseError> {
    admit_origin(csp, origin, DIRECTIVES)
}
