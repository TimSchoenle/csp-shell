//! Fathom Analytics.

use csp_policy::ParseError;
use csp_policy::SourceDirective::{ConnectSrc, ImgSrc, ScriptSrc};

use crate::presets::{admit, admit_origin, Origins};
use crate::Csp;

/// The CDN host, in the three directives the tracker touches: it is fetched as a script, posts
/// events back to the same host, and falls back to a pixel when the beacon is unavailable.
pub(crate) const CLOUD: Origins = &[
    (ScriptSrc, &["https://cdn.usefathom.com"]),
    (ConnectSrc, &["https://cdn.usefathom.com"]),
    (ImgSrc, &["https://cdn.usefathom.com"]),
];

/// The directives a Fathom host has to appear in, whichever host it is.
const DIRECTIVES: &[csp_policy::SourceDirective] = &[ScriptSrc, ConnectSrc, ImgSrc];

/// Admits Fathom's CDN host.
#[must_use]
pub fn cloud(csp: Csp) -> Csp {
    admit(csp, CLOUD)
}

/// Admits a Fathom custom domain, which replaces the CDN host rather than adding to it.
///
/// Call this *instead of* [`cloud`]. Calling both admits an origin the deployment does not use,
/// which is not dangerous and is not tidy either.
///
/// # Errors
///
/// [`ParseError`] if `origin` is not a host source.
pub fn custom_domain(csp: Csp, origin: &str) -> Result<Csp, ParseError> {
    admit_origin(csp, origin, DIRECTIVES)
}
