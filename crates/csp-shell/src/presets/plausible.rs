//! Plausible Analytics.

use csp_policy::ParseError;
use csp_policy::SourceDirective::{ConnectSrc, ScriptSrc};

use crate::presets::{admit, admit_origin, Origins};
use crate::Csp;

/// One host in two directives: the script is fetched from it and the events are posted back to
/// it.
pub(crate) const CLOUD: Origins = &[
    (ScriptSrc, &["https://plausible.io"]),
    (ConnectSrc, &["https://plausible.io"]),
];

/// The directives a Plausible instance's origin has to appear in, whichever host it is.
const DIRECTIVES: &[csp_policy::SourceDirective] = &[ScriptSrc, ConnectSrc];

/// Admits Plausible Cloud.
#[must_use]
pub fn cloud(csp: Csp) -> Csp {
    admit(csp, CLOUD)
}

/// Admits a self-hosted instance, or a Plausible Cloud custom domain.
///
/// The proxying setup Plausible documents — serving the script from the caller's own origin to
/// survive blockers — needs no preset at all: `default-src 'self'` covers it.
///
/// # Errors
///
/// [`ParseError`] if `origin` is not a host source.
pub fn self_hosted(csp: Csp, origin: &str) -> Result<Csp, ParseError> {
    admit_origin(csp, origin, DIRECTIVES)
}
