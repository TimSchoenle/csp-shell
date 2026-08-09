//! Stripe.js, Elements and Checkout.
//!
//! Stripe is the clearest case in this module tree for why a preset is about *directives* rather
//! than hosts. `api.stripe.com` is reached by `fetch`, so it belongs in `connect-src`;
//! `js.stripe.com` serves both a script and the iframes Elements mounts, so it belongs in
//! `script-src` **and** `frame-src`; `hooks.stripe.com` is only ever framed. Put any one of them
//! in the wrong directive and the failure is a declined payment with a console error nobody sees.

use csp_policy::SourceDirective::{ConnectSrc, FrameSrc, ScriptSrc};

use crate::presets::{admit, Origins};
use crate::Csp;

/// Stripe.js and the frames it mounts.
///
/// `hooks.stripe.com` is the 3-D Secure and redirect-authentication frame. It is here rather than
/// behind a separate preset because a payment method that needs it is chosen by the *shopper*,
/// not by the integration — a policy that omits it works until the first challenge.
pub(crate) const ELEMENTS: Origins = &[
    (ScriptSrc, &["https://js.stripe.com"]),
    (
        FrameSrc,
        &["https://js.stripe.com", "https://hooks.stripe.com"],
    ),
    (ConnectSrc, &["https://api.stripe.com"]),
];

/// What embedded Checkout needs *in addition to* [`ELEMENTS`].
pub(crate) const CHECKOUT: Origins = &[(FrameSrc, &["https://checkout.stripe.com"])];

/// Admit Stripe.js and Elements.
///
/// Address autocomplete is not covered: it loads `maps.googleapis.com`, a Google origin that has
/// no business being admitted by a call named `stripe::elements`. Integrations using it add that
/// origin themselves.
#[must_use]
pub fn elements(csp: Csp) -> Csp {
    admit(csp, ELEMENTS)
}

/// Admit embedded Checkout: everything [`elements`] admits, plus the Checkout frame host.
///
/// Only for the *embedded* form. Hosted Checkout navigates the browser to a Stripe-served
/// document carrying its own policy, so it needs nothing here — including nothing in
/// `form-action`, because it is a `location` assignment rather than a form submission.
#[must_use]
pub fn checkout(csp: Csp) -> Csp {
    admit(elements(csp), CHECKOUT)
}
