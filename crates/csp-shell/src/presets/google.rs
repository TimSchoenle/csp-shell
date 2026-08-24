//! Google Tag Manager, Google Analytics 4, Google Fonts and reCAPTCHA.
//!
//! Four products, one company, and no shared origin between them worth factoring out: Tag Manager
//! is `googletagmanager.com`, Analytics reports to `google-analytics.com`, Fonts is
//! `googleapis.com` plus `gstatic.com`, and reCAPTCHA is `google.com` plus a different path on
//! `gstatic.com`. They are one module because a consumer reaches for them together, not because
//! they are one thing.

use csp_policy::SourceDirective::{ConnectSrc, FontSrc, FrameSrc, ImgSrc, ScriptSrc, StyleSrc};

use crate::presets::{admit, Origins};
use crate::Csp;

/// The container loader. One host; the tags it then injects are the caller's problem, and
/// deliberately so — a container can load anything.
pub(crate) const TAG_MANAGER: Origins = &[(ScriptSrc, &["https://www.googletagmanager.com"])];

/// GA4 by way of `gtag.js`.
///
/// The script comes from Tag Manager's host even when no container is involved, and the
/// measurement traffic goes to a *regional* `google-analytics.com` subdomain — `region1.`,
/// `region2.` — which is why the wildcard is there rather than the bare `www.` host a policy
/// written against one capture session would contain. `img-src` covers the beacon's fallback
/// transport, which is a pixel when `sendBeacon` is unavailable or the payload is small.
pub(crate) const ANALYTICS: Origins = &[
    (ScriptSrc, &["https://www.googletagmanager.com"]),
    (
        ConnectSrc,
        &[
            "https://*.google-analytics.com",
            "https://*.analytics.google.com",
            "https://*.googletagmanager.com",
        ],
    ),
    (
        ImgSrc,
        &[
            "https://*.google-analytics.com",
            "https://*.googletagmanager.com",
        ],
    ),
];

/// The stylesheet host and the font-file host, which are not the same host.
pub(crate) const FONTS: Origins = &[
    (StyleSrc, &["https://fonts.googleapis.com"]),
    (FontSrc, &["https://fonts.gstatic.com"]),
];

/// Path-scoped, because both hosts serve far more than reCAPTCHA.
///
/// `https://www.google.com` in `script-src` admits every script Google serves from that origin;
/// `https://www.google.com/recaptcha/` admits the widget and nothing else. CSP matches a source
/// whose path ends in `/` as a prefix, so this is the tighter policy at no cost.
pub(crate) const RECAPTCHA: Origins = &[
    (
        ScriptSrc,
        &[
            "https://www.google.com/recaptcha/",
            "https://www.gstatic.com/recaptcha/",
        ],
    ),
    (FrameSrc, &["https://www.google.com/recaptcha/"]),
];

/// Admits the Tag Manager container loader in `script-src`.
///
/// This is the loader only. A container that loads Google Analytics needs [`analytics`] as well,
/// and a container that loads a third party needs that third party's origins — a preset cannot
/// know what a container was configured to do, and pretending otherwise would be the worst kind
/// of allowance: one that looks specific and is not.
///
/// A Custom HTML tag injects **inline** script, which no host allowance admits.
/// That needs `tag_manager_nonce`, behind the `nonce` feature.
#[must_use]
pub fn tag_manager(csp: Csp) -> Csp {
    admit(csp, TAG_MANAGER)
}

/// Reserves the per-response nonce slot for the inline script Tag Manager injects.
///
/// # Stamping the nonce into the shell
///
/// Cloudflare reads the nonce out of the response header. Tag Manager does not: it reads it off
/// **its own loader element** — `document.currentScript.nonce` — and copies that onto the script
/// elements it injects. So the header alone does nothing here. The caller has to put the same
/// nonce on the GTM `<script>` in the served document, and
/// [`Headers::nonce`](crate::Headers::nonce) hands back the value that was spliced into the
/// header for exactly that purpose:
///
/// ```
/// # use csp_shell::{presets::google, scan_shell, Csp};
/// let scan = scan_shell(r#"<script>window.dataLayer = [];</script>"#);
/// let policy = google::tag_manager_nonce(google::tag_manager(Csp::spa_wasm()).with_scan(&scan))
///     .build();
///
/// let headers = policy.headers();
/// let nonce = headers.nonce.expect("a slot is reserved");
/// // Stamp `nonce.as_str()` onto the loader tag as you render the shell. A `nonce` attribute is
/// // not script text, so the hashes computed above are unaffected.
/// assert!(headers.content_security_policy.contains(nonce.as_str()));
/// ```
///
/// Stamping means the shell is now templated per response, which is a real cost: it is no longer
/// a static file, and [`Headers::cache_control`](crate::Headers::cache_control) is an obligation
/// rather than a suggestion. If the container has no Custom HTML tag, skip this and use
/// [`tag_manager`] alone — the tags Tag Manager loads by URL are admitted by host.
///
/// # What the nonce does not reach
///
/// A Custom HTML tag with "Support document.write" enabled bypasses the injection path that
/// carries the nonce. A tag that injects a *third-party* script still needs that third party's
/// host. And a nonce admits whatever the container was configured to run — the concession is the
/// container's editors, which is an access-control question rather than a CSP one.
#[must_use]
#[cfg(feature = "nonce")]
#[cfg_attr(docsrs, doc(cfg(feature = "nonce")))]
pub fn tag_manager_nonce(csp: Csp) -> Csp {
    csp.per_response_nonce(true)
}

/// Admits Google Analytics 4: the `gtag.js` host, the regional measurement endpoints, and the
/// pixel fallback.
///
/// Scoped to plain GA4. Google Signals, Ads remarketing and conversion linking add
/// `google.com`, every `google.<tld>` ccTLD and `googlesyndication.com` — a list this crate will
/// not add under an "analytics" name, because a consumer reading the call site would not expect
/// an ad network in it.
#[must_use]
pub fn analytics(csp: Csp) -> Csp {
    admit(csp, ANALYTICS)
}

/// Admits Google Fonts: `fonts.googleapis.com` in `style-src`, `fonts.gstatic.com` in `font-src`.
///
/// Two hosts because the stylesheet and the font files it references are served from different
/// origins. Admitting the first without the second gives a page with the right metrics and no
/// glyphs, which renders as the fallback font — a silent failure, and a common one.
///
/// No nonce is involved. A `<link rel="stylesheet">` is admitted by host.
#[must_use]
pub fn fonts(csp: Csp) -> Csp {
    admit(csp, FONTS)
}

/// Admits reCAPTCHA v2 and v3: the API script, the widget frame, and the `gstatic.com` payload.
///
/// Both script origins are path-scoped to `/recaptcha/`, so this does not admit the rest of what
/// `google.com` and `gstatic.com` serve.
///
/// # The inline style, which this preset will not add for you
///
/// reCAPTCHA injects an inline `<style>` for its badge. Under a policy that has neither
/// `'unsafe-inline'` nor a nonce in `style-src`, the badge is unstyled and the widget still
/// works. [`Csp::spa_wasm`](crate::Csp::spa_wasm) sets `style-src 'unsafe-inline'` already, so on
/// that starting point there is nothing to do. On a stricter one, widening `style-src` is a
/// decision this preset leaves to the caller rather than making quietly on the strength of a
/// captcha.
///
/// # Regions where `google.com` is unreachable
///
/// `https://www.recaptcha.net` is Google's documented drop-in for the API host. It is not in this
/// preset because it is the alternative rather than the default; a caller serving it adds the
/// origin with [`Csp::extend`](crate::Csp::extend).
#[must_use]
pub fn recaptcha(csp: Csp) -> Csp {
    admit(csp, RECAPTCHA)
}
