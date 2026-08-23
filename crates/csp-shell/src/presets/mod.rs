//! Ready-made policy fragments for third-party services (`presets` feature).
//!
//! A preset is a named `fn(Csp) -> Csp` carrying one fact this crate can state precisely and a
//! consumer cannot look up reliably: **which origins a service loads from, and which directives
//! they have to appear in**. Getting the second half wrong is the failure this module exists to
//! prevent — admitting Turnstile's script without its frame renders an empty box, and admitting
//! Stripe's `api.stripe.com` in `script-src` rather than `connect-src` fails a payment.
//!
//! # Two kinds, named apart
//!
//! The distinction is load-bearing enough to be visible at the call site rather than only in a
//! doc comment:
//!
//! | Kind | Naming | What it does | Obligation on the caller |
//! |---|---|---|---|
//! | **Origins** | a noun — [`google::fonts`], [`stripe::elements`] | appends host sources | none |
#![cfg_attr(
    feature = "nonce",
    doc = "| **Nonce** | a `_nonce` suffix — [`cloudflare::script_nonce`], [`google::tag_manager_nonce`] | reserves the per-response nonce slot | `Cache-Control: no-cache`, and for some services stamping [`Headers::nonce`](crate::Headers::nonce) into the shell |"
)]
#![cfg_attr(
    not(feature = "nonce"),
    doc = "| **Nonce** | a `_nonce` suffix, behind the `nonce` feature | reserves the per-response nonce slot | `Cache-Control: no-cache`, and for some services stamping the minted value into the shell |"
)]
//!
//! Conflating them ships a policy that looks nonce-protected and is not. A nonce preset costs a
//! per-response header render and a cache obligation; an origins preset costs neither, and no
//! amount of host allowance substitutes for a nonce when the injected script is inline.
//!
//! # A preset only ever widens
//!
//! Appending to a directive the policy does not set would otherwise *narrow* it: before the
//! append the browser fell back to `default-src` — or to `child-src`, or to `script-src` — and
//! afterwards it does not. Every preset therefore seeds an absent directive from whatever it was
//! falling back to before adding anything, so `cloudflare::turnstile` on a policy with
//! `default-src 'self'` and no `frame-src` yields `frame-src 'self' https://challenges.cloudflare.com`
//! rather than silently revoking same-origin frames.
//!
//! Presets compose in any order and are idempotent: a source already present is not appended
//! twice.
//!
//! # What a preset is not
//!
//! Not a substitute for reading the service's own documentation, and not a promise that the
//! service will keep the hosts it has today. Each preset's origins are literals in this crate
//! with a version behind them; a service that adds a host ships it before this crate does. The
//! escape hatch is [`Csp::extend`](crate::Csp::extend), which takes any origin a preset missed.
//!
//! Not an abstraction, either. There is no `Vendor` trait: the services here agree on nothing
//! beyond "some origins in some directives", which is [`Csp::extend`]'s signature already, and a
//! trait over that would add a vtable to spell a function call. What is worth sharing between
//! them — the seeding rule above, the parse-or-it-is-a-bug handling of a literal origin — is
//! shared as functions in this module rather than as a type.
//!
//! [`Csp::extend`]: crate::Csp::extend

use csp_policy::{HostSource, ParseError, Source, SourceDirective};

use crate::Csp;

pub mod cloudflare;
pub mod fathom;
pub mod google;
pub mod matomo;
pub mod plausible;
pub mod sentry;
pub mod stripe;

/// The origins one preset admits, as the directives they have to appear in.
///
/// A table rather than a chain of builder calls so that a single test can walk every preset in
/// this module tree and hold its literals to account — see the tests at the foot of this file.
pub(crate) type Origins = &'static [(SourceDirective, &'static [&'static str])];

/// Admits every origin in `origins`, in the directives the table names.
pub(crate) fn admit(csp: Csp, origins: Origins) -> Csp {
    origins.iter().fold(csp, |csp, (directive, literals)| {
        csp.extend_unrouted(
            *directive,
            literals.iter().copied().filter_map(literal_host),
        )
    })
}

/// Admits one caller-supplied origin in each of `directives`.
///
/// For the services whose host is deployment-specific — a Sentry ingest endpoint, a self-hosted
/// analytics instance. The preset still owns the part that is not deployment-specific, which is
/// *which directives the origin belongs in*.
///
/// # Errors
///
/// [`ParseError`] if `origin` is not a host source. Refusing here is the point: a configuration
/// value that would have carried a `;` into the rendered header stops at the parse.
pub(crate) fn admit_origin(
    csp: Csp,
    origin: &str,
    directives: &[SourceDirective],
) -> Result<Csp, ParseError> {
    let host = HostSource::parse(origin)?;
    Ok(directives.iter().fold(csp, |csp, directive| {
        csp.extend_unrouted(*directive, [Source::Host(host.clone())])
    }))
}

/// Parses one of this crate's own origin literals.
///
/// A literal that stopped parsing is a bug in this crate, not a condition a caller can handle;
/// dropping it keeps the policy valid and renderable while the test below fails.
fn literal_host(literal: &str) -> Option<Source> {
    let Ok(host) = HostSource::parse(literal) else {
        debug_assert!(false, "a preset origin must parse as a host source");
        return None;
    };
    Some(Source::Host(host))
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use csp_policy::{HostPattern, HostSource, Scheme, SourceDirective};

    use super::Origins;

    /// Every origin table in this module tree, so that one test covers all of them.
    ///
    /// A new preset has to be registered here, and the registration sits beside the `mod`
    /// declarations above for exactly that reason. Forgetting it costs the coverage below, not
    /// correctness of the preset itself.
    const TABLES: &[(&str, Origins)] = &[
        ("cloudflare::turnstile", super::cloudflare::TURNSTILE),
        (
            "cloudflare::web_analytics",
            super::cloudflare::WEB_ANALYTICS,
        ),
        ("fathom::cloud", super::fathom::CLOUD),
        ("google::analytics", super::google::ANALYTICS),
        ("google::fonts", super::google::FONTS),
        ("google::recaptcha", super::google::RECAPTCHA),
        ("google::tag_manager", super::google::TAG_MANAGER),
        ("plausible::cloud", super::plausible::CLOUD),
        ("sentry::loader", super::sentry::LOADER),
        ("stripe::checkout", super::stripe::CHECKOUT),
        ("stripe::elements", super::stripe::ELEMENTS),
    ];

    /// A preset renders its origins from a parse of these literals. One that stops parsing stops
    /// being admitted — silently, and the service it belongs to then breaks in a browser rather
    /// than in CI.
    #[test]
    fn every_preset_origin_parses_and_round_trips() {
        for (preset, origins) in TABLES {
            for (_, literals) in *origins {
                for literal in *literals {
                    let parsed = HostSource::parse(literal)
                        .unwrap_or_else(|_| panic!("{preset}: {literal} must parse"));
                    assert_eq!(&parsed.to_string(), literal, "{preset}: {literal}");
                }
            }
        }
    }

    /// Every origin is `https`, and none of them is a bare wildcard.
    ///
    /// A preset is a value a consumer accepts without reading, so the two ways an origin table
    /// could quietly nullify a policy — `http:` downgrading a directive to cleartext, `*` opening
    /// it to every host — are refused here rather than trusted to review.
    #[test]
    fn no_preset_origin_downgrades_or_opens_a_directive() {
        for (preset, origins) in TABLES {
            for (_, literals) in *origins {
                for literal in *literals {
                    let parsed = HostSource::parse(literal).expect("checked above");
                    assert_eq!(
                        parsed.scheme(),
                        Some(&Scheme::Https),
                        "{preset}: {literal} must name https"
                    );
                    assert_ne!(
                        parsed.host_pattern(),
                        &HostPattern::Any,
                        "{preset}: {literal} must name a host"
                    );
                }
            }
        }
    }

    /// A repeated origin lengthens every response without changing what the policy permits.
    /// `Csp::extend` deduplicates, so this is about the tables being readable rather than about
    /// the rendered header.
    #[test]
    fn no_preset_repeats_an_origin_within_one_directive() {
        for (preset, origins) in TABLES {
            let mut seen: alloc::vec::Vec<(SourceDirective, &str)> = alloc::vec::Vec::new();
            for (directive, literals) in *origins {
                for literal in *literals {
                    let entry = (*directive, *literal);
                    assert!(!seen.contains(&entry), "{preset}: {literal} listed twice");
                    seen.push(entry);
                }
            }
        }
    }
}
