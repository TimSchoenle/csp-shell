//! The presets, the properties their doc comments claim, and — mostly — how they combine.
//!
//! A preset is only useful in company: a real policy carries a payment provider, an analytics
//! tag, a font host and a captcha at once, on top of the shell's own hashes and possibly a nonce.
//! Each preset being individually correct says nothing about that, so most of what follows is
//! about composition rather than about any one service.

#![cfg(feature = "presets")]

use csp_policy::SourceDirective;
use csp_shell::presets::{cloudflare, fathom, google, matomo, plausible, sentry, stripe};
use csp_shell::{scan_shell, Csp};

/// One preset that only admits origins, under the name it is reported by when it fails.
type OriginsPreset = (&'static str, fn(Csp) -> Csp);

/// Every origins preset, so that one test can hold all of them to a property.
///
/// The parameterised ones — `sentry::ingest`, `matomo::instance`, `plausible::self_hosted`,
/// `fathom::custom_domain` — are not here because they take a second argument; they are covered
/// individually below.
const ORIGINS_PRESETS: &[OriginsPreset] = &[
    ("cloudflare::turnstile", cloudflare::turnstile),
    ("cloudflare::web_analytics", cloudflare::web_analytics),
    ("fathom::cloud", fathom::cloud),
    ("google::analytics", google::analytics),
    ("google::fonts", google::fonts),
    ("google::recaptcha", google::recaptcha),
    ("google::tag_manager", google::tag_manager),
    ("plausible::cloud", plausible::cloud),
    ("sentry::loader", sentry::loader),
    ("sentry::session_replay", sentry::session_replay),
    ("stripe::checkout", stripe::checkout),
    ("stripe::elements", stripe::elements),
];

/// The policy as a set of `(directive, source)` pairs, which is what a browser reads it as.
///
/// Directive *order* is an artefact of the order presets were applied and carries no meaning, so
/// comparing rendered headers would fail tests that ought to pass. This normalisation is what
/// "the same policy" means for the order-independence and idempotence tests below.
fn pairs(csp: &Csp) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for directive in csp.policy() {
        let name = directive.name().as_str().to_string();
        if let Some(sources) = directive.source_list() {
            for source in sources.sources() {
                out.push((name.clone(), source.to_string()));
            }
            if sources.sources().is_empty() {
                out.push((name.clone(), "'none'".to_string()));
            }
        } else {
            // `frame-ancestors`, `sandbox` and the rest render as a whole.
            let mut rendered = String::new();
            directive.render_into(&mut rendered);
            out.push((name, rendered));
        }
    }
    out.sort();
    out
}

/// The sources one directive carries, as rendered strings.
fn sources_of(csp: &Csp, directive: SourceDirective) -> Vec<String> {
    csp.policy()
        .source_list(directive)
        .map(|list| list.sources().iter().map(ToString::to_string).collect())
        .unwrap_or_default()
}

/// The rendered header, for the assertions that are genuinely about the header text.
fn header(csp: Csp) -> String {
    csp.build().headers().content_security_policy
}

// ---------------------------------------------------------------------------------------------
// The property every origins preset has to have
// ---------------------------------------------------------------------------------------------

/// A preset only ever widens.
///
/// This is the one that matters for composition: a consumer applies a preset for a service they
/// added and must not discover that an unrelated directive stopped permitting what it did before.
/// Every source the base policy carried has to survive, in the same directive.
#[test]
fn no_preset_takes_anything_away() {
    let base = Csp::spa_wasm();

    for (name, preset) in ORIGINS_PRESETS {
        let after = preset(base.clone());

        for directive in base.policy() {
            let found = after
                .policy()
                .into_iter()
                .find(|candidate| candidate.name() == directive.name())
                .unwrap_or_else(|| panic!("{name} dropped {}", directive.name().as_str()));

            match (directive.source_list(), found.source_list()) {
                (Some(before), Some(now)) => {
                    for source in before.sources() {
                        assert!(
                            now.contains(source),
                            "{name} dropped {source} from {}",
                            directive.name().as_str()
                        );
                    }
                }
                _ => assert_eq!(
                    directive,
                    found,
                    "{name} changed {}",
                    directive.name().as_str()
                ),
            }
        }
    }
}

/// A directive a preset creates inherits what the policy was falling back to, so creating it
/// permits everything it permitted a moment earlier plus the preset's own origins.
///
/// `spa_wasm` sets no `frame-src`, so a browser resolved frames through `default-src 'self'`.
/// Turnstile must not turn that into "Turnstile and nothing else".
#[test]
fn creating_a_directive_preserves_the_fallback_it_replaces() {
    let frames = sources_of(
        &cloudflare::turnstile(Csp::spa_wasm()),
        SourceDirective::FrameSrc,
    );
    assert_eq!(frames, ["'self'", "https://challenges.cloudflare.com"]);

    // `worker-src` is the case where losing the fallback would break the application outright:
    // a policy with `worker-src blob:` alone revokes every same-origin worker.
    let workers = sources_of(
        &sentry::session_replay(Csp::spa_wasm()),
        SourceDirective::WorkerSrc,
    );
    assert_eq!(workers, ["'self'", "blob:"]);
}

/// With no `default-src` there is no fallback to preserve, so the directive starts empty and
/// carries the preset's origins alone rather than a phantom `'self'`.
#[test]
fn a_preset_on_an_empty_policy_seeds_nothing() {
    assert_eq!(
        header(cloudflare::turnstile(Csp::new())),
        "script-src https://challenges.cloudflare.com; \
         frame-src https://challenges.cloudflare.com"
    );
}

/// Applying a preset twice permits exactly what applying it once permits. A repeated origin
/// lengthens every response without changing anything.
#[test]
fn every_preset_is_idempotent() {
    for (name, preset) in ORIGINS_PRESETS {
        let once = preset(Csp::spa_wasm());
        let twice = preset(preset(Csp::spa_wasm()));
        assert_eq!(pairs(&once), pairs(&twice), "{name} is not idempotent");
    }
}

// ---------------------------------------------------------------------------------------------
// Combining presets with each other
// ---------------------------------------------------------------------------------------------

/// The order presets are applied in changes the order of directives in the header and nothing
/// else. A consumer must not have to know that fonts go before Stripe.
#[test]
fn presets_compose_in_any_order() {
    let forwards = stripe::checkout(google::fonts(google::analytics(cloudflare::turnstile(
        Csp::spa_wasm(),
    ))));
    let backwards = cloudflare::turnstile(google::analytics(google::fonts(stripe::checkout(
        Csp::spa_wasm(),
    ))));

    assert_eq!(pairs(&forwards), pairs(&backwards));
}

/// Presets that touch the same directive accumulate in it rather than replacing one another.
///
/// Four services want `script-src` here and three want `frame-src`; every one of them has to be
/// in the rendered list, alongside what `spa_wasm` put there.
#[test]
fn presets_sharing_a_directive_accumulate() {
    let csp = stripe::checkout(google::recaptcha(google::tag_manager(
        cloudflare::turnstile(Csp::spa_wasm()),
    )));

    let scripts = sources_of(&csp, SourceDirective::ScriptSrc);
    for expected in [
        "'self'",
        "'wasm-unsafe-eval'",
        "https://challenges.cloudflare.com",
        "https://www.googletagmanager.com",
        "https://www.google.com/recaptcha/",
        "https://www.gstatic.com/recaptcha/",
        "https://js.stripe.com",
    ] {
        assert!(
            scripts.contains(&expected.to_string()),
            "script-src lost {expected}"
        );
    }

    let frames = sources_of(&csp, SourceDirective::FrameSrc);
    for expected in [
        "'self'",
        "https://challenges.cloudflare.com",
        "https://www.google.com/recaptcha/",
        "https://js.stripe.com",
        "https://hooks.stripe.com",
        "https://checkout.stripe.com",
    ] {
        assert!(
            frames.contains(&expected.to_string()),
            "frame-src lost {expected}"
        );
    }
}

/// Two presets naming the same origin — Tag Manager's host is also GA4's script host — admit it
/// once. The header is a per-response cost, and a duplicate source expression is pure weight.
#[test]
fn an_origin_two_presets_share_is_admitted_once() {
    let csp = google::analytics(google::tag_manager(Csp::spa_wasm()));
    let repeats = sources_of(&csp, SourceDirective::ScriptSrc)
        .iter()
        .filter(|source| *source == "https://www.googletagmanager.com")
        .count();
    assert_eq!(repeats, 1);
}

/// `stripe::checkout` is `stripe::elements` plus a frame host, and calling both is not an error.
#[test]
fn checkout_subsumes_elements() {
    let both = stripe::elements(stripe::checkout(Csp::spa_wasm()));
    let checkout_only = stripe::checkout(Csp::spa_wasm());
    assert_eq!(pairs(&both), pairs(&checkout_only));
}

/// The parameterised presets compose with the fixed ones, and their origin lands in the
/// directives the service actually uses rather than in `script-src` by default.
#[test]
fn parameterised_presets_compose_with_the_rest() {
    let csp = sentry::ingest(
        matomo::instance(
            google::fonts(Csp::spa_wasm()),
            "https://analytics.example.com",
        )
        .expect("a literal origin parses"),
        "https://o1.ingest.us.sentry.io",
    )
    .expect("a literal origin parses");

    assert!(sources_of(&csp, SourceDirective::ConnectSrc)
        .contains(&"https://o1.ingest.us.sentry.io".to_string()));
    assert!(sources_of(&csp, SourceDirective::ScriptSrc)
        .contains(&"https://analytics.example.com".to_string()));
    // Sentry's ingest origin is reached by `fetch` and belongs nowhere else.
    assert!(!sources_of(&csp, SourceDirective::ScriptSrc)
        .contains(&"https://o1.ingest.us.sentry.io".to_string()));
    assert!(sources_of(&csp, SourceDirective::FontSrc)
        .contains(&"https://fonts.gstatic.com".to_string()));
}

/// An origin that does not parse is refused at the call, not rendered into the header. This is
/// the header injection the typed vocabulary exists to make unreachable, arriving by the one
/// route a preset still accepts a string.
#[test]
fn a_parameterised_preset_refuses_an_unparseable_origin() {
    assert!(sentry::ingest(Csp::spa_wasm(), "https://evil.example; script-src *").is_err());
    assert!(matomo::instance(Csp::spa_wasm(), "https://evil.example; script-src *").is_err());
    assert!(plausible::self_hosted(Csp::spa_wasm(), "not a host source at all").is_err());
    assert!(fathom::custom_domain(Csp::spa_wasm(), "https://evil.example; img-src *").is_err());
}

/// No preset touches `frame-ancestors`, which governs who may frame *this* page rather than what
/// this page may frame. Confusing the two is the most common way a policy is accidentally opened.
#[test]
fn no_preset_touches_frame_ancestors() {
    for (name, preset) in ORIGINS_PRESETS {
        assert!(
            header(preset(Csp::spa_wasm())).contains("frame-ancestors 'none'"),
            "{name} disturbed frame-ancestors"
        );
    }
}

/// No preset reaches the three routed source expressions. <!-- csp-lint: allow — an assertion that a token is absent has to name the token -->
///
/// They are routed to named methods precisely so they cannot arrive as data, and a preset is data
/// a consumer accepts without reading. The builder's own routing check does not cover this: a
/// preset appends through the crate-internal path, which trusts its caller.
#[test]
fn no_preset_smuggles_in_a_routed_source_expression() {
    const ROUTED: [&str; 3] = ["'unsafe-eval'", "'unsafe-inline'", "'strict-dynamic'"]; // csp-lint: allow — an assertion that a token is absent has to name the token

    for (name, preset) in ORIGINS_PRESETS {
        let scripts = sources_of(&preset(Csp::new()), SourceDirective::ScriptSrc);
        for forbidden in ROUTED {
            assert!(
                !scripts.contains(&forbidden.to_string()),
                "{name} added {forbidden}"
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Combining presets with the shell scan
// ---------------------------------------------------------------------------------------------

/// Hashes and preset origins live in the same directive and neither displaces the other — under
/// CSP3 a script runs if it matches *any* source expression, which is what makes this safe.
#[test]
fn presets_and_the_scan_combine_in_either_order() {
    let scan = scan_shell("<script>window.__theme = 'dark';</script>");

    let scan_first = stripe::elements(google::tag_manager(Csp::spa_wasm().with_scan(&scan)));
    let preset_first = stripe::elements(google::tag_manager(Csp::spa_wasm())).with_scan(&scan);

    assert_eq!(pairs(&scan_first), pairs(&preset_first));

    let scripts = sources_of(&scan_first, SourceDirective::ScriptSrc);
    assert!(scripts.contains(&scan.hashes[0].to_string()));
    assert!(scripts.contains(&"https://www.googletagmanager.com".to_string()));
    assert!(scripts.contains(&"https://js.stripe.com".to_string()));
}

/// A shell with several inline scripts keeps every hash once presets are layered on.
#[test]
fn every_hash_survives_a_stack_of_presets() {
    let scan = scan_shell("<script>a()</script><script>b()</script><script>c()</script>");
    assert_eq!(scan.hashes.len(), 3);

    let csp = google::recaptcha(google::analytics(cloudflare::turnstile(
        Csp::spa_wasm().with_scan(&scan),
    )));
    let scripts = sources_of(&csp, SourceDirective::ScriptSrc);

    for hash in &scan.hashes {
        assert!(scripts.contains(&hash.to_string()), "lost {hash}");
    }
}

/// A preset applied before the policy has any `script-src` still finds one afterwards, because
/// `with_scan` extends the directive the preset created rather than replacing it.
#[test]
fn a_preset_before_the_scan_does_not_swallow_the_hashes() {
    let scan = scan_shell("<script>alert(1)</script>");
    let header = header(google::tag_manager(Csp::new()).with_scan(&scan));

    assert!(header.contains("https://www.googletagmanager.com"));
    assert!(header.contains(&scan.hashes[0].to_string()));
}

// ---------------------------------------------------------------------------------------------
// The nonce presets
// ---------------------------------------------------------------------------------------------

/// The text `Policy::headers` splices a nonce in behind.
#[cfg(feature = "nonce")]
const SPLICE: &str = " 'nonce-";

/// The concession is the nonce; nothing else moves. Cloudflare reads the response header and
/// copies the nonce onto what it injects, so nothing is stamped into the shell either.
#[cfg(feature = "nonce")]
#[test]
fn script_nonce_reserves_a_slot_and_nothing_else() {
    let with = cloudflare::script_nonce(Csp::spa_wasm()).build();
    let without = Csp::spa_wasm().build();

    assert!(with.is_per_response());
    assert_eq!(with.headers().cache_control, Some("no-cache"));

    let with_header = with.headers().content_security_policy;
    let start = with_header.find(SPLICE).expect("a nonce is spliced in");
    let closing_quote = start
        + SPLICE.len()
        + with_header[start + SPLICE.len()..]
            .find('\'')
            .expect("the nonce is quoted");
    let mut stripped = with_header.clone();
    stripped.replace_range(start..=closing_quote, "");
    assert_eq!(stripped, without.headers().content_security_policy);
}

/// The shell's own inline scripts keep running by hash alongside the nonce — the coexistence that
/// makes the concession narrow rather than a return to `'unsafe-inline'`.
#[cfg(feature = "nonce")]
#[test]
fn the_shells_hashes_survive_the_concession() {
    let scan = scan_shell("<script>alert(1)</script>");
    let header = cloudflare::script_nonce(Csp::spa_wasm().with_scan(&scan))
        .build()
        .headers()
        .content_security_policy;

    assert!(header.contains(&scan.hashes[0].to_string()));
    assert!(header.contains("'nonce-"));
}

/// The nonce is spliced after every source `script-src` ended up with, whichever preset supplied
/// them and whenever the slot was reserved. Reserving it first must not strand it before the
/// origins that arrive later.
#[cfg(feature = "nonce")]
#[test]
fn the_nonce_lands_after_every_preset_origin_whenever_it_was_reserved() {
    let scan = scan_shell("<script>alert(1)</script>");

    let reserved_first = stripe::elements(
        google::tag_manager(cloudflare::script_nonce(Csp::spa_wasm())).with_scan(&scan),
    );
    let reserved_last = cloudflare::script_nonce(
        stripe::elements(google::tag_manager(Csp::spa_wasm())).with_scan(&scan),
    );

    for csp in [reserved_first, reserved_last] {
        let header = csp.build().headers().content_security_policy;
        let nonce_at = header.find(SPLICE).expect("a nonce is spliced in");
        for origin in [
            "https://www.googletagmanager.com",
            "https://js.stripe.com",
            &scan.hashes[0].to_string(),
        ] {
            let origin_at = header.find(origin).expect("the origin is admitted");
            assert!(origin_at < nonce_at, "{origin} rendered after the nonce");
        }
        // `frame-src` follows `script-src`, so the splice must not have landed in it.
        assert!(header[..nonce_at].contains("script-src"));
        assert!(!header[..nonce_at].contains("frame-src"));
    }
}

/// Tag Manager reads the nonce off its own loader element rather than out of the header, so the
/// value has to be reachable from the response. It is the same value the header carries.
#[cfg(feature = "nonce")]
#[test]
fn the_minted_nonce_is_handed_back_for_stamping() {
    let policy = google::tag_manager_nonce(google::tag_manager(Csp::spa_wasm())).build();
    let headers = policy.headers();

    let nonce = headers.nonce.as_ref().expect("a slot is reserved");
    assert!(headers
        .content_security_policy
        .contains(&format!("'nonce-{}'", nonce.as_str())));

    // Per response, not per policy: two renders of one policy must not share a nonce.
    let second = policy.headers();
    assert_ne!(headers.nonce, second.nonce);
}

/// A policy with no slot reserved hands back no nonce, so a consumer stamping the field
/// unconditionally writes nothing rather than a stale value.
#[cfg(feature = "nonce")]
#[test]
fn a_constant_policy_mints_no_nonce() {
    let headers = stripe::elements(Csp::spa_wasm()).build().headers();
    assert!(headers.nonce.is_none());
    assert!(headers.cache_control.is_none());
}

/// The two kinds of preset compose: origins from four services, a nonce slot, and the shell's
/// hashes, in one policy.
#[cfg(feature = "nonce")]
#[test]
fn the_whole_stack_composes() {
    let scan = scan_shell("<script>window.dataLayer = [];</script>");
    let csp = cloudflare::script_nonce(google::fonts(google::analytics(stripe::checkout(
        cloudflare::turnstile(Csp::spa_wasm().with_scan(&scan)),
    ))));

    let policy = csp.build();
    assert!(policy.is_per_response());

    let headers = policy.headers();
    assert_eq!(headers.cache_control, Some("no-cache"));
    assert!(headers.nonce.is_some());

    let header = headers.content_security_policy;
    for expected in [
        "https://challenges.cloudflare.com",
        "https://js.stripe.com",
        "https://checkout.stripe.com",
        "https://www.googletagmanager.com",
        "https://fonts.googleapis.com",
        "https://fonts.gstatic.com",
        "'nonce-",
    ] {
        assert!(header.contains(expected), "the stack lost {expected}");
    }
    assert!(header.contains(&scan.hashes[0].to_string()));
    assert!(header.contains("frame-ancestors 'none'"));
    assert!(header.contains("base-uri 'none'"));
    assert!(header.contains("object-src 'none'"));
}
