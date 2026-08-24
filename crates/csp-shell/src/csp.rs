//! The policy builder and the rendered policy.

use alloc::string::String;
use alloc::vec::Vec;

use csp_policy::{
    AncestorSourceList, Directive, DirectiveName, Policy as TypedPolicy, Source, SourceDirective,
    SourceList,
};

use crate::error::CspError;
use crate::scan::ScanResult;

/// A Content-Security-Policy under construction, with the shell's inline scripts folded in.
///
/// A thin layer over [`csp_policy::Policy`]: everything about *what a policy can say* lives in
/// that crate, and what lives here is the part that depends on the document being served — the
/// hashes, the per-response nonce, and the two or three source expressions worth naming rather
/// than passing as data.
///
/// # Examples
///
/// ```
/// use csp_shell::{scan_shell, Csp};
///
/// let scan = scan_shell("<script>window.__theme = 'dark';</script>");
/// let policy = Csp::spa_wasm().with_scan(&scan).build();
///
/// let headers = policy.headers();
/// assert!(headers.content_security_policy.contains("'sha256-"));
/// assert_eq!(headers.cache_control, None);
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Csp {
    policy: TypedPolicy,
    #[cfg(feature = "nonce")]
    per_response_nonce: bool,
}

impl Csp {
    /// Empty. Every directive is opt-in.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The policy this crate was extracted from: a WASM single-page application on one origin.
    ///
    /// `default-src 'self'`, `script-src 'self' 'wasm-unsafe-eval'`,
    /// `style-src 'self' 'unsafe-inline'`, `connect-src 'self'`, `img-src 'self' https: data:`,
    /// `font-src 'self' data:`, `object-src 'none'`, `base-uri 'none'`, `form-action 'self'`,
    /// `frame-ancestors 'none'`.
    ///
    /// `'unsafe-eval'` is absent, so WASM compilation needs Chrome 97+, Firefox 102+ or <!-- csp-lint: allow — an exclusion cannot be documented without naming what is excluded -->
    /// Safari 16.4+. A deliberate exclusion, asserted by a unit test.
    #[must_use]
    pub fn spa_wasm() -> Self {
        use SourceDirective::{
            BaseUri, ConnectSrc, DefaultSrc, FontSrc, FormAction, ImgSrc, ObjectSrc, ScriptSrc,
            StyleSrc,
        };

        let https = Source::Scheme(csp_policy::Scheme::Https);
        let data = Source::Scheme(csp_policy::Scheme::Data);

        Self {
            policy: TypedPolicy::new()
                .with(Directive::sources(DefaultSrc, [Source::SelfOrigin]))
                .with(Directive::sources(
                    ScriptSrc,
                    [Source::SelfOrigin, Source::WasmUnsafeEval],
                ))
                .with(Directive::sources(
                    StyleSrc,
                    [Source::SelfOrigin, Source::UnsafeInline],
                ))
                .with(Directive::sources(ConnectSrc, [Source::SelfOrigin]))
                .with(Directive::sources(
                    ImgSrc,
                    [Source::SelfOrigin, https, data.clone()],
                ))
                .with(Directive::sources(FontSrc, [Source::SelfOrigin, data]))
                .with(Directive::sources(ObjectSrc, SourceList::None))
                .with(Directive::sources(BaseUri, SourceList::None))
                .with(Directive::sources(FormAction, [Source::SelfOrigin]))
                .with(Directive::FrameAncestors(AncestorSourceList::None)),
            #[cfg(feature = "nonce")]
            per_response_nonce: false,
        }
    }

    /// Sets a source-list directive, replacing any existing one of the same name.
    ///
    /// The replacement keeps the original directive's position, so a policy's order is the order
    /// its directives were first introduced.
    ///
    /// # Errors
    ///
    /// [`CspError::RoutedSourceExpression`] for the three source expressions that have a named
    /// method. Nothing else can fail: a [`Source`] that exists is a source expression that
    /// renders, and there is no directive name outside [`SourceDirective`].
    ///
    /// # Examples
    ///
    /// ```
    /// use csp_shell::{Csp, Source, SourceDirective};
    ///
    /// let csp = Csp::new().directive(
    ///     SourceDirective::ConnectSrc,
    ///     [Source::SelfOrigin, Source::host("https://api.example.com")?],
    /// )?;
    /// assert_eq!(
    ///     csp.build().headers().content_security_policy,
    ///     "connect-src 'self' https://api.example.com"
    /// );
    /// # Ok::<(), Box<dyn core::error::Error>>(())
    /// ```
    ///
    /// A header injection through a config-derived origin never reaches this method: the origin
    /// fails to parse into a [`Source`] at all.
    ///
    /// ```
    /// # use csp_shell::Source;
    /// assert!(Source::host("https://evil.example; script-src *").is_err());
    /// ```
    pub fn directive(
        mut self,
        directive: SourceDirective,
        sources: impl Into<SourceList>,
    ) -> Result<Self, CspError> {
        let sources = sources.into();
        check_routing(directive, sources.sources())?;
        self.policy.set(Directive::Sources(directive, sources));
        Ok(self)
    }

    /// Appends source expressions to a directive, creating it if absent.
    ///
    /// Sources already present are not appended twice; a repeated source expression lengthens
    /// every response without changing what the policy permits.
    ///
    /// # Errors
    ///
    /// The same refusal as [`Csp::directive`], and it is checked before anything is stored, so a
    /// rejected call leaves the builder untouched rather than half-applied.
    pub fn extend<I>(mut self, directive: SourceDirective, sources: I) -> Result<Self, CspError>
    where
        I: IntoIterator<Item = Source>,
    {
        let sources: SourceList = SourceList::of(sources);
        check_routing(directive, sources.sources())?;
        self.policy
            .extend_sources(directive, sources.into_sources());
        Ok(self)
    }

    /// Sets any directive, including the ones whose value is not a source list — `sandbox`,
    /// `webrtc`, `trusted-types`, the reporting directives.
    ///
    /// # Errors
    ///
    /// The same refusal as [`Csp::directive`], which applies only to source-list directives.
    ///
    /// # Examples
    ///
    /// ```
    /// use csp_shell::{Csp, Directive, SandboxToken, TrustedTypeSink};
    ///
    /// let csp = Csp::spa_wasm()
    ///     .set(Directive::sandbox([SandboxToken::AllowForms]))?
    ///     .set(Directive::require_trusted_types_for([TrustedTypeSink::Script]))?;
    /// assert!(csp
    ///     .build()
    ///     .headers()
    ///     .content_security_policy
    ///     .contains("sandbox allow-forms"));
    /// # Ok::<(), csp_shell::CspError>(())
    /// ```
    pub fn set(mut self, directive: Directive) -> Result<Self, CspError> {
        if let Directive::Sources(name, sources) = &directive {
            check_routing(*name, sources.sources())?;
        }
        self.policy.set(directive);
        Ok(self)
    }

    /// Removes a directive entirely, so the policy stops saying anything about it.
    ///
    /// Not the same as setting it to an empty list: `img-src 'none'` blocks every image, while an
    /// absent `img-src` falls back to `default-src`. Both are reachable, and confusing one for the
    /// other is the kind of silent difference this crate exists to keep visible — so removal is
    /// its own method rather than a special case of [`Csp::directive`].
    ///
    /// Unguarded, because removal can only loosen a policy and [`Csp::directive`] can already
    /// loosen one further than this does.
    ///
    /// # Examples
    ///
    /// ```
    /// use csp_shell::{Csp, DirectiveName};
    ///
    /// let policy = Csp::spa_wasm()
    ///     .remove(DirectiveName::FontSrc)
    ///     .build()
    ///     .headers()
    ///     .content_security_policy;
    /// assert!(!policy.contains("font-src"));
    /// ```
    #[must_use]
    pub fn remove(mut self, name: DirectiveName) -> Self {
        self.policy.remove(name);
        self
    }

    /// Removes one source expression from a directive, leaving the rest of the list alone.
    ///
    /// For tuning a preset without restating it: a list restated in full stops tracking the preset,
    /// so a source added by a later version of this crate is silently dropped. A directive this
    /// empties keeps its name and renders as `'none'`; use [`Csp::remove`] to drop it outright.
    ///
    /// Nothing to refuse here — a routed source expression that is already in the policy arrived
    /// through the method that names it, and taking it back out again needs no ceremony.
    ///
    /// # Examples
    ///
    /// ```
    /// use csp_shell::{Csp, Scheme, Source, SourceDirective};
    ///
    /// let policy = Csp::spa_wasm()
    ///     .remove_source(SourceDirective::ImgSrc, &Source::Scheme(Scheme::Data))
    ///     .build()
    ///     .headers()
    ///     .content_security_policy;
    /// assert!(policy.contains("img-src 'self' https:;"));
    /// ```
    #[must_use]
    pub fn remove_source(self, directive: SourceDirective, source: &Source) -> Self {
        self.retain_sources(directive, |existing| existing != source)
    }

    /// Keeps only the source expressions `keep` accepts, for a directive the policy already sets.
    ///
    /// The general form of [`Csp::remove_source`], for a rule rather than a value — dropping every
    /// scheme source, or every host outside one origin. A no-op if the directive is absent: there
    /// is no list to filter, and creating one to empty it would replace a `default-src` fallback
    /// with a flat refusal.
    #[must_use]
    pub fn retain_sources(
        mut self,
        directive: SourceDirective,
        keep: impl FnMut(&Source) -> bool,
    ) -> Self {
        if let Some(sources) = self.policy.source_list_mut(directive) {
            sources.retain(keep);
        }
        self
    }

    /// Returns the policy as it stands.
    #[must_use]
    pub const fn policy(&self) -> &TypedPolicy {
        &self.policy
    }

    /// Adds the shell's inline-script hashes to `script-src`.
    ///
    /// `script-src` is created if absent, seeded from the sources it was inheriting through
    /// `default-src`, so creating it permits what the policy permitted before plus the hashes.
    ///
    /// Adding a hash does not disable `'self'` or any other host source; under CSP a script runs
    /// if it matches *any* source expression. It does disable `'unsafe-inline'`, which is the
    /// point.
    #[must_use]
    pub fn with_scan(mut self, scan: &ScanResult) -> Self {
        self.ensure_script_src();
        self.policy.extend_sources(
            SourceDirective::ScriptSrc,
            scan.hashes.iter().cloned().map(Source::Hash),
        );
        self
    }

    /// Admits `'unsafe-eval'` in `script-src`. Needed for WASM compilation on Safari before 16.4, <!-- csp-lint: allow — the method exists to be the one named token for this source expression -->
    /// and nowhere else.
    ///
    /// Deliberately a named method rather than a source expression [`Csp::directive`] would
    /// accept: it gives a consumer's own lint a token to match that cannot be assembled from
    /// string fragments or read out of a configuration file.
    #[must_use]
    pub fn allow_unsafe_eval(self) -> Self {
        self.push_script_source(Source::UnsafeEval)
    }

    /// Admits `'unsafe-inline'` in `script-src`. A no-op wherever hashes or a nonce are
    /// present, which is everywhere this crate is useful.
    ///
    /// Do not reach for this as a compatibility fallback: any browser that understands hashes or
    /// nonces ignores it, and any browser that does not is outside `'wasm-unsafe-eval'`'s support
    /// floor anyway.
    #[must_use]
    pub fn allow_unsafe_inline_script(self) -> Self {
        self.push_script_source(Source::UnsafeInline)
    }

    /// Adds `'strict-dynamic'` to `script-src`, which disables host source expressions for
    /// scripts. `'self'` stops matching `<script src>` in the shell.
    ///
    /// A named method for a different reason than the other two: a policy acquires
    /// `'strict-dynamic'` by accident far more easily than it acquires the others, and what it
    /// disables is invisible in the header that carries it.
    #[must_use]
    pub fn strict_dynamic(self) -> Self {
        self.push_script_source(Source::StrictDynamic)
    }

    /// Reserves a per-response nonce slot in `script-src`.
    ///
    /// See the `presets` module for the services that need one, and for the difference between
    /// those that read the nonce out of the response header and those that need it stamped into
    /// the document as well.
    ///
    /// The nonce itself is minted by [`Policy::headers`], once per response. If the policy has no
    /// `script-src` by the time it is built, [`Csp::build`] creates one seeded from `default-src`'s
    /// sources: a browser already falls back to `default-src` for scripts, so an explicit
    /// `script-src` carrying the same sources permits exactly what the policy permitted before,
    /// plus the nonce. Without the seeding the nonce would either tighten the policy silently or
    /// be dropped silently, and both of those are this crate's own failure mode.
    ///
    /// The slot is order-independent: reserving it before `default-src` is set still seeds from
    /// the `default-src` that ends up in the policy.
    #[cfg(feature = "nonce")]
    #[cfg_attr(docsrs, doc(cfg(feature = "nonce")))]
    #[must_use]
    pub fn per_response_nonce(mut self, enabled: bool) -> Self {
        self.per_response_nonce = enabled;
        self
    }

    /// Renders the policy.
    ///
    /// Infallible: the rendered value is assembled from types that were checked when they were
    /// built, so it is ASCII, free of any `;` the builder did not emit itself, and a valid HTTP
    /// field value by construction.
    #[must_use]
    pub fn build(self) -> Policy {
        #[cfg(feature = "nonce")]
        if self.per_response_nonce {
            return Policy {
                rendered: self.split_around_script_src(),
            };
        }

        Policy {
            rendered: Rendered::Constant(self.policy.to_header_value()),
        }
    }

    /// Renders into the two halves a nonce is spliced between.
    ///
    /// Infallible, because it establishes what it needs: `script-src` is created here rather than
    /// only where the nonce slot is reserved, so the invariant does not depend on call order. A
    /// `remove(ScriptSrc)` after `per_response_nonce(true)` would otherwise drop the nonce with no
    /// diagnostic, which is this crate's own failure mode.
    #[cfg(feature = "nonce")]
    fn split_around_script_src(mut self) -> Rendered {
        self.ensure_script_src();
        let script_src = self
            .policy
            .iter()
            .position(|directive| directive.name() == DirectiveName::ScriptSrc)
            .expect("ensure_script_src has just created it");

        let mut head = String::new();
        let mut tail = String::new();
        for (index, directive) in self.policy.iter().enumerate() {
            let out = if index <= script_src {
                &mut head
            } else {
                &mut tail
            };
            if index > 0 {
                out.push_str("; ");
            }

            // A `script-src` with no other sources renders as a bare name: the nonce follows
            // immediately, and `'none'` beside a nonce is a list a browser reads as the nonce
            // alone. Spelling it out would state a restriction that is not in force.
            if index == script_src
                && directive
                    .source_list()
                    .is_some_and(SourceList::matches_nothing)
            {
                out.push_str(DirectiveName::ScriptSrc.as_str());
            } else {
                directive.render_into(out);
            }
        }

        Rendered::PerResponse { head, tail }
    }

    /// Appends source expressions supplied by this crate's own presets.
    ///
    /// Infallible where [`Csp::extend`] is not, because the sources come from literals in this
    /// crate rather than from a caller: none of them is a routed keyword, and the debug assertion
    /// holds that claim to account rather than leaving it as a comment.
    ///
    /// The directive is seeded from its fallback chain first, so a preset can only ever widen a
    /// policy — see [`Csp::ensure_seeded`].
    #[cfg(feature = "presets")]
    pub(crate) fn extend_unrouted(
        mut self,
        directive: SourceDirective,
        sources: impl IntoIterator<Item = Source>,
    ) -> Self {
        let sources: Vec<Source> = sources.into_iter().collect();
        debug_assert!(
            check_routing(directive, &sources).is_ok(),
            "a preset must not supply a source expression that has a dedicated method"
        );

        self.ensure_seeded(directive);
        self.policy.extend_sources(directive, sources);
        self
    }

    /// Adds one source to `script-src`, creating it from `default-src`'s sources if absent.
    fn push_script_source(mut self, source: Source) -> Self {
        self.ensure_script_src();
        self.policy
            .extend_sources(SourceDirective::ScriptSrc, [source]);
        self
    }

    /// Creates `script-src` from `default-src`'s sources if it is absent.
    fn ensure_script_src(&mut self) {
        self.ensure_seeded(SourceDirective::ScriptSrc);
    }

    /// Creates `directive` from whatever it was falling back to, if the policy does not set it.
    ///
    /// Appending to an absent directive would otherwise *narrow* the policy: before the append a
    /// browser resolved it through the fallback chain, and afterwards it does not. Seeding with
    /// the sources it was inheriting leaves what the policy permits unchanged, so the append can
    /// only widen. When nothing in the chain is set there is no fallback to preserve and the
    /// directive starts empty.
    fn ensure_seeded(&mut self, directive: SourceDirective) {
        if self.policy.contains(directive.name()) {
            return;
        }

        let inherited = fallback_chain(directive)
            .iter()
            .find_map(|fallback| self.policy.source_list(*fallback))
            .cloned()
            .unwrap_or_else(|| SourceList::Sources(Vec::new()));
        self.policy.set(Directive::Sources(directive, inherited));
    }
}

/// The directives an absent directive is resolved through, nearest first.
///
/// A browser walks this chain, so seeding a directive this crate is about to create has to walk
/// the same one: seeding `worker-src` from `default-src` while the policy sets `child-src` would
/// drop the sources that were actually in force.
///
/// `base-uri` and `form-action` have no fallback — absent, they are unrestricted rather than
/// inherited, so there is nothing to preserve and creating one is a tightening the caller asked
/// for. Every remaining fetch directive resolves to `default-src`.
const fn fallback_chain(directive: SourceDirective) -> &'static [SourceDirective] {
    use SourceDirective::{ChildSrc, DefaultSrc, ScriptSrc, StyleSrc};

    match directive {
        SourceDirective::DefaultSrc | SourceDirective::BaseUri | SourceDirective::FormAction => &[],
        SourceDirective::ScriptSrcAttr | SourceDirective::ScriptSrcElem => &[ScriptSrc, DefaultSrc],
        SourceDirective::StyleSrcAttr | SourceDirective::StyleSrcElem => &[StyleSrc, DefaultSrc],
        SourceDirective::FrameSrc | SourceDirective::WorkerSrc => &[ChildSrc, DefaultSrc],
        _ => &[DefaultSrc],
    }
}

/// Source expressions that have a dedicated builder method, and the method that produces them.
///
/// The third field restricts the routing to one directive; `None` routes in every directive.
/// `'unsafe-inline'` in `style-src` is untouched — `Csp::spa_wasm` sets it.
const ROUTED_SOURCES: &[(Source, &str, Option<SourceDirective>)] = &[
    (Source::UnsafeEval, "allow_unsafe_eval", None), // csp-lint: allow — routing the token is what closes the data path to it
    (
        Source::UnsafeInline,
        "allow_unsafe_inline_script",
        Some(SourceDirective::ScriptSrc),
    ),
    (
        Source::StrictDynamic,
        "strict_dynamic",
        Some(SourceDirective::ScriptSrc),
    ),
];

/// Refuses the routed source expressions before any of them is stored.
fn check_routing(directive: SourceDirective, sources: &[Source]) -> Result<(), CspError> {
    for (routed, method, only_in) in ROUTED_SOURCES {
        if let Some(only) = *only_in {
            if only != directive {
                continue;
            }
        }
        if sources.contains(routed) {
            return Err(CspError::RoutedSourceExpression {
                source: routed.clone(),
                method,
            });
        }
    }
    Ok(())
}

/// A rendered policy, in the form its per-response cost demands.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Rendered {
    /// The whole header value, identical for every response.
    Constant(String),
    /// The header value either side of the nonce source, which is spliced in per response.
    #[cfg(feature = "nonce")]
    PerResponse {
        /// Everything through the last `script-src` source.
        head: String,
        /// Everything after it, including the leading `; ` when there is more.
        tail: String,
    },
}

/// A rendered Content-Security-Policy.
///
/// Build it once at startup. If [`Policy::is_per_response`] is false the header is constant and
/// [`Policy::headers`] may be called once and its result reused; if it is true, call it per
/// response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    rendered: Rendered,
}

/// The response headers this policy requires. Both fields belong to one response.
///
/// A consumer that reads only `content_security_policy` is visibly ignoring a field, which is a
/// stronger reminder than a `tower::Layer` they might not mount — and it works on `axum`,
/// `actix`, `warp` or a bare `hyper` service.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Headers {
    /// `Content-Security-Policy`.
    pub content_security_policy: String,

    /// `Cache-Control`, when the policy obliges one. `Some("no-cache")` for a per-response
    /// policy: without it the minted nonce is shared by every reader served from cache,
    /// which admits exactly the inline script the nonce exists to constrain.
    pub cache_control: Option<&'static str>,

    /// The nonce minted for this response, when a slot is reserved. `None` otherwise.
    ///
    /// Already spliced into `content_security_policy`; this is the same value, handed back for the
    /// services that do not read it out of the header. Cloudflare does read the header and needs
    /// nothing from this field. Google Tag Manager reads the nonce off *its own loader element*,
    /// so a shell using it must carry the same value on that `<script>` — as must any SSR template
    /// whose inline script is generated rather than hashed.
    ///
    /// Stamping a `nonce` attribute does not change a script's text, so the hashes
    /// [`Csp::with_scan`] computed remain valid alongside it.
    #[cfg(feature = "nonce")]
    #[cfg_attr(docsrs, doc(cfg(feature = "nonce")))]
    pub nonce: Option<crate::Nonce>,
}

impl Policy {
    /// Renders for one response, minting a nonce if a slot is reserved.
    #[cfg_attr(
        feature = "nonce",
        doc = r"
# Panics

Only through [`Nonce::mint`](crate::Nonce::mint), and only if the operating system's CSPRNG is
unavailable — a condition under which continuing would mean serving a guessable nonce.
"
    )]
    #[must_use]
    pub fn headers(&self) -> Headers {
        match &self.rendered {
            Rendered::Constant(text) => Headers {
                content_security_policy: text.clone(),
                cache_control: None,
                #[cfg(feature = "nonce")]
                nonce: None,
            },
            #[cfg(feature = "nonce")]
            Rendered::PerResponse { head, tail } => {
                use core::fmt::Write as _;

                let nonce = crate::Nonce::mint();
                let mut policy = String::with_capacity(head.len() + tail.len() + 34);
                policy.push_str(head);
                policy.push(' ');
                // The nonce renders through the same type as every other source expression, so
                // there is one implementation of what a `'nonce-…'` looks like rather than two.
                let _ = write!(policy, "{}", nonce.as_source());
                policy.push_str(tail);

                Headers {
                    content_security_policy: policy,
                    cache_control: Some("no-cache"),
                    nonce: Some(nonce),
                }
            }
        }
    }

    /// Whether [`Policy::headers`] differs between calls. False when no nonce slot is reserved, in
    /// which case the result can be computed once at startup and reused.
    #[must_use]
    pub fn is_per_response(&self) -> bool {
        match &self.rendered {
            Rendered::Constant(_) => false,
            #[cfg(feature = "nonce")]
            Rendered::PerResponse { .. } => true,
        }
    }
}
