//! The policy builder and the rendered policy.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::CspError;
use crate::scan::ScanResult;
use crate::util::push_unique;
use crate::validate::{canonical_directive_name, validate_source};

/// `script-src`, referenced often enough to be worth naming once.
const SCRIPT_SRC: &str = "script-src";

/// One directive: a canonical (lowercase) name and its source expressions, in the order they were
/// added.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Directive {
    name: String,
    sources: Vec<String>,
}

/// A Content-Security-Policy under construction. Directives, not a string.
///
/// Nothing reaches the rendered header without passing source-expression validation, which is the
/// whole reason the builder holds directives rather than a `String` the caller appends to.
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
    directives: Vec<Directive>,
    #[cfg(feature = "nonce")]
    per_response_nonce: bool,
}

impl Csp {
    /// Empty. Every directive is opt-in.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The policy this crate was extracted from: `default-src 'self'`,
    /// `script-src 'self' 'wasm-unsafe-eval'`, `style-src 'self' 'unsafe-inline'`,
    /// `connect-src 'self'`, `img-src 'self' https: data:`, `font-src 'self' data:`,
    /// `object-src 'none'`, `base-uri 'none'`, `form-action 'self'`,
    /// `frame-ancestors 'none'`.
    ///
    /// Note the absence of `'unsafe-eval'`: WASM compilation under this policy requires <!-- csp-lint: allow — an exclusion cannot be documented without naming what is excluded -->
    /// Chrome 97+, Firefox 102+ or Safari 16.4+. A deliberate exclusion, asserted by a unit test.
    ///
    /// Infallible because every source expression here is a literal that validation accepts;
    /// the `debug_assert!`s in the body hold that claim to account rather than leaving it to
    /// review.
    #[must_use]
    pub fn spa_wasm() -> Self {
        const DIRECTIVES: &[(&str, &[&str])] = &[
            ("default-src", &["'self'"]),
            (SCRIPT_SRC, &["'self'", "'wasm-unsafe-eval'"]),
            ("style-src", &["'self'", "'unsafe-inline'"]),
            ("connect-src", &["'self'"]),
            ("img-src", &["'self'", "https:", "data:"]),
            ("font-src", &["'self'", "data:"]),
            ("object-src", &["'none'"]),
            ("base-uri", &["'none'"]),
            ("form-action", &["'self'"]),
            ("frame-ancestors", &["'none'"]),
        ];

        let mut csp = Self::new();
        for (name, sources) in DIRECTIVES {
            debug_assert!(
                canonical_directive_name(name).is_ok(),
                "spa_wasm directive name must pass validation: {name}"
            );
            debug_assert!(
                sources.iter().all(|s| validate_source(name, s).is_ok()),
                "spa_wasm sources must pass validation: {name}"
            );
            csp.directives.push(Directive {
                name: (*name).to_string(),
                sources: sources.iter().map(|s| (*s).to_string()).collect(),
            });
        }
        csp
    }

    /// Set a directive, replacing any existing one of the same name.
    ///
    /// The replacement keeps the original directive's position, so a policy's order is the order
    /// its directives were first introduced.
    ///
    /// # Errors
    ///
    /// Rejects invalid directive names and source expressions. Duplicates are replaced
    /// rather than appended, because a repeated directive is ignored by the browser with only
    /// a console warning.
    ///
    /// [`CspError::UnknownDirective`] is returned for a well-formed but unrecognised name **in
    /// debug builds only**: a browser silently ignores a directive it cannot parse, so a typo is
    /// a missing restriction worth failing a test run over — and not worth breaking a running
    /// deployment over when the crate's table is merely older than the specification.
    ///
    /// # Examples
    ///
    /// ```
    /// use csp_shell::Csp;
    ///
    /// let csp = Csp::new()
    ///     .directive("connect-src", ["'self'", "https://api.example.com"])
    ///     .unwrap();
    /// assert_eq!(
    ///     csp.build().headers().content_security_policy,
    ///     "connect-src 'self' https://api.example.com"
    /// );
    /// ```
    ///
    /// A header injection through a config-derived origin, refused:
    ///
    /// ```
    /// # use csp_shell::Csp;
    /// assert!(Csp::new()
    ///     .directive("img-src", ["https://evil.example; script-src *"])
    ///     .is_err());
    /// ```
    pub fn directive<I, S>(mut self, name: &str, sources: I) -> Result<Self, CspError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let name = canonical_directive_name(name)?;
        let sources = validated(&name, sources)?;

        match self.position(&name) {
            Some(index) => self.directives[index].sources = sources,
            None => self.directives.push(Directive { name, sources }),
        }
        Ok(self)
    }

    /// Append source expressions to an existing directive, creating it if absent.
    ///
    /// Sources already present are not appended twice; a repeated source expression lengthens
    /// every response without changing what the policy permits.
    ///
    /// # Errors
    ///
    /// The same rejections as [`Csp::directive`].
    pub fn extend<I, S>(mut self, name: &str, sources: I) -> Result<Self, CspError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let name = canonical_directive_name(name)?;
        let sources = validated(&name, sources)?;

        let index = if let Some(index) = self.position(&name) {
            index
        } else {
            self.directives.push(Directive {
                name,
                sources: Vec::new(),
            });
            self.directives.len() - 1
        };
        for source in sources {
            push_unique(&mut self.directives[index].sources, source);
        }
        Ok(self)
    }

    /// Add the shell's inline-script hashes to `script-src`.
    ///
    /// `script-src` is created if absent, seeded from `default-src` — see
    /// [`Csp::per_response_nonce`] for why that seeding is a no-op rather than a policy change.
    ///
    /// Adding a hash does not disable `'self'` or any other host source; under CSP a script runs
    /// if it matches *any* source expression. It does disable `'unsafe-inline'`, which is the
    /// point.
    #[must_use]
    pub fn with_scan(mut self, scan: &ScanResult) -> Self {
        let index = self.ensure_script_src();
        for hash in &scan.hashes {
            push_unique(&mut self.directives[index].sources, hash.clone());
        }
        self
    }

    /// Admit `'unsafe-eval'` in `script-src`. Needed for WASM compilation on Safari before 16.4, <!-- csp-lint: allow — the method exists to be the one named token for this source expression -->
    /// and nowhere else.
    ///
    /// Deliberately a named method rather than a source expression [`Csp::directive`] would
    /// accept: it gives a consumer's own lint a token to match that cannot be assembled from
    /// string fragments.
    #[must_use]
    pub fn allow_unsafe_eval(mut self) -> Self {
        let index = self.ensure_script_src();
        let source = "'unsafe-eval'".to_string(); // csp-lint: allow — the single construction site of the token this crate routes
        push_unique(&mut self.directives[index].sources, source);
        self
    }

    /// Admit `'unsafe-inline'` in `script-src`. A no-op wherever hashes or a nonce are
    /// present, which is everywhere this crate is useful.
    ///
    /// Do not reach for this as a compatibility fallback: any browser that understands hashes or
    /// nonces ignores it, and any browser that does not is outside `'wasm-unsafe-eval'`'s support
    /// floor anyway.
    #[must_use]
    pub fn allow_unsafe_inline_script(mut self) -> Self {
        let index = self.ensure_script_src();
        push_unique(
            &mut self.directives[index].sources,
            "'unsafe-inline'".to_string(),
        );
        self
    }

    /// Add `'strict-dynamic'` to `script-src`, which disables host source expressions for
    /// scripts. `'self'` stops matching `<script src>` in the shell.
    ///
    /// A named method for a different reason than the other two: a policy acquires
    /// `'strict-dynamic'` by accident far more easily than it acquires the others, and what it
    /// disables is invisible in the header that carries it.
    #[must_use]
    pub fn strict_dynamic(mut self) -> Self {
        let index = self.ensure_script_src();
        push_unique(
            &mut self.directives[index].sources,
            "'strict-dynamic'".to_string(),
        );
        self
    }

    /// Reserve a per-response nonce slot in `script-src`. See
    /// [`cloudflare::script_nonce`](crate::cloudflare::script_nonce).
    ///
    /// The nonce itself is minted by [`Policy::headers`], once per response. Reserving the slot
    /// creates `script-src` if it is absent, seeded from `default-src`'s sources: a browser
    /// already falls back to `default-src` for scripts, so an explicit `script-src` carrying the
    /// same sources permits exactly what the policy permitted before, plus the nonce. Without the
    /// seeding the nonce would either tighten the policy silently or be dropped silently, and
    /// both of those are this crate's own failure mode.
    #[cfg(feature = "nonce")]
    #[cfg_attr(docsrs, doc(cfg(feature = "nonce")))]
    #[must_use]
    pub fn per_response_nonce(mut self, enabled: bool) -> Self {
        self.per_response_nonce = enabled;
        if enabled {
            self.ensure_script_src();
        }
        self
    }

    /// Render the policy.
    ///
    /// Infallible: source-expression validation is what makes the rendered string ASCII, free of
    /// any `;` the builder did not emit itself, and a valid HTTP field value by construction.
    #[must_use]
    pub fn build(self) -> Policy {
        let mut text = String::new();
        #[cfg(feature = "nonce")]
        let mut nonce_slot = None;

        for (index, directive) in self.directives.iter().enumerate() {
            if index > 0 {
                text.push_str("; ");
            }
            text.push_str(&directive.name);
            for source in &directive.sources {
                text.push(' ');
                text.push_str(source);
            }

            #[cfg(feature = "nonce")]
            if self.per_response_nonce && directive.name == SCRIPT_SRC {
                // Everything through the last `script-src` source is the head; everything from
                // here on is the tail. Splicing at one index is simpler to verify than rebuilding
                // the policy per response, and a round-trip test asserts that a spliced policy
                // equals the policy built with that nonce as a literal source.
                nonce_slot = Some(text.len());
            }
        }

        Policy {
            text,
            #[cfg(feature = "nonce")]
            nonce_slot,
        }
    }

    /// Index of `script-src`, creating it from `default-src`'s sources if it is absent.
    fn ensure_script_src(&mut self) -> usize {
        if let Some(index) = self.position(SCRIPT_SRC) {
            return index;
        }
        let inherited = self
            .position("default-src")
            .map(|index| self.directives[index].sources.clone())
            .unwrap_or_default();
        self.directives.push(Directive {
            name: SCRIPT_SRC.to_string(),
            sources: inherited,
        });
        self.directives.len() - 1
    }

    /// Index of the directive with this canonical name.
    fn position(&self, name: &str) -> Option<usize> {
        self.directives
            .iter()
            .position(|directive| directive.name == name)
    }
}

/// Validate every source expression before any of them is stored, so a rejected list leaves the
/// builder untouched rather than half-applied.
fn validated<I, S>(directive: &str, sources: I) -> Result<Vec<String>, CspError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let iter = sources.into_iter();
    let mut accepted = Vec::with_capacity(iter.size_hint().0);
    for source in iter {
        let source = source.as_ref();
        validate_source(directive, source)?;
        push_unique(&mut accepted, source.to_string());
    }
    Ok(accepted)
}

/// A rendered Content-Security-Policy.
///
/// Build it once at startup. If [`Policy::is_per_response`] is false the header is constant and
/// [`Policy::headers`] may be called once and its result reused; if it is true, call it per
/// response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// The policy, complete except for the nonce source expression.
    text: String,
    /// Byte offset in `text` at which a `'nonce-…'` source is spliced into `script-src`.
    #[cfg(feature = "nonce")]
    nonce_slot: Option<usize>,
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
}

impl Policy {
    /// Render for one response, minting a nonce if a slot is reserved.
    ///
    /// # Panics
    ///
    /// Only through [`Nonce::mint`](crate::Nonce::mint), and only if the operating system's
    /// CSPRNG is unavailable — a condition under which continuing would mean serving a guessable
    /// nonce.
    #[must_use]
    pub fn headers(&self) -> Headers {
        #[cfg(feature = "nonce")]
        if let Some(slot) = self.nonce_slot {
            let nonce = crate::Nonce::mint();
            let nonce = nonce.as_str();
            let mut policy = String::with_capacity(self.text.len() + nonce.len() + 10);
            policy.push_str(&self.text[..slot]);
            policy.push_str(" 'nonce-");
            policy.push_str(nonce);
            policy.push('\'');
            policy.push_str(&self.text[slot..]);
            return Headers {
                content_security_policy: policy,
                cache_control: Some("no-cache"),
            };
        }

        Headers {
            content_security_policy: self.text.clone(),
            cache_control: None,
        }
    }

    /// Whether [`Policy::headers`] differs between calls. False when no nonce slot is reserved, in
    /// which case the result can be computed once at startup and reused.
    #[must_use]
    pub fn is_per_response(&self) -> bool {
        #[cfg(feature = "nonce")]
        {
            self.nonce_slot.is_some()
        }
        #[cfg(not(feature = "nonce"))]
        {
            false
        }
    }
}
