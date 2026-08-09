<!--
Generated from .github/templates/csp-shell.README.md.hbs — edit that file, not this one. CI
renders it on every pull request and commits the result back to the branch; a push to main whose
README.md does not match its template fails the `readme` check in .github/workflows/docs.yml.

Variables come from .github/scripts/readme-variables.sh, which reads the manifests:

    msrv            the workspace rust-version, e.g. 1.85.0
    shell_version   this crate's [package] version, e.g. 0.1.0
    shell_tag       the tag that release carries, e.g. csp-shell-v0.1.0

That is what keeps the install snippets and the MSRV badge correct across a release: the release
pull request is the commit that changes those numbers, so it arrives with the rendered README
already updated.
-->
# csp-shell

[![CI](https://github.com/TimSchoenle/csp-shell/actions/workflows/ci.yml/badge.svg)](https://github.com/TimSchoenle/csp-shell/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-0.1.0-blue)](https://github.com/TimSchoenle/csp-shell/releases/tag/csp-shell-v0.1.0)
[![MSRV](https://img.shields.io/badge/MSRV-1.85.0-blue)](../../Cargo.toml)
[![Licence](https://img.shields.io/badge/licence-MIT-blue)](../../LICENSE)

A `Content-Security-Policy` assembled from the app shell you actually serve — inline-script
hashes computed the way the HTML parser computes them, plus the per-response nonce that lets an
edge-injected script run alongside them.

```toml
[dependencies]
csp-shell = { git = "https://github.com/TimSchoenle/csp-shell", tag = "csp-shell-v0.1.0" }
```

Pin by tag, not branch. `Cargo.lock` records the resolved revision either way, but a branch
dependency lets `cargo update` move silently across arbitrary commits, whereas a tag makes every
bump a deliberate manifest edit that shows up in review.

## Quick start

```rust
use csp_shell::{scan_shell_at, Csp};
use std::path::Path;

let scan = scan_shell_at(Path::new("dist/index.html"))?;
let policy = Csp::spa_wasm().with_scan(&scan).build();

let headers = policy.headers();
// headers.content_security_policy -> "default-src 'self'; script-src 'self' 'wasm-unsafe-eval' 'sha256-…'; …"
// headers.cache_control            -> None, unless a per-response nonce is reserved
```

`scan_shell_at` reads the file the server is about to serve and returns a `'sha256-…'` source for
every `<script>` element that has no `src`. `Csp::spa_wasm` is a starting policy for a WebAssembly
single-page application; `Csp::new` starts from nothing at all.

The policy vocabulary underneath — every directive, source expression and token as a type — is
[`csp-policy`](../csp-policy), a dependency-free `no_std` crate in this repository. `csp-shell`
re-exports all of it, so building a policy needs one dependency rather than two.

Everything around that — static serving, SPA fallback, a reverse proxy, baseline security
headers, a `tower::Layer` to attach the result — already exists elsewhere and belongs to your
application. This crate has no web-framework dependency and will not acquire one.

## The failure mode is silent

The header looks correct, the browser refuses the inline scripts, the page is blank, and the only
evidence is in a console nobody is watching. Three specific ways that happens:

| Cause | What the browser sees | What this crate does |
|-------|-----------------------|----------------------|
| A hand-maintained list of `sha256-…` values drifts from the shell | hashes that match a shell nobody serves any more | reads the file the server is about to serve, so the two cannot disagree |
| Line endings | a CRLF checkout hashes to a value no browser ever computes | folds `\r\n` and lone `\r` to `\n` first, as the parser does, and runs its CI on Windows and Linux for that reason |
| A byte order mark | the parser discarded the BOM before the document existed | strips a leading BOM before hashing |

A CSP hash covers a script element's text content *as the HTML parser produces it*, not the
file's wire bytes. Both normalisations are input-stream preprocessing performed before the script
element's text exists, and both are invisible in the rendered header when they are wrong.

## Serving the header

`Policy::headers()` returns two fields, and both belong to one response:

```rust
let csp_shell::Headers { content_security_policy, cache_control, .. } = policy.headers();
```

`cache_control` is an obligation, not a suggestion. A per-response nonce served from cache is
pinned across every reader for the lifetime of the cache entry, which admits exactly the inline
script the nonce exists to constrain.

`Policy::is_per_response()` tells you whether the header varies. When it is false — no nonce
reserved — render once at startup and reuse the result.

There is deliberately no `tower::Layer` here: a layer you forget to mount is invisible, whereas a
struct field you ignore is visible at the call site, and this way the crate works on `axum`,
`actix`, `warp` or a bare `hyper` service.

## Examples

### Failing open or failing closed

`scan_shell_at` returns a `Result` and stops there. It does not log, and it does not fall back to
a hashless policy on your behalf, because the right posture depends on your shell:

```rust
// Fail open: correct when the inline scripts are a progressive enhancement and the rest of the
// application works without them.
let scan = match csp_shell::scan_shell_at(&shell) {
    Ok(scan) => Some(scan),
    Err(err) => {
        tracing::warn!(%err, "shell unreadable; serving a policy without inline-script hashes");
        None
    }
};

// Fail closed: correct when the shell is substantially inline-scripted, where the degraded
// outcome is a blank page.
let scan = csp_shell::scan_shell_at(&shell)?;
```

### What goes into the header is typed, not validated

The obvious second consumer of a policy builder passes a CDN origin in from configuration, and a
source containing `;` closes the directive and opens a new one:

```text
img-src 'self' https://evil.example; script-src 'unsafe-inline'
```

That is a header injection with an environment variable as the vector, and the resulting header
parses cleanly in every browser. So a policy here is not assembled from strings. Every term is a
type from [`csp-policy`](../csp-policy), re-exported by this crate, and the parse happens where
the value is read rather than where the header is rendered:

```rust
use csp_shell::{Csp, Source, SourceDirective};

let cdn = Source::host(&std::env::var("CDN_ORIGIN")?)?;   // fails here, on bad configuration
let csp = Csp::spa_wasm().extend(SourceDirective::ImgSrc, [Source::SelfOrigin, cdn])?;
```

What that buys, beyond the injection:

| Mistake | What a browser does with it | What the types do |
|---------|-----------------------------|-------------------|
| `scrpit-src` | ignores the directive; the restriction is silently absent | not a `SourceDirective`, so it does not compile |
| `sandbox 'self'` | parses it and ignores the value | a `Directive` carries a value of the shape its name requires |
| `frame-ancestors 'unsafe-inline'` | drops the expression | `AncestorSource` has no keyword but `'self'` |
| `script-src 'none' 'self'` | ignores the `'none'` | `SourceList` is `'none'` *or* a list, never both |
| A `'sha256-…'` of the wrong length | matches nothing; the script never runs | `HashSource` checks the length the algorithm implies |
| A repeated directive | ignores the second one with a console warning | replaced in place, keeping the first one's position |

Seven fuzz targets and two stable-toolchain property tests assert that no accepted input can put a
separator into the rendered header that the builder did not emit itself.

### Adjusting a preset

`Csp::spa_wasm` is a starting point, not a fixed policy. Four methods adjust one, and each keeps
the directive's position so the shape of the header does not shift under an override:

| Want | Method |
|------|--------|
| Replace a directive's whole list | `Csp::directive(name, sources)` |
| Add to a list, creating it if absent | `Csp::extend(name, sources)` |
| Take one source expression out | `Csp::remove_source(name, &source)` |
| Take out everything matching a rule | `Csp::retain_sources(name, keep)` |
| Drop the directive entirely | `Csp::remove(name)` |

```rust
use csp_shell::{Csp, DirectiveName, Scheme, Source, SourceDirective};

let csp = Csp::spa_wasm()
    // `img-src 'self' https: data:` becomes `img-src 'self' https:`
    .remove_source(SourceDirective::ImgSrc, &Source::Scheme(Scheme::Data))
    // and `font-src` falls back to `default-src` again
    .remove(DirectiveName::FontSrc);
```

Prefer removing a source to restating the list. A restated list stops tracking the preset, so a
source a later version of this crate adds is dropped without a diagnostic — the same silent failure
a hand-maintained header has.

Removing every source from a directive is not the same as removing the directive. `img-src 'none'`
blocks every image; an absent `img-src` falls back to `default-src`. The two are spelled
differently here because a browser treats them differently, and the difference is invisible in a
page that renders one image fewer than it should.

None of these is refused. Removal can only loosen a policy, and `Csp::directive` can already loosen
one further than any of them.

### Everything else a policy can say

`Csp` covers the directives this crate has an opinion about. Everything else — `sandbox`,
`trusted-types`, `webrtc`, the reporting directives — goes through `Csp::set` with the same
vocabulary:

```rust
use csp_shell::{Csp, Directive, SandboxToken, TrustedTypeSink};

let csp = Csp::spa_wasm()
    .set(Directive::sandbox([SandboxToken::AllowForms]))?
    .set(Directive::require_trusted_types_for([TrustedTypeSink::Script]))?;
```

### Reaching the three routed source expressions

Three source expressions are routed through named methods rather than accepted as data:

| Source | Directive | Use instead |
|--------|-----------|-------------|
| `'unsafe-eval'` <!-- csp-lint: allow — the routing table cannot be documented without naming what it routes --> | any | `Csp::allow_unsafe_eval()` |
| `'unsafe-inline'` | `script-src` only | `Csp::allow_unsafe_inline_script()` |
| `'strict-dynamic'` | `script-src` | `Csp::strict_dynamic()` |

All three are spec-valid and one of them is occasionally correct — WebAssembly compilation on
Safari before 16.4 needs the first. A library that refuses a valid source expression is a library
people work around by formatting the header themselves, which discards the validation along with
the restriction.

The point is grep-ability in *your* repository. A method name is a stable token that cannot be
produced by `format!`, `concat!` or a config value, so a lint matching `allow_unsafe_eval` is
exact where a lint matching a variant reached through `Source::parse` on a config value is a
heuristic. `'unsafe-inline'` in `style-src` is untouched; `Csp::spa_wasm()` sets it.

### Minting a nonce for an edge-injected script

A nonce is not a Cloudflare feature. Anything that injects inline script downstream of your
origin — an edge worker, a CDN's RUM beacon, an SSR template — needs one, because your hashes
were computed before that script existed.

```rust
use csp_shell::presets::cloudflare;

let policy = cloudflare::script_nonce(Csp::spa_wasm().with_scan(&scan)).build();
assert!(policy.is_per_response());
assert_eq!(policy.headers().cache_control, Some("no-cache"));
```

Cloudflare is the motivating case. Its bot products (Bot Fight Mode, JavaScript Detections, the
challenge platform) inject an inline `<script>` at the edge, `script-src` refuses it, and the
detection silently never runs: bot management appears enabled and does nothing. Cloudflare's
documented answer is to parse your `Content-Security-Policy` response header and copy the nonce
onto what it injects — which is why nothing is stamped into the shell. The header is the entire
contract, and your own inline scripts keep running by hash either way, because under CSP3 a
script executes if it matches *any* source expression.

Two conditions, and only the first is enforceable from inside your process:

1. The shell must be served `Cache-Control: no-cache`. `Policy::headers()` hands it to you.
2. No Cloudflare Cache Rule may cache the shell. A "Cache Everything" rule overrides the origin
   `Cache-Control` — satisfying condition 1 at the origin and violating it at the edge. That one
   belongs in your deployment checklist.

### Stamping the nonce into the shell

Cloudflare reads the nonce out of the response header. Most services do not — Google Tag Manager
reads it off *its own loader element* and copies it onto the tags it injects, and an SSR template
has to put it on the scripts it generates. For those, `Headers::nonce` hands back the value that
was spliced into the header:

```rust
let headers = policy.headers();
if let Some(nonce) = &headers.nonce {
    // Render the shell with `nonce="{nonce}"` on the tags that need it. A `nonce` attribute is
    // not script text, so the hashes computed from the shell stay valid alongside it.
}
```

This turns the shell into a per-response render rather than a static file, which is a real cost.
Skip it when nothing needs the value in the document.

### Third-party services

`presets` carries the origins a service loads from, in the directives they belong in — the second
half being the part that is easy to get wrong and silent when you do. Presets compose in any
order, are idempotent, and only ever widen: a preset that creates a directive seeds it from
whatever the browser was falling back to first, so adding Turnstile does not quietly revoke
same-origin frames.

```rust
use csp_shell::presets::{cloudflare, google, stripe};

let csp = cloudflare::script_nonce(
    google::fonts(stripe::checkout(cloudflare::turnstile(
        Csp::spa_wasm().with_scan(&scan),
    ))),
);
```

| Module | Origins presets | Nonce presets |
|---|---|---|
| `cloudflare` | `turnstile`, `web_analytics` | `script_nonce` |
| `google` | `tag_manager`, `analytics`, `fonts`, `recaptcha` | `tag_manager_nonce` |
| `stripe` | `elements`, `checkout` | — |
| `sentry` | `loader`, `session_replay`, `ingest(origin)` | — |
| `plausible` | `cloud`, `self_hosted(origin)` | — |
| `fathom` | `cloud`, `custom_domain(origin)` | — |
| `matomo` | `instance(origin)` | — |

The `_nonce` suffix is the whole distinction: those reserve the per-response nonce slot and bring
a `Cache-Control` obligation with them, while the others append host sources and cost nothing. A
preset taking an `origin` argument is one whose host is deployment-specific; it returns a
`Result`, because a configuration value that would carry a `;` into the header stops at the parse.

A preset is not a promise that a service will keep the hosts it has today, and not a substitute
for its own documentation. `Csp::extend` takes any origin a preset missed.

### Detecting a shell that changed underneath the policy

The hashes are computed once, at startup, from a file that may not stay put. A bundle mounted as
a volume, served from a host directory in development, or shipped as its own `ConfigMap` changes
with no configuration change anywhere: nothing wakes up, the hashes go stale, and the browser
silently refuses the scripts.

`ScanResult::digest` is SHA-256 of the shell's raw bytes, so detecting that costs no second read:

```rust
struct FrontendSources {
    config: your_config::Sources,
    static_dir: PathBuf,
    shell: Option<[u8; 32]>,   // ScanResult::digest
    watch: Vec<PathBuf>,       // config paths ∪ [static_dir]
}

// A changed shell is a changed configuration, and rebuilds the runtime through the same path as
// a rotated secret.
fn differs_from(&self, previous: &Self) -> bool {
    self.config.differs_from(&previous.config) || self.shell != previous.shell
}
```

The crate deliberately owns none of this — it exposes the digest and stays reload-agnostic. Three
things to know if you implement it on Kubernetes:

- **`ConfigMap` and `Secret` volume updates are atomic symlink swaps of a `..data` directory.** An
  inotify watch on `index.html` never fires. Watch the mount directory, and treat any event as
  "re-scan and compare digests" rather than trusting event kinds.
- **`subPath` mounts never update.** If the bundle is mounted that way, the watch is dead weight
  and the redeploy assumption holds after all. Document which one you use.
- **A non-atomic deploy can be scanned mid-write.** A torn read yields a valid-looking scan with
  wrong hashes. Debounce, and accept a digest only when two reads separated by the debounce
  interval agree.

The nonce needs none of this. It is minted per response from the OS CSPRNG; only the hashes are
startup-derived state.

## What the scanner does not do

It is not an HTML parser and must not become one. It reads one generated file, and the cases it
handles are the ones that arise there:

- `<scriptfoo>` is not a `<script>` — only a name or attribute boundary may follow the tag name,
  in the opening and the closing tag alike.
- An element carrying `src` is skipped; `'self'` already covers it. The check requires an
  attribute boundary before `src` and an `=` after it, and ignores matches inside quoted
  attribute values.
- An unterminated opening tag stops the scan rather than producing a reversed range.
- A `>` inside an attribute value mis-splits the tag. Accepted and reported.

Anything accepted is reported in `ScanResult::warnings`, so the limits are observable at runtime
rather than only in this document. A NUL in script data is reported too: the tokenizer replaces
it with U+FFFD, so the hash will not match, and something upstream is already broken.

## Feature flags

| Feature | Contents | Dependencies |
|---------|----------|--------------|
| *(core)* | `Csp`, `Policy`, `Headers`, `ScanResult`, `scan_shell`, the typed vocabulary, SHA-256 hashing | `csp-policy`, `sha2` |
| `std` (default) | `scan_shell_at`, `ScanError`, `std::error::Error` impls | — |
| `nonce` | `Nonce`, `Csp::per_response_nonce`, `Headers::nonce`, nonce splicing in `Policy::headers` | `getrandom` |
| `presets` | `presets::*` — the origins third-party services load from, in the directives they belong in | — |
| `cloudflare` | `presets` and `nonce` together, under the name the Cloudflare concessions were first published as | — |

The default build compiles `csp-policy` — which has no dependencies of its own — and `sha2`, and
nothing else. `default-features = false` gives a
`no_std + alloc` core — usable from a build script, a bundler, or a bare-metal target — where you
pass the shell's text in yourself:

```toml
csp-shell = { git = "…", tag = "csp-shell-v0.1.0", default-features = false }
```

Feature-gated code rots silently, which is why the full feature powerset is a CI gate from the
first commit rather than something added after `--no-default-features` has already broken.

## Compared with

| Crate | What it gives you | What it lacks |
|-------|-------------------|---------------|
| [`csp`](https://crates.io/crates/csp) | a typed builder for the header string, so directive names and source expressions are hard to typo | no shell scanning and no hashing; documents that it accepts invalid policies unchanged. `csp-policy` is this repository's answer to the same problem, and refuses what it cannot render |
| [`content-security-policy`](https://crates.io/crates/content-security-policy) | Servo's CSP3 parser and matcher — the enforcement side | not a producer: nothing derives a policy from a document you are about to serve |
| [`tower-helmet`](https://crates.io/crates/tower-helmet) | the whole security-header set as a `tower` layer, CSP included | directives are an unvalidated `HashMap<&str, Vec<&str>>`; no hashes, no per-response nonce; tied to `tower` |
| a bundler CSP plugin | hashes computed at build time, in the toolchain that emits the shell | the hashes then travel separately from the file; the server has no way to notice when the two stop agreeing |

## Contributing

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org): the type
decides the changelog section and the version bump. `feat` and a breaking change move the minor
while the crate is pre-1.0; `fix` moves the patch.

The two crates in this repository release independently, so the path a commit touches decides
which of them it bumps: `crates/csp-shell` moves `csp-shell-v0.1.0`, `crates/csp-policy` moves its
own tag, and release-please rewrites the version requirement between them so the pair can never
disagree about which release is being built.

`README.md` is generated. Edit `.github/templates/csp-shell.README.md.hbs` instead — CI renders it
on every pull request and commits the result back to the branch, and a push to `main` whose
`README.md` does not match its template fails.

The gates a pull request has to pass are in [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml);
all of them run locally:

```bash
cargo fmt --all --check
cargo hack --workspace --feature-powerset clippy --all-targets -- -D warnings
cargo hack --workspace --each-feature test
cargo test --workspace --all-features
cargo build -p csp-shell --no-default-features --target thumbv7em-none-eabi   # the no_std core
cargo deny check
```

Newline normalisation is a line-endings bug, so `clippy` and `test` run on both Windows and Linux
in CI; running them on one platform locally is enough for review.

Fuzzing lives in its own workspace under each crate's `fuzz/`, and comes in two halves.

The oracles — the code that decides whether an input is a finding — are an ordinary library, not
bodies buried in the target binaries. So the committed seeds and a deterministic sweep through
each oracle replay on a plain `cargo test`, with no sanitizer and no nightly. That is the half
CI gates on, and the half a reproducer stays in forever:

```bash
cd fuzz && cargo test                    # from crates/csp-shell or crates/csp-policy
CSP_FUZZ_ITERATIONS=200000 cargo test    # a longer sweep, no recompile
```

The other half is the campaign, which discovers inputs rather than re-checking known ones. It
needs nightly, because `libfuzzer-sys` compiles the crate under test with `-Z sanitizer=address`:

```bash
cd crates/csp-shell
cargo +nightly fuzz run scan_shell fuzz/corpus/scan_shell fuzz/seeds/scan_shell \
  -- -dict=fuzz/dictionaries/shell.dict
cargo +nightly fuzz run csp_directive
cargo +nightly fuzz run csp_builder
cargo +nightly fuzz run shell_to_header

cd ../csp-policy
cargo +nightly fuzz run parse_source fuzz/corpus/parse_source fuzz/seeds/parse_source \
  -- -dict=fuzz/dictionaries/csp.dict
cargo +nightly fuzz run parse_terms
cargo +nightly fuzz run build_policy
```

`corpus/` is gitignored — a campaign's output is machine-specific and grows without bound. When a
campaign finds something worth keeping, the input belongs in `seeds/`, where the replay suite
picks it up on every push.

## Licence

MIT. See [LICENSE](../../LICENSE).
