# csp-shell

[![CI](https://github.com/TimSchoenle/csp-shell/actions/workflows/ci.yml/badge.svg)](https://github.com/TimSchoenle/csp-shell/actions/workflows/ci.yml)
[![Version](https://img.shields.io/github/v/tag/TimSchoenle/csp-shell?label=version&sort=semver&color=blue)](https://github.com/TimSchoenle/csp-shell/tags)
[![MSRV](https://img.shields.io/badge/MSRV-1.82-blue)](Cargo.toml)
[![Licence](https://img.shields.io/badge/licence-MIT-blue)](LICENSE)

A `Content-Security-Policy` assembled from the app shell you actually serve — inline-script
hashes computed the way the HTML parser computes them, plus the per-response nonce that lets an
edge-injected script run alongside them.

```toml
[dependencies]
csp-shell = { git = "https://github.com/TimSchoenle/csp-shell", tag = "v0.1.0" }
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

`scan_shell_at` reads the file the server is about to serve and returns a `'sha256-…'` source
expression for every `<script>` element that has no `src`. `Csp::spa_wasm` is a starting policy
for a WebAssembly single-page application; `Csp::new` starts from `default-src 'self'` alone.

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

### Validating what goes into the header

`Csp::directive` and `Csp::extend` validate every directive name and source expression, because
the obvious second consumer of a policy builder passes a CDN origin in from configuration. A
source containing `;` closes the directive and opens a new one:

```text
img-src 'self' https://evil.example; script-src 'unsafe-inline'
```

That is a header injection with an environment variable as the vector, and the resulting header
parses cleanly. The rules:

| Input | Rule |
|-------|------|
| Directive name | `[a-zA-Z][a-zA-Z0-9-]*`, matched case-insensitively against the known set; an unrecognised name is an error in debug builds and accepted in release builds |
| Source expression | Non-empty, and every byte in printable ASCII excluding space, `,` and `;` |
| Whitespace in a source | Rejected — it would silently split into two sources rather than fail |
| Duplicate directive | Replaced, not appended; a browser ignores a repeated directive with only a console warning |

Four fuzz targets and a stable-toolchain property test assert that no accepted input can put a
separator into the rendered header that the builder did not emit itself.

### Reaching the three routed source expressions

Three source expressions are routed through named methods rather than accepted as strings:

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
exact where a lint matching the source expression inside an arbitrary string literal is a
heuristic. `'unsafe-inline'` in `style-src` is untouched; `Csp::spa_wasm()` sets it.

### Minting a nonce for an edge-injected script

A nonce is not a Cloudflare feature. Anything that injects inline script downstream of your
origin — an edge worker, a CDN's RUM beacon, an SSR template — needs one, because your hashes
were computed before that script existed.

```rust
let policy = csp_shell::cloudflare::script_nonce(Csp::spa_wasm().with_scan(&scan)).build();
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

`cloudflare::turnstile` admits `https://challenges.cloudflare.com` in `script-src` **and**
`frame-src`, because Turnstile loads `api.js` and then frames the widget from the same host.
Admitting the script without the frame renders an empty box.

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
| *(core)* | `Csp`, `Policy`, `Headers`, `ScanResult`, `scan_shell`, SHA-256 hashing | `sha2` |
| `std` (default) | `scan_shell_at`, `ScanError`, `std::error::Error` impls | — |
| `nonce` | `Nonce`, `Csp::per_response_nonce`, nonce splicing in `Policy::headers` | `getrandom` |
| `cloudflare` | `cloudflare::script_nonce`, `cloudflare::turnstile`; implies `nonce` | — |

The default build compiles `sha2` and nothing else. `default-features = false` gives a
`no_std + alloc` core — usable from a build script, a bundler, or a bare-metal target — where you
pass the shell's text in yourself:

```toml
csp-shell = { git = "…", tag = "v0.1.0", default-features = false }
```

Feature-gated code rots silently, which is why the full feature powerset is a CI gate from the
first commit rather than something added after `--no-default-features` has already broken.

## Compared with

| Crate | What it gives you | What it lacks |
|-------|-------------------|---------------|
| [`csp`](https://crates.io/crates/csp) | a typed builder for the header string, so directive names and source expressions are hard to typo | no shell scanning and no hashing; documents that it accepts invalid policies unchanged |
| [`content-security-policy`](https://crates.io/crates/content-security-policy) | Servo's CSP3 parser and matcher — the enforcement side | not a producer: nothing derives a policy from a document you are about to serve |
| [`tower-helmet`](https://crates.io/crates/tower-helmet) | the whole security-header set as a `tower` layer, CSP included | directives are an unvalidated `HashMap<&str, Vec<&str>>`; no hashes, no per-response nonce; tied to `tower` |
| a bundler CSP plugin | hashes computed at build time, in the toolchain that emits the shell | the hashes then travel separately from the file; the server has no way to notice when the two stop agreeing |

## Contributing

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org): the type
decides the changelog section and the version bump. `feat` and a breaking change move the minor
while the crate is pre-1.0; `fix` moves the patch.

The gates a pull request has to pass are in [`.github/workflows/ci.yml`](.github/workflows/ci.yml);
all of them run locally:

```bash
cargo fmt --all --check
cargo hack --feature-powerset clippy --all-targets -- -D warnings
cargo hack --each-feature test
cargo test --all-features
cargo test --all-features --release   # the release-mode branch of the unknown-directive check
cargo build --no-default-features --target thumbv7em-none-eabi   # the no_std core
cargo deny check
```

Newline normalisation is a line-endings bug, so `clippy` and `test` run on both Windows and Linux
in CI; running them on one platform locally is enough for review.

Fuzzing needs nightly and lives in its own workspace under `fuzz/`. CI runs each target for two
minutes per push and explores on a weekly schedule:

```bash
cargo +nightly fuzz run scan_shell fuzz/corpus/scan_shell fuzz/seeds/scan_shell
cargo +nightly fuzz run csp_directive
cargo +nightly fuzz run csp_builder
cargo +nightly fuzz run shell_to_header
```

## Licence

MIT. See [LICENSE](LICENSE).
