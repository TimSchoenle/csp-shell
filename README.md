# csp-shell

[![CI](https://github.com/TimSchoenle/csp-shell/actions/workflows/ci.yml/badge.svg)](https://github.com/TimSchoenle/csp-shell/actions/workflows/ci.yml)
[![Version](https://img.shields.io/github/v/tag/TimSchoenle/csp-shell?label=version&sort=semver&color=blue)](https://github.com/TimSchoenle/csp-shell/tags)
[![MSRV](https://img.shields.io/badge/MSRV-1.82-blue)](Cargo.toml)
[![Licence](https://img.shields.io/badge/licence-MIT-blue)](LICENSE)

A `Content-Security-Policy` assembled from the app shell you actually serve — inline-script hashes
computed the way the HTML parser computes them, plus the per-response nonce that lets an
edge-injected script run alongside them.

```toml
[dependencies]
csp-shell = { git = "https://github.com/TimSchoenle/csp-shell", tag = "v0.1.0" }
```

```rust
use csp_shell::{scan_shell_at, Csp};
use std::path::Path;

let scan = scan_shell_at(Path::new("dist/index.html"))?;
let policy = Csp::spa_wasm().with_scan(&scan).build();

let headers = policy.headers();
// headers.content_security_policy -> "default-src 'self'; script-src 'self' 'wasm-unsafe-eval' 'sha256-…'; …"
// headers.cache_control            -> None, unless a per-response nonce is reserved
```

## The crates

| Crate | What it is | Dependencies |
|-------|------------|--------------|
| [`csp-shell`](crates/csp-shell) | the shell scanner, the hashes, the per-response nonce, and the Cloudflare concessions | `csp-policy`, `sha2` |
| [`csp-policy`](crates/csp-policy) | a Content-Security-Policy as data: every directive, source expression and token as a type | none |

Most consumers want `csp-shell`, which re-exports the whole of `csp-policy` — building a policy
needs one dependency, not two. `csp-policy` stands alone for anything that needs a typed policy
without a document to derive it from: an edge worker, a config validator, a test fixture.

Both are `no_std + alloc` at their core, and neither depends on a web framework.

## Why

Every failure mode in this area is **silent**. The header looks correct, the browser refuses the
scripts, the page is blank, and the only evidence is in a console nobody is watching. A
hand-maintained list of `sha256-…` values drifts the moment anyone edits the shell; a directive
name with a typo in it is a restriction that simply is not there; an origin read from an
environment variable can carry a `;` and open a directive nobody wrote.

The full argument, the deployment obligations, and the reload pattern are in
[`crates/csp-shell/README.md`](crates/csp-shell/README.md). The typing argument is in
[`crates/csp-policy/README.md`](crates/csp-policy/README.md).

## Development

Every gate a pull request has to pass is in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml); all of them run locally:

```bash
cargo fmt --all --check
cargo hack --workspace --feature-powerset clippy --all-targets -- -D warnings
cargo hack --workspace --each-feature test
cargo test --workspace --all-features
cargo build -p csp-shell --no-default-features --target thumbv7em-none-eabi   # the no_std core
cargo deny check
```

Fuzzing needs nightly and lives in its own workspace under each crate's `fuzz/`.

## Licence

MIT. See [LICENSE](LICENSE).
