<!--
Generated from .github/templates/README.md.hbs — edit that file, not this one. CI renders it on
every pull request and commits the result back to the branch; a push to main whose README.md
does not match its template fails the `readme` check in .github/workflows/docs.yml.

Variables come from .github/scripts/readme-variables.sh, which reads the manifests:

    msrv            the workspace rust-version, e.g. 1.85.0
    shell_version   the csp-shell [package] version, e.g. 0.1.0
    shell_tag       the tag that release carries, e.g. csp-shell-v0.1.0
    policy_version  the csp-policy [package] version
    policy_tag      the tag that release carries, e.g. csp-policy-v0.1.0

That is what keeps the install snippet and the MSRV badge correct across a release: the release
pull request is the commit that changes those numbers, so it arrives with the rendered README
already updated.
-->
# csp-shell

[![CI](https://github.com/TimSchoenle/csp-shell/actions/workflows/ci.yml/badge.svg)](https://github.com/TimSchoenle/csp-shell/actions/workflows/ci.yml)
[![csp-shell](https://img.shields.io/badge/csp--shell-0.1.0-blue)](https://github.com/TimSchoenle/csp-shell/releases/tag/csp-shell-v0.1.0)
[![csp-policy](https://img.shields.io/badge/csp--policy-0.1.0-blue)](https://github.com/TimSchoenle/csp-shell/releases/tag/csp-policy-v0.1.0)
[![MSRV](https://img.shields.io/badge/MSRV-1.85.0-blue)](Cargo.toml)
[![Licence](https://img.shields.io/badge/licence-MIT-blue)](LICENSE)

A `Content-Security-Policy` assembled from the app shell you actually serve — inline-script hashes
computed the way the HTML parser computes them, plus the per-response nonce that lets an
edge-injected script run alongside them.

```toml
[dependencies]
csp-shell = { git = "https://github.com/TimSchoenle/csp-shell", tag = "csp-shell-v0.1.0" }
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
| [`csp-shell`](crates/csp-shell) | the shell scanner, the hashes, the per-response nonce, and the third-party service presets | `csp-policy`, `sha2` |
| [`csp-policy`](crates/csp-policy) | a Content-Security-Policy as data: every directive, source expression and token as a type | none |

Most consumers want `csp-shell`, which re-exports the whole of `csp-policy` — building a policy
needs one dependency, not two. `csp-policy` stands alone for anything that needs a typed policy
without a document to derive it from: an edge worker, a config validator, a test fixture.

Both are `no_std + alloc` at their core, and neither depends on a web framework.

The two version independently, and each carries its own tag: `csp-shell-v0.1.0` and
`csp-policy-v0.1.0`. `csp-policy` is a data model that sits still for long stretches while
`csp-shell` moves with the scanner and the presets, and a shared version would mean releasing the
one to describe a change in the other.

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

Fuzzing lives in its own workspace under each crate's `fuzz/`. The oracles are an ordinary
library there, so the committed seeds and the deterministic sweeps replay on a plain `cargo test`
without a sanitizer and without nightly:

```bash
cd crates/csp-policy/fuzz && cargo test
cd ../../csp-shell/fuzz  && cargo test
```

A campaign — the part that discovers new inputs rather than re-checking known ones — does need
nightly, and is described in [`crates/csp-shell/README.md`](crates/csp-shell/README.md).

`README.md` is generated. Edit `.github/templates/README.md.hbs` instead: CI renders every README
on each pull request and commits the result back to the branch, and a push to `main` whose
committed files do not match their templates fails.

## Licence

MIT. See [LICENSE](LICENSE).
