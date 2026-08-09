//! Replays the committed corpus through the oracles, without libFuzzer.
//!
//! Two jobs. The first is regression: every seed under `seeds/` — and every input a campaign
//! promoted into `corpus/` — is run through the matching oracle on a plain `cargo test`, so a
//! reproducer keeps being checked long after whoever found it moved on.
//!
//! The second is validating the oracles themselves. An oracle that models the crate wrongly
//! reports crashes that are not bugs, and the way to find that out is to run it over inputs
//! designed to hit its edges. [`generated`] does that from a fixed seed, so a failure is
//! reproducible from the test name and the iteration index alone rather than from a `corpus/`
//! blob that is not committed.
//!
//! `corpus/` is deliberately not in the repository — a campaign's output is machine-specific and
//! grows without bound. That shapes what the generated sweeps have to do here: three of the four
//! targets decode their input with `arbitrary`, and a hand-authored seed file for those is a byte
//! blob nobody can read or maintain. So those targets are swept twice: once through the typed
//! `run`, which is where the interesting states actually are, and once through `check` with raw
//! bytes, which is what keeps the decode itself covered.

use std::path::{Path, PathBuf};

use csp_shell_fuzz::oracle;

/// The oracle under test. Every one takes raw bytes so a single replay loop can drive them all.
type Oracle = fn(&[u8]);

fn input_dir(kind: &str, target: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(kind)
        .join(target)
}

/// Run every file in `dir` through `oracle`, returning how many were replayed.
///
/// A directory that does not exist is not a failure: `corpus/` is where a campaign writes, and a
/// fresh clone has none.
fn replay(dir: &Path, oracle: Oracle) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };

    let mut replayed = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() || path.file_name().is_some_and(|name| name == ".gitkeep") {
            continue;
        }
        let Ok(data) = std::fs::read(&path) else {
            continue;
        };
        // `catch_unwind` is deliberately *not* used. A panic is the finding, and the harness
        // already names the test; wrapping it would only make the report worse.
        oracle(&data);
        replayed += 1;
    }
    replayed
}

/// `scan_shell` takes a document, so its seeds are documents — reviewable, and the only place a
/// line-ending or byte-order-mark regression can be pinned down by name.
#[test]
fn scan_shell_seeds() {
    let seeds = replay(&input_dir("seeds", "scan_shell"), oracle::scan_shell::check);
    assert!(
        seeds > 0,
        "no seeds found for `scan_shell` — the corpus is what makes this test mean anything"
    );
    replay(
        &input_dir("corpus", "scan_shell"),
        oracle::scan_shell::check,
    );
}

#[test]
fn csp_directive_corpus() {
    replay(
        &input_dir("corpus", "csp_directive"),
        oracle::csp_directive::check,
    );
}

#[test]
fn csp_builder_corpus() {
    replay(
        &input_dir("corpus", "csp_builder"),
        oracle::csp_builder::check,
    );
}

#[test]
fn shell_to_header_corpus() {
    replay(
        &input_dir("corpus", "shell_to_header"),
        oracle::shell_to_header::check,
    );
}

/// A deterministic input generator, standing in for a mutation engine.
///
/// Not a substitute for a real campaign — it has no coverage feedback, so it explores by
/// combination rather than by discovery. What it is good at is the thing a campaign is slow at:
/// hitting every *pairing* of the interesting tokens quickly, which is where an oracle that
/// models the crate wrongly gives itself away.
mod generated {
    use csp_shell_fuzz::oracle::{
        self,
        csp_builder::{Operation, Session, SourceSpec},
        shell_to_header::Deployment,
    };

    use super::Oracle;

    /// xorshift64*, so the sequence is fixed across platforms and runs. A failure reproduces from
    /// the test name and the iteration index printed with it.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn below(&mut self, bound: u64) -> u64 {
            self.next() % bound
        }

        fn flip(&mut self) -> bool {
            self.next().is_multiple_of(2)
        }

        fn byte(&mut self) -> u8 {
            u8::try_from(self.next() & 0xff).expect("masked to a byte")
        }

        fn pick<'a, T>(&mut self, options: &'a [T]) -> &'a T {
            let index = usize::try_from(self.next() % options.len() as u64).expect("fits");
            &options[index]
        }
    }

    // ---------------------------------------------------------------------------------------
    // Documents
    //
    // The scanner decides where a script starts and ends by looking at bytes, so the fragments
    // below are the boundaries of that decision: a tag that never closes, a closing tag inside a
    // string literal, an attribute whose value contains `>`, and the two line endings whose
    // equivalence the oracle asserts.
    // ---------------------------------------------------------------------------------------

    const OPENERS: &[&str] = &[
        "<script>",
        "<SCRIPT>",
        "<script type=\"module\">",
        "<script type='module' defer>",
        "<script src=\"/assets/app.js\">",
        "<script src=\"/a.js\" integrity=\"sha256-x\">",
        "<script data-attr=\"a>b\">",
        "<script\n>",
        "<script\t>",
        "<script",
        "<scriptish>",
        "<style>",
        "<!--",
        "<div>",
    ];

    const BODIES: &[&str] = &[
        "",
        "let x = 1;",
        "console.log(1)",
        "var s = '</scr' + 'ipt>';",
        "// </script>",
        "\r\n",
        "\n\n\n",
        "\r",
        "\u{feff}",
        "ünïcode",
        "\0",
        "a>b<c",
        "\"quoted\"",
    ];

    const CLOSERS: &[&str] = &[
        "</script>",
        "</SCRIPT>",
        "</script >",
        "</script\t>",
        "</script",
        "",
        "-->",
        "</style>",
    ];

    /// Build one document of up to four elements.
    fn document(rng: &mut Rng) -> String {
        let elements = 1 + rng.below(4);
        let mut html = String::new();
        if rng.flip() {
            html.push_str("<!doctype html><html><head>");
        }
        for _ in 0..elements {
            html.push_str(rng.pick(OPENERS));
            html.push_str(rng.pick(BODIES));
            html.push_str(rng.pick(CLOSERS));
        }
        html
    }

    // ---------------------------------------------------------------------------------------
    // Source expressions
    //
    // The same alphabet the typed crate's sweep uses, because this is the text a consumer's
    // configuration supplies and the builder is the layer that must not let a separator through.
    // ---------------------------------------------------------------------------------------

    const PREFIXES: &[&str] = &[
        "", "'", "https://", "http://", "*.", "//", " ", "'nonce-", "'sha256-",
    ];

    const TERMS: &[&str] = &[
        "self",
        "unsafe-inline",
        "strict-dynamic",
        "wasm-unsafe-eval",
        "none",
        "example.com",
        "cdn.example.com",
        "*",
        "",
        "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
        "cnNkZ2p3ZW9pcmpnb2llcmpn",
    ];

    const SUFFIXES: &[&str] = &[
        "",
        "'",
        ":",
        ":443",
        ":*",
        "/",
        "/path/app.js",
        ";",
        ",",
        " x",
        "\r\n",
        "=",
    ];

    /// One source-expression-shaped string.
    fn term(rng: &mut Rng) -> String {
        let mut text = String::new();
        text.push_str(rng.pick(PREFIXES));
        text.push_str(rng.pick(TERMS));
        text.push_str(rng.pick(SUFFIXES));
        text
    }

    fn terms(rng: &mut Rng) -> Vec<String> {
        (0..rng.below(4)).map(|_| term(rng)).collect()
    }

    // ---------------------------------------------------------------------------------------
    // Builder sessions
    // ---------------------------------------------------------------------------------------

    fn source_spec(rng: &mut Rng) -> SourceSpec {
        match rng.below(5) {
            0 => SourceSpec::SelfOrigin,
            1 => SourceSpec::WasmUnsafeEval,
            2 => SourceSpec::Parsed(term(rng)),
            3 => SourceSpec::Host(term(rng)),
            _ => {
                let mut digest = [0u8; 32];
                for byte in &mut digest {
                    *byte = rng.byte();
                }
                SourceSpec::Sha256(digest)
            }
        }
    }

    fn source_specs(rng: &mut Rng) -> Vec<SourceSpec> {
        (0..rng.below(4)).map(|_| source_spec(rng)).collect()
    }

    fn operation(rng: &mut Rng) -> Operation {
        match rng.below(9) {
            0 => Operation::Directive {
                directive: rng.byte(),
                sources: source_specs(rng),
            },
            1 => Operation::Extend {
                directive: rng.byte(),
                sources: source_specs(rng),
            },
            2 => Operation::Deny {
                directive: rng.byte(),
            },
            3 => Operation::Sandbox((0..rng.below(4)).map(|_| rng.byte()).collect()),
            4 => Operation::WithScan {
                shell: document(rng),
            },
            5 => Operation::AllowUnsafeEval,
            6 => Operation::AllowUnsafeInlineScript,
            7 => Operation::StrictDynamic,
            _ => Operation::PerResponseNonce {
                enabled: rng.flip(),
            },
        }
    }

    fn session(rng: &mut Rng) -> Session {
        Session {
            from_preset: rng.flip(),
            operations: (0..=rng.below(6)).map(|_| operation(rng)).collect(),
        }
    }

    fn deployment(rng: &mut Rng) -> Deployment {
        Deployment {
            shell: document(rng),
            script_nonce: rng.flip(),
            turnstile: rng.flip(),
            extra_connect_src: terms(rng),
        }
    }

    /// Raw bytes, for sweeping the `arbitrary` decode in `check` rather than the oracle behind
    /// it. Length varies so the decoder's short-input paths are reached as often as its deep
    /// ones.
    fn raw_bytes(rng: &mut Rng) -> Vec<u8> {
        let length = usize::try_from(rng.below(192)).expect("fits");
        (0..length).map(|_| rng.byte()).collect()
    }

    /// The default budget per target. Large enough to pair most tokens, small enough that the
    /// suite stays a couple of seconds — every document is scanned and hashed for real.
    const DEFAULT_ITERATIONS: usize = 2000;

    /// The budget, overridable so a longer hunt does not need a recompile.
    fn iterations() -> usize {
        std::env::var("CSP_FUZZ_ITERATIONS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(DEFAULT_ITERATIONS)
    }

    /// Run `body` over the iteration budget, naming the iteration that fails.
    ///
    /// `catch_unwind` rather than a panic hook: a hook is process-global, these tests run in
    /// parallel, and the input it printed would belong to whichever sweep installed it last.
    /// `catch_unwind` attributes the failure to the iteration that actually produced it.
    ///
    /// The corpus replay above deliberately does *not* do this — there the file name is the
    /// context, and the harness already prints it.
    fn sweep<T: std::fmt::Debug>(seed: u64, generate: fn(&mut Rng) -> T, run: impl Fn(&T)) {
        let mut rng = Rng(seed);
        for iteration in 0..iterations() {
            let input = generate(&mut rng);
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(&input)));
            assert!(
                outcome.is_ok(),
                "seed {seed:#x}, iteration {iteration} failed on input:\n{input:?}"
            );
        }
    }

    /// Sweep an oracle's byte entry point, so the `arbitrary` decode is exercised too.
    fn sweep_bytes(seed: u64, oracle: Oracle) {
        sweep(seed, raw_bytes, |input| oracle(input));
    }

    #[test]
    fn scan_shell_sweep() {
        sweep(0x5EED_0001, document, |html| oracle::scan_shell::run(html));
    }

    #[test]
    fn csp_directive_sweep() {
        sweep(0x5EED_0002, terms, |texts| {
            for index in 0..8u8 {
                oracle::csp_directive::run(index, texts);
            }
        });
    }

    #[test]
    fn csp_builder_sweep() {
        // `Session` is consumed by `run`, so each iteration regenerates it rather than sharing
        // one — which is also what keeps the sweep from depending on operation order across
        // iterations.
        let mut rng = Rng(0x5EED_0003);
        for iteration in 0..iterations() {
            let input = session(&mut rng);
            let described = format!("{input:?}");
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                oracle::csp_builder::run(input);
            }));
            assert!(
                outcome.is_ok(),
                "iteration {iteration} failed on session:\n{described}"
            );
        }
    }

    #[test]
    fn shell_to_header_sweep() {
        sweep(0x5EED_0004, deployment, |input| {
            oracle::shell_to_header::run(input);
        });
    }

    #[test]
    fn csp_directive_decode_sweep() {
        sweep_bytes(0x5EED_0005, oracle::csp_directive::check);
    }

    #[test]
    fn csp_builder_decode_sweep() {
        sweep_bytes(0x5EED_0006, oracle::csp_builder::check);
    }

    #[test]
    fn shell_to_header_decode_sweep() {
        sweep_bytes(0x5EED_0007, oracle::shell_to_header::check);
    }
}
