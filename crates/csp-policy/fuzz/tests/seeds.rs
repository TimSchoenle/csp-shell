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
//! grows without bound. That is why the generated sweep carries the weight for the targets whose
//! inputs are `arbitrary`-decoded bytes: a hand-authored seed file for those is a byte blob
//! nobody can read or maintain, whereas a text-shaped target has seeds a human can write and
//! review.

use std::path::{Path, PathBuf};

use csp_policy_fuzz::oracle;

/// The oracle under test. Every one takes raw bytes so a single replay loop can drive them all.
type Oracle = fn(&[u8]);

fn input_dir(kind: &str, target: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(kind)
        .join(target)
}

/// Runs every file in `dir` through `oracle`, returning how many were replayed.
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
        // already names the test; wrapping it would only make the report worse. The file that
        // failed is the last one the panic message can be traced to.
        oracle(&data);
        replayed += 1;
    }
    replayed
}

/// Replays a target whose inputs are text a human can author, and insists there are some.
fn replay_seeded(target: &str, oracle: Oracle) {
    let seeds = replay(&input_dir("seeds", target), oracle);
    assert!(
        seeds > 0,
        "no seeds found for `{target}` — the corpus is what makes this test mean anything"
    );
    replay(&input_dir("corpus", target), oracle);
}

#[test]
fn parse_source_seeds() {
    replay_seeded("parse_source", oracle::parse_source::check);
}

#[test]
fn parse_terms_seeds() {
    replay_seeded("parse_terms", oracle::parse_terms::check);
}

/// `build_policy` decodes its input with `arbitrary`, so a seed file is an opaque byte string
/// rather than something reviewable. Its committed regression suite is whatever a campaign
/// promoted; its systematic coverage is [`generated::build_policy_sweep`].
#[test]
fn build_policy_corpus() {
    replay(
        &input_dir("corpus", "build_policy"),
        oracle::build_policy::check,
    );
}

/// A deterministic input generator, standing in for a mutation engine.
///
/// Not a substitute for a real campaign — it has no coverage feedback, so it explores by
/// combination rather than by discovery. What it is good at is the thing a campaign is slow at:
/// hitting every *pairing* of the interesting tokens quickly, which is where an oracle that
/// models the crate wrongly gives itself away.
mod generated {
    use super::{oracle, Oracle};

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

        fn pick<'a, T>(&mut self, options: &'a [T]) -> &'a T {
            let index = usize::try_from(self.next() % options.len() as u64).expect("fits");
            &options[index]
        }
    }

    /// What a source expression can start with: the quote that makes it a keyword, the schemes,
    /// the wildcard label, and the hash and nonce framings.
    const PREFIXES: &[&str] = &[
        "", "'", "https://", "http://", "ws://", "data:", "*.", "//", " ", "'nonce-", "'sha256-",
        "'sha384-", "'sha512-",
    ];

    /// The body, chosen to sit on a rule boundary: the keywords, an empty label, a host that is
    /// only separators, non-ASCII, and base64 of the three digest lengths.
    const BODIES: &[&str] = &[
        "self",
        "unsafe-inline",
        "strict-dynamic",
        "wasm-unsafe-eval",
        "report-sample",
        "none",
        "example.com",
        "cdn.example.com",
        "*",
        "",
        "..",
        "-",
        "ünïcode.example",
        "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
        "OLBgp1GsljhM2TJ+sbHjaiH9txEUvgdDTAzHv2P24donTt6/529l+9Ua0vFImLlb",
        "abcd",
        "cnNkZ2p3ZW9pcmpnb2llcmpn",
        "script-src",
        "allow-scripts",
        "default",
    ];

    /// What can follow, including every character that would end the term early if it leaked into
    /// the rendered form.
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
        "\n",
        "=",
        "==",
        "\t",
        "\0",
        "%0d%0a",
    ];

    /// Builds one input from one to three concatenated fragments.
    fn generate(rng: &mut Rng) -> Vec<u8> {
        let fragments = 1 + rng.next() % 3;
        let mut input = String::new();
        for _ in 0..fragments {
            input.push_str(rng.pick(PREFIXES));
            input.push_str(rng.pick(BODIES));
            input.push_str(rng.pick(SUFFIXES));
        }
        input.into_bytes()
    }

    /// Raw bytes, for the targets that decode their input with `arbitrary` rather than reading it
    /// as text. Length varies so the decoder's short-input paths are reached as often as its
    /// deep ones.
    fn generate_bytes(rng: &mut Rng) -> Vec<u8> {
        let length = usize::try_from(rng.next() % 192).expect("fits");
        (0..length)
            .map(|_| u8::try_from(rng.next() & 0xff).expect("masked to a byte"))
            .collect()
    }

    /// The default budget per target. Large enough to pair most tokens, small enough that the
    /// suite stays a couple of seconds.
    const DEFAULT_ITERATIONS: usize = 4000;

    /// The budget, overridable so a longer hunt does not need a recompile.
    fn iterations() -> usize {
        std::env::var("CSP_FUZZ_ITERATIONS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(DEFAULT_ITERATIONS)
    }

    /// Runs `oracle` over the generated inputs, naming the one that fails.
    ///
    /// `catch_unwind` rather than a panic hook: a hook is process-global, these tests run in
    /// parallel, and the input it printed would belong to whichever sweep installed it last.
    /// `catch_unwind` attributes the failure to the iteration that actually produced it.
    ///
    /// The corpus replay above deliberately does *not* do this — there the file name is the
    /// context, and the harness already prints it.
    fn sweep(seed: u64, oracle: Oracle, generate: fn(&mut Rng) -> Vec<u8>) {
        let mut rng = Rng(seed);
        for iteration in 0..iterations() {
            let input = generate(&mut rng);
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| oracle(&input)));
            assert!(
                outcome.is_ok(),
                "seed {seed:#x}, iteration {iteration} failed on input: {:?}",
                String::from_utf8_lossy(&input)
            );
        }
    }

    #[test]
    fn parse_source_sweep() {
        sweep(0x5EED_0001, oracle::parse_source::check, generate);
    }

    #[test]
    fn parse_terms_sweep() {
        sweep(0x5EED_0002, oracle::parse_terms::check, generate);
    }

    #[test]
    fn build_policy_sweep() {
        sweep(0x5EED_0003, oracle::build_policy::check, generate_bytes);
    }
}
