//! Decompiler-output regression against the Kuna / Ghidra datatest corpus.
//!
//! rsleigh's other oracles compare P-code. This one checks decompiled C: each
//! XML case is raw bytes + a Ghidra language id + a script (`lo fu f`,
//! `decompile`, `print C`) + `<stringmatch>` regex assertions over the output.
//!
//! Corpus: Kuna (https://github.com/Noelo-Lab/kuna, Apache-2.0)
//! `tests/datatests/` (Ghidra's own regression tests) and `tests/stages/`
//! (Kuna's issue testcases). Fetch with `scripts/fetch-kuna-tests.sh`; the
//! pinned commit and the passing set live in `fixtures/kuna-baseline.json`.
//!
//! Matching follows Ghidra's `FunctionTestProperty`: a pattern is one regex per
//! line, it matches when its lines match consecutive output lines, and a case
//! passes when every pattern's match count is within `[min, max]`.
//!
//! Normalization is deliberately strict: only naming conventions are mapped
//! (see `normalize_output` / `normalize_pattern`), never structure, types of
//! different width, or whitespace. A case that passes computed the same text.
//!
//! Cases are skipped, not failed, when rsleigh cannot run them as written:
//! unsupported architecture, or scripts that need decompiler options, C
//! declarations or symbol edits (`option`, `parse`, `map`, `rename`, ...).
//!
//! Env:
//!   KUNA_TESTS_DIR                corpus root (default fixtures/kuna-tests)
//!   RSLEIGH_REQUIRE_KUNA_TESTS=1  fail instead of skipping when it is missing
//!   RSLEIGH_KUNA_BLESS=1          rewrite the baseline with the current passes
//!   RSLEIGH_KUNA_FILTER=substr    only run case ids containing substr
//!   RSLEIGH_KUNA_REPORT=path      write per-case JSON (default target/kuna-datatests.json)

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use regex::Regex;
use rsleigh_api::{Architecture, Decoder};
use serde::{Deserialize, Serialize};

const CASE_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_FUNC_BYTES: usize = 4096;
const MAX_IMAGE_BYTES: u64 = 64 << 20;
const NORMALIZATION: &str = "strict-v1";

fn harness_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn baseline_path() -> PathBuf {
    harness_dir().join("fixtures/kuna-baseline.json")
}

#[derive(Serialize, Deserialize)]
struct Baseline {
    kuna_commit: String,
    normalization: String,
    passing: Vec<String>,
}

/// Which corpus a case came from; decides the parameter naming convention.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Corpus {
    /// Ghidra datatests: `param_1`, `param_2`, ...
    Ghidra,
    /// Kuna stages: `a0`, `a1`, ...
    Kuna,
}

#[derive(Clone, Debug)]
enum Cmd {
    Load(String),
    Decompile,
    PrintC,
    Thumb,
}

struct Pattern {
    name: String,
    min: u32,
    max: u32,
    lines: Vec<Regex>,
}

struct Case {
    id: String,
    corpus: Corpus,
    arch: Architecture,
    cortex: bool,
    chunks: Vec<(u64, Vec<u8>)>,
    symbols: Vec<(u64, String)>,
    script: Vec<Cmd>,
    patterns: Vec<Pattern>,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Outcome {
    Pass,
    Fail { failed: Vec<String>, output: String },
    Skip { reason: String },
    Timeout,
    Panic { message: String },
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

fn map_arch(lang: &str) -> Result<(Architecture, bool), String> {
    let parts: Vec<&str> = lang.split(':').collect();
    let (proc, endian, size, variant) = (
        parts.first().copied().unwrap_or(""),
        parts.get(1).copied().unwrap_or(""),
        parts.get(2).copied().unwrap_or(""),
        parts.get(3).copied().unwrap_or(""),
    );
    match (proc, endian, size) {
        ("x86", "LE", "64") => Ok((Architecture::X86_64, false)),
        ("x86", "LE", "32") => Ok((Architecture::X86_32, false)),
        ("AARCH64", "LE", "64") => Ok((Architecture::AArch64, false)),
        ("ARM", "LE", "32") => Ok((Architecture::ARM32, variant == "Cortex")),
        ("MIPS", "BE", "32") if variant == "default" => Ok((Architecture::MIPS32, false)),
        ("RISCV", "LE", "64") => Ok((Architecture::RiscV64, false)),
        _ => Err(format!("arch {lang}")),
    }
}

fn parse_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}

fn parse_hex_bytes(text: &str) -> Option<Vec<u8>> {
    let digits: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if digits.len() % 2 != 0 {
        return None;
    }
    digits
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).ok()?, 16).ok())
        .collect()
}

/// Script commands rsleigh can run. Anything that configures the decompiler
/// or feeds it declarations makes the case non-portable.
fn parse_command(cmd: &str) -> Result<Option<Cmd>, String> {
    let words: Vec<&str> = cmd.split_whitespace().collect();
    match words.as_slice() {
        [] | ["quit"] | ["read", "symbols"] | ["clear", "architecture"] | ["functions"] => Ok(None),
        ["lo", "fu", name] | ["load", "function" | "addr", name] => {
            Ok(Some(Cmd::Load(name.to_string())))
        }
        ["decompile"] | ["dec"] => Ok(Some(Cmd::Decompile)),
        ["print", "C"] => Ok(Some(Cmd::PrintC)),
        ["set", "context", "TMode", "1", ..] => Ok(Some(Cmd::Thumb)),
        [first, rest @ ..] => {
            let what = match (*first, rest.first()) {
                ("option" | "map" | "set", Some(sub)) => format!("{first} {sub}"),
                _ => first.to_string(),
            };
            Err(format!("command `{what}`"))
        }
    }
}

/// Ghidra pattern lines: leading spaces/tabs stripped per line, blank tail dropped.
fn pattern_lines(text: &str) -> Vec<String> {
    let mut lines: Vec<String> = text
        .split('\n')
        .map(|l| l.trim_start_matches([' ', '\t']).to_string())
        .collect();
    while lines.last().is_some_and(|l| l.trim().is_empty()) {
        lines.pop();
    }
    lines
}

fn parse_case(path: &Path, corpus: Corpus, id: String) -> Result<Case, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("read: {e}"))?;
    let doc = roxmltree::Document::parse(&text).map_err(|e| format!("xml: {e}"))?;
    let image = doc
        .descendants()
        .find(|n| n.has_tag_name("binaryimage"))
        .ok_or("no <binaryimage>")?;
    let (arch, cortex) = map_arch(image.attribute("arch").unwrap_or(""))?;

    let mut chunks = Vec::new();
    let mut symbols = Vec::new();
    for n in image.children().filter(|n| n.is_element()) {
        let offset = n.attribute("offset").and_then(parse_u64);
        match n.tag_name().name() {
            "bytechunk" => {
                let bytes = parse_hex_bytes(n.text().unwrap_or("")).ok_or("bad bytechunk")?;
                chunks.push((offset.ok_or("bytechunk offset")?, bytes));
            }
            "symbol" => {
                symbols.push((
                    offset.ok_or("symbol offset")?,
                    n.attribute("name").unwrap_or("").to_string(),
                ));
            }
            other => return Err(format!("image tag <{other}>")),
        }
    }
    if chunks.is_empty() {
        return Err("no bytes".into());
    }

    let mut script = Vec::new();
    for com in doc.descendants().filter(|n| n.has_tag_name("com")) {
        if let Some(cmd) = parse_command(com.text().unwrap_or(""))? {
            script.push(cmd);
        }
    }

    let var_name = Regex::new(r"\b[a-z]{1,4}Var[0-9]+\b").unwrap();
    let mut patterns = Vec::new();
    for sm in doc.descendants().filter(|n| n.has_tag_name("stringmatch")) {
        let name = sm.attribute("name").unwrap_or("").to_string();
        let lines = pattern_lines(sm.text().unwrap_or(""))
            .iter()
            .map(|l| Regex::new(&var_name.replace_all(l, "[a-z]{1,4}Var[0-9]+")))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("regex `{name}`: {e}"))?;
        if lines.is_empty() {
            continue;
        }
        patterns.push(Pattern {
            min: sm.attribute("min").and_then(|s| s.parse().ok()).unwrap_or(1),
            max: sm.attribute("max").and_then(|s| s.parse().ok()).unwrap_or(u32::MAX),
            name,
            lines,
        });
    }
    if patterns.is_empty() {
        return Err("no assertions".into());
    }

    Ok(Case {
        id,
        corpus,
        arch,
        cortex,
        chunks,
        symbols,
        script,
        patterns,
    })
}

// ---------------------------------------------------------------------------
// Running
// ---------------------------------------------------------------------------

/// Flat image spanning all chunks; gaps are zero.
fn build_image(chunks: &[(u64, Vec<u8>)]) -> Result<(u64, Vec<u8>), String> {
    let base = chunks.iter().map(|(a, _)| *a).min().unwrap();
    let end = chunks.iter().map(|(a, b)| a + b.len() as u64).max().unwrap();
    if end - base > MAX_IMAGE_BYTES {
        return Err(format!("image spans {:#x} bytes", end - base));
    }
    let mut image = vec![0u8; (end - base) as usize];
    for (addr, bytes) in chunks {
        let off = (addr - base) as usize;
        image[off..off + bytes.len()].copy_from_slice(bytes);
    }
    Ok((base, image))
}

fn decompile_at(case: &Case, base: u64, image: &[u8], addr: u64, thumb: bool) -> String {
    // A function ends at the next known symbol or at the end of its chunk.
    let chunk_end = case
        .chunks
        .iter()
        .find(|(a, b)| addr >= *a && addr < a + b.len() as u64)
        .map(|(a, b)| a + b.len() as u64)
        .unwrap_or(addr);
    let next_sym = case
        .symbols
        .iter()
        .map(|(a, _)| *a)
        .filter(|a| *a > addr)
        .min()
        .unwrap_or(u64::MAX);
    let end = chunk_end.min(next_sym).min(addr + MAX_FUNC_BYTES as u64);

    let mut dec = Decoder::new(case.arch);
    if case.arch == Architecture::ARM32 {
        dec.set_arm_thumb(thumb);
    }
    let step = if thumb { 2 } else { 4 };
    let mut insts = Vec::new();
    let mut pc = addr;
    while pc < end {
        let off = (pc - base) as usize;
        match dec.decode(&image[off..], pc) {
            Ok(inst) if inst.len > 0 => {
                pc += inst.len;
                insts.push((pc - inst.len, inst));
            }
            _ => pc += step,
        }
    }
    rsleigh_decompile::decompile_with_binary(case.arch, &insts, Some(image), None)
}

fn run_script(case: &Case) -> Result<String, String> {
    let (base, image) = build_image(&case.chunks)?;
    let thumb = case.cortex || case.script.iter().any(|c| matches!(c, Cmd::Thumb));
    let mut current = None;
    let mut last = String::new();
    let mut out = String::new();
    for cmd in &case.script {
        match cmd {
            Cmd::Load(name) => {
                let addr = case
                    .symbols
                    .iter()
                    .find(|(_, n)| n == name)
                    .map(|(a, _)| *a)
                    .or_else(|| parse_u64(name))
                    .ok_or_else(|| format!("unknown function `{name}`"))?;
                current = Some(addr);
            }
            Cmd::Decompile => {
                let addr = current.ok_or("decompile before load")?;
                last = decompile_at(case, base, &image, addr, thumb);
            }
            Cmd::PrintC => {
                out.push_str(&normalize_output(&last, case));
                out.push('\n');
            }
            Cmd::Thumb => {}
        }
    }
    Ok(out)
}

/// Map rsleigh naming onto the reference corpus's conventions. Names only.
fn normalize_output(text: &str, case: &Case) -> String {
    let sym = |addr: u64| case.symbols.iter().find(|(a, _)| *a == addr).map(|(_, n)| n.clone());

    let func = Regex::new(r"\b(?:func|FUN)_([0-9a-fA-F]+)\b").unwrap();
    let text = func.replace_all(text, |c: &regex::Captures| {
        u64::from_str_radix(&c[1], 16)
            .ok()
            .and_then(sym)
            .unwrap_or_else(|| c[0].to_string())
    });

    let param = Regex::new(r"\bparam_([0-9]+)\b").unwrap();
    let text = param.replace_all(&text, |c: &regex::Captures| {
        let n: u32 = c[1].parse().unwrap_or(0);
        match case.corpus {
            Corpus::Ghidra => format!("param_{}", n + 1),
            Corpus::Kuna => format!("a{n}"),
        }
    });

    let dat = Regex::new(r"\bDAT_0*([0-9a-fA-F]+)\b").unwrap();
    let text = dat.replace_all(&text, |c: &regex::Captures| format!("dat_{}", c[1].to_lowercase()));

    let ty = Regex::new(r"\b(u?)int(8|16|32|64)_t\b").unwrap();
    ty.replace_all(&text, |c: &regex::Captures| {
        let bytes: u32 = c[2].parse::<u32>().unwrap() / 8;
        format!("{}int{bytes}", &c[1])
    })
    .into_owned()
}

fn evaluate(case: &Case, output: &str) -> Vec<String> {
    let mut failed = Vec::new();
    for p in &case.patterns {
        let (mut count, mut at) = (0u32, 0usize);
        for line in output.lines() {
            if p.lines[at].is_match(line) {
                at += 1;
                if at == p.lines.len() {
                    count += 1;
                    at = 0;
                }
            } else if at > 0 {
                at = usize::from(p.lines[0].is_match(line));
            }
        }
        if count < p.min || count > p.max {
            failed.push(format!("{} (matched {count}, want {}..={})", p.name, p.min, p.max));
        }
    }
    failed
}

fn run_case(case: Case) -> Outcome {
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name(case.id.clone())
        .stack_size(64 << 20)
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                match run_script(&case) {
                    Err(reason) => Outcome::Skip { reason },
                    Ok(output) => {
                        let failed = evaluate(&case, &output);
                        if failed.is_empty() {
                            Outcome::Pass
                        } else {
                            Outcome::Fail { failed, output }
                        }
                    }
                }
            }));
            let _ = tx.send(result.unwrap_or_else(|e| Outcome::Panic {
                message: e
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_default(),
            }));
        })
        .expect("spawn case thread");
    // A hung decompile cannot be killed; its thread is abandoned.
    rx.recv_timeout(CASE_TIMEOUT).unwrap_or(Outcome::Timeout)
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

fn corpus_root() -> Option<PathBuf> {
    let root = std::env::var_os("KUNA_TESTS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| harness_dir().join("fixtures/kuna-tests"));
    if root.join("datatests").is_dir() {
        return Some(root);
    }
    if std::env::var_os("RSLEIGH_REQUIRE_KUNA_TESTS").is_some() {
        panic!("kuna corpus missing at {}; run scripts/fetch-kuna-tests.sh", root.display());
    }
    eprintln!("[skip] kuna corpus missing at {}; run scripts/fetch-kuna-tests.sh", root.display());
    None
}

fn list_cases(root: &Path) -> Vec<(PathBuf, Corpus, String)> {
    let mut cases = Vec::new();
    for (dir, corpus) in [("datatests", Corpus::Ghidra), ("stages", Corpus::Kuna)] {
        let Ok(entries) = std::fs::read_dir(root.join(dir)) else { continue };
        for e in entries.flatten() {
            let path = e.path();
            if path.extension().is_some_and(|x| x == "xml") {
                let stem = path.file_stem().unwrap().to_string_lossy();
                cases.push((path.clone(), corpus, format!("{dir}/{stem}")));
            }
        }
    }
    cases.sort_by(|a, b| a.2.cmp(&b.2));
    cases
}

#[test]
fn kuna_datatests_no_regressions() {
    let Some(root) = corpus_root() else { return };
    let filter = std::env::var("RSLEIGH_KUNA_FILTER").ok();

    let mut results: BTreeMap<String, Outcome> = BTreeMap::new();
    for (path, corpus, id) in list_cases(&root) {
        if filter.as_deref().is_some_and(|f| !id.contains(f)) {
            continue;
        }
        let outcome = match parse_case(&path, corpus, id.clone()) {
            Ok(case) => run_case(case),
            Err(reason) => Outcome::Skip { reason },
        };
        results.insert(id, outcome);
    }

    // Summary: status counts, then skip reasons.
    let mut status: BTreeMap<&str, usize> = BTreeMap::new();
    let mut skips: BTreeMap<String, usize> = BTreeMap::new();
    for o in results.values() {
        let s = match o {
            Outcome::Pass => "pass",
            Outcome::Fail { .. } => "fail",
            Outcome::Timeout => "timeout",
            Outcome::Panic { .. } => "panic",
            Outcome::Skip { reason } => {
                *skips.entry(reason.split(':').next().unwrap().to_string()).or_default() += 1;
                "skip"
            }
        };
        *status.entry(s).or_default() += 1;
    }
    let ran = results.len() - status.get("skip").copied().unwrap_or(0);
    eprintln!("kuna datatests ({NORMALIZATION}): {} cases, {ran} ran", results.len());
    for (s, n) in &status {
        eprintln!("  {s:8} {n}");
    }
    let mut skips: Vec<_> = skips.into_iter().collect();
    skips.sort_by(|a, b| b.1.cmp(&a.1));
    for (reason, n) in skips.iter().take(15) {
        eprintln!("  skip {n:4}  {reason}");
    }

    let report = std::env::var_os("RSLEIGH_KUNA_REPORT")
        .map(PathBuf::from)
        .unwrap_or_else(|| harness_dir().join("../target/kuna-datatests.json"));
    if let Ok(json) = serde_json::to_string_pretty(&results) {
        let _ = std::fs::write(&report, json);
        eprintln!("  report   {}", report.display());
    }

    let passing: Vec<String> = results
        .iter()
        .filter(|(_, o)| **o == Outcome::Pass)
        .map(|(id, _)| id.clone())
        .collect();

    if std::env::var_os("RSLEIGH_KUNA_BLESS").is_some() {
        assert!(filter.is_none(), "bless the full corpus, not a filtered run");
        let commit = std::fs::read_to_string(root.join("COMMIT"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let baseline = Baseline {
            kuna_commit: commit,
            normalization: NORMALIZATION.into(),
            passing,
        };
        let json = serde_json::to_string_pretty(&baseline).unwrap() + "\n";
        std::fs::write(baseline_path(), json).expect("write baseline");
        eprintln!("  blessed  {} passing cases", baseline.passing.len());
        return;
    }

    let baseline: Baseline = serde_json::from_str(
        &std::fs::read_to_string(baseline_path()).expect("read kuna-baseline.json"),
    )
    .expect("parse kuna-baseline.json");
    assert_eq!(baseline.normalization, NORMALIZATION, "normalization changed; re-bless");

    let regressed: Vec<String> = baseline
        .passing
        .iter()
        .filter(|id| filter.as_deref().map_or(true, |f| id.contains(f)))
        .filter(|id| results.get(*id) != Some(&Outcome::Pass))
        .map(|id| format!("{id}: {:?}", results.get(id)))
        .collect();
    let gained = passing.iter().filter(|id| !baseline.passing.contains(id)).count();
    if gained > 0 {
        eprintln!("  {gained} newly passing; RSLEIGH_KUNA_BLESS=1 to record them");
    }
    assert!(regressed.is_empty(), "regressed cases:\n{}", regressed.join("\n"));
}
