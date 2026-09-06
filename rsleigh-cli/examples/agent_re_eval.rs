//! Deterministic RE task evaluation. Invoke with CLI path, output JSON, and
//! optional --baseline to use the pre-selector, two-command workflow.
#[path = "../../test-harness/fixtures/agent-re/cache_workload.rs"]
mod cache_workload;
#[path = "../../test-harness/fixtures/agent-re/seed.rs"]
mod seed;
use seed as re_seed;
#[path = "../../test-harness/fixtures/agent-re/corpus.rs"]
mod corpus;
#[path = "agent_re_eval/full_corpus.rs"]
mod full_corpus;
#[path = "../../test-harness/fixtures/agent-re/traversal.rs"]
mod traversal;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn invoke(tool: &Path, binary: &Path, args: &[String], root: &Path) -> Value {
    let out = root.join("stdout.json");
    let err = root.join("stderr.txt");
    let start = Instant::now();
    let mut child = Command::new(tool)
        .arg(binary)
        .args(args)
        .env_remove("RSLEIGH_OPAQUE_FOLD")
        .stdout(Stdio::from(std::fs::File::create(&out).unwrap()))
        .stderr(Stdio::from(std::fs::File::create(&err).unwrap()))
        .spawn()
        .expect("start CLI");
    let mut timeout = false;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if start.elapsed() > Duration::from_secs(30) {
            timeout = true;
            child.kill().unwrap();
            break child.wait().unwrap();
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    let bytes = std::fs::read(out).unwrap();
    json!({"args":args,"exit_code":status.code(),"timeout":timeout,
        "elapsed_us":start.elapsed().as_micros(),"stdout_bytes":bytes.len(),
        "stderr":std::fs::read_to_string(err).unwrap(),
        "output":serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null)})
}

// The baseline has only debug-text terminators. Parse their variable IDs here
// to reproduce the analyst's legacy dump-then-slice workflow. Production query
// code must resolve typed SSA directly instead.
fn ids(text: &str) -> Vec<u64> {
    text.split("VarId(")
        .skip(1)
        .filter_map(|s| s.split(')').next()?.parse().ok())
        .collect()
}

fn baseline_root(dump: &Value, task: &seed::Task) -> Option<u64> {
    let site = match task.selector {
        seed::Selector::Return(site)
        | seed::Selector::Argument(site, _)
        | seed::Selector::Condition(site) => site,
    };
    let block = dump["blocks"]
        .as_array()?
        .iter()
        .filter_map(|b| {
            let addr =
                u64::from_str_radix(b["addr"].as_str()?.trim_start_matches("0x"), 16).ok()?;
            (addr <= site).then_some((addr, b))
        })
        .max_by_key(|(addr, _)| *addr)?
        .1;
    let term = block["terminator"].as_str()?;
    match task.selector {
        seed::Selector::Return(_) if term.starts_with("Return(") => ids(term).first().copied(),
        seed::Selector::Condition(_) if term.starts_with("CBranch {") => ids(term).first().copied(),
        seed::Selector::Argument(_, index) if term.starts_with("Call {") => {
            let args = term.split("args: [").nth(1)?.split(']').next()?;
            ids(args).get(index).copied()
        }
        _ => None,
    }
}

fn origins_correct(output: &Value, task: &seed::Task, data: &[u8]) -> bool {
    let Some(nodes) = output["slice"]["nodes"].as_array() else {
        return false;
    };
    let Some(evidence) = output["evidence"]["operations"].as_array() else {
        return false;
    };
    // Addresses come from the hand-authored seed.asm, not pseudocode.
    let expected = match task.id {
        "return-seven" => 0x401000,
        "first-call-arg-zero" => 0x401022,
        "first-call-arg-one" => 0x401020,
        "second-call-arg-zero" => 0x40102e,
        "branch-input-unknown" => 0x401040,
        "first-return-site" => 0x401044,
        "second-return-site" => 0x40104a,
        _ => 0x401060,
    };
    if !nodes
        .first()
        .and_then(|n| n["origins"]["operations"].as_array())
        .is_some_and(|origins| origins.iter().any(|o| o["instruction_address"] == expected))
    {
        return false;
    }
    let mut decoder = rsleigh_api::Decoder::new(rsleigh_api::Architecture::X86_32);
    for node in nodes {
        let Some(origins) = node["origins"]["operations"].as_array() else {
            return false;
        };
        if origins.len() > 32 || (origins.is_empty() && !node["origins_unavailable"].is_string()) {
            return false;
        }
        for origin in origins {
            let Some(record) = evidence.iter().find(|r| &r["origin"] == origin) else {
                return false;
            };
            let Some(address) = origin["instruction_address"].as_u64() else {
                return false;
            };
            let Some(index) = origin["operation_index"].as_u64() else {
                return false;
            };
            let Some(relative) = address.checked_sub(0x401000) else {
                return false;
            };
            let Some(bytes) = data.get(0x200 + relative as usize..) else {
                return false;
            };
            let Ok(instruction) = decoder.decode_unoptimized(bytes, address) else {
                return false;
            };
            let Some(op) = instruction.ops.get(index as usize) else {
                return false;
            };
            if record["operation"] != serde_json::to_value(op).unwrap() {
                return false;
            }
        }
    }
    output["metrics"]["snapshot_id"]
        .as_str()
        .is_some_and(|s| s.len() == 64)
        && output["evidence"]["snapshot_id"] == output["metrics"]["snapshot_id"]
        && output["evidence"]["operation_stage"] == "raw-pcode/v1"
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert!(
        args.len() >= 3,
        "usage: agent_re_eval CLI OUTPUT.json [--full-corpus|--cache-benchmark] [--baseline] [--write-fixtures DIR]"
    );
    let tool = std::fs::canonicalize(&args[1]).expect("CLI path");
    let baseline = args.iter().any(|a| a == "--baseline");
    if let Some(index) = args.iter().position(|a| a == "--write-fixtures") {
        let directory = Path::new(args.get(index + 1).expect("--write-fixtures DIR"));
        std::fs::create_dir_all(directory).unwrap();
        for task in corpus::tasks() {
            std::fs::write(directory.join(task.fixture), task.data).unwrap();
        }
    }
    if args.iter().any(|a| a == "--full-corpus") {
        full_corpus::run(&tool, Path::new(&args[2]), baseline);
        return;
    }
    if args.iter().any(|a| a == "--cache-benchmark") {
        cache_benchmark(&tool, Path::new(&args[2]), baseline);
        return;
    }
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("rsleigh-re-eval-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let binary = root.join("seed.exe");
    let data = seed::binary();
    std::fs::write(&binary, &data).unwrap();
    let mut results = Vec::new();
    for task in seed::tasks() {
        for repetition in 0..3 {
            let mut commands = Vec::new();
            let mut query = vec!["--ssa-slice".into(), format!("0x{:x}", task.function)];
            let can_query = if baseline {
                let dump = invoke(
                    &tool,
                    &binary,
                    &["--ssa-json".into(), format!("0x{:x}", task.function)],
                    &root,
                );
                let root_id = baseline_root(&dump["output"], &task);
                commands.push(dump);
                if let Some(id) = root_id {
                    query.extend(["--var".into(), id.to_string()]);
                }
                root_id.is_some()
            } else {
                match task.selector {
                    seed::Selector::Return(site) => {
                        query.extend(["--return".into(), "--at".into(), format!("0x{site:x}")])
                    }
                    seed::Selector::Argument(site, index) => query.extend([
                        "--call-site".into(),
                        format!("0x{site:x}"),
                        "--arg".into(),
                        index.to_string(),
                    ]),
                    seed::Selector::Condition(site) => {
                        query.extend(["--condition".into(), format!("0x{site:x}")])
                    }
                }
                true
            };
            if can_query {
                commands.push(invoke(&tool, &binary, &query, &root));
            }
            let output = &commands.last().unwrap()["output"];
            let nodes = output["slice"]["nodes"].as_array();
            let correct = can_query
                && nodes.is_some_and(|nodes| {
                    if let Some(expected) = task.constant {
                        nodes.first().is_some_and(|n| n["constant"] == expected)
                    } else {
                        nodes
                            .iter()
                            .any(|n| n["boundary"].as_str() == task.boundary)
                            && output["slice"]["complete"] == false
                    }
                });
            let valid_exits = commands
                .iter()
                .all(|c| matches!(c["exit_code"].as_i64(), Some(0 | 2)) && c["timeout"] == false);
            results.push(json!({"task":task.id,"question":task.question,"architecture":"x86-32",
                "repetition":repetition,"cache_state":"disabled","answer_correct":correct && valid_exits,
                "evidence_correct":correct && valid_exits && output["file_sha256"] == format!("{:x}",Sha256::digest(&data))
                    && (baseline || origins_correct(output, &task, &data)),
                "command_count":commands.len(),
                "stdout_bytes":commands.iter().map(|c| c["stdout_bytes"].as_u64().unwrap()).sum::<u64>(),
                "elapsed_us":commands.iter().map(|c| c["elapsed_us"].as_u64().unwrap()).sum::<u64>(),
                "commands":commands}));
        }
    }
    let correct = results
        .iter()
        .filter(|r| r["answer_correct"] == true)
        .count();
    let evidence_correct = results
        .iter()
        .filter(|r| r["evidence_correct"] == true)
        .count();
    let report = json!({"schema":"rsleigh.agent-re-evaluation/v1","workflow":if baseline {"legacy"} else {"selectors"},
        "fixture_sha256":format!("{:x}",Sha256::digest(&data)),
        "tool_sha256":format!("{:x}",Sha256::digest(std::fs::read(&tool).unwrap())),
        "tool_path":tool,"host":std::env::consts::OS,"host_arch":std::env::consts::ARCH,
        "task_count":seed::tasks().len(),"repetitions":3,"correct_runs":correct,"evidence_correct_runs":evidence_correct,"results":results});
    std::fs::write(&args[2], serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    std::fs::remove_dir_all(root).unwrap();
    println!(
        "{correct}/{} correct runs; report: {}",
        seed::tasks().len() * 3,
        args[2]
    );
    if !baseline && (correct != seed::tasks().len() * 3 || evidence_correct != correct) {
        std::process::exit(1);
    }
}

fn directory_bytes(path: &Path) -> u64 {
    std::fs::read_dir(path)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            if path.is_dir() {
                directory_bytes(&path)
            } else {
                std::fs::metadata(path).unwrap().len()
            }
        })
        .sum()
}

fn cache_benchmark(tool: &Path, output: &Path, baseline: bool) {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root =
        std::env::temp_dir().join(format!("rsleigh-cache-eval-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let binary = root.join("cache.exe");
    let data = cache_workload::binary();
    std::fs::write(&binary, &data).unwrap();
    let args: Vec<String> = [
        "0x401000",
        "--card",
        "--json",
        "--pcode",
        "--operation-cursor",
        "120",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    let mut runs = Vec::new();
    for repetition in 0..3 {
        let uncached = invoke(tool, &binary, &args, &root);
        assert_eq!(uncached["exit_code"], 0, "{uncached}");
        if baseline {
            runs.push(json!({"repetition":repetition,"baseline":uncached}));
            continue;
        }
        let cache = root.join(format!("cache-{repetition}"));
        let mut cached_args = args.clone();
        cached_args.extend(["--analysis-cache".into(), cache.to_str().unwrap().into()]);
        let cold = invoke(tool, &binary, &cached_args, &root);
        let warm = invoke(tool, &binary, &cached_args, &root);
        assert_eq!(cold["exit_code"], 0, "{cold}");
        assert_eq!(warm["exit_code"], 0, "{warm}");
        assert_eq!(cold["output"]["metrics"]["cache"], "miss", "{cold}");
        assert_eq!(warm["output"]["metrics"]["cache"], "hit", "{warm}");
        assert_eq!(warm["output"]["metrics"]["ssa_builds"], 0);
        assert_eq!(warm["output"]["metrics"]["decode_builds"], 0);
        assert_eq!(cold["output"]["operations"], warm["output"]["operations"]);
        assert_eq!(
            uncached["output"]["operations"],
            warm["output"]["operations"]
        );
        assert_eq!(warm["output"]["operations"][0]["index"], 120);
        runs.push(json!({"repetition":repetition,"uncached":uncached,"cold":cold,"warm":warm,"cache_storage_bytes":directory_bytes(&cache)}));
    }
    let report = json!({"schema":"rsleigh.agent-re-cache-evaluation/v1","fixture_sha256":format!("{:x}",Sha256::digest(&data)),
        "tool_sha256":format!("{:x}",Sha256::digest(std::fs::read(tool).unwrap())),"host":std::env::consts::OS,"host_arch":std::env::consts::ARCH,
        "runs":runs});
    std::fs::write(output, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    std::fs::remove_dir_all(root).unwrap();
    println!(
        "3 cache benchmark repetitions verified; report: {}",
        output.display()
    );
}
