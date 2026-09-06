//! Full source-backed corpus evaluation; called by agent_re_eval --full-corpus.
use super::{
    baseline_root,
    corpus::{self, Answer, Task},
    directory_bytes, invoke, seed,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

fn value(nodes: &[Value], context: u64, id: u64, active: &mut HashSet<(u64, u64)>) -> Option<u64> {
    if !active.insert((context, id)) {
        return None;
    }
    let node = nodes
        .iter()
        .find(|n| n["var_id"] == id && n["context_id"].as_u64().unwrap_or(0) == context)?;
    let result = (|| {
        if let Some(v) = node["constant"].as_u64() {
            return Some(v);
        }
        if node["boundary"].as_str().is_some() {
            return None;
        }
        if let Some(links) = node["links"].as_array().filter(|ls| !ls.is_empty()) {
            let mut values = links.iter().map(|l| {
                if !l["stop_reason"].is_null() {
                    return None;
                }
                value(
                    nodes,
                    l["target"]["context_id"].as_u64()?,
                    l["target"]["var_id"].as_u64()?,
                    active,
                )
            });
            let first = values.next()??;
            return values.all(|v| v == Some(first)).then_some(first);
        }
        let inputs = node["inputs"].as_array()?;
        let mut values = inputs.iter().map(|i| {
            if !i["stop_reason"].is_null() {
                return None;
            }
            value(nodes, context, i["var_id"].as_u64()?, active)
        });
        let first = values.next()??;
        match node["kind"].as_str()? {
            "var" | "unary.Zext" => Some(first),
            "phi" => values.all(|v| v == Some(first)).then_some(first),
            "binary.Add" => Some(first.wrapping_add(values.next()??)),
            "binary.Sub" => Some(first.wrapping_sub(values.next()??)),
            _ => None,
        }
    })();
    active.remove(&(context, id));
    result
}
fn answer(output: &Value, task: &Task, baseline: bool) -> bool {
    let Some(nodes) = output["slice"]["nodes"].as_array() else {
        return false;
    };
    match task.answer {
        Answer::Constant(expected) | Answer::Helper(expected) => {
            value(
                nodes,
                0,
                output["slice"]["root"].as_u64().unwrap_or(u64::MAX),
                &mut HashSet::new(),
            ) == Some(expected)
        }
        Answer::Unknown(boundary) => {
            output["slice"]["complete"] == false
                && nodes.iter().any(|n| {
                    n["boundary"] == boundary
                        || (baseline
                            && match boundary {
                                "recursion_limit" => n["boundary"] == "unmodeled_call",
                                "ambiguous_alias" => n["boundary"] == "unmodeled_memory",
                                _ => false,
                            })
                })
        }
        Answer::Comparison(constant) => {
            nodes.iter().any(|n| n["constant"] == constant)
                && nodes
                    .iter()
                    .any(|n| matches!(n["kind"].as_str(), Some("binary.Eq" | "binary.NotEq")))
                && output["slice"]["complete"] == false
        }
        Answer::Dispatch(target) => nodes.iter().any(|n| {
            n["call"]["target_address"] == target
                && n["call"]["resolution"] == "cfg_resolved_indirect"
                && n["call"]["confidence"] == "heuristic"
        }),
    }
}
fn evidence(output: &Value, task: &Task) -> bool {
    if output["file_sha256"] != format!("{:x}", Sha256::digest(&task.data)) {
        return false;
    }
    let (Some(nodes), Some(records), Some(functions)) = (
        output["slice"]["nodes"].as_array(),
        output["evidence"]["operations"].as_array(),
        output["evidence"]["functions"].as_array(),
    ) else {
        return false;
    };
    let mut decoder = rsleigh_api::Decoder::new(task.architecture);
    let mut addresses = HashSet::new();
    for n in nodes {
        let Some(origins) = n["origins"]["operations"].as_array() else {
            return false;
        };
        if origins.len() > 32 || (origins.is_empty() && !n["origins_unavailable"].is_string()) {
            return false;
        }
        for o in origins {
            let Some(record) = records
                .iter()
                .find(|r| r["origin"] == *o && r["function_address"] == n["function_address"])
            else {
                return false;
            };
            if !functions.iter().any(|f| {
                f["function_address"] == record["function_address"]
                    && f["snapshot_id"] == record["snapshot_id"]
                    && f["snapshot_id"].as_str().is_some_and(|s| s.len() == 64)
            }) {
                return false;
            }
            let (Some(addr), Some(index)) = (
                o["instruction_address"].as_u64(),
                o["operation_index"].as_u64(),
            ) else {
                return false;
            };
            let Some(relative) = addr.checked_sub(0x401000) else {
                return false;
            };
            let Some(bytes) = task.data.get(task.text_offset + relative as usize..) else {
                return false;
            };
            let Ok(instruction) = decoder.decode_unoptimized(bytes, addr) else {
                return false;
            };
            let Some(op) = instruction.ops.get(index as usize) else {
                return false;
            };
            if record["operation"] != serde_json::to_value(op).unwrap() {
                return false;
            }
            addresses.insert(addr);
        }
    }
    task.evidence_addresses
        .iter()
        .all(|a| addresses.contains(a))
        && output["evidence"]["snapshot_id"] == output["metrics"]["snapshot_id"]
        && output["evidence"]["operation_stage"] == "raw-pcode/v1"
}
fn query(task: &Task) -> Vec<String> {
    let mut args = vec!["--ssa-slice".into(), format!("0x{:x}", task.function)];
    match task.selector {
        seed::Selector::Return(at) => {
            args.extend(["--return".into(), "--at".into(), format!("0x{at:x}")])
        }
        seed::Selector::Argument(at, index) => args.extend([
            "--call-site".into(),
            format!("0x{at:x}"),
            "--arg".into(),
            index.to_string(),
        ]),
        seed::Selector::Condition(at) => args.extend(["--condition".into(), format!("0x{at:x}")]),
    }
    args
}
pub fn run(tool: &Path, report_path: &Path, baseline: bool) {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root =
        std::env::temp_dir().join(format!("rsleigh-full-eval-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let tasks = corpus::tasks();
    let mut results = vec![];
    for task in &tasks {
        let binary = root.join(task.fixture);
        std::fs::write(&binary, &task.data).unwrap();
        for repetition in 0..3 {
            let cache = root.join(format!("cache-{}-{repetition}", task.id));
            let mut reference = Value::Null;
            for state in if baseline {
                &["disabled"][..]
            } else {
                &["disabled", "cold", "warm"][..]
            } {
                let mut commands = vec![];
                let mut args = query(task);
                let mut can_query = true;
                let mut legacy_dispatch_answer = None;
                if baseline {
                    let dump = invoke(
                        tool,
                        &binary,
                        &["--ssa-json".into(), format!("0x{:x}", task.function)],
                        &root,
                    );
                    let legacy = seed::Task {
                        id: task.id,
                        question: task.question,
                        function: task.function,
                        selector: task.selector,
                        constant: None,
                        boundary: None,
                    };
                    let selected = baseline_root(&dump["output"], &legacy);
                    if let Answer::Dispatch(expected) = task.answer {
                        // The legacy dump already exposes a resolved call target.
                        // Credit that answer without requiring v3 metadata or an
                        // unnecessary return-value slice for a dispatch question.
                        let targets: Vec<_> = dump["output"]["blocks"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .filter_map(|b| {
                                b["terminator"]
                                    .as_str()?
                                    .strip_prefix("Call { target: Direct(")?
                                    .split(')')
                                    .next()?
                                    .parse::<u64>()
                                    .ok()
                            })
                            .collect();
                        legacy_dispatch_answer = Some(targets == vec![expected]);
                    }
                    commands.push(dump);
                    args = vec!["--ssa-slice".into(), format!("0x{:x}", task.function)];
                    if let Some(id) = selected {
                        args.extend(["--var".into(), id.to_string()]);
                    } else {
                        can_query = false;
                    }
                    if legacy_dispatch_answer.is_some() {
                        can_query = false;
                    }
                } else if *state != "disabled" {
                    args.extend(["--analysis-cache".into(), cache.to_str().unwrap().into()]);
                    if *state == "warm" {
                        args.extend([
                            "--max-ssa-work".into(),
                            "0".into(),
                            "--max-decode-instructions".into(),
                            "0".into(),
                        ]);
                    }
                }
                if can_query {
                    commands.push(invoke(tool, &binary, &args, &root));
                }
                let output = commands.last().unwrap()["output"].clone();
                let answer_correct = legacy_dispatch_answer
                    .unwrap_or_else(|| can_query && answer(&output, task, baseline));
                // Legacy snapshots have no retained raw operation origins. Record
                // their answer separately; absent origin evidence is not a pass.
                let evidence_correct = answer_correct && !baseline && evidence(&output, task);
                let valid = commands.iter().all(|c| {
                    matches!(c["exit_code"].as_i64(), Some(0 | 2)) && c["timeout"] == false
                });
                let equal = baseline
                    || *state == "disabled"
                    || (output["slice"] == reference["slice"]
                        && output["evidence"] == reference["evidence"]);
                if *state == "disabled" {
                    reference = output.clone();
                }
                let warm_avoids_work = *state != "warm"
                    || (output["metrics"]["execution"]["decode_instructions"] == 0
                        && output["metrics"]["execution"]["ssa_work"] == 0
                        && output["metrics"]["functions"].as_array().is_some_and(|fs| {
                            !fs.is_empty()
                                && fs.iter().all(|f| {
                                    f["metrics"]["cache"] == "hit"
                                        && f["metrics"]["ssa_builds"] == 0
                                })
                        }));
                results.push(json!({"task":task.id,"question":task.question,"architecture":task.architecture_name(),"fixture":task.fixture,
                    "expected_answer":task.answer,"origin_evidence_available":!baseline && output["evidence"]["operations"].is_array(),
                    "fixture_sha256":format!("{:x}",Sha256::digest(&task.data)),"expected_unresolved":matches!(task.answer,Answer::Unknown(_)),
                    "repetition":repetition,"cache_state":state,"answer_correct":answer_correct && valid,"evidence_correct":evidence_correct && valid,
                    "cache_equivalent":equal,"warm_avoids_work":warm_avoids_work,
                    "command_count":commands.len(),"stdout_bytes":commands.iter().map(|c|c["stdout_bytes"].as_u64().unwrap()).sum::<u64>(),
                    "elapsed_us":commands.iter().map(|c|c["elapsed_us"].as_u64().unwrap()).sum::<u64>(),
                    "cache_storage_bytes":if cache.exists(){directory_bytes(&cache)}else{0},"commands":commands}));
            }
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
    let checks = results.iter().all(|r| {
        r["answer_correct"] == true
            && r["evidence_correct"] == true
            && r["cache_equivalent"] == true
            && r["warm_avoids_work"] == true
    });
    let report = json!({"schema":"rsleigh.agent-re-evaluation/v2","workflow":if baseline {"legacy"} else {"semantic-contexts"},
        "tool_sha256":format!("{:x}",Sha256::digest(std::fs::read(tool).unwrap())),"tool_path":tool,
        "host":std::env::consts::OS,"host_arch":std::env::consts::ARCH,"task_count":tasks.len(),"repetitions":3,
        "correct_runs":correct,"evidence_correct_runs":evidence_correct,"results":results});
    std::fs::write(report_path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    std::fs::remove_dir_all(root).unwrap();
    println!(
        "{correct}/{} answers; {evidence_correct} origin checks; report {}",
        report["results"].as_array().unwrap().len(),
        report_path.display()
    );
    if !baseline && !checks {
        std::process::exit(1);
    }
}
