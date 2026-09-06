//! Immutable, verified cache generations for folded analysis snapshots.
use super::*;
use rsleigh_decompile::ir::{Expr, SsaCfg, SsaTerminator, Stmt, VarId};
use serde::{Deserialize, Serialize};
use std::io::Read;

const SCHEMA: &str = "rsleigh.analysis-cache/v1";
const MAX_SNAPSHOT_BYTES: u64 = 64 * 1024 * 1024;

/// Linker-assigned IDs identify the actual linked build without hashing the
/// executable on every query. Unsupported/ID-less images use a full SHA-256.
fn tool_build_id(executable: &Path) -> Result<Value, String> {
    let file = std::fs::File::open(executable).map_err(|e| e.to_string())?;
    let size = file.metadata().map_err(|e| e.to_string())?.len();
    let mut prefix = Vec::new();
    file.take(1024 * 1024)
        .read_to_end(&mut prefix)
        .map_err(|e| e.to_string())?;
    if let Ok(mach) = goblin::mach::MachO::parse_lossy(&prefix, 0) {
        for command in mach.load_commands {
            if let goblin::mach::load_command::CommandVariant::Uuid(uuid) = command.command {
                if uuid.uuid.iter().any(|b| *b != 0) {
                    let id = uuid
                        .uuid
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>();
                    return Ok(json!({"kind":"macho_uuid","id":id,"size":size}));
                }
            }
        }
    }
    let bytes = std::fs::read(executable).map_err(|e| e.to_string())?;
    if let Ok(goblin::Object::Elf(elf)) = goblin::Object::parse(&bytes) {
        if let Some(notes) = elf.iter_note_headers(&bytes) {
            for note in notes.flatten() {
                if note.n_type == goblin::elf::note::NT_GNU_BUILD_ID
                    && note.name == "GNU"
                    && !note.desc.is_empty()
                {
                    let id = note
                        .desc
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>();
                    return Ok(json!({"kind":"elf_build_id","id":id,"size":size}));
                }
            }
        }
    }
    Ok(json!({"kind":"sha256","id":compute_sha256(&bytes),"size":size}))
}

pub(super) fn identity(
    data: &[u8],
    address: u64,
    arch: rsleigh_api::Architecture,
    analysis: &str,
    auxiliary_inputs: Value,
) -> Result<Value, String> {
    let executable = std::env::current_exe().map_err(|e| e.to_string())?;
    Ok(json!({"binary_sha256":compute_sha256(data),
        "tool_build":tool_build_id(&executable)?,
        "architecture":format!("{arch:?}"),"function_address":address,"analysis":analysis,
        "opaque_fold":std::env::var("RSLEIGH_OPAQUE_FOLD").as_deref()==Ok("1"),
        "auxiliary_inputs":auxiliary_inputs}))
}

pub(super) fn publish_bytes(root: &Path, identity: &Value, bytes: Vec<u8>, metrics: &mut Value) {
    metrics["snapshot_bytes"] = json!(bytes.len());
    if rsleigh_decompile::budget::poll("cache").is_err() {
        metrics["cache_write_skipped"] = json!("execution_limit");
    } else if bytes.len() as u64 > MAX_SNAPSHOT_BYTES {
        metrics["cache_write_skipped"] = json!("snapshot_size_limit");
    } else if let Err(error) = index::publish(
        root,
        json!({"schema":SCHEMA,"status":"complete","identity":identity}),
        &[("snapshot.json", bytes)],
    ) {
        metrics["cache_write_error"] = json!(error.to_string());
    }
}

pub(super) enum Outcome {
    Complete(Snapshot),
    Stopped {
        instructions: Vec<DecodedInstruction>,
        diagnostics: Vec<Value>,
    },
}

pub(super) fn decoded(instructions: Vec<(u64, pcode_ir::Instruction)>) -> Vec<DecodedInstruction> {
    instructions.into_iter().map(|(address,inst)|DecodedInstruction {
        address,len:inst.len,disassembly:inst.disassembly,operations:inst.ops,
        constructor:inst.constructor.map(|c|json!({"source":c.source,"table_id":c.table_id,"constructor_id":c.constructor_id})),
    }).collect()
}

fn stop(
    instructions: Vec<DecodedInstruction>,
    mut diagnostics: Vec<Value>,
    mut metrics: Value,
) -> (Outcome, Value) {
    if let Some(stop) = rsleigh_decompile::budget::stopped() {
        if !diagnostics.iter().any(|d| d["code"] == "execution_limit") {
            diagnostics.push(json!({"stage":stop.stage,"code":"execution_limit","stop":stop}));
        }
    }
    metrics["execution"] = json!(rsleigh_decompile::budget::metrics());
    metrics["cache_write_skipped"] = json!("execution_limit");
    (
        Outcome::Stopped {
            instructions,
            diagnostics,
        },
        metrics,
    )
}

#[derive(Serialize, Deserialize)]
pub(super) struct DecodedInstruction {
    pub address: u64,
    pub len: u64,
    pub disassembly: String,
    pub operations: Vec<pcode_ir::PcodeOp>,
    // Owned metadata: restoring a cache must not leak strings to fabricate
    // the decoder's static ConstructorSpan lifetime.
    pub constructor: Option<Value>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct Snapshot {
    pub ssa: SsaCfg,
    pub instructions: Vec<DecodedInstruction>,
    pub diagnostics: Vec<Value>,
}

impl rsleigh_decompile::slice::interprocedural::Function for Snapshot {
    fn ssa(&self) -> &SsaCfg {
        &self.ssa
    }
    fn operation(
        &self,
        origin: rsleigh_decompile::provenance::OperationOrigin,
    ) -> Option<&pcode_ir::PcodeOp> {
        let index = self
            .instructions
            .binary_search_by_key(&origin.instruction_address, |i| i.address)
            .ok()?;
        self.instructions[index]
            .operations
            .get(origin.operation_index)
    }
}

impl Snapshot {
    fn validate(&self) -> Result<(), String> {
        if self.instructions.is_empty() || self.ssa.blocks.is_empty() {
            return Err("empty snapshot".into());
        }
        if self
            .instructions
            .windows(2)
            .any(|w| w[0].address >= w[1].address)
            || self.instructions.iter().any(|i| i.len == 0)
        {
            return Err("invalid instruction sequence".into());
        }
        let valid_var = |id: VarId| (id.0 as usize) < self.ssa.vars.len();
        let blocks: std::collections::HashSet<_> = self.ssa.blocks.iter().map(|b| b.id).collect();
        if blocks.len() != self.ssa.blocks.len() || !blocks.contains(&self.ssa.entry) {
            return Err("invalid block identities".into());
        }
        for (index, var) in self.ssa.vars.iter().enumerate() {
            if var.id.0 as usize != index || var.display_type.is_some() {
                return Err("invalid or unsupported variable metadata".into());
            }
            if var.origins.operations.len() > rsleigh_decompile::provenance::MAX_ORIGINS
                || var.origins.operations.windows(2).any(|w| w[0] >= w[1])
                || var.origins.operations.iter().any(|origin| {
                    self.instructions
                        .binary_search_by_key(&origin.instruction_address, |i| i.address)
                        .ok()
                        .and_then(|i| self.instructions[i].operations.get(origin.operation_index))
                        .is_none()
                })
            {
                return Err("invalid operation origins".into());
            }
            if let Some(rsleigh_decompile::memory::Access::Load {
                stores, boundary, ..
            }) = &var.memory
            {
                if stores.len() > 8
                    || stores.iter().any(|v| !valid_var(*v))
                    || (boundary.is_some() && !stores.is_empty())
                {
                    return Err("invalid memory dependencies".into());
                }
            }
            let inputs = match &var.expr {
                Expr::Var(v) | Expr::Load(v) | Expr::FieldAccess(v, _) | Expr::UnaryOp(_, v) => {
                    vec![*v]
                }
                Expr::BinOp(_, a, b) => vec![*a, *b],
                Expr::Phi(v) | Expr::UserOp { inputs: v, .. } => v.clone(),
                Expr::Ternary(c, a, b) => vec![*c, *a, *b],
                _ => vec![],
            };
            if !inputs.into_iter().all(valid_var) {
                return Err("dangling expression input".into());
            }
        }
        for block in &self.ssa.blocks {
            for stmt in &block.stmts {
                let valid = match stmt {
                    Stmt::Assign(v) => valid_var(*v),
                    Stmt::Store { addr, val } => valid_var(*addr) && valid_var(*val),
                    Stmt::Call { args, out, .. } => {
                        args.iter().copied().all(valid_var) && out.is_none_or(valid_var)
                    }
                };
                if !valid {
                    return Err("dangling statement input".into());
                }
            }
            let valid = match &block.terminator {
                SsaTerminator::Fallthrough(b) | SsaTerminator::Branch(b) => blocks.contains(b),
                SsaTerminator::CBranch {
                    cond,
                    taken,
                    fallthrough,
                } => valid_var(*cond) && blocks.contains(taken) && blocks.contains(fallthrough),
                SsaTerminator::Call {
                    args,
                    out,
                    fallthrough,
                    ..
                } => {
                    args.iter().copied().all(valid_var)
                        && out.is_none_or(valid_var)
                        && blocks.contains(fallthrough)
                }
                SsaTerminator::Return(v) => v.is_none_or(valid_var),
                SsaTerminator::Indirect(v) => valid_var(*v),
            };
            if !valid {
                return Err("dangling terminator input".into());
            }
        }
        Ok(())
    }
}

fn read_limited(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    if file.metadata().map_err(|e| e.to_string())?.len() > limit {
        return Err("cache artifact exceeds size limit".into());
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > limit {
        return Err("cache artifact exceeds size limit".into());
    }
    Ok(bytes)
}

pub(super) fn load_bytes(root: &Path, identity: &Value) -> Result<Vec<u8>, String> {
    let manifest_bytes = read_limited(&root.join("index.json"), 1024 * 1024)?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes).map_err(|e| e.to_string())?;
    if manifest["schema"] != SCHEMA
        || manifest["status"] != "complete"
        || manifest["identity"] != *identity
    {
        return Err("cache schema, completeness, or identity mismatch".into());
    }
    let generation = manifest["generation"]
        .as_str()
        .ok_or("missing cache generation")?;
    if generation.is_empty() || !generation.bytes().all(|b| b.is_ascii_digit() || b == b'-') {
        return Err("invalid generation name".into());
    }
    let directory = root.join("generations").join(generation);
    if read_limited(&directory.join("index.json"), 1024 * 1024)? != manifest_bytes {
        return Err("generation manifest mismatch".into());
    }
    let files = manifest["files"]
        .as_array()
        .ok_or("missing cache artifacts")?;
    if files.len() != 1
        || files[0]["name"] != "snapshot.json"
        || files[0]["path"] != format!("generations/{generation}/snapshot.json")
    {
        return Err("invalid cache artifact map".into());
    }
    let bytes = read_limited(&directory.join("snapshot.json"), MAX_SNAPSHOT_BYTES)?;
    if files[0]["size"].as_u64() != Some(bytes.len() as u64)
        || files[0]["sha256"] != compute_sha256(&bytes)
    {
        return Err("cache artifact size or checksum mismatch".into());
    }
    Ok(bytes)
}

fn load(root: &Path, identity: &Value) -> Result<Snapshot, String> {
    let snapshot: Snapshot =
        serde_json::from_slice(&load_bytes(root, identity)?).map_err(|e| e.to_string())?;
    snapshot.validate()?;
    if !snapshot.diagnostics.is_empty() {
        return Err("incomplete decode snapshot".into());
    }
    Ok(snapshot)
}

pub(super) fn analyze(
    data: &[u8],
    address: u64,
    arch: rsleigh_api::Architecture,
    args: &[String],
) -> Result<(Outcome, Value), String> {
    let cache_dir = value_arg(args, "--analysis-cache")?;
    if rsleigh_decompile::budget::poll("cache").is_err() {
        return Ok(stop(
            vec![],
            vec![],
            json!({"cache":if cache_dir.is_some(){"skipped"}else{"disabled"},"decode_builds":0,"ssa_builds":0}),
        ));
    }
    let identity = Some(identity(
        data,
        address,
        arch,
        "post-fold/v3",
        json!("none: folded_ssa consumes only binary content and decoded instructions"),
    )?);
    let key = identity
        .as_ref()
        .map(|id| compute_sha256(&serde_json::to_vec(id).unwrap()));
    let root = cache_dir
        .zip(key.as_ref())
        .map(|(dir, key)| Path::new(dir).join(key));
    let mut metrics = json!({"cache":if root.is_some(){"miss"}else{"disabled"},"snapshot_id":key,
        "decode_builds":0,"ssa_builds":0,"decoded_instructions":0,"ssa_variables":0});
    if let Some(root) = &root {
        match load(root, identity.as_ref().unwrap()) {
            Ok(snapshot) => {
                let mut metrics = json!({"cache":"hit","snapshot_id":key,"decode_builds":0,"ssa_builds":0,"decoded_instructions":0,"ssa_variables":0});
                if rsleigh_decompile::budget::poll("cache").is_err() {
                    return Ok(stop(snapshot.instructions, snapshot.diagnostics, metrics));
                }
                metrics["execution"] = json!(rsleigh_decompile::budget::metrics());
                return Ok((Outcome::Complete(snapshot), metrics));
            }
            Err(reason) => metrics["cache_miss_reason"] = json!(reason),
        }
    }
    let (instructions, diagnostics) = ssa_instructions(data, address)?;
    metrics["decode_builds"] = json!(1);
    metrics["decoded_instructions"] = json!(instructions.len());
    if rsleigh_decompile::budget::stopped().is_some() {
        return Ok(stop(decoded(instructions), diagnostics, metrics));
    }
    metrics["ssa_builds"] = json!(1);
    let ssa = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rsleigh_decompile::folded_ssa(arch, &instructions, Some(data))
    })) {
        Ok(ssa) => ssa,
        Err(_) if rsleigh_decompile::budget::stopped().is_some() => {
            return Ok(stop(decoded(instructions), diagnostics, metrics))
        }
        Err(_) => return Err("SSA construction or folding panicked".into()),
    };
    if rsleigh_decompile::budget::poll("ssa").is_err() {
        return Ok(stop(decoded(instructions), diagnostics, metrics));
    }
    metrics["ssa_variables"] = json!(ssa.vars.len());
    let snapshot = Snapshot {
        ssa,
        diagnostics,
        instructions: decoded(instructions),
    };
    if let Some(root) = &root {
        if snapshot.diagnostics.is_empty() && snapshot.validate().is_ok() {
            let bytes = serde_json::to_vec(&snapshot).map_err(|e| e.to_string())?;
            if rsleigh_decompile::budget::poll("cache").is_err() {
                return Ok(stop(snapshot.instructions, snapshot.diagnostics, metrics));
            }
            metrics["snapshot_bytes"] = json!(bytes.len());
            if bytes.len() as u64 <= MAX_SNAPSHOT_BYTES {
                let manifest = json!({"schema":SCHEMA,"status":"complete","identity":identity});
                if let Err(error) = index::publish(root, manifest, &[("snapshot.json", bytes)]) {
                    metrics["cache_write_error"] = json!(error.to_string());
                }
            } else {
                metrics["cache_write_skipped"] = json!("snapshot_size_limit");
            }
        } else {
            metrics["cache_write_skipped"] = json!("incomplete_or_unsupported_snapshot");
        }
    }
    metrics["execution"] = json!(rsleigh_decompile::budget::metrics());
    Ok((Outcome::Complete(snapshot), metrics))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_validation_rejects_dangling_and_unbounded_origins() {
        use pcode_ir::{Instruction, PcodeOp, Varnode};
        use rsleigh_decompile::provenance::OperationOrigin;
        let instructions = vec![(
            0x1000,
            Instruction {
                len: 1,
                disassembly: "mov eax,7".into(),
                constructor: None,
                ops: vec![PcodeOp::Copy {
                    out: Varnode::register(0, 4),
                    input: Varnode::constant(7, 4),
                }],
            },
        )];
        let ssa =
            rsleigh_decompile::folded_ssa(rsleigh_api::Architecture::X86_32, &instructions, None);
        let mut snapshot = Snapshot {
            ssa,
            instructions: decoded(instructions),
            diagnostics: vec![],
        };
        snapshot.validate().unwrap();
        let origin = OperationOrigin {
            instruction_address: 0x1000,
            operation_index: 0,
        };
        for operations in [
            vec![OperationOrigin {
                operation_index: 99,
                ..origin
            }],
            vec![OperationOrigin {
                instruction_address: 0x2000,
                ..origin
            }],
            vec![origin; 33],
            vec![origin; 2],
        ] {
            snapshot.ssa.vars[0].origins.operations = operations;
            assert_eq!(
                snapshot.validate().unwrap_err(),
                "invalid operation origins"
            );
        }
    }

    #[test]
    fn tool_identity_tracks_macho_and_elf_linker_builds_with_hash_fallback() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "rsleigh-build-identity-{}-{nonce}",
            std::process::id()
        ));
        let mut mach = vec![0u8; 56];
        for (offset, value) in [
            (0, 0xfeedfacfu32),
            (4, 0x0100000c),
            (12, 2),
            (16, 1),
            (20, 24),
            (32, 0x1b),
            (36, 24),
        ] {
            mach[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        mach[40..56].fill(1);
        std::fs::write(&path, &mach).unwrap();
        let first = tool_build_id(&path).unwrap();
        assert_eq!(first["kind"], "macho_uuid");
        mach[40..56].fill(2);
        std::fs::write(&path, &mach).unwrap();
        assert_ne!(first, tool_build_id(&path).unwrap());
        let mut elf = vec![0u8; 156];
        elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        for (offset, value) in [(16, 2u16), (18, 62), (52, 64), (54, 56), (56, 1)] {
            elf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        for (offset, value) in [(20, 1u32), (64, 4), (120, 4), (124, 20), (128, 3)] {
            elf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        for (offset, value) in [(32, 64u64), (72, 120), (96, 36), (104, 36), (112, 4)] {
            elf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        elf[132..136].copy_from_slice(b"GNU\0");
        elf[136..].fill(3);
        std::fs::write(&path, elf).unwrap();
        let identity = tool_build_id(&path).unwrap();
        assert_eq!(identity["kind"], "elf_build_id");
        assert_eq!(identity["id"], "03".repeat(20));
        std::fs::write(&path, b"no build ID").unwrap();
        let identity = tool_build_id(&path).unwrap();
        assert_eq!(identity["kind"], "sha256");
        assert_eq!(identity["id"], compute_sha256(b"no build ID"));
        std::fs::remove_file(path).unwrap();
    }
}
