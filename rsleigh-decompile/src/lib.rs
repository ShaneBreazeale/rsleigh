pub mod ir;
pub mod cfg;
pub mod ssa;
pub mod fold;
pub mod dominators;
pub mod structure;
pub mod printer;
pub mod imports;
pub mod dwarf;
pub mod pdb_info;
pub mod signatures;
pub mod eqsat;
pub mod analysis;
pub mod cpp_class;
mod signatures_libc;
mod signatures_win32;

use std::path::Path;
use pcode_ir::Instruction;
use rsleigh_api::Architecture;

/// Detect calling convention from binary format and architecture.
fn detect_cc(arch: Architecture, binary: Option<&[u8]>) -> fold::CallingConv {
    if let Some(binary) = binary {
        if let Ok(goblin::Object::PE(pe)) = goblin::Object::parse(binary) {
            return if pe.is_64 {
                fold::CallingConv::Win64
            } else {
                fold::CallingConv::Cdecl32
            };
        }
    }
    match arch {
        Architecture::X86_32 | Architecture::ARM32 | Architecture::MIPS32 => fold::CallingConv::Cdecl32,
        Architecture::AArch64 => fold::CallingConv::AArch64,
        _ => fold::CallingConv::SysV,
    }
}

/// Decompile a function's instructions into C-like pseudocode.
pub fn decompile(arch: Architecture, instructions: &[(u64, Instruction)]) -> String {
    decompile_with_binary(arch, instructions, None, None)
}

/// Decompile with optional binary data for string literals and import resolution.
/// If `binary_path` is provided, DWARF debug info will be extracted (including from
/// macOS .dSYM bundles) to recover parameter and local variable names.
pub fn decompile_with_binary(
    arch: Architecture,
    instructions: &[(u64, Instruction)],
    binary: Option<&[u8]>,
    binary_path: Option<&Path>,
) -> String {
    if instructions.is_empty() {
        return "// empty function\n".to_string();
    }

    // Pass instructions through unchanged — intra-instruction CBranch (CSEL/CMOV)
    // patterns are handled by the SSA builder as Expr::Ternary, not as CFG branches.
    let expanded: Vec<(u64, pcode_ir::Instruction)> = instructions.to_vec();

    let cfg = cfg::build_cfg(&expanded);
    if cfg.blocks.is_empty() {
        return "// no blocks\n".to_string();
    }

    let import_map = binary
        .map(|b| imports::resolve_imports(b))
        .unwrap_or_default();

    let cc = detect_cc(arch, binary);
    let mut ssa = ssa::build_ssa_with_cc(&cfg, cc);

    fold::fold_with_cc(&mut ssa, cc);

    // Apply function signature parameter names and return types
    fold::apply_signature_names(&mut ssa, &import_map);
    fold::propagate_signature_return_types(&mut ssa, &import_map);

    // Apply DWARF debug info if available: replace param_N with actual names
    let debug_info = if let Some(path) = binary_path {
        let info = dwarf::parse_dwarf_from_path(path);
        if !info.is_empty() { Some(info) } else { None }
    } else if let Some(binary) = binary {
        let info = dwarf::parse_dwarf(binary);
        if !info.is_empty() { Some(info) } else { None }
    } else {
        None
    };

    // Try PDB debug info for PE binaries when DWARF is absent
    let (pdb_debug_info, pdb_struct_fields) = if debug_info.is_none() {
        if let Some(path) = binary_path {
            pdb_info::parse_pdb_from_path(path)
        } else {
            (std::collections::HashMap::new(), std::collections::HashMap::new())
        }
    } else {
        (std::collections::HashMap::new(), std::collections::HashMap::new())
    };

    // Merge: prefer DWARF, fall back to PDB
    let effective_debug_info = if debug_info.is_some() {
        debug_info.clone()
    } else if !pdb_debug_info.is_empty() {
        Some(pdb_debug_info)
    } else {
        None
    };

    // Build local variable name map from debug info: var_N → actual_name
    let mut local_var_names = std::collections::HashMap::new();
    if let Some(ref debug_info) = effective_debug_info {
        let func_addr = instructions[0].0;
        if let Some(info) = debug_info.get(&func_addr) {
            // Apply parameter names
            for v in &mut ssa.vars {
                if let Some(ref param_name) = v.param_name {
                    if let Some(idx) = param_name.strip_prefix("param_").and_then(|s| s.parse::<usize>().ok()) {
                        if let Some(dwarf_name) = info.param_names.get(idx) {
                            v.param_name = Some(dwarf_name.clone());
                        }
                    }
                }
            }
            // Build local variable name map: fbreg/stack offset → var_N name
            // Try both the direct mapping and an 8-byte adjusted mapping
            // (some toolchains have a consistent 8-byte offset between DWARF and actual layout)
            for (offset, name) in &info.local_names {
                if *offset < 0 {
                    let positive = (-offset) as u64;
                    let var_name = format!("var_{:x}", positive);
                    local_var_names.insert(var_name, name.clone());
                    // Also try with 8-byte adjustment (CFA vs RBP frame base mismatch)
                    let adjusted = positive + 8;
                    let adj_name = format!("var_{:x}", adjusted);
                    local_var_names.entry(adj_name).or_insert_with(|| name.clone());
                } else if *offset > 0 {
                    let var_name = format!("var_{:x}", *offset as u64);
                    local_var_names.insert(var_name, name.clone());
                }
            }
        }
    }

    // Parse struct field names from DWARF, then PDB
    let mut struct_fields = if let Some(path) = binary_path {
        dwarf::parse_struct_fields_from_path(path)
    } else if let Some(binary) = binary {
        dwarf::parse_struct_fields(binary)
    } else {
        std::collections::HashMap::new()
    };
    // Merge PDB struct fields (don't overwrite DWARF fields)
    for (offset, name) in pdb_struct_fields {
        struct_fields.entry(offset).or_insert(name);
    }

    // Resolve function name from import map or DWARF
    let func_addr = instructions[0].0;
    let func_name = import_map.get(&func_addr).cloned()
        .or_else(|| debug_info.as_ref().and_then(|di| di.get(&func_addr).and_then(|f|
            Some(f.param_names.first()?.clone()))).and(None)) // DWARF doesn't have func name easily
        .unwrap_or_else(|| format!("func_{:x}", func_addr));

    let structured = structure::recover_structure(&ssa, &cfg);
    printer::print_c(&structured, &ssa, arch, binary, &import_map, &local_var_names, &struct_fields, &func_name)
}

/// Learned type information for a function, extracted after decompilation.
/// Used for two-pass interprocedural type propagation.
#[derive(Debug, Clone)]
pub struct LearnedFuncType {
    pub addr: u64,
    pub param_types: Vec<Option<&'static str>>,  // display_type per param (None = unknown)
    pub return_type: Option<&'static str>,         // display_type of return value
}

/// Extract type information from a function's SSA (after fold pass).
/// Call this after decompile_with_binary to learn parameter/return types,
/// then register them as synthetic signatures for the second pass.
pub fn extract_learned_types(
    arch: Architecture,
    instructions: &[(u64, Instruction)],
    binary: Option<&[u8]>,
) -> Option<LearnedFuncType> {
    if instructions.is_empty() { return None; }

    let mut expanded = Vec::new();
    for (addr, inst) in instructions {
        expanded.push((*addr, inst.clone()));
    }

    let cfg = cfg::build_cfg(&expanded);
    if cfg.blocks.is_empty() { return None; }

    let import_map = binary
        .map(|b| imports::resolve_imports(b))
        .unwrap_or_default();

    let cc = detect_cc(arch, binary);
    let mut ssa = ssa::build_ssa_with_cc(&cfg, cc);

    fold::fold_with_cc(&mut ssa, cc);
    fold::apply_signature_names(&mut ssa, &import_map);
    fold::propagate_signature_return_types(&mut ssa, &import_map);

    let func_addr = instructions[0].0;

    // Collect parameter types
    let mut params: Vec<(u32, Option<&'static str>)> = Vec::new();
    for v in &ssa.vars {
        if let Some(ref name) = v.param_name {
            if let Some(idx) = name.strip_prefix("param_").and_then(|s| s.parse::<u32>().ok()) {
                params.push((idx, v.display_type));
            }
        }
    }
    params.sort_by_key(|(idx, _)| *idx);
    params.dedup_by_key(|(idx, _)| *idx);
    let param_types: Vec<Option<&'static str>> = params.into_iter().map(|(_, dt)| dt).collect();

    // Collect return type
    let mut return_type = None;
    for block in &ssa.blocks {
        if let ir::SsaTerminator::Return(Some(v)) = &block.terminator {
            let vdef = ssa.var(*v);
            if let Some(dt) = vdef.display_type {
                return_type = Some(dt);
            }
            break;
        }
    }

    // Also detect non-void return even without display_type:
    // If any Return terminator has Some(var), the function returns a value.
    let has_return_val = ssa.blocks.iter().any(|b|
        matches!(&b.terminator, ir::SsaTerminator::Return(Some(_))));
    if has_return_val && return_type.is_none() {
        // We know it returns something, just don't know the display type.
        // Mark as "int" (conservative — better than void).
        return_type = Some("int");
    }

    // Only return if we learned something useful
    if param_types.iter().any(|t| t.is_some()) || return_type.is_some() {
        Some(LearnedFuncType { addr: func_addr, param_types, return_type })
    } else {
        None
    }
}

/// Learned struct parameter: records that a function's parameter was identified as a struct pointer.
/// Used for cross-function struct propagation in two-pass decompilation.
#[derive(Debug, Clone)]
pub struct LearnedStructParam {
    pub func_addr: u64,
    pub param_index: u32,
    pub struct_name: String,
}

/// Extract struct parameter identifications from decompiled output.
/// Parses "// param_N is STRUCT_NAME *" comments emitted by the printer's struct identification.
/// Also parses call sites to learn which arguments are struct pointers, enabling
/// propagation to callees.
pub fn extract_learned_structs(
    func_addr: u64,
    output: &str,
) -> Vec<LearnedStructParam> {
    let mut results = Vec::new();

    for line in output.lines() {
        let t = line.trim();
        // Match: "// param_N is STRUCT_NAME *"
        if let Some(rest) = t.strip_prefix("// param_") {
            if let Some(is_pos) = rest.find(" is ") {
                if let Ok(idx) = rest[..is_pos].parse::<u32>() {
                    let struct_part = &rest[is_pos + 4..];
                    let struct_name = struct_part.trim().trim_end_matches('*').trim();
                    if !struct_name.is_empty() {
                        results.push(LearnedStructParam {
                            func_addr,
                            param_index: idx,
                            struct_name: struct_name.to_string(),
                        });
                    }
                }
            }
        }
    }

    results
}

/// Analyze call sites in a function's SSA to infer which callees return non-void.
/// Returns a list of (callee_addr, inferred_return_type) pairs.
///
/// A callee is non-void if the caller:
/// - Reads the call return register (EAX/RAX) after the call
/// - Uses the result in a comparison, store, or as an argument to another call
pub fn infer_returns_from_callsites(
    arch: Architecture,
    instructions: &[(u64, Instruction)],
    binary: Option<&[u8]>,
) -> Vec<(u64, &'static str)> {
    if instructions.is_empty() { return Vec::new(); }

    let mut expanded = Vec::new();
    for (addr, inst) in instructions {
        expanded.push((*addr, inst.clone()));
    }
    let cfg_result = cfg::build_cfg(&expanded);
    if cfg_result.blocks.is_empty() { return Vec::new(); }

    let import_map = binary.map(|b| imports::resolve_imports(b)).unwrap_or_default();
    let cc = detect_cc(arch, binary);
    let mut ssa = ssa::build_ssa_with_cc(&cfg_result, cc);

    fold::fold_with_cc(&mut ssa, cc);

    let mut results = Vec::new();

    // Check Call terminators: if the fallthrough block reads EAX, the call returns a value
    for bi in 0..ssa.blocks.len() {
        let (target_addr, ft) = match &ssa.blocks[bi].terminator {
            ir::SsaTerminator::Call { target: ir::CallTarget::Direct(addr), fallthrough, .. } => {
                (*addr, fallthrough.0)
            }
            _ => continue,
        };

        // Skip known imports (they already have signatures)
        if import_map.contains_key(&target_addr) { continue; }

        // Check if the fallthrough block reads the call return register
        if ft < ssa.blocks.len() {
            for stmt in &ssa.blocks[ft].stmts {
                if let ir::Stmt::Assign(var_id) = stmt {
                    let vdef = &ssa.vars[var_id.0 as usize];
                    if vdef.call_return && vdef.use_count > 0 {
                        // The return value is used — callee is not void
                        results.push((target_addr, "int"));
                        break;
                    }
                }
            }
        }
    }

    // Also check Stmt::Call with out variable that has use_count > 0
    for block in &ssa.blocks {
        for stmt in &block.stmts {
            if let ir::Stmt::Call { target: ir::CallTarget::Direct(addr), out: Some(out_var), .. } = stmt {
                if import_map.contains_key(addr) { continue; }
                let vdef = &ssa.vars[out_var.0 as usize];
                if vdef.use_count > 0 {
                    results.push((*addr, "int"));
                }
            }
        }
    }

    results.sort_by_key(|(addr, _)| *addr);
    results.dedup_by_key(|(addr, _)| *addr);
    results
}
