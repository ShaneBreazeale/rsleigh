pub mod ir;
pub mod cfg;
pub mod ssa;
pub mod fold;
pub mod dominators;
pub mod structure;
pub mod printer;
pub mod imports;
pub mod dwarf;

use std::path::Path;
use pcode_ir::Instruction;
use rsleigh_api::Architecture;

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

    // Preprocess: expand intra-instruction CBranches (CMOV, CSEL) into
    // separate instruction entries so the CFG builder creates proper branches.
    let mut expanded: Vec<(u64, pcode_ir::Instruction)> = Vec::new();
    for (addr, inst) in instructions {
        // Look for CBranch(Const, cond) within the instruction's ops
        let cbranch_idx = inst.ops.iter().position(|op| matches!(op,
            pcode_ir::PcodeOp::CBranch { dest, .. }
                if dest.space == pcode_ir::AddressSpaceId::Const));

        if let Some(ci) = cbranch_idx {
            if let pcode_ir::PcodeOp::CBranch { dest, cond } = &inst.ops[ci] {
                let target = dest.offset;
                // The ops after the CBranch are conditional
                if ci + 1 < inst.ops.len() {
                    // Split into: [pre-ops + CBranch(Ram, target)] and [post-ops + Branch(target)]
                    let mut pre_ops: Vec<pcode_ir::PcodeOp> = inst.ops[..ci].to_vec();
                    let post_ops: Vec<pcode_ir::PcodeOp> = inst.ops[ci + 1..].to_vec();

                    // CBranch to target in RAM space so the CFG builder handles it
                    pre_ops.push(pcode_ir::PcodeOp::CBranch {
                        dest: pcode_ir::Varnode { space: pcode_ir::AddressSpaceId::Ram, offset: target, size: dest.size },
                        cond: *cond,
                    });

                    expanded.push((*addr, pcode_ir::Instruction {
                        ops: pre_ops,
                        len: 1, // Synthetic: 1-byte so next_addr = addr + 1
                        disassembly: String::new(),
                    }));

                    // Fallthrough: the conditional ops at a synthetic address
                    // Use addr+1 since the pre part has len=0, giving space for the fallthrough
                    let mut fall_ops = post_ops;
                    // Add unconditional branch to the real target
                    fall_ops.push(pcode_ir::PcodeOp::Branch {
                        dest: pcode_ir::Varnode { space: pcode_ir::AddressSpaceId::Ram, offset: target, size: dest.size },
                    });

                    // Use a synthetic address between this instruction and the next
                    // The CBranch target IS the next real instruction, so the fallthrough
                    // block sits between this addr and the target
                    let synth_addr = *addr + 1; // +1 byte offset as synthetic
                    expanded.push((synth_addr, pcode_ir::Instruction {
                        ops: fall_ops,
                        len: (target - synth_addr).max(1), // span to the target
                        disassembly: String::new(),
                    }));
                    continue;
                }
            }
        }

        expanded.push((*addr, inst.clone()));
    }

    let cfg = cfg::build_cfg(&expanded);
    if cfg.blocks.is_empty() {
        return "// no blocks\n".to_string();
    }

    let import_map = binary
        .map(|b| imports::resolve_imports(b))
        .unwrap_or_default();

    let mut ssa = ssa::build_ssa(&cfg);
    fold::fold(&mut ssa);

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

    // Build local variable name map from DWARF: var_N → actual_name
    let mut local_var_names = std::collections::HashMap::new();
    if let Some(ref debug_info) = debug_info {
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
            // Build local variable name map: DWARF fbreg offset → var_N name
            // Try both the direct mapping and an 8-byte adjusted mapping
            // (some toolchains have a consistent 8-byte offset between DWARF and actual layout)
            for (dwarf_offset, name) in &info.local_names {
                if *dwarf_offset < 0 {
                    let positive = (-dwarf_offset) as u64;
                    let var_name = format!("var_{:x}", positive);
                    local_var_names.insert(var_name, name.clone());
                    // Also try with 8-byte adjustment (CFA vs RBP frame base mismatch)
                    let adjusted = positive + 8;
                    let adj_name = format!("var_{:x}", adjusted);
                    local_var_names.entry(adj_name).or_insert_with(|| name.clone());
                } else if *dwarf_offset > 0 {
                    let var_name = format!("var_{:x}", *dwarf_offset as u64);
                    local_var_names.insert(var_name, name.clone());
                }
            }
        }
    }

    // Parse struct field names from DWARF
    let struct_fields = if let Some(path) = binary_path {
        dwarf::parse_struct_fields_from_path(path)
    } else if let Some(binary) = binary {
        dwarf::parse_struct_fields(binary)
    } else {
        std::collections::HashMap::new()
    };

    // Resolve function name from import map or DWARF
    let func_addr = instructions[0].0;
    let func_name = import_map.get(&func_addr).cloned()
        .or_else(|| debug_info.as_ref().and_then(|di| di.get(&func_addr).and_then(|f|
            Some(f.param_names.first()?.clone()))).and(None)) // DWARF doesn't have func name easily
        .unwrap_or_else(|| format!("func_{:x}", func_addr));

    let structured = structure::recover_structure(&ssa, &cfg);
    printer::print_c(&structured, &ssa, arch, binary, &import_map, &local_var_names, &struct_fields, &func_name)
}
