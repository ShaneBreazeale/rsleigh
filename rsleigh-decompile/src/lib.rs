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

    let cfg = cfg::build_cfg(instructions);
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

    if let Some(ref debug_info) = debug_info {
        let func_addr = instructions[0].0;
        if let Some(info) = debug_info.get(&func_addr) {
            for v in &mut ssa.vars {
                if let Some(ref param_name) = v.param_name {
                    if let Some(idx) = param_name.strip_prefix("param_").and_then(|s| s.parse::<usize>().ok()) {
                        if let Some(dwarf_name) = info.param_names.get(idx) {
                            v.param_name = Some(dwarf_name.clone());
                        }
                    }
                }
            }
        }
    }

    let structured = structure::recover_structure(&ssa, &cfg);
    printer::print_c(&structured, &ssa, arch, binary, &import_map)
}
