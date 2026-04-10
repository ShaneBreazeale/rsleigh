pub mod ir;
pub mod cfg;
pub mod ssa;
pub mod fold;
pub mod dominators;
pub mod structure;
pub mod printer;
pub mod imports;

use pcode_ir::Instruction;
use rsleigh_api::Architecture;

/// Decompile a function's instructions into C-like pseudocode.
pub fn decompile(arch: Architecture, instructions: &[(u64, Instruction)]) -> String {
    decompile_with_binary(arch, instructions, None)
}

/// Decompile with optional binary data for string literals and import resolution.
pub fn decompile_with_binary(
    arch: Architecture,
    instructions: &[(u64, Instruction)],
    binary: Option<&[u8]>,
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
    let structured = structure::recover_structure(&ssa, &cfg);
    printer::print_c(&structured, &ssa, arch, binary, &import_map)
}
