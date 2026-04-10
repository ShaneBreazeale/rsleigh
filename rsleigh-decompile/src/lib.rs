pub mod ir;
pub mod cfg;
pub mod ssa;
pub mod fold;
pub mod dominators;
pub mod structure;
pub mod printer;

use pcode_ir::Instruction;
use rsleigh_api::Architecture;

/// Decompile a function's instructions into C-like pseudocode.
///
/// `instructions` should be sorted by address and cover a single function.
/// `binary` is optional raw binary data for string literal resolution.
/// Returns a C-like pseudocode string.
pub fn decompile(arch: Architecture, instructions: &[(u64, Instruction)]) -> String {
    decompile_with_binary(arch, instructions, None)
}

/// Decompile with optional binary data for string literal detection.
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

    let mut ssa = ssa::build_ssa(&cfg);
    fold::fold(&mut ssa);
    let structured = structure::recover_structure(&ssa, &cfg);
    printer::print_c(&structured, &ssa, arch, binary)
}
