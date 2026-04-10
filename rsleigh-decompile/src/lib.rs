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
/// Returns a C-like pseudocode string.
pub fn decompile(arch: Architecture, instructions: &[(u64, Instruction)]) -> String {
    if instructions.is_empty() {
        return "// empty function\n".to_string();
    }

    // Pass 1: Build CFG
    let cfg = cfg::build_cfg(instructions);
    if cfg.blocks.is_empty() {
        return "// no blocks\n".to_string();
    }

    // Pass 2: SSA construction
    let mut ssa = ssa::build_ssa(&cfg);

    // Pass 3: Expression folding
    fold::fold(&mut ssa);

    // Pass 4: Structure recovery
    let structured = structure::recover_structure(&ssa, &cfg);

    // Pass 5: C printer
    printer::print_c(&structured, &ssa, arch)
}
