#![allow(
    unused_comparisons,
    unused_assignments,
    non_camel_case_types,
    non_snake_case,
    unused_variables,
    unused_mut,
    unused_parens,
    unused_imports,
    clippy::all
)]
pub use x86_instr_00::*;
pub use x86_instr_01::*;
pub use x86_instr_02::*;
pub use x86_instr_03::*;
pub use x86_instr_04::*;
pub use x86_instr_05::*;
pub use x86_instr_06::*;
pub use x86_instr_07::*;
pub use x86_shared::*;
pub use x86_subtables::*;
include!("../out/root.rs");
