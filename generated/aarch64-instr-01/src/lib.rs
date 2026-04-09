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
pub use aarch64_shared::*;
pub use aarch64_subtables::*;
include!("../out/batch.rs");
