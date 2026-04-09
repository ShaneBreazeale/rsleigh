use std::path::Path;

use quote::ToTokens;

use proc_macro2::TokenStream;

use crate::{file_to_sleigh, SleighError};

mod builder;
use builder::Disassembler;

pub(crate) const DISASSEMBLY_ALLOW_OVERFLOW: bool = true;

fn disassembler(file: impl AsRef<Path>, debug: bool) -> Result<TokenStream, Box<SleighError>> {
    let sleigh = file_to_sleigh(file.as_ref())?;
    Ok(Disassembler::new(sleigh, debug).into_token_stream())
}

pub fn generate_disassembler(file: impl AsRef<Path>) -> Result<TokenStream, Box<SleighError>> {
    disassembler(file, false)
}

pub fn generate_debug_disassembler(
    file: impl AsRef<Path>,
) -> Result<TokenStream, Box<SleighError>> {
    disassembler(file, true)
}

/// A named chunk of generated code suitable for writing to a separate file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GeneratedModuleKind {
    Shared,
    TableBatch,
    /// A self-contained table (constructors + enum in one module).
    TableEnum,
    /// The enum half of a split table — references types from TableBatch modules
    /// and must be placed in a crate that depends on the batch crates.
    SplitTableEnum,
    Root,
}

pub struct GeneratedModule {
    /// Semantic role of the generated module.
    pub kind: GeneratedModuleKind,
    /// True if this module belongs to the instruction table (table 0).
    /// Only meaningful for TableBatch and SplitTableEnum kinds.
    pub is_instruction_table: bool,
    /// Filename (without path), e.g. "shared.rs", "table_0.rs", "root.rs"
    pub filename: String,
    /// The generated Rust source code as a TokenStream. For "root.rs" this
    /// may be empty — use `raw_code` instead (contains `include!()` macros
    /// with literal paths).
    pub code: TokenStream,
    /// Raw string code (used for root.rs which needs literal include paths).
    pub raw_code: Option<String>,
}

/// Generate the disassembler split into multiple files for faster compilation.
///
/// Returns a list of `GeneratedModule`s. Write each `.code` to
/// `out_dir/filename`. Then in your crate, include the root:
///
/// ```ignore
/// mod generated {
///     include!(concat!(env!("OUT_DIR"), "/x86_64/root.rs"));
/// }
/// ```
///
/// The `out_dir` parameter is the absolute path where files will live,
/// embedded in `include!()` paths in root.rs.
pub fn generate_split_disassembler(
    file: impl AsRef<Path>,
    tables_per_file: usize,
    out_dir: &str,
) -> Result<Vec<GeneratedModule>, Box<SleighError>> {
    let sleigh = file_to_sleigh(file.as_ref())?;
    let dis = Disassembler::new(sleigh, false);
    Ok(dis.to_split_modules(tables_per_file, out_dir))
}
