use std::path::Path;

use quote::ToTokens;

use proc_macro2::TokenStream;

use sleigh_rs::{file_to_sleigh, SleighError};

mod builder;
use builder::Disassembler;

pub(crate) use sleigh_rs::{DisassemblyType, NonZeroTypeU, NumberSuperSigned};
pub(crate) const DISASSEMBLY_ALLOW_OVERFLOW: bool = true;

fn disassembler(
    file: impl AsRef<Path>,
    debug: bool,
) -> Result<TokenStream, Box<SleighError>> {
    let sleigh = file_to_sleigh(file.as_ref())?;
    Ok(Disassembler::new(sleigh, debug).into_token_stream())
}

pub fn generate_disassembler(
    file: impl AsRef<Path>,
) -> Result<TokenStream, Box<SleighError>> {
    disassembler(file, false)
}

pub fn generate_debug_disassembler(
    file: impl AsRef<Path>,
) -> Result<TokenStream, Box<SleighError>> {
    disassembler(file, true)
}

/// A named chunk of generated code suitable for writing to a separate file.
pub struct GeneratedModule {
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
