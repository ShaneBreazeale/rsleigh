use proc_macro2::{Ident, TokenStream};

use quote::{format_ident, quote, ToTokens};

use super::{
    ContextMemory, DisplayElement, Meanings, RegistersEnum, TokenFieldFunction,
    TokenFieldFunctions, WorkType,
};

mod table;
pub use table::*;

mod constructor;
pub use constructor::*;

pub struct Disassembler {
    pub debug: bool,
    //enum with all the registers used (or possibly used) by the to display
    pub registers: RegistersEnum,
    //all the interger -> interger/name/register translations,
    //AKA `attach values/names/variables`
    pub meanings: Meanings,
    //all possible display elements: Literal/Register/Value
    pub display: DisplayElement,
    //all tables, that will implement parser/disassembly/display
    pub tables: Vec<TableEnum>,
    pub token_field_functions: TokenFieldFunctions,
    pub addr_type: Ident,
    pub inst_work_type: WorkType,
    pub context: ContextMemory,
    //make sure sleigh is not droped, so the inner references are not dropped
    pub sleigh: sleigh_rs::Sleigh,
}

impl Disassembler {
    pub fn new(sleigh: sleigh_rs::Sleigh, debug: bool) -> Self {
        let registers =
            RegistersEnum::from_all(format_ident!("Register"), &sleigh);
        //TODO make sleigh to include all the meanings on the struct?
        //TODO removing the borrow in attach will simplifi this a lot
        let inst_work_type = WorkType::unsigned_from_bytes(
            sleigh.addr_bytes().get().try_into().unwrap(),
        );

        let display = DisplayElement::new(format_ident!("DisplayElement"));

        let meanings = Meanings::new(&sleigh);
        let tables: Vec<TableEnum> = sleigh
            .tables()
            .iter()
            .enumerate()
            .map(|(i, table)| {
                let table_id = sleigh_rs::TableId(i);
                TableEnum::new(&sleigh, table, table_id)
            })
            .collect();
        let field_structs = TokenFieldFunctions::new(&sleigh);
        let context =
            ContextMemory::new(&sleigh, format_ident!("ContextMemory"));
        Self {
            addr_type: format_ident!("AddrType"),
            display,
            registers,
            tables,
            meanings,
            inst_work_type,
            sleigh,
            context,
            debug,
            token_field_functions: field_structs,
        }
    }

    pub fn table_struct(&self, table: sleigh_rs::TableId) -> &TableEnum {
        &self.tables[table.0]
    }

    pub fn token_field_function(
        &self,
        id: sleigh_rs::TokenFieldId,
    ) -> &TokenFieldFunction {
        self.token_field_functions.read_function(&self.sleigh, id)
    }
}

use crate::GeneratedModule;

impl Disassembler {
    /// Split the generated code into multiple files for faster compilation.
    ///
    /// Returns a list of files. The build.rs should:
    /// 1. Write each file to `OUT_DIR/dirname/filename`
    /// 2. Generate a root file that `include!`s everything via inline modules
    ///
    /// The first entry is always "shared.rs" (types), followed by "table_N.rs" files.
    /// The last entry is "root.rs" which uses `include!()` to assemble everything.
    /// The `out_dir` parameter is embedded in the root.rs `include!()` paths.
    pub fn to_split_modules(&self, tables_per_file: usize, out_dir: &str) -> Vec<GeneratedModule> {
        let tables_per_file = tables_per_file.max(1);
        let mut modules = Vec::new();

        // 1. shared.rs — all type definitions
        let mut shared = TokenStream::new();
        let addr_type = &self.addr_type;
        let inst_work_type = &self.inst_work_type;
        shared.extend(quote! {
            pub type #addr_type = #inst_work_type;
        });
        self.registers.to_tokens(&mut shared, self);
        self.meanings.to_tokens(&mut shared, self);
        self.display.to_tokens(&mut shared, self);
        self.token_field_functions.to_tokens(&mut shared, self);
        self.context.to_tokens(&mut shared, self);
        modules.push(GeneratedModule {
            filename: "shared.rs".into(),
            code: shared,
            raw_code: None,
        });

        // 2. table_N.rs — split tables across files
        // Large tables (like the instruction table with 4000+ constructors) get
        // their constructor structs distributed across multiple files.
        let max_constructors_per_file = tables_per_file.max(100);
        let mut file_idx = 0usize;

        // Track which file gets the table enum for each table
        let mut table_enum_file = vec![0usize; self.tables.len()];

        for (i, table) in self.tables.iter().enumerate() {
            if table.constructors.len() > max_constructors_per_file {
                // Large table: split constructor structs across files, enum in its own file
                let (constructor_batches, enum_tokens) =
                    table.to_tokens_split(max_constructors_per_file, self);

                for batch in constructor_batches {
                    let mut tokens = TokenStream::new();
                    tokens.extend(quote! { #[allow(unused_imports)] use super::*; });
                    tokens.extend(batch);
                    modules.push(GeneratedModule {
                        filename: format!("table_{}.rs", file_idx),
                        code: tokens,
                        raw_code: None,
                    });
                    file_idx += 1;
                }

                // Enum file (references constructors from other files via use super::*)
                let mut tokens = TokenStream::new();
                tokens.extend(quote! { #[allow(unused_imports)] use super::*; });
                tokens.extend(enum_tokens);
                table_enum_file[i] = file_idx;
                modules.push(GeneratedModule {
                    filename: format!("table_{}.rs", file_idx),
                    code: tokens,
                    raw_code: None,
                });
                file_idx += 1;
            } else {
                // Small table: emit all at once
                let mut tokens = TokenStream::new();
                tokens.extend(quote! { #[allow(unused_imports)] use super::*; });
                table.to_tokens(&mut tokens, self);
                table_enum_file[i] = file_idx;
                modules.push(GeneratedModule {
                    filename: format!("table_{}.rs", file_idx),
                    code: tokens,
                    raw_code: None,
                });
                file_idx += 1;
            }
        }

        let num_table_files = file_idx;

        // 3. root.rs — inline modules with include!(), re-exports, parse_instruction
        let display_data_type = &self.display.name;
        let instruction_table = self.table_struct(self.sleigh.instruction_table());
        let instruction_table_name = &instruction_table.name;
        let instruction_table_parse = &instruction_table.parse_fun;
        let instruction_table_display = &instruction_table.display_fun;
        let context_struct = &self.context.name;
        let globalset_struct = &self.context.globalset.name;

        // Build the root.rs as a string (not TokenStream) since include!() paths
        // need to be string literals, which quote! can't produce.
        let mut root = String::new();
        let allow = "#[allow(non_camel_case_types, non_snake_case, unused_variables, unused_mut, unused_parens, unused_imports, clippy::all)]";

        // Shared module
        root.push_str(&format!(
            "{allow}\npub mod shared {{ include!(\"{out_dir}/shared.rs\"); }}\npub use shared::*;\n"
        ));

        // Table modules
        for i in 0..num_table_files {
            root.push_str(&format!(
                "{allow}\npub mod table_{i} {{ include!(\"{out_dir}/table_{i}.rs\"); }}\npub use table_{i}::*;\n"
            ));
        }

        // parse_instruction — emit via quote then stringify
        let instr_table_idx = table_enum_file[self.sleigh.instruction_table().0];
        let instr_mod_name = format_ident!("table_{}", instr_table_idx);

        let parse_fn = quote! {
            pub fn parse_instruction(
                tokens: &[u8],
                context: &mut #context_struct,
                inst_start: #addr_type,
                global_set: &mut #globalset_struct,
            ) -> Option<(#inst_work_type, Vec<#display_data_type>, Vec<pcode_ir::PcodeOp>)> {
                let (inst_len, instruction) =
                    #instr_mod_name::#instruction_table_name::#instruction_table_parse(
                        tokens,
                        context,
                        inst_start,
                )?;
                let inst_next = inst_start + inst_len;
                let mut display = vec![];
                instruction.#instruction_table_display(
                    &mut display,
                    context,
                    inst_start,
                    inst_next,
                    global_set,
                );
                let pcode = instruction.lift(inst_start, inst_next);
                Some((inst_next, display, pcode))
            }
        };
        root.push_str(&parse_fn.to_string());

        modules.push(GeneratedModule {
            filename: "root.rs".into(),
            code: TokenStream::new(),
            raw_code: Some(root),
        });

        modules
    }
}

impl ToTokens for Disassembler {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let display_data_type = &self.display.name;
        let instruction_table =
            self.table_struct(self.sleigh.instruction_table());
        let instruction_table_name = &instruction_table.name;
        let instruction_table_parse = &instruction_table.parse_fun;
        let instruction_table_display = &instruction_table.display_fun;
        let context_struct = &self.context.name;
        let globalset_struct = &self.context.globalset.name;

        let addr_type = &self.addr_type;
        let inst_work_type = &self.inst_work_type;
        tokens.extend(quote! {
            pub type #addr_type = #inst_work_type;
        });
        self.registers.to_tokens(tokens, self);
        self.meanings.to_tokens(tokens, self);
        self.display.to_tokens(tokens, self);
        self.token_field_functions.to_tokens(tokens, self);
        self.context.to_tokens(tokens, self);
        for tables in self.tables.iter() {
            tables.to_tokens(tokens, self);
        }
        tokens.extend(quote! {
            pub fn parse_instruction(
                tokens: &[u8],
                context: &mut #context_struct,
                inst_start: #addr_type,
                global_set: &mut #globalset_struct,
            ) -> Option<(#inst_work_type, Vec<#display_data_type>, Vec<pcode_ir::PcodeOp>)> {
                let (inst_len, instruction) =
                    #instruction_table_name::#instruction_table_parse(
                        tokens,
                        context,
                        inst_start,
                )?;
                let inst_next = inst_start + inst_len;
                let mut display = vec![];
                instruction.#instruction_table_display(
                    &mut display,
                    context,
                    inst_start,
                    inst_next,
                    global_set,
                );
                let pcode = instruction.lift(inst_start, inst_next);
                Some((inst_next, display, pcode))
            }
        });
    }
}
