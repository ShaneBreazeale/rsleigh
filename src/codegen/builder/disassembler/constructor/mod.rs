use indexmap::IndexMap;
use std::cell::RefCell;

use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote, ToTokens};

use crate::codegen::builder::formater::from_sleigh;
use crate::codegen::builder::{DisassemblyGenerator, DISPLAY_WORK_TYPE};
use crate::execution::{
    AssignmentWrite, AssignmentWriteVariable, DynamicValueType, Export, Expr, ExprElement,
    ExprValue, Statement,
};

use super::Disassembler;

mod disassembly;
pub use disassembly::*;

mod execution;
pub use execution::*;

mod pattern;
pub use pattern::*;

pub struct ConstructorStruct {
    pub constructor_id: crate::table::ConstructorId,
    pub table_id: crate::TableId,
    //struct name
    pub struct_name: Ident,
    //variant name in the enum
    pub enum_name: Ident,
    //display function
    pub display_fun: Ident,
    pub disassembly_fun: Ident,
    pub parser_fun: Ident,
    pub table_fields: IndexMap<crate::TableId, Ident>,
    pub ass_fields: IndexMap<crate::TokenFieldId, Ident>,
    /// Context values referenced by execution/disassembly expressions and stored
    /// at decode time so `lift()` does not have to guess.
    pub context_fields: IndexMap<crate::ContextId, Ident>,
    /// Disassembly variables (e.g. `reloc` in rel8) stored as struct fields
    /// so they're available to both display_extend() and lift().
    pub dis_fields: IndexMap<crate::disassembly::VariableId, Ident>,
}
impl ConstructorStruct {
    fn context_field_ident(sleigh: &crate::Sleigh, context: crate::ContextId) -> Ident {
        let context = sleigh.context(context);
        format_ident!("ctx_{}", from_sleigh(context.name()))
    }

    fn collect_dynamic_context(value: &DynamicValueType, out: &mut Vec<crate::ContextId>) {
        if let DynamicValueType::Context(context) = value {
            out.push(*context);
        }
    }

    fn collect_expr_contexts(expr: &Expr, out: &mut Vec<crate::ContextId>) {
        match expr {
            Expr::Value(element) => Self::collect_expr_element_contexts(element, out),
            Expr::Op(op) => {
                Self::collect_expr_contexts(&op.left, out);
                Self::collect_expr_contexts(&op.right, out);
            }
        }
    }

    fn collect_expr_element_contexts(element: &ExprElement, out: &mut Vec<crate::ContextId>) {
        match element {
            ExprElement::Value { value, .. } => Self::collect_expr_value_contexts(value, out),
            ExprElement::UserCall(call) => {
                for param in call.params.iter() {
                    Self::collect_expr_contexts(param, out);
                }
            }
            ExprElement::Reference(_) => {}
            ExprElement::Op(op) => Self::collect_expr_contexts(&op.input, out),
            ExprElement::New(new_expr) => {
                Self::collect_expr_contexts(&new_expr.first, out);
                if let Some(second) = &new_expr.second {
                    Self::collect_expr_contexts(second, out);
                }
            }
            ExprElement::CPool(cpool) => {
                for param in cpool.params.iter() {
                    Self::collect_expr_contexts(param, out);
                }
            }
        }
    }

    fn collect_expr_value_contexts(value: &ExprValue, out: &mut Vec<crate::ContextId>) {
        match value {
            ExprValue::Context(context) => out.push(context.id),
            ExprValue::IntDynamic(dynamic) => {
                Self::collect_dynamic_context(&dynamic.attach_value, out);
            }
            ExprValue::VarnodeDynamic(dynamic) => {
                Self::collect_dynamic_context(&dynamic.attach_value, out);
            }
            _ => {}
        }
    }

    fn collect_dis_expr_contexts(expr: &crate::disassembly::Expr, out: &mut Vec<crate::ContextId>) {
        use crate::disassembly::{Expr as DisExpr, ExprElement as DisElement, ReadScope};
        match expr {
            DisExpr::Value(element) => match element {
                DisElement::Value {
                    value: ReadScope::Context(context),
                    ..
                } => out.push(*context),
                DisElement::Op(_, _, inner) => Self::collect_dis_expr_contexts(inner, out),
                _ => {}
            },
            DisExpr::Op(_, _, left, right) => {
                Self::collect_dis_expr_contexts(left, out);
                Self::collect_dis_expr_contexts(right, out);
            }
        }
    }

    pub fn new(
        sleigh: &crate::Sleigh,
        table_id: crate::TableId,
        constructor: &crate::table::Constructor,
        constructor_id: crate::table::ConstructorId,
        table_name: &str,
        number: usize,
    ) -> Self {
        //let mut calc_fields = IndexMap::new();
        let mut ass_fields: IndexMap<_, _> = IndexMap::new();
        let mut context_ids = Vec::new();
        //tables are always included to the struct, used or not
        let table_fields = constructor
            .pattern
            .produced_tables()
            .map(|produced_table| {
                let table = sleigh.table(produced_table.table);
                (
                    produced_table.table,
                    format_ident!("{}", from_sleigh(table.name())),
                )
            })
            .collect();

        //include on the enum all the required fields from the display
        for display in constructor.display.elements() {
            use crate::display::DisplayElement::*;
            match display {
                Context(_) | InstStart(_) | InstNext(_) | Varnode(_) | Literal(_) | Space => (),
                TokenField(ass) => {
                    ass_fields.entry(*ass).or_insert_with(|| {
                        let ass = sleigh.token_field(*ass);
                        format_ident!("{}", from_sleigh(ass.name()))
                    });
                }
                // disassembly is all done durint the display call
                Disassembly(_var) => {}
                //table is added independed if it shows up on display
                Table(_display_table) => {}
            }
        }
        //TODO only add fields required by the display, not all fields required
        //by the disassembly
        for field in constructor
            .pattern
            .blocks()
            .iter()
            .flat_map(|block| match block {
                crate::pattern::Block::And { pre, pos, .. } => pre.iter().chain(pos.iter()),
                crate::pattern::Block::Or { pos, .. } => {
                    pos.iter().chain([/*LOL*/].iter())
                }
            })
            .chain(constructor.pattern.disassembly_pos_match())
        {
            use crate::disassembly;
            match field {
                disassembly::Assertation::GlobalSet(disassembly::GlobalSet { .. }) => (),
                disassembly::Assertation::Assignment(disassembly::Assignment {
                    left: _,
                    right,
                }) => {
                    fn collect_token_fields(
                        expr: &disassembly::Expr,
                        out: &mut Vec<crate::TokenFieldId>,
                    ) {
                        match expr {
                            disassembly::Expr::Value(element) => match element {
                                disassembly::ExprElement::Value {
                                    value: disassembly::ReadScope::TokenField(ass),
                                    location: _,
                                } => out.push(*ass),
                                disassembly::ExprElement::Op(_, _, inner) => {
                                    collect_token_fields(inner, out);
                                }
                                _ => {}
                            },
                            disassembly::Expr::Op(_, _, left, right) => {
                                collect_token_fields(left, out);
                                collect_token_fields(right, out);
                            }
                        }
                    }
                    Self::collect_dis_expr_contexts(right, &mut context_ids);
                    let mut fields = Vec::new();
                    collect_token_fields(right, &mut fields);
                    for ass in fields {
                        ass_fields.entry(ass).or_insert_with(|| {
                            let ass = sleigh.token_field(ass);
                            format_ident!("{}", from_sleigh(ass.name()))
                        });
                    }
                }
            }
        }

        if let Some(execution) = &constructor.execution {
            for block in execution.blocks().iter() {
                for statement in block.statements.iter() {
                    match statement {
                        Statement::Assignment(assignment) => {
                            Self::collect_expr_contexts(&assignment.right, &mut context_ids);
                            match &assignment.var {
                                AssignmentWrite::Variable { value, .. } => {
                                    if let AssignmentWriteVariable::DynVarnode {
                                        value_id, ..
                                    } = value
                                    {
                                        Self::collect_dynamic_context(value_id, &mut context_ids);
                                    }
                                }
                                AssignmentWrite::Memory { addr, .. } => {
                                    Self::collect_expr_contexts(addr, &mut context_ids);
                                }
                                AssignmentWrite::TableExport { .. } => {}
                            }
                        }
                        Statement::CpuBranch(branch) => {
                            Self::collect_expr_contexts(&branch.dst, &mut context_ids);
                            if let Some(cond) = &branch.cond {
                                Self::collect_expr_contexts(cond, &mut context_ids);
                            }
                        }
                        Statement::LocalGoto(goto) => {
                            if let Some(cond) = &goto.cond {
                                Self::collect_expr_contexts(cond, &mut context_ids);
                            }
                        }
                        Statement::UserCall(call) => {
                            for param in call.params.iter() {
                                Self::collect_expr_contexts(param, &mut context_ids);
                            }
                        }
                        Statement::Export(export) => match export {
                            Export::Reference { addr, .. } => {
                                Self::collect_expr_contexts(addr, &mut context_ids);
                            }
                            Export::Value(addr) => {
                                Self::collect_expr_contexts(addr, &mut context_ids);
                            }
                            Export::AttachVarnode { attach_value, .. } => {
                                Self::collect_dynamic_context(attach_value, &mut context_ids);
                            }
                            Export::Table { .. } => {}
                        },
                        Statement::Build(_) | Statement::Declare(_) | Statement::Delayslot(_) => {}
                    }
                }
            }
        }

        context_ids.sort_by_key(|context| context.0);
        context_ids.dedup();
        let context_fields: IndexMap<crate::ContextId, Ident> = context_ids
            .into_iter()
            .map(|context| (context, Self::context_field_ident(sleigh, context)))
            .collect();

        // Collect disassembly variables as struct fields
        let dis_fields: IndexMap<crate::disassembly::VariableId, Ident> = constructor
            .pattern
            .disassembly_vars()
            .iter()
            .enumerate()
            .map(|(i, var)| {
                (
                    crate::disassembly::VariableId(i),
                    format_ident!("calc_{}", from_sleigh(var.name())),
                )
            })
            .collect();

        let struct_name = if let Some(mneumonic) = &constructor.display.mneumonic {
            format_ident!("{}_{}Var{}", from_sleigh(mneumonic), table_name, number)
        } else {
            format_ident!("{}Var{}", table_name, number)
        };

        Self {
            enum_name: format_ident!("Var{}", number),
            struct_name,
            display_fun: format_ident!("display_extend"),
            disassembly_fun: format_ident!("disassembly"),
            parser_fun: format_ident!("parse"),
            ass_fields,
            table_fields,
            context_fields,
            dis_fields,
            constructor_id,
            table_id,
        }
    }

    pub fn gen_display(&self, disassembler: &Disassembler) -> TokenStream {
        let Self {
            display_fun,
            struct_name: _,
            enum_name: _,
            disassembly_fun: _,
            parser_fun: _,
            constructor_id,
            table_id,
            table_fields: _,
            ass_fields: _,
            context_fields: _,
            dis_fields: _,
        } = self;
        let display_param = format_ident!("display");
        let context_param = format_ident!("context");
        let inst_start = format_ident!("inst_start");
        let inst_next = format_ident!("inst_next");
        let global_set_param = format_ident!("global_set");
        let display_struct = &disassembler.display.name;
        let register_enum = &disassembler.registers.name;

        use crate::display::DisplayElement as DisplayScope;
        let mut disassembly = DisassemblyDisplay {
            constructor: self,
            display_param: &display_param,
            context_param: &context_param,
            inst_start: &inst_start,
            inst_next: &inst_next,
            global_set_param: &global_set_param,
            vars: RefCell::new(IndexMap::new()),
            disassembler,
        };
        let constructor = disassembler
            .sleigh
            .table(*table_id)
            .constructor(*constructor_id);
        let mut disassembly_body: TokenStream = constructor
            .pattern
            .disassembly_vars()
            .iter()
            .enumerate()
            .map(|(i, var)| disassembly.new_variable(&crate::disassembly::VariableId(i), var))
            .collect();
        disassembly_body.extend(disassembly.to_token_stream());
        let add_mneumonic = constructor.display.mneumonic.as_ref().map(|mneumonic| {
            let display_element = &disassembler.display.name;
            let literal = &disassembler.display.literal_var;
            quote! { #display_param.push(#display_element::#literal(#mneumonic)); }
        });
        let elements: Vec<_> = constructor.display.elements().collect();
        let displays = elements
            .split_inclusive(|ele| matches!(ele, DisplayScope::Table(_)))
            .map(|eles| {
                let (ele, table) = match eles {
                    [ele @ .., DisplayScope::Table(table)] => {
                        (ele, Some(table))
                    }
                    _ => (eles, None),
                };
                let extend = (!ele.is_empty()).then(|| {
                    let display = ele.iter().map(|ele| match ele {
                        DisplayScope::Varnode(varnode) => {
                            let reg_var =
                                disassembler.registers.register(*varnode);
                            quote! {
                                <#display_struct>::Register(
                                    #register_enum::#reg_var
                                )
                            }
                        }
                        DisplayScope::Context(context) => {
                            disassembler.context.display_call(
                                disassembler,
                                &context_param,
                                *context,
                            )
                        }
                        DisplayScope::TokenField(ass) => {
                            let var_name = self.ass_fields.get(ass).unwrap();
                            let token_field =
                                disassembler.sleigh.token_field(*ass);
                            disassembler.meanings.display_function_call(
                                token_field.bits.len().get().try_into().unwrap(),
                                quote! {self.#var_name},
                                token_field.meaning(),
                            )
                        }
                        DisplayScope::Disassembly(var) => {
                            let vars = disassembly.vars.borrow();
                            let var_name = vars.get(var).unwrap();
                            let number_ele = &disassembler.display.number_var;
                            // VariableType was removed from sleigh-rs;
                            // display as signed number without masking
                            quote! {<#display_struct>::#number_ele(true, #var_name.is_negative(), #var_name.unsigned_abs() as #DISPLAY_WORK_TYPE)}
                        }
                        DisplayScope::Space => {
                            quote! {<#display_struct>::Literal(" ")}
                        }
                        DisplayScope::Literal(literal) => {
                            quote! {<#display_struct>::Literal(#literal)}
                        }
                        DisplayScope::Table(_) => unreachable!(),
                        DisplayScope::InstStart(_) => {
                            inst_start.to_token_stream()
                        }
                        DisplayScope::InstNext(_) => {
                            inst_next.to_token_stream()
                        }
                    });
                    let display_out_len = ele.len();
                    quote! {
                        let extend: [#display_struct; #display_out_len] = [
                            #(#display),*
                        ];
                        #display_param.extend_from_slice(&extend);
                    }
                });
                let build_table = table.map(|table_id| {
                    let field_name = self.table_fields.get(table_id).unwrap();
                    let table = disassembler.table_struct(*table_id);
                    let produced_table = constructor
                        .pattern
                        .produced_tables()
                        .find(|prod| prod.table == *table_id)
                        .unwrap();
                    let display_fun = &table.display_fun;
                    if produced_table.always {
                        quote! {
                            self.#field_name.#display_fun(
                                #display_param,
                                #context_param,
                                #inst_start,
                                #inst_next,
                                #global_set_param,
                            );
                        }
                    } else {
                        quote! {
                            self.#field_name.as_ref().map(|table| {
                                table.#display_fun(
                                    #display_param,
                                    #context_param,
                                    #inst_start,
                                    #inst_next,
                                    #global_set_param,
                                );
                            });
                        }
                    }
                });
                quote! {
                    #extend
                    #build_table
                }
            });
        let context_struct = &disassembler.context.name;
        let globalset_struct = &disassembler.context.globalset.name;
        let addr_type = &disassembler.addr_type;
        quote! {
            pub fn #display_fun(
                &self,
                #display_param: &mut Vec<#display_struct>,
                #context_param: &#context_struct,
                #inst_start: #addr_type,
                #inst_next: #addr_type,
                #global_set_param: &mut #globalset_struct,
            ) {
                #disassembly_body
                #add_mneumonic
                #(#displays)*
            }
        }
    }

    pub fn gen_execution(&self, disassembler: &Disassembler) -> TokenStream {
        let constructor = disassembler
            .sleigh
            .table(self.table_id)
            .constructor(self.constructor_id);

        let inst_start = format_ident!("inst_start");
        let inst_next = format_ident!("inst_next");

        match &constructor.execution {
            Some(execution) => {
                // Empty execution with subtable fields: emit builds for all subtables
                // This handles constructors like `:^instruction is ... & instruction {}`
                // where the subtable is implicitly built

                let gen = ExecutionGenerator::new(disassembler, self, &inst_start, &inst_next);
                gen.gen_lift(execution)
            }
            None => {
                let addr_type = &disassembler.addr_type;
                // No execution → build all subtables
                let builds: TokenStream = self
                    .table_fields
                    .values()
                    .map(|field| {
                        quote! {
                            {
                                let (s_ops, _, _) = self.#field.lift(#inst_start, #inst_next);
                                ops.extend(s_ops);
                            }
                        }
                    })
                    .collect();
                quote! {
                    pub fn lift(
                        &self,
                        #inst_start: #addr_type,
                        #inst_next: #addr_type,
                    ) -> (Vec<pcode_ir::PcodeOp>, Option<pcode_ir::Varnode>, Option<(pcode_ir::AddressSpaceId, pcode_ir::Varnode, u32)>) {
                        let mut ops = Vec::new();
                        #builds
                        (ops, None, None)
                    }
                }
            }
        }
    }

    pub fn to_tokens(&self, tokens: &mut TokenStream, disassembler: &Disassembler) {
        let Self {
            struct_name,
            table_fields,
            ass_fields,
            context_fields,
            dis_fields,
            parser_fun,
            enum_name: _,
            display_fun: _,
            disassembly_fun: _,
            constructor_id,
            table_id,
        } = self;
        let constructor = disassembler
            .sleigh
            .table(*table_id)
            .constructor(*constructor_id);
        let doc = format!("Constructor at {}", &constructor.location);
        let ass_fields = ass_fields.iter().map(|(field_id, name)| {
            let data_type = &disassembler.token_field_function(*field_id).read_type;
            quote! { #name: #data_type }
        });
        let table_fields = table_fields.iter().map(|(table_id, name)| {
            let produced_table = constructor
                .pattern
                .produced_tables()
                .find(|produced| produced.table == *table_id)
                .unwrap();
            let table_struct_name = &disassembler.table_struct(*table_id).name;
            let mut table_data = table_struct_name.into_token_stream();
            if produced_table.recursive {
                table_data = quote! {Box<#table_data>};
            }
            if !produced_table.always {
                table_data = quote! {Option<#table_data>};
            }
            quote! { #name: #table_data }
        });
        let context_fields = context_fields.values().map(|name| {
            quote! { #name: i128 }
        });
        let display_impl = self.gen_display(disassembler);
        let lift_impl = self.gen_execution(disassembler);
        let parser_function = root_pattern_function(parser_fun, self, disassembler);
        let dis_field_defs = dis_fields.values().map(|name| {
            quote! { #name: i128 }
        });
        tokens.extend(quote! {
            #[doc = #doc]
            #[derive(Clone, Debug)]
            pub struct #struct_name {
                #(pub #ass_fields,)*
                #(pub #table_fields,)*
                #(pub #context_fields,)*
                #(pub #dis_field_defs,)*
            }
            impl #struct_name {
                #display_impl
                #lift_impl
                #parser_function
            }
        })
    }
}
