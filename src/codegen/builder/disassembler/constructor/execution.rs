use std::cell::Cell;

use indexmap::IndexMap;
use std::cell::RefCell;

use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote};

use crate::execution::{
    Assignment, AssignmentOp, AssignmentWrite, AssignmentWriteVariable, Binary, Block, BranchCall,
    Build, CpuBranch, Execution, Export, Expr, ExprBinaryOp, ExprElement, ExprNumber, ExprUnaryOp,
    ExprValue, LocalGoto, Statement, Unary, UserCall, VariableId,
};
use crate::space::SpaceType;

use super::ConstructorStruct;
use crate::codegen::builder::Disassembler;

pub struct ExecutionGenerator<'a> {
    pub disassembler: &'a Disassembler,
    pub constructor: &'a ConstructorStruct,
    pub inst_start: &'a Ident,
    pub inst_next: &'a Ident,
    pub unique_counter: Cell<u64>,
    pub vars: RefCell<IndexMap<VariableId, Ident>>,
}

impl<'a> ExecutionGenerator<'a> {
    pub fn new(
        disassembler: &'a Disassembler,
        constructor: &'a ConstructorStruct,
        inst_start: &'a Ident,
        inst_next: &'a Ident,
    ) -> Self {
        Self {
            disassembler,
            constructor,
            inst_start,
            inst_next,
            unique_counter: Cell::new(0),
            vars: RefCell::new(IndexMap::new()),
        }
    }

    fn fresh_unique(&self, size_bytes: u64) -> TokenStream {
        let offset = self.unique_counter.get();
        self.unique_counter.set(offset + size_bytes.max(1));
        let size = size_bytes as u32;
        quote! { pcode_ir::Varnode::unique(unique_base + #offset, #size) }
    }

    fn bytes_from_bits(bits: u64) -> u64 {
        (bits + 7) / 8
    }

    /// Emit a varnode expression for a register-space varnode.
    fn varnode_expr(&self, varnode_id: crate::VarnodeId) -> TokenStream {
        let v = self.disassembler.sleigh.varnode(varnode_id);
        let offset = v.address;
        let size = v.len_bytes.get() as u32;
        match self.disassembler.sleigh.space(v.space).space_type {
            SpaceType::Register => quote! { pcode_ir::Varnode::register(#offset, #size) },
            _ => quote! { pcode_ir::Varnode::ram(#offset, #size) },
        }
    }

    fn space_id_expr(&self, space_id: crate::SpaceId) -> TokenStream {
        match self.disassembler.sleigh.space(space_id).space_type {
            SpaceType::Register => quote! { pcode_ir::AddressSpaceId::Register },
            _ => quote! { pcode_ir::AddressSpaceId::Ram },
        }
    }

    fn addr_size(&self) -> u32 {
        self.disassembler.sleigh.addr_bytes().get() as u32
    }

    /// Generate a runtime expression for a DynamicValueType (token field or context value).
    fn dynamic_value_expr(&self, dv: &crate::execution::DynamicValueType) -> TokenStream {
        match dv {
            crate::execution::DynamicValueType::TokenField(tf_id) => {
                match self.constructor.ass_fields.get(tf_id) {
                    Some(n) => quote! { self.#n as u64 },
                    None => quote! { 0u64 },
                }
            }
            crate::execution::DynamicValueType::Context(ctx_id) => {
                let _read_fn = &self.disassembler.context.context_functions(*ctx_id).read;
                // Context is read via self on the ContextMemory but we don't have it in lift.
                // Context values are fixed at decode time, so we'd need to store them.
                // For now, generate a zero — context-dependent register selection is rare.
                quote! { 0u64 }
            }
        }
    }

    /// Generate a varnode expression for a dynamically-selected register (AttachVarnode lookup).
    fn dynamic_varnode_expr(
        &self,
        attach_id: crate::AttachVarnodeId,
        value_expr: &TokenStream,
    ) -> TokenStream {
        let attach = self.disassembler.sleigh.attach_varnode(attach_id);
        let varnode_size = attach
            .0
            .first()
            .map(|(_, vid)| self.disassembler.sleigh.varnode(*vid).len_bytes.get() as u32)
            .unwrap_or(8);
        let arms: Vec<_> = attach
            .0
            .iter()
            .map(|(idx, vid)| {
                let v = self.disassembler.sleigh.varnode(*vid);
                let offset = v.address;
                let index = *idx as u64;
                quote! { #index => #offset }
            })
            .collect();
        let size = varnode_size;
        quote! {{
            let reg_val = #value_expr;
            let offset = match reg_val { #(#arms,)* _ => 0 };
            pcode_ir::Varnode::register(offset, #size)
        }}
    }

    /// Generate a constant expression for a dynamically-selected integer (AttachNumber lookup).
    fn dynamic_int_expr(
        &self,
        attach_id: crate::AttachNumberId,
        value_expr: &TokenStream,
        size: u32,
    ) -> TokenStream {
        let attach = self.disassembler.sleigh.attach_number(attach_id);
        let arms: Vec<_> = attach
            .0
            .iter()
            .map(|(idx, val)| {
                let index = *idx as u64;
                let v = val.signed_super() as u64;
                quote! { #index => #v }
            })
            .collect();
        quote! {{
            let num_val = #value_expr;
            let value = match num_val { #(#arms,)* _ => 0u64 };
            pcode_ir::Varnode::constant(value, #size)
        }}
    }

    // ── Top-level ────────────────────────────────────────────────────

    pub fn gen_lift(&self, execution: &Execution) -> TokenStream {
        let addr_type = &self.disassembler.addr_type;
        let inst_start = self.inst_start;
        let inst_next = self.inst_next;
        let var_decls = self.gen_variable_decls(execution);
        let block_code = self.gen_blocks(execution);
        let local_op_estimate = self.estimate_execution_ops(execution);

        // Collect all tables referenced in the execution (Build, expressions, assignments)
        // These will be lifted explicitly — no implicit build needed
        let mut referenced_tables = std::collections::HashSet::new();
        fn collect_table_refs(
            stmt: &Statement,
            out: &mut std::collections::HashSet<crate::TableId>,
        ) {
            match stmt {
                Statement::Build(b) => {
                    out.insert(b.table);
                }
                Statement::Assignment(a) => {
                    collect_expr_tables(&a.right, out);
                    if let AssignmentWrite::TableExport { table_id, .. } = &a.var {
                        out.insert(*table_id);
                    }
                }
                Statement::Export(e) => {
                    if let Export::Table { table_id, .. } = e {
                        out.insert(*table_id);
                    }
                }
                Statement::CpuBranch(b) => {
                    collect_expr_tables(&b.dst, out);
                }
                _ => {}
            }
        }
        fn collect_expr_tables(expr: &Expr, out: &mut std::collections::HashSet<crate::TableId>) {
            match expr {
                Expr::Value(elem) => {
                    if let ExprElement::Value {
                        value: ExprValue::Table(tid),
                        ..
                    } = elem
                    {
                        out.insert(*tid);
                    }
                }
                Expr::Op(op) => {
                    collect_expr_tables(&op.left, out);
                    collect_expr_tables(&op.right, out);
                }
            }
        }
        for block in execution.blocks().iter() {
            for stmt in block.statements.iter() {
                collect_table_refs(stmt, &mut referenced_tables);
            }
        }
        // Pre-lift all subtable fields once and cache results.
        // Referenced tables get their ops/exports cached; unreferenced ones just get ops.
        // Pre-lift all subtable fields, then remap unique offsets so no two subtables
        // collide. Each subtable gets its unique varnodes shifted by (idx+1) * 0x10000.
        let subtable_cache: TokenStream = self.constructor.table_fields.iter()
            .enumerate()
            .map(|(idx, (_, field))| {
                let cache_ops = format_ident!("{}_ops", field);
                let cache_exp = format_ident!("{}_exp", field);
                let cache_ref = format_ident!("{}_ref", field);
                let offset = ((idx as u64) + 1) * 0x10000;
                quote! {
                    let (mut #cache_ops, mut #cache_exp, mut #cache_ref) = self.#field.lift(#inst_start, #inst_next);
                    // Remap unique offsets to avoid collision with other subtables
                    for op in #cache_ops.iter_mut() {
                        pcode_ir::offset_unique_varnodes(op, #offset);
                    }
                    if let Some(ref mut v) = #cache_exp {
                        if v.space == pcode_ir::AddressSpaceId::Unique { v.offset += #offset; }
                    }
                    if let Some((_, ref mut v, _)) = #cache_ref {
                        if v.space == pcode_ir::AddressSpaceId::Unique { v.offset += #offset; }
                    }
                }
            })
            .collect();

        let subtable_cached_capacity: TokenStream = self
            .constructor
            .table_fields
            .iter()
            .map(|(_, field)| {
                let cache_ops = format_ident!("{}_ops", field);
                quote! { + #cache_ops.len() }
            })
            .collect();

        // Extend ops from all subtable caches
        let subtable_ops_extend: TokenStream = self
            .constructor
            .table_fields
            .iter()
            .map(|(_, field)| {
                let cache_ops = format_ident!("{}_ops", field);
                quote! { ops.extend(#cache_ops); }
            })
            .collect();

        let num_fields = self.constructor.table_fields.len() as u64;

        // Recompute disassembly variables in lift using the correct inst_next
        let dis_recompute = self.gen_dis_recompute(execution);

        quote! {
            pub fn lift(
                &self,
                #inst_start: #addr_type,
                #inst_next: #addr_type,
            ) -> (Vec<pcode_ir::PcodeOp>, Option<pcode_ir::Varnode>, Option<(pcode_ir::AddressSpaceId, pcode_ir::Varnode, u32)>) {
                // Offset unique_base past subtable ranges to avoid collision
                // Subtables use offsets (1..N)*0x10000, parent uses N*0x10000+
                let unique_base: u64 = (#inst_start as u64).wrapping_shl(16) + #num_fields as u64 * 0x10000;
                let mut export_varnode: Option<pcode_ir::Varnode> = None;
                let mut export_ref: Option<(pcode_ir::AddressSpaceId, pcode_ir::Varnode, u32)> = None;
                // Lift all subtables once and cache results
                #subtable_cache
                let cached_ops_capacity: usize = 0usize #subtable_cached_capacity;
                let mut ops: Vec<pcode_ir::PcodeOp> =
                    Vec::with_capacity(cached_ops_capacity + #local_op_estimate);
                #subtable_ops_extend
                #dis_recompute
                #var_decls
                #block_code
                (ops, export_varnode, export_ref)
            }
        }
    }

    /// Recompute disassembly variables using the correct inst_next from lift params.
    /// This fixes the off-by-one issue where parse computes inst_next from the
    /// subtable's local pattern_len instead of the full instruction length.
    fn gen_dis_recompute(&self, _execution: &Execution) -> TokenStream {
        let constructor = self
            .disassembler
            .sleigh
            .table(self.constructor.table_id)
            .constructor(self.constructor.constructor_id);
        let _inst_start = self.inst_start;
        let _inst_next = self.inst_next;
        let mut tokens = TokenStream::new();

        // Declare mutable locals for all disassembly variables
        for (_var_id, name) in &self.constructor.dis_fields {
            tokens.extend(quote! { let mut #name: i128 = self.#name; });
        }

        // Re-run post-match assertions with correct inst_next
        for ass in constructor.pattern.disassembly_pos_match() {
            use crate::disassembly::Assertation;
            if let Assertation::Assignment(assignment) = ass {
                // Check if this assignment uses inst_next
                if Self::expr_uses_inst_next(&assignment.right) {
                    let value = self.gen_dis_expr_for_lift(&assignment.right);
                    if let crate::disassembly::WriteScope::Local(var_id) = &assignment.left {
                        if let Some(name) = self.constructor.dis_fields.get(var_id) {
                            tokens.extend(quote! { #name = #value; });
                        }
                    }
                }
            }
        }
        tokens
    }

    fn expr_uses_inst_next(expr: &crate::disassembly::Expr) -> bool {
        use crate::disassembly::{Expr, ExprElement, ReadScope};
        match expr {
            Expr::Value(element) => match element {
                ExprElement::Value {
                    value: ReadScope::InstNext(_),
                    ..
                } => true,
                ExprElement::Op(_, _, inner) => Self::expr_uses_inst_next(inner),
                _ => false,
            },
            Expr::Op(_, _, left, right) => {
                Self::expr_uses_inst_next(left) || Self::expr_uses_inst_next(right)
            }
        }
    }

    fn gen_dis_expr_for_lift(&self, expr: &crate::disassembly::Expr) -> TokenStream {
        use crate::disassembly::{Expr, ExprElement, ReadScope};
        let inst_start = self.inst_start;
        let inst_next = self.inst_next;
        match expr {
            Expr::Value(element) => match element {
                ExprElement::Value { value, .. } => match value {
                    ReadScope::Integer(v) => {
                        let v = v.signed_super();
                        quote! { #v }
                    }
                    ReadScope::InstStart(_) => {
                        quote! { i128::from(#inst_start) }
                    }
                    ReadScope::InstNext(_) => {
                        quote! { i128::from(#inst_next) }
                    }
                    ReadScope::TokenField(tf) => match self.constructor.ass_fields.get(tf) {
                        Some(n) => quote! { i128::from(self.#n) },
                        None => quote! { 0i128 },
                    },
                    ReadScope::Context(_) => quote! { 0i128 },
                    ReadScope::Local(var_id) => match self.constructor.dis_fields.get(var_id) {
                        Some(name) => quote! { #name },
                        None => quote! { 0i128 },
                    },
                },
                ExprElement::Op(_, op, inner) => {
                    let x = self.gen_dis_expr_for_lift(inner);
                    crate::codegen::builder::disassembly::op_unary(op, x)
                }
            },
            Expr::Op(_, op, left, right) => {
                let l = self.gen_dis_expr_for_lift(left);
                let r = self.gen_dis_expr_for_lift(right);
                crate::codegen::builder::disassembly::disassembly_op(l, op, r)
            }
        }
    }

    fn gen_variable_decls(&self, execution: &Execution) -> TokenStream {
        let mut tokens = TokenStream::new();
        for (i, var) in execution.variables().iter().enumerate() {
            let var_id = VariableId(i);
            let size_bytes = Self::bytes_from_bits(var.len_bits.get());
            let var_name = format_ident!(
                "v_{}",
                crate::codegen::builder::formater::from_sleigh(var.name())
            );
            self.vars.borrow_mut().insert(var_id, var_name.clone());
            let offset = self.unique_counter.get();
            self.unique_counter.set(offset + size_bytes.max(1));
            let size = size_bytes as u32;
            tokens.extend(quote! {
                let #var_name = pcode_ir::Varnode::unique(unique_base + #offset, #size);
            });
        }
        tokens
    }

    fn estimate_execution_ops(&self, execution: &Execution) -> usize {
        execution
            .blocks()
            .iter()
            .map(|block| {
                block
                    .statements
                    .iter()
                    .map(|stmt| self.estimate_statement_ops(stmt))
                    .sum::<usize>()
            })
            .sum()
    }

    fn estimate_statement_ops(&self, stmt: &Statement) -> usize {
        match stmt {
            Statement::Assignment(a) => match &a.var {
                AssignmentWrite::Variable { .. } => self.estimate_expr_ops(&a.right) + 1,
                AssignmentWrite::Memory { addr, .. } => {
                    self.estimate_expr_ops(&a.right) + self.estimate_expr_ops(addr) + 1
                }
                AssignmentWrite::TableExport { .. } => self.estimate_expr_ops(&a.right) + 1,
            },
            Statement::CpuBranch(b) => {
                self.estimate_expr_ops(&b.dst)
                    + b.cond
                        .as_ref()
                        .map(|expr| self.estimate_expr_ops(expr))
                        .unwrap_or(0)
                    + 1
            }
            Statement::LocalGoto(g) => {
                g.cond
                    .as_ref()
                    .map(|expr| self.estimate_expr_ops(expr))
                    .unwrap_or(0)
                    + 1
            }
            Statement::Build(_) => 0,
            Statement::UserCall(call) => {
                call.params
                    .iter()
                    .map(|expr| self.estimate_expr_ops(expr))
                    .sum::<usize>()
                    + 1
            }
            Statement::Export(export) => match export {
                Export::Value(expr) => self.estimate_expr_ops(expr),
                Export::Reference { addr, .. } => self.estimate_expr_ops(addr),
                Export::Table { .. } | Export::AttachVarnode { .. } => 0,
            },
            Statement::Declare(_) | Statement::Delayslot(_) => 0,
        }
    }

    fn estimate_expr_ops(&self, expr: &Expr) -> usize {
        match expr {
            Expr::Value(element) => self.estimate_element_ops(element),
            Expr::Op(binary_op) => {
                self.estimate_expr_ops(&binary_op.left)
                    + self.estimate_expr_ops(&binary_op.right)
                    + 1
            }
        }
    }

    fn estimate_element_ops(&self, element: &ExprElement) -> usize {
        match element {
            ExprElement::Value { value, .. } => self.estimate_value_ops(value),
            ExprElement::Op(unary_op) => self.estimate_expr_ops(&unary_op.input) + 1,
            ExprElement::UserCall(call) => {
                call.params
                    .iter()
                    .map(|expr| self.estimate_expr_ops(expr))
                    .sum::<usize>()
                    + 1
            }
            ExprElement::Reference(_) | ExprElement::New(_) | ExprElement::CPool(_) => 0,
        }
    }

    fn estimate_value_ops(&self, value: &ExprValue) -> usize {
        match value {
            ExprValue::Table(_) => 1,
            _ => 0,
        }
    }

    fn gen_blocks(&self, execution: &Execution) -> TokenStream {
        let mut tokens = TokenStream::new();
        for block in execution.blocks().iter() {
            tokens.extend(self.gen_block(block, execution));
        }
        tokens
    }

    fn gen_block(&self, block: &Block, execution: &Execution) -> TokenStream {
        block
            .statements
            .iter()
            .map(|stmt| self.gen_statement(stmt, execution))
            .collect()
    }

    fn gen_statement(&self, stmt: &Statement, execution: &Execution) -> TokenStream {
        match stmt {
            Statement::Assignment(a) => self.gen_assignment(a, execution),
            Statement::CpuBranch(b) => self.gen_branch(b, execution),
            Statement::LocalGoto(g) => self.gen_local_goto(g, execution),
            Statement::Build(b) => self.gen_build(b),
            Statement::UserCall(c) => self.gen_user_call(c, execution),
            Statement::Export(e) => self.gen_export(e, execution),
            Statement::Declare(_) | Statement::Delayslot(_) => quote! {},
        }
    }

    // ── Assignment ───────────────────────────────────────────────────

    fn gen_assignment(&self, assignment: &Assignment, execution: &Execution) -> TokenStream {
        let (rhs, rhs_code) = self.lower_expr(&assignment.right, execution);

        match &assignment.var {
            AssignmentWrite::Variable { value, op } => {
                let dest = self.gen_write_variable(value);
                let mut tokens = rhs_code;
                match op {
                    None => {
                        tokens.extend(quote! {
                            ops.push(pcode_ir::PcodeOp::Copy { out: #dest, input: #rhs });
                        });
                    }
                    Some(AssignmentOp::TakeLsb(bytes)) => {
                        let size = bytes.get() as u32;
                        tokens.extend(quote! {
                            ops.push(pcode_ir::PcodeOp::Subpiece {
                                out: pcode_ir::Varnode { size: #size, ..#dest },
                                input: #rhs, lsb: 0,
                            });
                        });
                    }
                    Some(AssignmentOp::TrunkLsb(trunk)) => {
                        let lsb = *trunk as u32;
                        tokens.extend(quote! {
                            ops.push(pcode_ir::PcodeOp::Subpiece { out: #dest, input: #rhs, lsb: #lsb });
                        });
                    }
                    Some(AssignmentOp::BitRange(range)) => {
                        let lsb = (range.start / 8) as u32;
                        tokens.extend(quote! {
                            ops.push(pcode_ir::PcodeOp::Subpiece { out: #dest, input: #rhs, lsb: #lsb });
                        });
                    }
                }
                tokens
            }
            AssignmentWrite::Memory { mem, addr } => {
                let (addr_vn, addr_code) = self.lower_expr(addr, execution);
                let sp = self.space_id_expr(mem.space);
                let mut tokens = rhs_code;
                tokens.extend(addr_code);
                tokens.extend(quote! {
                    ops.push(pcode_ir::PcodeOp::Store { space: #sp, ptr: #addr_vn, val: #rhs });
                });
                tokens
            }
            AssignmentWrite::TableExport {
                table_id, op: _, ..
            } => {
                let mut tokens = TokenStream::new();
                let c = self.unique_counter.get();
                self.unique_counter.set(c + 1);
                let dest_name = format_ident!("dest_export_{}", c);
                let ref_name = format_ident!("dest_ref_{}", c);
                // Use cached subtable export
                match self.constructor.table_fields.get(table_id) {
                    Some(field) => {
                        let cache_exp = format_ident!("{}_exp", field);
                        let cache_ref = format_ident!("{}_ref", field);
                        tokens.extend(quote! {
                            let #dest_name = #cache_exp;
                            let #ref_name = #cache_ref;
                        });
                    }
                    None => {
                        tokens.extend(quote! {
                            let #dest_name: Option<pcode_ir::Varnode> = None;
                            let #ref_name: Option<(pcode_ir::AddressSpaceId, pcode_ir::Varnode, u32)> = None;
                        });
                    }
                }
                tokens.extend(rhs_code);
                // For reference exports, use Store; for value exports, use Copy
                tokens.extend(quote! {
                    if let Some((space, ptr, _size)) = #ref_name {
                        ops.push(pcode_ir::PcodeOp::Store { space, ptr, val: #rhs });
                    } else if let Some(dest) = #dest_name {
                        ops.push(pcode_ir::PcodeOp::Copy { out: dest, input: #rhs });
                    }
                });
                tokens
            }
        }
    }

    fn gen_write_variable(&self, var: &AssignmentWriteVariable) -> TokenStream {
        match var {
            AssignmentWriteVariable::Varnode(id) => self.varnode_expr(*id),
            AssignmentWriteVariable::Variable(id) => {
                let vars = self.vars.borrow();
                let n = vars.get(id).unwrap();
                quote! { #n }
            }
            AssignmentWriteVariable::Bitrange(id) => {
                let br = self.disassembler.sleigh.bitrange(*id);
                self.varnode_expr(br.varnode)
            }
            AssignmentWriteVariable::DynVarnode {
                value_id,
                attach_id,
            } => {
                let value_expr = self.dynamic_value_expr(value_id);
                self.dynamic_varnode_expr(*attach_id, &value_expr)
            }
        }
    }

    // ── Branch / LocalGoto / Build / UserCall / Export ────────────────

    fn gen_branch(&self, branch: &CpuBranch, execution: &Execution) -> TokenStream {
        // For branch destinations from table references, use the reference address
        // (not the loaded value) since branches target addresses, not memory contents
        let (dst, dst_code) = self.lower_branch_dest(&branch.dst, execution);
        let mut tokens = dst_code;

        match (&branch.cond, &branch.call) {
            (None, BranchCall::Goto) if branch.direct => {
                tokens.extend(quote! { ops.push(pcode_ir::PcodeOp::Branch { dest: #dst }); });
            }
            (None, BranchCall::Goto) => {
                tokens.extend(quote! { ops.push(pcode_ir::PcodeOp::BranchInd { dest: #dst }); });
            }
            (Some(cond), BranchCall::Goto) => {
                let (cv, cc) = self.lower_expr(cond, execution);
                tokens.extend(cc);
                tokens.extend(
                    quote! { ops.push(pcode_ir::PcodeOp::CBranch { dest: #dst, cond: #cv }); },
                );
            }
            (None, BranchCall::Call) if branch.direct => {
                tokens.extend(quote! { ops.push(pcode_ir::PcodeOp::Call { dest: #dst }); });
            }
            (None, BranchCall::Call) => {
                tokens.extend(quote! { ops.push(pcode_ir::PcodeOp::CallInd { dest: #dst }); });
            }
            (Some(cond), BranchCall::Call) => {
                let (_, cc) = self.lower_expr(cond, execution);
                tokens.extend(cc);
                if branch.direct {
                    tokens.extend(quote! { ops.push(pcode_ir::PcodeOp::Call { dest: #dst }); });
                } else {
                    tokens.extend(quote! { ops.push(pcode_ir::PcodeOp::CallInd { dest: #dst }); });
                }
            }
            (_, BranchCall::Return) => {
                tokens.extend(quote! { ops.push(pcode_ir::PcodeOp::Return { dest: #dst }); });
            }
        }
        tokens
    }

    fn gen_local_goto(&self, goto: &LocalGoto, execution: &Execution) -> TokenStream {
        let idx = goto.dst.0 as u64;
        let dest = quote! { pcode_ir::Varnode::constant(#idx, 8) };
        match &goto.cond {
            None => quote! { ops.push(pcode_ir::PcodeOp::Branch { dest: #dest }); },
            Some(cond) => {
                let (cv, cc) = self.lower_expr(cond, execution);
                let mut t = cc;
                t.extend(
                    quote! { ops.push(pcode_ir::PcodeOp::CBranch { dest: #dest, cond: #cv }); },
                );
                t
            }
        }
    }

    fn gen_build(&self, _build: &Build) -> TokenStream {
        // Build ops are already added via the subtable cache at the top of lift()
        quote! {}
    }

    fn gen_user_call(&self, call: &UserCall, execution: &Execution) -> TokenStream {
        let func_id = call.function.0 as u64;
        let mut tokens = TokenStream::new();
        let mut inputs = Vec::new();
        for param in call.params.iter() {
            let (vn, code) = self.lower_expr(param, execution);
            tokens.extend(code);
            inputs.push(vn);
        }
        let inputs_iter = inputs.iter();
        tokens.extend(quote! {
            ops.push(pcode_ir::PcodeOp::CallOther {
                out: None, func_id: #func_id, inputs: vec![#(#inputs_iter),*],
            });
        });
        tokens
    }

    fn gen_export(&self, export: &Export, execution: &Execution) -> TokenStream {
        match export {
            Export::Value(expr) => {
                let (vn, code) = self.lower_expr(expr, execution);
                let mut tokens = code;
                tokens.extend(quote! { export_varnode = Some(#vn); });
                tokens
            }
            Export::Reference { addr, memory } => {
                let (vn, code) = self.lower_expr(addr, execution);
                let space_type = self.disassembler.sleigh.space(memory.space).space_type;
                // len_bytes is actually in bits despite the name
                let size_bytes = Self::bytes_from_bits(memory.len_bytes.get());
                let size = size_bytes as u32;
                let mut tokens = code;

                match space_type {
                    SpaceType::Register => {
                        // Register-space reference (e.g. `export ZF`): just export the
                        // register varnode directly — no Load needed
                        tokens.extend(quote! {
                            export_varnode = Some(pcode_ir::Varnode::register(#vn.offset, #size));
                        });
                    }
                    _ => {
                        // RAM/other space reference (e.g. `export *[ram]:8 addr`):
                        // For value reads, a Load is needed; for branches, use address directly.
                        // Set export_ref so parent can decide.
                        let sp = self.space_id_expr(memory.space);
                        tokens.extend(quote! {
                            export_varnode = Some(pcode_ir::Varnode { space: #sp, offset: #vn.offset, size: #size });
                            export_ref = Some((#sp, #vn, #size));
                        });
                    }
                }
                tokens
            }
            Export::Table { table_id, .. } => match self.constructor.table_fields.get(table_id) {
                Some(field) => {
                    let cache_exp = format_ident!("{}_exp", field);
                    let cache_ref = format_ident!("{}_ref", field);
                    quote! {
                        export_varnode = #cache_exp;
                        export_ref = #cache_ref;
                    }
                }
                None => quote! {},
            },
            Export::AttachVarnode {
                attach_value,
                attach_id,
                ..
            } => {
                let value_expr = self.dynamic_value_expr(attach_value);
                let vn = self.dynamic_varnode_expr(*attach_id, &value_expr);
                quote! { export_varnode = Some(#vn); }
            }
        }
    }

    /// Lower a branch destination — for table references that export a reference,
    /// use the address directly instead of loading the value at that address.
    fn lower_branch_dest(&self, expr: &Expr, execution: &Execution) -> (TokenStream, TokenStream) {
        // Check if the expression is a simple table reference
        if let Expr::Value(ExprElement::Value {
            value: ExprValue::Table(table_id),
            ..
        }) = expr
        {
            let sz = self.addr_size();
            if let Some(field) = self.constructor.table_fields.get(table_id) {
                let cache_exp = format_ident!("{}_exp", field);
                let cache_ref = format_ident!("{}_ref", field);
                let var_name = format_ident!("branch_dest_{}", {
                    let c = self.unique_counter.get();
                    self.unique_counter.set(c + 1);
                    c
                });
                return (
                    quote! { #var_name },
                    quote! {
                        let #var_name = if let Some((ref_space, ref_ptr, ref_size)) = #cache_ref {
                            pcode_ir::Varnode { space: ref_space, offset: ref_ptr.offset, size: ref_size }
                        } else {
                            #cache_exp.unwrap_or(pcode_ir::Varnode::constant(0, #sz))
                        };
                    },
                );
            }
        }
        // Fall back to normal expression lowering
        self.lower_expr(expr, execution)
    }

    // ── Expression lowering ──────────────────────────────────────────

    fn lower_expr(&self, expr: &Expr, execution: &Execution) -> (TokenStream, TokenStream) {
        match expr {
            Expr::Value(element) => self.lower_element(element, execution),
            Expr::Op(binary_op) => self.lower_binary(binary_op, execution),
        }
    }

    fn lower_element(
        &self,
        element: &ExprElement,
        execution: &Execution,
    ) -> (TokenStream, TokenStream) {
        match element {
            ExprElement::Value { value, .. } => self.lower_value(value, execution),
            ExprElement::Op(unary_op) => self.lower_unary(unary_op, execution),
            ExprElement::UserCall(call) => {
                let func_id = call.function.0 as u64;
                let sz = self.addr_size() as u64;
                let out = self.fresh_unique(sz);
                let mut code = TokenStream::new();
                let mut inputs = Vec::new();
                for param in call.params.iter() {
                    let (vn, c) = self.lower_expr(param, execution);
                    code.extend(c);
                    inputs.push(vn);
                }
                let out2 = out.clone();
                let inputs_iter = inputs.iter();
                code.extend(quote! {
                    ops.push(pcode_ir::PcodeOp::CallOther {
                        out: Some(#out2), func_id: #func_id, inputs: vec![#(#inputs_iter),*],
                    });
                });
                (out, code)
            }
            ExprElement::Reference(reference) => {
                use crate::execution::ReferencedValue;
                let sz = Self::bytes_from_bits(reference.len_bits.get()) as u32;
                match &reference.value {
                    ReferencedValue::InstStart(_) => {
                        let is = self.inst_start;
                        (
                            quote! { pcode_ir::Varnode::constant(#is as u64, #sz) },
                            quote! {},
                        )
                    }
                    ReferencedValue::InstNext(_) => {
                        let in_ = self.inst_next;
                        (
                            quote! { pcode_ir::Varnode::constant(#in_ as u64, #sz) },
                            quote! {},
                        )
                    }
                    ReferencedValue::TokenField(tf) => {
                        match self.constructor.ass_fields.get(&tf.id) {
                            Some(n) => (
                                quote! { pcode_ir::Varnode::constant(self.#n as u64, #sz) },
                                quote! {},
                            ),
                            None => (quote! { pcode_ir::Varnode::constant(0, #sz) }, quote! {}),
                        }
                    }
                    ReferencedValue::Table(_) => {
                        (quote! { pcode_ir::Varnode::constant(0, #sz) }, quote! {})
                    }
                }
            }
            ExprElement::New(_) | ExprElement::CPool(_) => {
                (quote! { pcode_ir::Varnode::constant(0, 8) }, quote! {})
            }
        }
    }

    fn lower_value(&self, value: &ExprValue, _execution: &Execution) -> (TokenStream, TokenStream) {
        match value {
            ExprValue::Int(ExprNumber { size, number }) => {
                let sz = Self::bytes_from_bits(size.get()) as u32;
                let val = number.signed_super();
                (
                    quote! { pcode_ir::Varnode::constant(#val as u64, #sz) },
                    quote! {},
                )
            }
            ExprValue::Varnode(id) => (self.varnode_expr(*id), quote! {}),
            ExprValue::ExeVar(id) => {
                let vars = self.vars.borrow();
                let n = vars.get(id).unwrap();
                (quote! { #n }, quote! {})
            }
            ExprValue::InstStart(_) => {
                let is = self.inst_start;
                let sz = self.addr_size();
                (
                    quote! { pcode_ir::Varnode::constant(#is as u64, #sz) },
                    quote! {},
                )
            }
            ExprValue::InstNext(_) => {
                let in_ = self.inst_next;
                let sz = self.addr_size();
                (
                    quote! { pcode_ir::Varnode::constant(#in_ as u64, #sz) },
                    quote! {},
                )
            }
            ExprValue::TokenField(tf) => {
                let sz = Self::bytes_from_bits(tf.size.get()) as u32;
                match self.constructor.ass_fields.get(&tf.id) {
                    Some(n) => (
                        quote! { pcode_ir::Varnode::constant(self.#n as u64, #sz) },
                        quote! {},
                    ),
                    None => (quote! { pcode_ir::Varnode::constant(0, #sz) }, quote! {}),
                }
            }
            ExprValue::Context(ctx) => {
                // Context values are fixed at decode time and rarely appear in P-code
                // execution. Would need context to be passed to lift() to read properly.
                let sz = Self::bytes_from_bits(ctx.size.get()) as u32;
                (quote! { pcode_ir::Varnode::constant(0, #sz) }, quote! {})
            }
            ExprValue::Table(table_id) => {
                let sz = self.addr_size();
                match self.constructor.table_fields.get(table_id) {
                    Some(field) => {
                        let cache_exp = format_ident!("{}_exp", field);
                        let cache_ref = format_ident!("{}_ref", field);
                        let var_name = format_ident!("table_val_{}", {
                            let c = self.unique_counter.get();
                            self.unique_counter.set(c + 1);
                            c
                        });
                        (
                            quote! { #var_name },
                            quote! {
                                let #var_name = if let Some((ref_space, ref_ptr, ref_size)) = #cache_ref {
                                    let loaded = pcode_ir::Varnode::unique(
                                        unique_base + (ops.len() as u64 + 0x8000),
                                        ref_size,
                                    );
                                    ops.push(pcode_ir::PcodeOp::Load {
                                        out: loaded.clone(), space: ref_space, ptr: ref_ptr,
                                    });
                                    loaded
                                } else {
                                    #cache_exp.unwrap_or(pcode_ir::Varnode::constant(0, #sz))
                                };
                            },
                        )
                    }
                    None => (quote! { pcode_ir::Varnode::constant(0, #sz) }, quote! {}),
                }
            }
            ExprValue::DisVar(dv) => {
                let sz = Self::bytes_from_bits(dv.size.get()) as u32;
                match self.constructor.dis_fields.get(&dv.id) {
                    Some(name) => {
                        // Use the local recomputed variable (shadowed from self)
                        (
                            quote! { pcode_ir::Varnode::constant(#name as u64, #sz) },
                            quote! {},
                        )
                    }
                    None => (quote! { pcode_ir::Varnode::constant(0, #sz) }, quote! {}),
                }
            }
            ExprValue::Bitrange(br) => (
                self.varnode_expr(self.disassembler.sleigh.bitrange(br.id).varnode),
                quote! {},
            ),
            ExprValue::IntDynamic(d) => {
                let sz = Self::bytes_from_bits(d.bits.get()) as u32;
                let value_expr = self.dynamic_value_expr(&d.attach_value);
                let vn = self.dynamic_int_expr(d.attach_id, &value_expr, sz);
                (vn, quote! {})
            }
            ExprValue::VarnodeDynamic(dv) => {
                let value_expr = self.dynamic_value_expr(&dv.attach_value);
                let vn = self.dynamic_varnode_expr(dv.attach_id, &value_expr);
                (vn, quote! {})
            }
        }
    }

    // ── Binary operations ────────────────────────────────────────────

    fn lower_binary(&self, op: &ExprBinaryOp, execution: &Execution) -> (TokenStream, TokenStream) {
        let (l, lc) = self.lower_expr(&op.left, execution);
        let (r, rc) = self.lower_expr(&op.right, execution);
        let sz = Self::bytes_from_bits(op.len_bits.get());
        let out = self.fresh_unique(sz);
        let o = out.clone();
        let mut code = lc;
        code.extend(rc);

        // For Greater variants, swap operands and use Less variant.
        macro_rules! bin {
            ($V:ident) => {
                quote! { ops.push(pcode_ir::PcodeOp::$V { out: #o, left: #l, right: #r }); }
            };
            ($V:ident, swap) => {
                quote! { ops.push(pcode_ir::PcodeOp::$V { out: #o, left: #r, right: #l }); }
            };
        }

        code.extend(match op.op {
            Binary::Add => bin!(IntAdd),
            Binary::Sub => bin!(IntSub),
            Binary::Mult => bin!(IntMult),
            Binary::Div => bin!(IntDiv),
            Binary::SigDiv => bin!(IntSDiv),
            Binary::Rem => bin!(IntRem),
            Binary::SigRem => bin!(IntSRem),
            Binary::FloatAdd => bin!(FloatAdd),
            Binary::FloatSub => bin!(FloatSub),
            Binary::FloatMult => bin!(FloatMult),
            Binary::FloatDiv => bin!(FloatDiv),
            Binary::Lsl => bin!(IntLsl),
            Binary::Lsr => bin!(IntLsr),
            Binary::Asr => bin!(IntAsr),
            Binary::BitAnd => bin!(IntAnd),
            Binary::BitOr => bin!(IntOr),
            Binary::BitXor => bin!(IntXor),
            Binary::And => bin!(BoolAnd),
            Binary::Or => bin!(BoolOr),
            Binary::Xor => bin!(BoolXor),
            Binary::Eq => bin!(IntEq),
            Binary::Ne => bin!(IntNotEq),
            Binary::Less => bin!(IntLess),
            Binary::Greater => bin!(IntLess, swap),
            Binary::LessEq => bin!(IntLessEq),
            Binary::GreaterEq => bin!(IntLessEq, swap),
            Binary::SigLess => bin!(IntSLess),
            Binary::SigGreater => bin!(IntSLess, swap),
            Binary::SigLessEq => bin!(IntSLessEq),
            Binary::SigGreaterEq => bin!(IntSLessEq, swap),
            Binary::FloatEq => bin!(FloatEq),
            Binary::FloatNe => bin!(FloatNotEq),
            Binary::FloatLess => bin!(FloatLess),
            Binary::FloatGreater => bin!(FloatLess, swap),
            Binary::FloatLessEq => bin!(FloatLessEq),
            Binary::FloatGreaterEq => bin!(FloatLessEq, swap),
            Binary::Carry => bin!(IntCarry),
            Binary::SCarry => bin!(IntSCarry),
            Binary::SBorrow => bin!(IntSBorrow),
        });
        (out, code)
    }

    // ── Unary operations ─────────────────────────────────────────────

    fn lower_unary(&self, op: &ExprUnaryOp, execution: &Execution) -> (TokenStream, TokenStream) {
        let (inp, mut code) = self.lower_expr(&op.input, execution);

        match &op.op {
            Unary::Dereference(mem) => {
                // len_bytes is actually in bits despite the name
                let out = self.fresh_unique(Self::bytes_from_bits(mem.len_bytes.get()));
                let sp = self.space_id_expr(mem.space);
                let o = out.clone();
                code.extend(quote! { ops.push(pcode_ir::PcodeOp::Load { out: #o, space: #sp, ptr: #inp }); });
                (out, code)
            }
            Unary::TakeLsb(bytes) => {
                let out = self.fresh_unique(bytes.get());
                let o = out.clone();
                code.extend(quote! { ops.push(pcode_ir::PcodeOp::Subpiece { out: #o, input: #inp, lsb: 0 }); });
                (out, code)
            }
            Unary::TrunkLsb { trunk, bits } => {
                let lsb = (*trunk / 8) as u32;
                let out = self.fresh_unique(Self::bytes_from_bits(bits.get()));
                let o = out.clone();
                code.extend(quote! { ops.push(pcode_ir::PcodeOp::Subpiece { out: #o, input: #inp, lsb: #lsb }); });
                (out, code)
            }
            Unary::BitRange { range, bits } => {
                let lsb = (range.start / 8) as u32;
                let out = self.fresh_unique(Self::bytes_from_bits(bits.get()));
                let o = out.clone();
                code.extend(quote! { ops.push(pcode_ir::PcodeOp::Subpiece { out: #o, input: #inp, lsb: #lsb }); });
                (out, code)
            }
            // All remaining unary ops follow the pattern: allocate out, emit op
            other => {
                let (variant, out_size) = match other {
                    Unary::Zext(b) => (quote! { IntZext }, Self::bytes_from_bits(b.get())),
                    Unary::Sext(b) => (quote! { IntSext }, Self::bytes_from_bits(b.get())),
                    Unary::Negation => (quote! { BoolNot }, 1),
                    Unary::BitNegation => (quote! { IntNot }, self.addr_size() as u64),
                    Unary::Negative => (quote! { IntNeg }, self.addr_size() as u64),
                    Unary::FloatNegative => (quote! { FloatNeg }, self.addr_size() as u64),
                    Unary::FloatAbs => (quote! { FloatAbs }, self.addr_size() as u64),
                    Unary::FloatSqrt => (quote! { FloatSqrt }, self.addr_size() as u64),
                    Unary::FloatCeil => (quote! { FloatCeil }, self.addr_size() as u64),
                    Unary::FloatFloor => (quote! { FloatFloor }, self.addr_size() as u64),
                    Unary::FloatRound => (quote! { FloatRound }, self.addr_size() as u64),
                    Unary::FloatNan(_) => (quote! { FloatNan }, 1),
                    Unary::Int2Float(b) => (quote! { Int2Float }, Self::bytes_from_bits(b.get())),
                    Unary::Float2Float(b) => {
                        (quote! { Float2Float }, Self::bytes_from_bits(b.get()))
                    }
                    Unary::SignTrunc(b) => (quote! { Trunc }, Self::bytes_from_bits(b.get())),
                    Unary::Popcount(b) => (quote! { Popcount }, Self::bytes_from_bits(b.get())),
                    Unary::Lzcount(b) => (quote! { Lzcount }, Self::bytes_from_bits(b.get())),
                    _ => unreachable!(),
                };
                let out = self.fresh_unique(out_size);
                let o = out.clone();
                code.extend(quote! {
                    ops.push(pcode_ir::PcodeOp::#variant { out: #o, input: #inp });
                });
                (out, code)
            }
        }
    }
}
