use std::cell::Cell;

use indexmap::IndexMap;
use std::cell::RefCell;

use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote};

use crate::execution::{
    Assignment, AssignmentOp, AssignmentWrite, AssignmentWriteVariable, Binary,
    Block, BlockId, Build, BranchCall, CpuBranch, Execution, Export, Expr,
    ExprBinaryOp, ExprElement, ExprNumber, ExprUnaryOp, ExprValue, LocalGoto,
    Statement, Unary, UserCall, VariableId,
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

    // ── Top-level ────────────────────────────────────────────────────

    pub fn gen_lift(&self, execution: &Execution) -> TokenStream {
        let addr_type = &self.disassembler.addr_type;
        let inst_start = self.inst_start;
        let inst_next = self.inst_next;
        let var_decls = self.gen_variable_decls(execution);
        let block_code = self.gen_blocks(execution);

        quote! {
            fn lift(
                &self,
                #inst_start: #addr_type,
                #inst_next: #addr_type,
            ) -> Vec<pcode_ir::PcodeOp> {
                let mut ops: Vec<pcode_ir::PcodeOp> = Vec::new();
                let unique_base: u64 = (#inst_start as u64) << 16;
                #var_decls
                #block_code
                ops
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

    fn gen_blocks(&self, execution: &Execution) -> TokenStream {
        let mut tokens = TokenStream::new();
        for (i, block) in execution.blocks().iter().enumerate() {
            let block_code = self.gen_block(block, execution);
            if block.name.is_some() {
                let label = format_ident!("block_{}", i);
                tokens.extend(quote! { #label: { #block_code } });
            } else {
                tokens.extend(block_code);
            }
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
            AssignmentWrite::TableExport { .. } => rhs_code,
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
            AssignmentWriteVariable::DynVarnode { .. } => {
                quote! { pcode_ir::Varnode::unique(0, 8) }
            }
        }
    }

    // ── Branch / LocalGoto / Build / UserCall / Export ────────────────

    fn gen_branch(&self, branch: &CpuBranch, execution: &Execution) -> TokenStream {
        let (dst, dst_code) = self.lower_expr(&branch.dst, execution);
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
                tokens.extend(quote! { ops.push(pcode_ir::PcodeOp::CBranch { dest: #dst, cond: #cv }); });
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
                t.extend(quote! { ops.push(pcode_ir::PcodeOp::CBranch { dest: #dest, cond: #cv }); });
                t
            }
        }
    }

    fn gen_build(&self, build: &Build) -> TokenStream {
        match self.constructor.table_fields.get(&build.table) {
            Some(field) => {
                let is = self.inst_start;
                let in_ = self.inst_next;
                quote! { ops.extend(self.#field.lift(#is, #in_)); }
            }
            None => quote! {},
        }
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
            Export::Value(expr) | Export::Reference { addr: expr, .. } => {
                self.lower_expr(expr, execution).1
            }
            _ => quote! {},
        }
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
                        (quote! { pcode_ir::Varnode::constant(#is as u64, #sz) }, quote! {})
                    }
                    ReferencedValue::InstNext(_) => {
                        let in_ = self.inst_next;
                        (quote! { pcode_ir::Varnode::constant(#in_ as u64, #sz) }, quote! {})
                    }
                    ReferencedValue::TokenField(tf) => {
                        match self.constructor.ass_fields.get(&tf.id) {
                            Some(n) => (quote! { pcode_ir::Varnode::constant(self.#n as u64, #sz) }, quote! {}),
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

    fn lower_value(&self, value: &ExprValue, execution: &Execution) -> (TokenStream, TokenStream) {
        match value {
            ExprValue::Int(ExprNumber { size, number }) => {
                let sz = Self::bytes_from_bits(size.get()) as u32;
                let val = number.signed_super();
                (quote! { pcode_ir::Varnode::constant(#val as u64, #sz) }, quote! {})
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
                (quote! { pcode_ir::Varnode::constant(#is as u64, #sz) }, quote! {})
            }
            ExprValue::InstNext(_) => {
                let in_ = self.inst_next;
                let sz = self.addr_size();
                (quote! { pcode_ir::Varnode::constant(#in_ as u64, #sz) }, quote! {})
            }
            ExprValue::TokenField(tf) => {
                let sz = Self::bytes_from_bits(tf.size.get()) as u32;
                match self.constructor.ass_fields.get(&tf.id) {
                    Some(n) => (quote! { pcode_ir::Varnode::constant(self.#n as u64, #sz) }, quote! {}),
                    None => (quote! { pcode_ir::Varnode::constant(0, #sz) }, quote! {}),
                }
            }
            ExprValue::Context(ctx) => {
                let sz = Self::bytes_from_bits(ctx.size.get()) as u32;
                (quote! { pcode_ir::Varnode::constant(0, #sz) }, quote! {})
            }
            ExprValue::Table(table_id) => {
                let sz = self.addr_size();
                match self.constructor.table_fields.get(table_id) {
                    Some(field) => {
                        let is = self.inst_start;
                        let in_ = self.inst_next;
                        (
                            quote! { pcode_ir::Varnode::constant(0, #sz) },
                            quote! { ops.extend(self.#field.lift(#is, #in_)); },
                        )
                    }
                    None => (quote! { pcode_ir::Varnode::constant(0, #sz) }, quote! {}),
                }
            }
            ExprValue::DisVar(dv) => {
                let sz = Self::bytes_from_bits(dv.size.get()) as u32;
                (quote! { pcode_ir::Varnode::constant(0, #sz) }, quote! {})
            }
            ExprValue::Bitrange(br) => {
                (self.varnode_expr(self.disassembler.sleigh.bitrange(br.id).varnode), quote! {})
            }
            ExprValue::IntDynamic(d) => {
                let sz = Self::bytes_from_bits(d.bits.get()) as u32;
                (quote! { pcode_ir::Varnode::constant(0, #sz) }, quote! {})
            }
            ExprValue::VarnodeDynamic(_) => {
                let sz = self.addr_size();
                (quote! { pcode_ir::Varnode::unique(0, #sz) }, quote! {})
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
            ($V:ident) => { quote! { ops.push(pcode_ir::PcodeOp::$V { out: #o, left: #l, right: #r }); } };
            ($V:ident, swap) => { quote! { ops.push(pcode_ir::PcodeOp::$V { out: #o, left: #r, right: #l }); } };
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
                let out = self.fresh_unique(mem.len_bytes.get());
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
                    Unary::Float2Float(b) => (quote! { Float2Float }, Self::bytes_from_bits(b.get())),
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
