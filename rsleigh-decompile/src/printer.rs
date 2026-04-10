use pcode_ir::{Varnode, AddressSpaceId};
use rsleigh_api::Architecture;
use crate::ir::*;

/// Print structured statements as C-like pseudocode.
pub fn print_c(stmts: &[StructuredStmt], ssa: &SsaCfg, arch: Architecture) -> String {
    let mut out = String::new();
    let filtered = filter_boilerplate(stmts, ssa);
    print_stmts(&filtered, ssa, arch, 0, &mut out);
    out
}

/// Remove prologue/epilogue boilerplate from the top level.
fn filter_boilerplate(stmts: &[StructuredStmt], ssa: &SsaCfg) -> Vec<StructuredStmt> {
    stmts.iter().filter(|stmt| {
        match stmt {
            StructuredStmt::Assign { lhs, .. } => {
                let vdef = ssa.var(*lhs);
                // Skip RSP adjustments (prologue/epilogue stack management)
                if is_stack_management(vdef, ssa) { return false; }
                // Skip RBP = RSP (frame pointer setup) and RBP = *(RSP) (restore)
                if is_frame_pointer_op(vdef) { return false; }
                // Skip RIP writes
                if vdef.varnode.space == AddressSpaceId::Register && vdef.varnode.offset == 648 {
                    return false;
                }
                true
            }
            StructuredStmt::Store { addr, val: _ } => {
                let addr_def = ssa.var(*addr);
                // Skip stores to RSP (push return address, push RBP)
                if addr_def.varnode.space == AddressSpaceId::Register
                    && addr_def.varnode.offset == 32
                {
                    return false;
                }
                // Skip stores where address is an RSP-derived expression
                if is_rsp_expr(&addr_def.expr, ssa) { return false; }
                true
            }
            _ => true,
        }
    }).cloned().collect()
}

fn is_stack_management(vdef: &VarDef, ssa: &SsaCfg) -> bool {
    if vdef.varnode.space != AddressSpaceId::Register { return false; }
    // RSP = RSP +/- N
    if vdef.varnode.offset == 32 {
        if let Expr::BinOp(BinOpKind::Add | BinOpKind::Sub, l, _) = &vdef.expr {
            let lv = ssa.var(*l);
            return lv.varnode.space == AddressSpaceId::Register && lv.varnode.offset == 32;
        }
        // RSP = RBP (leave instruction)
        if let Expr::Var(id) = &vdef.expr {
            let v = ssa.var(*id);
            return v.varnode.space == AddressSpaceId::Register && v.varnode.offset == 40;
        }
    }
    false
}

fn is_frame_pointer_op(vdef: &VarDef) -> bool {
    if vdef.varnode.space != AddressSpaceId::Register { return false; }
    // RBP = RSP or RBP = *(RSP) or RSP = RBP
    if vdef.varnode.offset == 40 || vdef.varnode.offset == 32 {
        match &vdef.expr {
            Expr::Var(_) => true, // RBP = RSP, RSP = RBP
            Expr::Load(_) => vdef.varnode.offset == 40, // RBP = *(RSP)
            _ => false,
        }
    } else {
        false
    }
}

fn is_rsp_expr(expr: &Expr, ssa: &SsaCfg) -> bool {
    match expr {
        Expr::Var(id) => {
            let v = ssa.var(*id);
            v.varnode.space == AddressSpaceId::Register && v.varnode.offset == 32
        }
        Expr::BinOp(_, l, _) => {
            let v = ssa.var(*l);
            v.varnode.space == AddressSpaceId::Register && v.varnode.offset == 32
        }
        _ => false,
    }
}

/// Check if a body would produce no visible output after filtering.
fn is_body_empty(stmts: &[StructuredStmt], ssa: &SsaCfg) -> bool {
    for stmt in stmts {
        match stmt {
            StructuredStmt::Assign { lhs, .. } => {
                let vdef = ssa.var(*lhs);
                if vdef.varnode.space == AddressSpaceId::Unique { continue; }
                if vdef.varnode.space == AddressSpaceId::Register && is_flag(vdef.varnode.offset) { continue; }
                if matches!(&vdef.expr, Expr::Phi(_)) { continue; }
                if vdef.varnode.space == AddressSpaceId::Register {
                    if let Expr::UnaryOp(UnaryOpKind::Zext, inner_id) = &vdef.expr {
                        let inner = ssa.var(*inner_id);
                        if inner.varnode.space == AddressSpaceId::Register
                            && inner.varnode.offset == vdef.varnode.offset
                            && inner.varnode.size < vdef.varnode.size { continue; }
                    }
                }
                return false;
            }
            StructuredStmt::Return(_) | StructuredStmt::Store { .. }
            | StructuredStmt::Call { .. } | StructuredStmt::While { .. }
            | StructuredStmt::Goto(_) => return false,
            StructuredStmt::IfElse { then_body, else_body, .. } => {
                if !is_body_empty(then_body, ssa) || !is_body_empty(else_body, ssa) {
                    return false;
                }
            }
            StructuredStmt::Label(_) => {}
        }
    }
    true
}

fn print_stmts(stmts: &[StructuredStmt], ssa: &SsaCfg, arch: Architecture, indent: usize, out: &mut String) {
    for stmt in stmts {
        print_stmt(stmt, ssa, arch, indent, out);
    }
}

fn print_stmt(stmt: &StructuredStmt, ssa: &SsaCfg, arch: Architecture, indent: usize, out: &mut String) {
    let pad: String = "    ".repeat(indent);

    match stmt {
        StructuredStmt::Assign { lhs, .. } => {
            let vdef = ssa.var(*lhs);
            // Skip all Unique-space vars
            if vdef.varnode.space == AddressSpaceId::Unique {
                return;
            }
            // Skip flag register assignments
            if vdef.varnode.space == AddressSpaceId::Register && is_flag(vdef.varnode.offset) {
                return;
            }
            // Skip phi nodes in output
            if matches!(&vdef.expr, Expr::Phi(_)) {
                return;
            }
            // Skip sub-register zero-extension artifacts:
            // e.g. RAX = (uint64_t)EAX after a 32-bit op on x86
            if vdef.varnode.space == AddressSpaceId::Register {
                if let Expr::UnaryOp(UnaryOpKind::Zext, inner_id) = &vdef.expr {
                    let inner = ssa.var(*inner_id);
                    if inner.varnode.space == AddressSpaceId::Register
                        && inner.varnode.offset == vdef.varnode.offset
                        && inner.varnode.size < vdef.varnode.size
                    {
                        return; // RAX = zext(EAX) is implicit on x86-64
                    }
                }
            }
            // Skip self-assignments (Copy of same register)
            if let Expr::Var(src_id) = &vdef.expr {
                let src = ssa.var(*src_id);
                if src.varnode == vdef.varnode {
                    return;
                }
            }
            let name = var_name(&vdef.varnode, arch);
            let rhs = format_expr(&vdef.expr, ssa, arch);
            out.push_str(&format!("{}{} = {};\n", pad, name, rhs));
        }
        StructuredStmt::Store { addr, val } => {
            let addr_str = format_expr_for_addr(*addr, ssa, arch);
            let val_expr = format_var(*val, ssa, arch);
            let size = ssa.var(*val).size;
            let type_name = size_to_type(size);
            out.push_str(&format!("{}*({}*)({}) = {};\n", pad, type_name, addr_str, val_expr));
        }
        StructuredStmt::Call { target, args, out: call_out } => {
            let target_name = match target {
                CallTarget::Direct(addr) => format!("func_{:x}", addr),
                CallTarget::Indirect(vn) => {
                    // Try to resolve through Load to show the actual target address
                    format!("(*{})", var_name(vn, arch))
                }
            };
            let args_str: Vec<String> = args.iter()
                .map(|a| format_var(*a, ssa, arch))
                .collect();
            if let Some(out_var) = call_out {
                let name = var_name(&ssa.var(*out_var).varnode, arch);
                out.push_str(&format!("{}{} = {}({});\n", pad, name, target_name, args_str.join(", ")));
            } else {
                out.push_str(&format!("{}{}({});\n", pad, target_name, args_str.join(", ")));
            }
        }
        StructuredStmt::Return(val) => {
            if let Some(v) = val {
                let expr = format_var(*v, ssa, arch);
                out.push_str(&format!("{}return {};\n", pad, expr));
            } else {
                out.push_str(&format!("{}return;\n", pad));
            }
        }
        StructuredStmt::IfElse { cond, then_body, else_body } => {
            let cond_expr = format_var(*cond, ssa, arch);
            let then_filtered = filter_boilerplate(then_body, ssa);
            let else_filtered = filter_boilerplate(else_body, ssa);

            let then_empty = is_body_empty(&then_filtered, ssa);
            let else_empty = is_body_empty(&else_filtered, ssa);

            if then_empty && else_empty {
                // Both empty after filtering — skip entirely
                return;
            } else if then_empty && !else_empty {
                // Negate: if (cond) {} else { body } → if (!cond) { body }
                out.push_str(&format!("{}if (!{}) {{\n", pad, cond_expr));
                print_stmts(&else_filtered, ssa, arch, indent + 1, out);
                out.push_str(&format!("{}}}\n", pad));
            } else {
                out.push_str(&format!("{}if ({}) {{\n", pad, cond_expr));
                print_stmts(&then_filtered, ssa, arch, indent + 1, out);
                if !else_empty {
                    out.push_str(&format!("{}}} else {{\n", pad));
                    print_stmts(&else_filtered, ssa, arch, indent + 1, out);
                }
                out.push_str(&format!("{}}}\n", pad));
            }
        }
        StructuredStmt::While { cond, body } => {
            let cond_expr = format_var(*cond, ssa, arch);
            let body_filtered = filter_boilerplate(body, ssa);
            out.push_str(&format!("{}while ({}) {{\n", pad, cond_expr));
            print_stmts(&body_filtered, ssa, arch, indent + 1, out);
            out.push_str(&format!("{}}}\n", pad));
        }
        StructuredStmt::Goto(addr) => {
            out.push_str(&format!("{}goto label_{:x};\n", pad, addr));
        }
        StructuredStmt::Label(addr) => {
            out.push_str(&format!("label_{:x}:\n", addr));
        }
    }
}

/// Format an address expression, recognizing RBP-relative stack accesses.
fn format_expr_for_addr(id: VarId, ssa: &SsaCfg, arch: Architecture) -> String {
    let expr = resolve_through_vars(id, ssa);
    if let Expr::BinOp(BinOpKind::Add, base_id, off_id) = &expr {
        let base_expr = resolve_through_vars(*base_id, ssa);
        let off_expr = resolve_through_vars(*off_id, ssa);
        // Check if base is RBP
        let is_rbp = match &base_expr {
            Expr::Unknown => ssa.var(*base_id).varnode.space == AddressSpaceId::Register
                && ssa.var(*base_id).varnode.offset == 40,
            _ => {
                let bv = ssa.var(*base_id);
                bv.varnode.space == AddressSpaceId::Register && bv.varnode.offset == 40
            }
        };
        if is_rbp {
            let const_val = match &off_expr {
                Expr::Const(val, _) => Some(*val),
                _ => {
                    let off_vdef = ssa.var(*off_id);
                    match &off_vdef.expr {
                        Expr::Const(val, _) => Some(*val),
                        _ => None,
                    }
                }
            };
            if let Some(val) = const_val {
                return format_rbp_offset(val);
            }
        }
    }
    format_var(id, ssa, arch)
}

/// Format an RBP-relative offset, detecting negative stack frame offsets.
/// Ghidra/rsleigh encodes `[RBP-8]` as `IntAdd(RBP, 0xf8)` where 0xf8 is the
/// unsigned byte encoding of -8. We detect this by checking common size boundaries.
fn format_rbp_offset(val: u64) -> String {
    // Full 64-bit negative
    if val > 0x7fffffffffffffff {
        let neg = (!val).wrapping_add(1);
        return format!("RBP - 0x{:x}", neg);
    }
    // Byte-sized negative (128..256)
    if val >= 0x80 && val < 0x100 {
        let neg = 0x100 - val;
        return format!("RBP - 0x{:x}", neg);
    }
    // Word-sized negative (0x8000..0x10000)
    if val >= 0x8000 && val < 0x10000 {
        let neg = 0x10000 - val;
        return format!("RBP - 0x{:x}", neg);
    }
    // Dword-sized negative
    if val >= 0x80000000 && val < 0x100000000 {
        let neg = 0x100000000 - val;
        return format!("RBP - 0x{:x}", neg);
    }
    if val == 0 {
        return "RBP".to_string();
    }
    format!("RBP + 0x{:x}", val)
}

/// Resolve a VarId through Var chains to find the underlying expression.
fn resolve_through_vars(id: VarId, ssa: &SsaCfg) -> Expr {
    let vdef = ssa.var(id);
    match &vdef.expr {
        Expr::Var(inner) => {
            // One level of indirection
            ssa.var(*inner).expr.clone()
        }
        other => other.clone(),
    }
}

fn format_var(id: VarId, ssa: &SsaCfg, arch: Architecture) -> String {
    let vdef = ssa.var(id);

    // Inline single-use unique temporaries
    if vdef.varnode.space == AddressSpaceId::Unique && vdef.use_count <= 1 {
        return format_expr(&vdef.expr, ssa, arch);
    }

    // Inline constants directly
    if let Expr::Const(val, sz) = &vdef.expr {
        return format_const(*val, *sz);
    }

    var_name(&vdef.varnode, arch)
}

fn format_expr(expr: &Expr, ssa: &SsaCfg, arch: Architecture) -> String {
    match expr {
        Expr::Var(id) => format_var(*id, ssa, arch),
        Expr::Const(val, sz) => format_const(*val, *sz),
        Expr::BinOp(kind, left, right) => {
            let l = format_var(*left, ssa, arch);
            let r = format_var(*right, ssa, arch);
            let op = binop_str(*kind);
            // Check for signed negative constant on right side of add
            if matches!(kind, BinOpKind::Add) {
                let rv = ssa.var(*right);
                if let Expr::Const(val, sz) = &rv.expr {
                    if *val > 0x7fffffffffffffff {
                        let neg = (!*val).wrapping_add(1);
                        return format!("{} - {}", l, format_const(neg, *sz));
                    }
                }
            }
            format!("{} {} {}", l, op, r)
        }
        Expr::UnaryOp(kind, input) => {
            let i = format_var(*input, ssa, arch);
            match kind {
                UnaryOpKind::Neg => format!("-{}", i),
                UnaryOpKind::Not => format!("~{}", i),
                UnaryOpKind::BoolNot => format!("!{}", i),
                UnaryOpKind::Zext => format!("(uint64_t){}", i),
                UnaryOpKind::Sext => format!("(int64_t){}", i),
                _ => format!("{}({})", unaryop_str(*kind), i),
            }
        }
        Expr::Load(ptr) => {
            let p = format_expr_for_addr(*ptr, ssa, arch);
            format!("*({})", p)
        }
        Expr::Phi(inputs) => {
            let args: Vec<String> = inputs.iter()
                .map(|i| format_var(*i, ssa, arch))
                .collect();
            format!("phi({})", args.join(", "))
        }
        Expr::Unknown => "?".to_string(),
    }
}

fn format_const(val: u64, size: u32) -> String {
    // Check for small positive values
    if val < 10 {
        return format!("{}", val);
    }
    // Check for negative values (high bit set based on size)
    let sign_bit = match size {
        1 => 0x80,
        2 => 0x8000,
        4 => 0x80000000,
        8 => 0x8000000000000000,
        _ => 0,
    };
    if sign_bit != 0 && val >= sign_bit && val != u64::MAX {
        let mask = match size {
            1 => 0xFF,
            2 => 0xFFFF,
            4 => 0xFFFFFFFF,
            8 => u64::MAX,
            _ => u64::MAX,
        };
        let neg = ((!val) & mask).wrapping_add(1);
        if neg <= 0x1000 {
            return format!("-0x{:x}", neg);
        }
    }
    format!("0x{:x}", val)
}

fn var_name(vn: &Varnode, arch: Architecture) -> String {
    match vn.space {
        AddressSpaceId::Register => {
            arch.register_name(vn.offset, vn.size)
                .unwrap_or("?reg")
                .to_string()
        }
        AddressSpaceId::Unique => format!("tmp_{:x}", vn.offset),
        AddressSpaceId::Ram => format!("mem_{:x}", vn.offset),
        AddressSpaceId::Const => format_const(vn.offset, 8),
    }
}

fn is_flag(offset: u64) -> bool {
    matches!(offset, 512..=523)
}

fn size_to_type(size: u32) -> &'static str {
    match size {
        1 => "uint8_t",
        2 => "uint16_t",
        4 => "uint32_t",
        8 => "uint64_t",
        16 => "__uint128_t",
        _ => "void",
    }
}

fn binop_str(kind: BinOpKind) -> &'static str {
    match kind {
        BinOpKind::Add | BinOpKind::FloatAdd => "+",
        BinOpKind::Sub | BinOpKind::FloatSub => "-",
        BinOpKind::Mult | BinOpKind::FloatMult => "*",
        BinOpKind::Div | BinOpKind::SDiv | BinOpKind::FloatDiv => "/",
        BinOpKind::Rem | BinOpKind::SRem => "%",
        BinOpKind::And => "&",
        BinOpKind::Or => "|",
        BinOpKind::Xor => "^",
        BinOpKind::Lsl => "<<",
        BinOpKind::Lsr | BinOpKind::Asr => ">>",
        BinOpKind::Eq | BinOpKind::FloatEq => "==",
        BinOpKind::NotEq | BinOpKind::FloatNotEq => "!=",
        BinOpKind::Less | BinOpKind::SLess | BinOpKind::FloatLess => "<",
        BinOpKind::LessEq | BinOpKind::SLessEq | BinOpKind::FloatLessEq => "<=",
        BinOpKind::BoolAnd => "&&",
        BinOpKind::BoolOr => "||",
        BinOpKind::BoolXor => "!=",
        BinOpKind::Carry => "CARRY",
        BinOpKind::SCarry => "SCARRY",
        BinOpKind::SBorrow => "SBORROW",
    }
}

fn unaryop_str(kind: UnaryOpKind) -> &'static str {
    match kind {
        UnaryOpKind::Neg => "-",
        UnaryOpKind::Not => "~",
        UnaryOpKind::BoolNot => "!",
        UnaryOpKind::Zext => "ZEXT",
        UnaryOpKind::Sext => "SEXT",
        UnaryOpKind::FloatNeg => "FNEG",
        UnaryOpKind::FloatAbs => "FABS",
        UnaryOpKind::FloatSqrt => "FSQRT",
        UnaryOpKind::FloatNan => "ISNAN",
        UnaryOpKind::Int2Float => "INT2FLOAT",
        UnaryOpKind::Float2Float => "FLOAT2FLOAT",
        UnaryOpKind::Trunc => "TRUNC",
        UnaryOpKind::FloatCeil => "CEIL",
        UnaryOpKind::FloatFloor => "FLOOR",
        UnaryOpKind::FloatRound => "ROUND",
        UnaryOpKind::Popcount => "POPCOUNT",
        UnaryOpKind::Lzcount => "LZCOUNT",
    }
}
