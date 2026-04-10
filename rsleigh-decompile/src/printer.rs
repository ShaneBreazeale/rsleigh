use pcode_ir::{Varnode, AddressSpaceId};
use rsleigh_api::Architecture;
use crate::ir::*;

const RBP_OFFSET: u64 = 40;
const RSP_OFFSET: u64 = 32;
const RIP_OFFSET: u64 = 648;

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
                if is_stack_management(vdef, ssa) { return false; }
                if is_frame_pointer_op(vdef) { return false; }
                if vdef.varnode.space == AddressSpaceId::Register && vdef.varnode.offset == RIP_OFFSET {
                    return false;
                }
                true
            }
            StructuredStmt::Store { addr, val: _ } => {
                let addr_def = ssa.var(*addr);
                if addr_def.varnode.space == AddressSpaceId::Register
                    && addr_def.varnode.offset == RSP_OFFSET
                { return false; }
                if is_rsp_expr(&addr_def.expr, ssa) { return false; }
                true
            }
            _ => true,
        }
    }).cloned().collect()
}

fn is_stack_management(vdef: &VarDef, ssa: &SsaCfg) -> bool {
    if vdef.varnode.space != AddressSpaceId::Register { return false; }
    if vdef.varnode.offset == RSP_OFFSET {
        if let Expr::BinOp(BinOpKind::Add | BinOpKind::Sub, l, _) = &vdef.expr {
            let lv = ssa.var(*l);
            return lv.varnode.space == AddressSpaceId::Register && lv.varnode.offset == RSP_OFFSET;
        }
        if let Expr::Var(id) = &vdef.expr {
            let v = ssa.var(*id);
            return v.varnode.space == AddressSpaceId::Register && v.varnode.offset == RBP_OFFSET;
        }
    }
    false
}

fn is_frame_pointer_op(vdef: &VarDef) -> bool {
    if vdef.varnode.space != AddressSpaceId::Register { return false; }
    if vdef.varnode.offset == RBP_OFFSET || vdef.varnode.offset == RSP_OFFSET {
        match &vdef.expr {
            Expr::Var(_) => true,
            Expr::Load(_) => vdef.varnode.offset == RBP_OFFSET,
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
            v.varnode.space == AddressSpaceId::Register && v.varnode.offset == RSP_OFFSET
        }
        Expr::BinOp(_, l, _) => {
            let v = ssa.var(*l);
            v.varnode.space == AddressSpaceId::Register && v.varnode.offset == RSP_OFFSET
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
                if is_zext_artifact(vdef, ssa) { continue; }
                if is_self_assign(vdef, ssa) { continue; }
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
            if vdef.varnode.space == AddressSpaceId::Unique { return; }
            if vdef.varnode.space == AddressSpaceId::Register && is_flag(vdef.varnode.offset) { return; }
            if matches!(&vdef.expr, Expr::Phi(_)) { return; }
            if is_zext_artifact(vdef, ssa) { return; }
            if is_self_assign(vdef, ssa) { return; }

            let name = var_name(&vdef.varnode, arch);
            let rhs = format_expr(&vdef.expr, ssa, arch);
            out.push_str(&format!("{}{} = {};\n", pad, name, rhs));
        }
        StructuredStmt::Store { addr, val } => {
            let addr_str = format_addr(*addr, ssa, arch);
            let val_expr = format_var(*val, ssa, arch);
            let size = ssa.var(*val).size;
            let type_name = size_to_type(size);

            // Use stack variable name if this is a stack store
            if let Some(stack_name) = try_stack_var_name(*addr, ssa) {
                out.push_str(&format!("{}{} = {};\n", pad, stack_name, val_expr));
            } else {
                out.push_str(&format!("{}*({}*)({}) = {};\n", pad, type_name, addr_str, val_expr));
            }
        }
        StructuredStmt::Call { target, args, out: call_out } => {
            let target_name = format_call_target(target, ssa, arch);
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
                let vdef = ssa.var(*v);
                // Show the expression, not just "RAX"
                let expr = format_expr(&vdef.expr, ssa, arch);
                out.push_str(&format!("{}return {};\n", pad, expr));
            } else {
                out.push_str(&format!("{}return;\n", pad));
            }
        }
        StructuredStmt::IfElse { cond, then_body, else_body } => {
            let cond_expr = format_condition(*cond, ssa, arch);
            let then_filtered = filter_boilerplate(then_body, ssa);
            let else_filtered = filter_boilerplate(else_body, ssa);
            let then_empty = is_body_empty(&then_filtered, ssa);
            let else_empty = is_body_empty(&else_filtered, ssa);

            if then_empty && else_empty { return; }
            if then_empty && !else_empty {
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
            let cond_expr = format_condition(*cond, ssa, arch);
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

// ---- Condition formatting ----

/// Format a condition, trying to show the comparison rather than a flag name.
fn format_condition(id: VarId, ssa: &SsaCfg, arch: Architecture) -> String {
    let vdef = ssa.var(id);

    // If this is a comparison expression, format it directly
    if let Expr::BinOp(kind, left, right) = &vdef.expr {
        if is_comparison(*kind) {
            let l = format_var(*left, ssa, arch);
            let r = format_var(*right, ssa, arch);
            return format!("{} {} {}", l, binop_str(*kind), r);
        }
    }

    // If it's a flag var, try to show the flag name at least
    if vdef.varnode.space == AddressSpaceId::Register {
        match vdef.varnode.offset {
            518 => return "ZF".to_string(), // fallback
            512 => return "CF".to_string(),
            519 => return "SF".to_string(),
            _ => {}
        }
    }

    format_var(id, ssa, arch)
}

fn is_comparison(kind: BinOpKind) -> bool {
    matches!(kind, BinOpKind::Eq | BinOpKind::NotEq | BinOpKind::Less
        | BinOpKind::LessEq | BinOpKind::SLess | BinOpKind::SLessEq)
}

// ---- Stack variable naming ----

/// Try to produce a stack variable name like "var_8" for RBP-relative accesses.
fn try_stack_var_name(addr_id: VarId, ssa: &SsaCfg) -> Option<String> {
    let offset = get_rbp_offset(addr_id, ssa)?;
    Some(format!("var_{:x}", offset))
}

/// Get the (positive) offset from RBP for a stack access, if this is RBP-relative.
fn get_rbp_offset(id: VarId, ssa: &SsaCfg) -> Option<u64> {
    let expr = resolve_through_vars(id, ssa);
    if let Expr::BinOp(BinOpKind::Add, base_id, off_id) = &expr {
        let base = ssa.var(*base_id);
        if base.varnode.space == AddressSpaceId::Register && base.varnode.offset == RBP_OFFSET {
            let off_val = get_const_val(*off_id, ssa)?;
            // Convert to negative offset
            if off_val >= 0x80 && off_val < 0x100 { return Some(0x100 - off_val); }
            if off_val >= 0x8000 && off_val < 0x10000 { return Some(0x10000 - off_val); }
            if off_val > 0x7fffffffffffffff { return Some((!off_val).wrapping_add(1)); }
            return None; // Positive offset — not a local variable
        }
    }
    None
}

fn get_const_val(id: VarId, ssa: &SsaCfg) -> Option<u64> {
    let vdef = ssa.var(id);
    match &vdef.expr {
        Expr::Const(val, _) => Some(*val),
        Expr::Var(inner) => {
            let inner_def = ssa.var(*inner);
            if let Expr::Const(val, _) = &inner_def.expr { Some(*val) } else { None }
        }
        _ => None,
    }
}

// ---- Address formatting ----

fn format_addr(id: VarId, ssa: &SsaCfg, arch: Architecture) -> String {
    // Try stack variable first
    if let Some(offset) = get_rbp_offset(id, ssa) {
        return format!("RBP - 0x{:x}", offset);
    }

    let expr = resolve_through_vars(id, ssa);
    if let Expr::BinOp(BinOpKind::Add, base_id, off_id) = &expr {
        let base = ssa.var(*base_id);
        if base.varnode.space == AddressSpaceId::Register && base.varnode.offset == RBP_OFFSET {
            if let Some(val) = get_const_val(*off_id, ssa) {
                return format_rbp_offset(val);
            }
        }
    }

    format_var(id, ssa, arch)
}

fn format_rbp_offset(val: u64) -> String {
    if val >= 0x80 && val < 0x100 { return format!("RBP - 0x{:x}", 0x100 - val); }
    if val >= 0x8000 && val < 0x10000 { return format!("RBP - 0x{:x}", 0x10000 - val); }
    if val >= 0x80000000 && val < 0x100000000 { return format!("RBP - 0x{:x}", 0x100000000u64 - val); }
    if val > 0x7fffffffffffffff { return format!("RBP - 0x{:x}", (!val).wrapping_add(1)); }
    if val == 0 { return "RBP".to_string(); }
    format!("RBP + 0x{:x}", val)
}

// ---- Call target formatting ----

fn format_call_target(target: &CallTarget, _ssa: &SsaCfg, arch: Architecture) -> String {
    match target {
        CallTarget::Direct(addr) => format!("func_{:x}", addr),
        CallTarget::Indirect(vn) => {
            // Try to resolve: if the target is a Load from a constant address,
            // show it as a function pointer dereference
            // The varnode here is from the original CFG, not an SSA var
            format!("(*{})", var_name(vn, arch))
        }
    }
}

// ---- Variable formatting ----

fn format_var(id: VarId, ssa: &SsaCfg, arch: Architecture) -> String {
    let vdef = ssa.var(id);

    // Inline Unique-space temporaries
    if vdef.varnode.space == AddressSpaceId::Unique {
        return format_expr(&vdef.expr, ssa, arch);
    }

    // Inline constants
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
            // Detect negative constant on right side of add
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
            // Try stack variable name
            if let Some(offset) = get_rbp_offset(*ptr, ssa) {
                return format!("var_{:x}", offset);
            }
            let p = format_addr(*ptr, ssa, arch);
            format!("*({})", p)
        }
        Expr::Phi(inputs) => {
            if inputs.len() == 1 { return format_var(inputs[0], ssa, arch); }
            let args: Vec<String> = inputs.iter().map(|i| format_var(*i, ssa, arch)).collect();
            format!("phi({})", args.join(", "))
        }
        Expr::Unknown => "?".to_string(),
    }
}

fn format_const(val: u64, size: u32) -> String {
    if val == 0 { return "0".to_string(); }
    if val < 10 { return format!("{}", val); }
    // Detect negative values
    let sign_bit = match size {
        1 => 0x80, 2 => 0x8000, 4 => 0x80000000, 8 => 0x8000000000000000, _ => 0,
    };
    if sign_bit != 0 && val >= sign_bit && val != u64::MAX {
        let mask = match size { 1 => 0xFF, 2 => 0xFFFF, 4 => 0xFFFFFFFF, _ => u64::MAX };
        let neg = ((!val) & mask).wrapping_add(1);
        if neg <= 0x1000 { return format!("-0x{:x}", neg); }
    }
    format!("0x{:x}", val)
}

fn var_name(vn: &Varnode, arch: Architecture) -> String {
    match vn.space {
        AddressSpaceId::Register => {
            arch.register_name(vn.offset, vn.size).unwrap_or("?reg").to_string()
        }
        AddressSpaceId::Unique => format!("tmp_{:x}", vn.offset),
        AddressSpaceId::Ram => format!("mem_{:x}", vn.offset),
        AddressSpaceId::Const => format_const(vn.offset, 8),
    }
}

fn resolve_through_vars(id: VarId, ssa: &SsaCfg) -> Expr {
    let vdef = ssa.var(id);
    match &vdef.expr {
        Expr::Var(inner) => ssa.var(*inner).expr.clone(),
        other => other.clone(),
    }
}

// ---- Helpers ----

fn is_flag(offset: u64) -> bool { matches!(offset, 512..=523) }

fn is_zext_artifact(vdef: &VarDef, ssa: &SsaCfg) -> bool {
    if vdef.varnode.space != AddressSpaceId::Register { return false; }
    if let Expr::UnaryOp(UnaryOpKind::Zext, inner_id) = &vdef.expr {
        let inner = ssa.var(*inner_id);
        inner.varnode.space == AddressSpaceId::Register
            && inner.varnode.offset == vdef.varnode.offset
            && inner.varnode.size < vdef.varnode.size
    } else {
        false
    }
}

fn is_self_assign(vdef: &VarDef, ssa: &SsaCfg) -> bool {
    if let Expr::Var(src_id) = &vdef.expr {
        let src = ssa.var(*src_id);
        src.varnode == vdef.varnode
    } else {
        false
    }
}

fn size_to_type(size: u32) -> &'static str {
    match size { 1 => "uint8_t", 2 => "uint16_t", 4 => "uint32_t", 8 => "uint64_t", 16 => "__uint128_t", _ => "void" }
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
        UnaryOpKind::Neg => "-", UnaryOpKind::Not => "~", UnaryOpKind::BoolNot => "!",
        UnaryOpKind::Zext => "ZEXT", UnaryOpKind::Sext => "SEXT",
        UnaryOpKind::FloatNeg => "FNEG", UnaryOpKind::FloatAbs => "FABS",
        UnaryOpKind::FloatSqrt => "FSQRT", UnaryOpKind::FloatNan => "ISNAN",
        UnaryOpKind::Int2Float => "INT2FLOAT", UnaryOpKind::Float2Float => "FLOAT2FLOAT",
        UnaryOpKind::Trunc => "TRUNC", UnaryOpKind::FloatCeil => "CEIL",
        UnaryOpKind::FloatFloor => "FLOOR", UnaryOpKind::FloatRound => "ROUND",
        UnaryOpKind::Popcount => "POPCOUNT", UnaryOpKind::Lzcount => "LZCOUNT",
    }
}
