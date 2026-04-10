use pcode_ir::{Varnode, AddressSpaceId};
use rsleigh_api::Architecture;
use crate::ir::*;

/// Print structured statements as C-like pseudocode.
pub fn print_c(stmts: &[StructuredStmt], ssa: &SsaCfg, arch: Architecture) -> String {
    let mut out = String::new();
    print_stmts(stmts, ssa, arch, 0, &mut out);
    out
}

fn print_stmts(
    stmts: &[StructuredStmt],
    ssa: &SsaCfg,
    arch: Architecture,
    indent: usize,
    out: &mut String,
) {
    for stmt in stmts {
        print_stmt(stmt, ssa, arch, indent, out);
    }
}

fn print_stmt(
    stmt: &StructuredStmt,
    ssa: &SsaCfg,
    arch: Architecture,
    indent: usize,
    out: &mut String,
) {
    let pad: String = "    ".repeat(indent);

    match stmt {
        StructuredStmt::Assign { lhs, .. } => {
            let vdef = ssa.var(*lhs);
            // Skip assignments to Unique-space vars that are only used once
            // (they'll be inlined into their consumer)
            if vdef.varnode.space == AddressSpaceId::Unique && vdef.use_count <= 1 {
                return;
            }
            // Skip flag register assignments
            if vdef.varnode.space == AddressSpaceId::Register && is_flag(vdef.varnode.offset) {
                return;
            }
            let name = var_name(&vdef.varnode, arch);
            let rhs = format_expr(&vdef.expr, ssa, arch);
            out.push_str(&format!("{}{} = {};\n", pad, name, rhs));
        }
        StructuredStmt::Store { addr, val } => {
            let addr_expr = format_var(*addr, ssa, arch);
            let val_expr = format_var(*val, ssa, arch);
            let size = ssa.var(*val).size;
            let type_name = size_to_type(size);
            out.push_str(&format!("{}*({} *)({}) = {};\n", pad, type_name, addr_expr, val_expr));
        }
        StructuredStmt::Call { target, args, out: call_out } => {
            let target_name = match target {
                CallTarget::Direct(addr) => format!("func_{:x}", addr),
                CallTarget::Indirect(vn) => format!("(*{})", var_name(vn, arch)),
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
            out.push_str(&format!("{}if ({}) {{\n", pad, cond_expr));
            print_stmts(then_body, ssa, arch, indent + 1, out);
            if !else_body.is_empty() {
                out.push_str(&format!("{}}} else {{\n", pad));
                print_stmts(else_body, ssa, arch, indent + 1, out);
            }
            out.push_str(&format!("{}}}\n", pad));
        }
        StructuredStmt::While { cond, body } => {
            let cond_expr = format_var(*cond, ssa, arch);
            out.push_str(&format!("{}while ({}) {{\n", pad, cond_expr));
            print_stmts(body, ssa, arch, indent + 1, out);
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

fn format_var(id: VarId, ssa: &SsaCfg, arch: Architecture) -> String {
    let vdef = ssa.var(id);

    // Inline single-use unique temporaries
    if vdef.varnode.space == AddressSpaceId::Unique && vdef.use_count <= 1 {
        return format_expr(&vdef.expr, ssa, arch);
    }

    // Inline constants directly
    if let Expr::Const(val, _) = &vdef.expr {
        return format_const(*val);
    }

    var_name(&vdef.varnode, arch)
}

fn format_expr(expr: &Expr, ssa: &SsaCfg, arch: Architecture) -> String {
    match expr {
        Expr::Var(id) => format_var(*id, ssa, arch),
        Expr::Const(val, _) => format_const(*val),
        Expr::BinOp(kind, left, right) => {
            let l = format_var(*left, ssa, arch);
            let r = format_var(*right, ssa, arch);
            let op = binop_str(*kind);
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
            let p = format_var(*ptr, ssa, arch);
            format!("*({})", p)
        }
        Expr::Phi(inputs) => {
            let args: Vec<String> = inputs.iter()
                .map(|i| format_var(*i, ssa, arch))
                .collect();
            format!("phi({})", args.join(", "))
        }
        Expr::Unknown => {
            "?".to_string()
        }
    }
}

fn format_const(val: u64) -> String {
    if val < 10 {
        format!("{}", val)
    } else {
        format!("0x{:x}", val)
    }
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
        AddressSpaceId::Const => format_const(vn.offset),
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
        BinOpKind::Div | BinOpKind::FloatDiv => "/",
        BinOpKind::SDiv => "/",
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
