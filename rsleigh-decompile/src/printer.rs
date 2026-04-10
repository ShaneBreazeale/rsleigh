use std::collections::HashMap;
use pcode_ir::{Varnode, AddressSpaceId};
use rsleigh_api::Architecture;
use crate::ir::*;

const RBP_OFFSET: u64 = 40;
const RSP_OFFSET: u64 = 32;
const RIP_OFFSET: u64 = 648;

/// Print structured statements as C-like pseudocode.
pub fn print_c(
    stmts: &[StructuredStmt],
    ssa: &SsaCfg,
    arch: Architecture,
    binary: Option<&[u8]>,
    imports: &HashMap<u64, String>,
) -> String {
    let mut out = String::new();
    let ctx = PrintCtx { arch, binary, imports };
    let filtered = filter_boilerplate(stmts, ssa);
    print_stmts(&filtered, ssa, &ctx, 0, &mut out);
    out
}

struct PrintCtx<'a> {
    arch: Architecture,
    binary: Option<&'a [u8]>,
    imports: &'a HashMap<u64, String>,
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

fn print_stmts(stmts: &[StructuredStmt], ssa: &SsaCfg, ctx: &PrintCtx, indent: usize, out: &mut String) {
    let mut tracker = RegTracker::new();
    for (i, stmt) in stmts.iter().enumerate() {
        print_stmt_tracked(stmt, stmts, i, ssa, ctx, indent, out, &mut tracker);
    }
}

/// Tracks what each register currently holds, for display-time copy elision.
struct RegTracker {
    /// Map: (register offset, size) → VarId of the source value
    reg_source: std::collections::HashMap<(u64, u32), VarId>,
    /// Map: (register offset, size) → formatted expression string (for call returns)
    reg_expr_str: std::collections::HashMap<(u64, u32), String>,
    /// Map: stack variable name → formatted value string (for Store alias tracking)
    stack_alias: std::collections::HashMap<String, String>,
}

impl RegTracker {
    fn new() -> Self {
        Self {
            reg_source: std::collections::HashMap::new(),
            reg_expr_str: std::collections::HashMap::new(),
            stack_alias: std::collections::HashMap::new(),
        }
    }

    fn set(&mut self, offset: u64, size: u32, source: VarId) {
        self.reg_source.insert((offset, size), source);
        self.reg_expr_str.remove(&(offset, size));
    }

    /// Record that a register holds a call return value with the given expression string.
    fn set_call_return(&mut self, offset: u64, size: u32, expr_str: String) {
        self.reg_expr_str.insert((offset, size), expr_str);
        self.reg_source.remove(&(offset, size));
    }

    fn get(&self, offset: u64, size: u32) -> Option<VarId> {
        self.reg_source.get(&(offset, size)).copied()
    }

    /// Get the formatted expression string for a register (call return value).
    fn get_expr_str(&self, offset: u64, size: u32) -> Option<&str> {
        self.reg_expr_str.get(&(offset, size)).map(|s| s.as_str())
    }

    fn invalidate(&mut self, offset: u64, size: u32) {
        self.reg_source.remove(&(offset, size));
        self.reg_expr_str.remove(&(offset, size));
    }

    fn invalidate_all(&mut self) {
        self.reg_source.clear();
        // Keep call return expressions — they survive across the call boundary
        // because the call itself produces them
    }

    /// Invalidate all, including call return expressions.
    fn invalidate_everything(&mut self) {
        self.reg_source.clear();
        self.reg_expr_str.clear();
    }

    /// Resolve a VarId through the tracker: if the var is a register that
    /// currently holds a known source, return that source instead.
    fn resolve(&self, id: VarId, ssa: &SsaCfg) -> VarId {
        let vdef = ssa.var(id);
        if vdef.varnode.space == AddressSpaceId::Register {
            if let Some(src) = self.get(vdef.varnode.offset, vdef.varnode.size) {
                return src;
            }
        }
        id
    }
}

fn print_stmt_tracked(stmt: &StructuredStmt, stmts: &[StructuredStmt], stmt_idx: usize, ssa: &SsaCfg, ctx: &PrintCtx, indent: usize, out: &mut String, tracker: &mut RegTracker) {
    let pad: String = "    ".repeat(indent);

    match stmt {
        StructuredStmt::Assign { lhs, .. } => {
            let vdef = ssa.var(*lhs);
            if vdef.varnode.space == AddressSpaceId::Unique { return; }
            if vdef.varnode.space == AddressSpaceId::Register && is_flag(vdef.varnode.offset) { return; }
            if matches!(&vdef.expr, Expr::Phi(_)) { return; }
            if is_zext_artifact(vdef, ssa) { return; }
            if is_self_assign(vdef, ssa) { return; }
            if vdef.call_return && vdef.use_count <= 1 { return; }
            if is_arg_consumed_by_call(*lhs, ssa) { return; }

            // Track register copies for display-time elision
            if vdef.varnode.space == AddressSpaceId::Register {
                if let Expr::Var(src_id) = &vdef.expr {
                    let src = ssa.var(*src_id);
                    if src.varnode.space == AddressSpaceId::Register {
                        // Check if source register has an inlined call return expression
                        if let Some(expr_str) = tracker.get_expr_str(src.varnode.offset, src.varnode.size) {
                            let s = expr_str.to_string();
                            tracker.set_call_return(vdef.varnode.offset, vdef.varnode.size, s);
                            return; // Elided: call return propagated through register copy
                        }
                        let resolved = tracker.resolve(*src_id, ssa);
                        tracker.set(vdef.varnode.offset, vdef.varnode.size, resolved);
                        let resolved_var = ssa.var(resolved);
                        if resolved_var.varnode.space != AddressSpaceId::Register
                            || resolved_var.param_name.is_some()
                        {
                            return; // Elided: value available via tracker
                        }
                    } else if src.varnode.space != AddressSpaceId::Unique {
                        // REG = stack_var/const: track it
                        tracker.set(vdef.varnode.offset, vdef.varnode.size, *src_id);
                    } else {
                        // REG = Unique (expression result): invalidate, don't track
                        tracker.invalidate(vdef.varnode.offset, vdef.varnode.size);
                    }
                } else if let Expr::Load(ptr) = &vdef.expr {
                    // REG = Load(addr): track so later uses resolve to the stack var
                    let had_call_return = tracker.get_expr_str(vdef.varnode.offset, vdef.varnode.size).is_some();
                    tracker.set(vdef.varnode.offset, vdef.varnode.size, *lhs);
                    // Skip printing if this register is just used as an intermediate
                    // to pass a stack value to another assignment or call.
                    // But DON'T skip if this overwrites a call return — the restore is important.
                    // Skip stack Loads that are only used as intermediates:
                    // - use_count <= 1: only used once (tracked at use site)
                    // - had_call_return: this is a restore after a call (tracked)
                    // - use_count <= 2 AND all uses are copies to other regs/stack
                    if get_rbp_offset(*ptr, ssa).is_some() && (vdef.use_count <= 1 || had_call_return) {
                        return; // Elided: stack Load tracked
                    }
                } else {
                    tracker.invalidate(vdef.varnode.offset, vdef.varnode.size);
                }
            }

            // For non-register assigns (stack vars), resolve the RHS through tracker
            let name = var_name(&vdef.varnode, ctx);
            let rhs = format_expr_tracked(&vdef.expr, ssa, ctx, tracker);
            if rhs == name { return; }
            // Skip dead stores and stores immediately before return
            if name.starts_with("var_") && vdef.use_count == 0 {
                return; // Dead store
            }
            // If next statement is Return, skip this store — return will show the value
            if name.starts_with("var_") {
                if let Some(StructuredStmt::Return(_)) = stmts.get(stmt_idx + 1) {
                    return; // Store before return — elided
                }
            }
            out.push_str(&format!("{}{} = {};\n", pad, name, rhs));
        }
        StructuredStmt::Store { addr, val } => {
            let addr_str = format_addr(*addr, ssa, ctx);
            let val_expr = format_var_tracked(*val, ssa, ctx, tracker);
            let size = ssa.var(*val).size;
            let type_name = size_to_type(size);

            if let Some(stack_name) = try_stack_var_name(*addr, ssa) {
                // Track this stack variable's value for later resolution
                tracker.stack_alias.insert(stack_name.clone(), val_expr.clone());

                // Skip redundant stores:
                // - Self-assign (var_8 = var_8)
                // - Parameter stores (var_4 = param_0) — tracked, resolved at use
                // - Save patterns (var_c = var_8) — tracked, resolved at restore
                if val_expr == stack_name {
                    return; // Self-assign
                }
                if val_expr.starts_with("param_") || val_expr.starts_with("var_") {
                    return; // Tracked alias — available via stack_alias at use sites
                }
                out.push_str(&format!("{}{} = {};\n", pad, stack_name, val_expr));
            } else {
                out.push_str(&format!("{}*({}*)({}) = {};\n", pad, type_name, addr_str, val_expr));
            }
        }
        StructuredStmt::Call { target, args, out: call_out } => {
            let target_name = format_call_target(target, ssa, ctx);
            let args_str: Vec<String> = args.iter()
                .map(|a| {
                    let vdef = ssa.var(*a);
                    format_expr_tracked(&vdef.expr, ssa, ctx, tracker)
                })
                .collect();
            let call_expr = format!("{}({})", target_name, args_str.join(", "));

            // Calls clobber all registers
            tracker.invalidate_all();

            if let Some(out_var) = call_out {
                let name = var_name(&ssa.var(*out_var).varnode, ctx);
                out.push_str(&format!("{}{} = {};\n", pad, name, call_expr));
            } else {
                // Check if the return value (EAX/RAX) is read by any subsequent
                // statement in this block. If so, the call will be inlined at the
                // use site — don't print it standalone.
                let return_consumed = stmts.iter().skip(stmt_idx + 1).any(|s| {
                    match s {
                        StructuredStmt::Assign { lhs, .. } => {
                            let v = ssa.var(*lhs);
                            // Check if this reads EAX (call return)
                            if let Expr::Var(src) = &v.expr {
                                let sv = ssa.var(*src);
                                sv.varnode.space == AddressSpaceId::Register
                                    && sv.varnode.offset == 0
                                    && sv.call_return
                            } else { false }
                        }
                        StructuredStmt::Store { val, .. } => {
                            let v = ssa.var(*val);
                            v.varnode.space == AddressSpaceId::Register
                                && v.varnode.offset == 0
                                && v.call_return
                        }
                        _ => false,
                    }
                });

                // Set call return expression for inlining
                tracker.set_call_return(0, 8, call_expr.clone()); // RAX
                tracker.set_call_return(0, 4, call_expr.clone()); // EAX

                if !return_consumed {
                    // Void call or return not used — print standalone
                    out.push_str(&format!("{}{};\n", pad, call_expr));
                }
                // If consumed, the call appears inlined at the use site
            }
        }
        StructuredStmt::Return(val) => {
            if let Some(v) = val {
                let resolved = tracker.resolve(*v, ssa);
                let vdef = ssa.var(resolved);
                let expr = format_expr_tracked(&vdef.expr, ssa, ctx, tracker);
                out.push_str(&format!("{}return {};\n", pad, expr));
            } else {
                out.push_str(&format!("{}return;\n", pad));
            }
        }
        StructuredStmt::IfElse { cond, then_body, else_body } => {
            let cond_expr = format_condition(*cond, ssa, ctx);
            let then_filtered = filter_boilerplate(then_body, ssa);
            let else_filtered = filter_boilerplate(else_body, ssa);
            let then_empty = is_body_empty(&then_filtered, ssa);
            let else_empty = is_body_empty(&else_filtered, ssa);
            if then_empty && else_empty { return; }
            if then_empty && !else_empty {
                out.push_str(&format!("{}if (!{}) {{\n", pad, cond_expr));
                print_stmts(&else_filtered, ssa, ctx, indent + 1, out);
                out.push_str(&format!("{}}}\n", pad));
            } else {
                out.push_str(&format!("{}if ({}) {{\n", pad, cond_expr));
                print_stmts(&then_filtered, ssa, ctx, indent + 1, out);
                if !else_empty {
                    out.push_str(&format!("{}}} else {{\n", pad));
                    print_stmts(&else_filtered, ssa, ctx, indent + 1, out);
                }
                out.push_str(&format!("{}}}\n", pad));
            }
        }
        StructuredStmt::While { cond, body } => {
            let cond_expr = format_condition(*cond, ssa, ctx);
            let body_filtered = filter_boilerplate(body, ssa);
            out.push_str(&format!("{}while ({}) {{\n", pad, cond_expr));
            print_stmts(&body_filtered, ssa, ctx, indent + 1, out);
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

/// Format a VarId with register tracking — resolves register copies to their source.
fn format_var_tracked(id: VarId, ssa: &SsaCfg, ctx: &PrintCtx, tracker: &RegTracker) -> String {
    let vdef = ssa.var(id);
    // For Unique-space: normally use standard formatting.
    // BUT: if this Unique wraps a UnaryOp(Sext/Zext) of a register that has
    // a call return expression, inline it.
    if vdef.varnode.space == AddressSpaceId::Unique {
        if let Expr::UnaryOp(kind, inner) = &vdef.expr {
            let iv = ssa.var(*inner);
            if iv.varnode.space == AddressSpaceId::Register {
                if let Some(expr_str) = tracker.get_expr_str(iv.varnode.offset, iv.varnode.size) {
                    // Inline the call return through the cast
                    return match kind {
                        UnaryOpKind::Sext => format!("(int64_t){}", expr_str),
                        UnaryOpKind::Zext => format!("(uint64_t){}", expr_str),
                        _ => expr_str.to_string(),
                    };
                }
                // Also resolve through regular tracking
                if let Some(tracked_id) = tracker.get(iv.varnode.offset, iv.varnode.size) {
                    let tv = ssa.var(tracked_id);
                    // If tracked to a Load (stack var), show the stack var name
                    if let Expr::Load(ptr) = &tv.expr {
                        if let Some(offset) = get_rbp_offset(*ptr, ssa) {
                            let var_name = format!("var_{:x}", offset);
                            // Resolve through stack alias (var_c → var_8 → param_0)
                            let resolved = resolve_stack_alias(&var_name, tracker);
                            return match kind {
                                UnaryOpKind::Sext => format!("(int64_t){}", resolved),
                                UnaryOpKind::Zext => format!("(uint64_t){}", resolved),
                                _ => resolved,
                            };
                        }
                    }
                    // If tracked to a Var (copy of another var), resolve that
                    if let Expr::Var(src) = &tv.expr {
                        let sv = ssa.var(*src);
                        if sv.param_name.is_some() || sv.varnode.space != AddressSpaceId::Register {
                            let name = format_var(*src, ssa, ctx);
                            return match kind {
                                UnaryOpKind::Sext => format!("(int64_t){}", name),
                                UnaryOpKind::Zext => format!("(uint64_t){}", name),
                                _ => name,
                            };
                        }
                    }
                }
            }
        }
        // Also check BinOp whose operands are Uniques wrapping tracked registers
        if let Expr::BinOp(kind, left, right) = &vdef.expr {
            let lv = ssa.var(*left);
            let rv = ssa.var(*right);
            let l_has_tracked = lv.varnode.space == AddressSpaceId::Unique
                && expr_has_tracked_reg(&lv.expr, ssa, tracker);
            let r_has_tracked = rv.varnode.space == AddressSpaceId::Unique
                && expr_has_tracked_reg(&rv.expr, ssa, tracker);
            if l_has_tracked || r_has_tracked {
                let l = format_var_tracked(*left, ssa, ctx, tracker);
                let r = format_var_tracked(*right, ssa, ctx, tracker);
                return format!("{} {} {}", l, binop_str(*kind), r);
            }
        }
        return format_expr(&vdef.expr, ssa, ctx);
    }
    // Check register tracking
    if vdef.varnode.space == AddressSpaceId::Register {
        if let Some(expr_str) = tracker.get_expr_str(vdef.varnode.offset, vdef.varnode.size) {
            return expr_str.to_string();
        }
        if let Some(tracked_id) = tracker.get(vdef.varnode.offset, vdef.varnode.size) {
            let tracked_vdef = ssa.var(tracked_id);
            if let Expr::Load(ptr) = &tracked_vdef.expr {
                if let Some(offset) = get_rbp_offset(*ptr, ssa) {
                    return format!("var_{:x}", offset);
                }
            }
            if tracked_vdef.varnode.space != AddressSpaceId::Register {
                return format_var(tracked_id, ssa, ctx);
            }
            if tracked_id != id {
                return format_var(tracked_id, ssa, ctx);
            }
        }
    }
    format_var(id, ssa, ctx)
}

/// Recursively check if an expression tree references any tracked register.
fn expr_has_tracked_reg(expr: &Expr, ssa: &SsaCfg, tracker: &RegTracker) -> bool {
    match expr {
        Expr::Var(inner) => {
            let iv = ssa.var(*inner);
            if iv.varnode.space == AddressSpaceId::Register {
                return tracker.get(iv.varnode.offset, iv.varnode.size).is_some()
                    || tracker.get_expr_str(iv.varnode.offset, iv.varnode.size).is_some();
            }
            if iv.varnode.space == AddressSpaceId::Unique {
                return expr_has_tracked_reg(&iv.expr, ssa, tracker);
            }
            false
        }
        Expr::UnaryOp(_, inner) => {
            let iv = ssa.var(*inner);
            if iv.varnode.space == AddressSpaceId::Register {
                return tracker.get(iv.varnode.offset, iv.varnode.size).is_some()
                    || tracker.get_expr_str(iv.varnode.offset, iv.varnode.size).is_some();
            }
            if iv.varnode.space == AddressSpaceId::Unique {
                return expr_has_tracked_reg(&iv.expr, ssa, tracker);
            }
            false
        }
        Expr::BinOp(_, left, right) => {
            expr_has_tracked_reg(&ssa.var(*left).expr, ssa, tracker)
                || expr_has_tracked_reg(&ssa.var(*right).expr, ssa, tracker)
        }
        _ => false,
    }
}

/// Resolve a stack variable name through the alias chain.
/// var_c → var_8 → param_0
fn resolve_stack_alias(name: &str, tracker: &RegTracker) -> String {
    let mut current = name.to_string();
    for _ in 0..5 { // max depth
        if let Some(alias) = tracker.stack_alias.get(&current) {
            if alias == &current { break; }
            current = alias.clone();
        } else {
            break;
        }
    }
    current
}

fn format_expr_tracked(expr: &Expr, ssa: &SsaCfg, ctx: &PrintCtx, tracker: &RegTracker) -> String {
    match expr {
        Expr::Var(id) => format_var_tracked(*id, ssa, ctx, tracker),
        Expr::BinOp(kind, left, right) => {
            let l = format_var_tracked(*left, ssa, ctx, tracker);
            let r = format_var_tracked(*right, ssa, ctx, tracker);
            let op = binop_str(*kind);
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
            let i = format_var_tracked(*input, ssa, ctx, tracker);
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
            if let Some(offset) = get_rbp_offset(*ptr, ssa) {
                return format!("var_{:x}", offset);
            }
            format_expr(expr, ssa, ctx)
        }
        _ => format_expr(expr, ssa, ctx),
    }
}

#[allow(dead_code)]
fn print_stmt(stmt: &StructuredStmt, ssa: &SsaCfg, ctx: &PrintCtx, indent: usize, out: &mut String) {
    let pad: String = "    ".repeat(indent);

    match stmt {
        StructuredStmt::Assign { lhs, .. } => {
            let vdef = ssa.var(*lhs);
            if vdef.varnode.space == AddressSpaceId::Unique { return; }
            if vdef.varnode.space == AddressSpaceId::Register && is_flag(vdef.varnode.offset) { return; }
            if matches!(&vdef.expr, Expr::Phi(_)) { return; }
            if is_zext_artifact(vdef, ssa) { return; }
            if is_self_assign(vdef, ssa) { return; }
            // Skip call return value captures (e.g., ECX = EAX after a call)
            // when the var is only used once — it will be inlined at the use site
            if vdef.call_return && vdef.use_count <= 1 { return; }
            // Skip argument register assignments that are consumed by a call
            // (they're shown inline in the call's argument list)
            if is_arg_consumed_by_call(*lhs, ssa) { return; }

            let name = var_name(&vdef.varnode, ctx);
            let rhs = format_expr(&vdef.expr, ssa, ctx);
            out.push_str(&format!("{}{} = {};\n", pad, name, rhs));
        }
        StructuredStmt::Store { addr, val } => {
            let addr_str = format_addr(*addr, ssa, ctx);
            let val_expr = format_var(*val, ssa, ctx);
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
            let target_name = format_call_target(target, ssa, ctx);
            // Show argument VALUES (the expression assigned to the arg register)
            let args_str: Vec<String> = args.iter()
                .map(|a| {
                    let vdef = ssa.var(*a);
                    // Show the RHS of the arg register assignment, not "RDI"
                    format_expr(&vdef.expr, ssa, ctx)
                })
                .collect();
            if let Some(out_var) = call_out {
                let name = var_name(&ssa.var(*out_var).varnode, ctx);
                out.push_str(&format!("{}{} = {}({});\n", pad, name, target_name, args_str.join(", ")));
            } else {
                out.push_str(&format!("{}{}({});\n", pad, target_name, args_str.join(", ")));
            }
        }
        StructuredStmt::Return(val) => {
            if let Some(v) = val {
                let vdef = ssa.var(*v);
                // Show the expression, not just "RAX"
                let expr = format_expr(&vdef.expr, ssa, ctx);
                out.push_str(&format!("{}return {};\n", pad, expr));
            } else {
                out.push_str(&format!("{}return;\n", pad));
            }
        }
        StructuredStmt::IfElse { cond, then_body, else_body } => {
            let cond_expr = format_condition(*cond, ssa, ctx);
            let then_filtered = filter_boilerplate(then_body, ssa);
            let else_filtered = filter_boilerplate(else_body, ssa);
            let then_empty = is_body_empty(&then_filtered, ssa);
            let else_empty = is_body_empty(&else_filtered, ssa);

            if then_empty && else_empty { return; }
            if then_empty && !else_empty {
                out.push_str(&format!("{}if (!{}) {{\n", pad, cond_expr));
                print_stmts(&else_filtered, ssa, ctx, indent + 1, out);
                out.push_str(&format!("{}}}\n", pad));
            } else {
                out.push_str(&format!("{}if ({}) {{\n", pad, cond_expr));
                print_stmts(&then_filtered, ssa, ctx, indent + 1, out);
                if !else_empty {
                    out.push_str(&format!("{}}} else {{\n", pad));
                    print_stmts(&else_filtered, ssa, ctx, indent + 1, out);
                }
                out.push_str(&format!("{}}}\n", pad));
            }
        }
        StructuredStmt::While { cond, body } => {
            let cond_expr = format_condition(*cond, ssa, ctx);
            let body_filtered = filter_boilerplate(body, ssa);
            out.push_str(&format!("{}while ({}) {{\n", pad, cond_expr));
            print_stmts(&body_filtered, ssa, ctx, indent + 1, out);
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
fn format_condition(id: VarId, ssa: &SsaCfg, ctx: &PrintCtx) -> String {
    let vdef = ssa.var(id);

    // If this is a comparison expression, format it directly
    if let Expr::BinOp(kind, left, right) = &vdef.expr {
        if is_comparison(*kind) {
            let l = format_var(*left, ssa, ctx);
            let r = format_var(*right, ssa, ctx);
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

    format_var(id, ssa, ctx)
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

fn format_addr(id: VarId, ssa: &SsaCfg, ctx: &PrintCtx) -> String {
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

    format_var(id, ssa, ctx)
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

fn format_call_target(target: &CallTarget, _ssa: &SsaCfg, ctx: &PrintCtx) -> String {
    match target {
        CallTarget::Direct(addr) => {
            // Try import map first
            if let Some(name) = ctx.imports.get(addr) {
                return name.clone();
            }
            format!("func_{:x}", addr)
        }
        CallTarget::Indirect(vn) => {
            format!("(*{})", var_name(vn, ctx))
        }
    }
}

// ---- Variable formatting ----

fn format_var(id: VarId, ssa: &SsaCfg, ctx: &PrintCtx) -> String {
    let vdef = ssa.var(id);

    // Use parameter name if available
    if let Some(ref name) = vdef.param_name {
        return name.clone();
    }

    // Call return values — if this var holds a call return and is only used once,
    // the printer at the use site should show the call expression
    // (handled by the caller checking call_return flag)

    // Inline Unique-space temporaries
    if vdef.varnode.space == AddressSpaceId::Unique {
        return format_expr(&vdef.expr, ssa, ctx);
    }

    // Inline constants
    if let Expr::Const(val, sz) = &vdef.expr {
        return format_const_ctx(*val, *sz, ctx);
    }

    var_name(&vdef.varnode, ctx)
}

fn format_expr(expr: &Expr, ssa: &SsaCfg, ctx: &PrintCtx) -> String {
    match expr {
        Expr::Var(id) => format_var(*id, ssa, ctx),
        Expr::Const(val, sz) => format_const_ctx(*val, *sz, ctx),
        Expr::BinOp(kind, left, right) => {
            let l = format_var(*left, ssa, ctx);
            let r = format_var(*right, ssa, ctx);
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
            let i = format_var(*input, ssa, ctx);
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
            let p = format_addr(*ptr, ssa, ctx);
            format!("*({})", p)
        }
        Expr::Phi(inputs) => {
            if inputs.len() == 1 { return format_var(inputs[0], ssa, ctx); }
            let args: Vec<String> = inputs.iter().map(|i| format_var(*i, ssa, ctx)).collect();
            format!("phi({})", args.join(", "))
        }
        Expr::Unknown => "?".to_string(),
    }
}

fn format_const_ctx(val: u64, size: u32, ctx: &PrintCtx) -> String {
    if val == 0 { return "0".to_string(); }
    if val < 10 { return format!("{}", val); }
    // Try string literal
    if size >= 4 && val > 0x1000 {
        if let Some(s) = try_read_string(val, ctx) {
            return format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n"));
        }
    }
    format_const(val, size)
}

fn format_const(val: u64, size: u32) -> String {
    if val == 0 { return "0".to_string(); }
    if val < 10 { return format!("{}", val); }
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

fn try_read_string(va: u64, ctx: &PrintCtx) -> Option<String> {
    let binary = ctx.binary?;
    let obj = goblin::Object::parse(binary).ok()?;
    let file_offset = match &obj {
        goblin::Object::Mach(goblin::mach::Mach::Binary(macho)) => {
            macho.segments.iter().find_map(|seg| {
                if va >= seg.vmaddr && va < seg.vmaddr + seg.vmsize {
                    Some((seg.fileoff + (va - seg.vmaddr)) as usize)
                } else { None }
            })?
        }
        goblin::Object::Elf(elf) => {
            elf.section_headers.iter().find_map(|sh| {
                if sh.sh_addr != 0 && va >= sh.sh_addr && va < sh.sh_addr + sh.sh_size {
                    Some((sh.sh_offset + (va - sh.sh_addr)) as usize)
                } else { None }
            })?
        }
        goblin::Object::PE(pe) => {
            let rva = va.checked_sub(pe.image_base as u64)? as u64;
            pe.sections.iter().find_map(|s| {
                let sr = s.virtual_address as u64;
                if rva >= sr && rva < sr + s.virtual_size as u64 {
                    Some((s.pointer_to_raw_data as u64 + (rva - sr)) as usize)
                } else { None }
            })?
        }
        _ => return None,
    };
    if file_offset >= binary.len() { return None; }
    let max = 80.min(binary.len() - file_offset);
    let slice = &binary[file_offset..file_offset + max];
    let null_pos = slice.iter().position(|&b| b == 0)?;
    if null_pos < 2 { return None; }
    let s = std::str::from_utf8(&slice[..null_pos]).ok()?;
    if s.chars().all(|c| c.is_ascii_graphic() || c == ' ' || c == '\n' || c == '\t') {
        Some(s.to_string())
    } else { None }
}

fn var_name(vn: &Varnode, ctx: &PrintCtx) -> String {
    match vn.space {
        AddressSpaceId::Register => {
            ctx.arch.register_name(vn.offset, vn.size).unwrap_or("?reg").to_string()
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

fn is_flag(offset: u64) -> bool {
    matches!(offset, 512..=523 | 256..=264)  // x86 flags + ARM64 flags
}

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

/// Check if an argument register assignment is consumed by a Call (shown inline).
fn is_arg_consumed_by_call(var_id: VarId, ssa: &SsaCfg) -> bool {
    for block in &ssa.blocks {
        // Check Call terminators
        if let SsaTerminator::Call { args, .. } = &block.terminator {
            if args.contains(&var_id) { return true; }
        }
        // Check Call statements
        for stmt in &block.stmts {
            if let Stmt::Call { args, .. } = stmt {
                if args.contains(&var_id) { return true; }
            }
        }
    }
    false
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
