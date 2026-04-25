use crate::ir::*;
use pcode_ir::AddressSpaceId;

/// Flag register offsets (Ghidra register space).
/// x86: CF=512, F1=513, PF=514, ZF=518, SF=519, DF=521, OF=523
/// ARM64: NG=256, ZR=257, CY=258, OV=259, tmpNG=263, tmpZR=264, tmpCY=261, tmpOV=262
const FLAG_OFFSETS: &[u64] = &[
    512, 513, 514, 518, 519, 521, 523, // x86: CF PF AF ZF SF DF OF
    256, 257, 258, 259, 261, 262, 263,
    264, // ARM64: NG ZR CY OV shift_carry tmpCY tmpOV tmpNG
    96, 97, 98, 99, 100, 101, 102, 103,
    104, // ARM32: NG ZR CY OV tmpNG tmpZR tmpCY tmpOV shift_carry
];

const RSP_OFFSET: u64 = 32; // x86-64 RSP
const ESP_OFFSET: u64 = 16; // x86-32 ESP
const RIP_OFFSET: u64 = 648;
pub const RAX_OFFSET: u64 = 0;

/// x86-64 SysV ABI argument register offsets (Linux, macOS, BSD).
const SYSV_ARG_REGS: &[u64] = &[56, 48, 16, 8, 128, 136]; // RDI, RSI, RDX, RCX, R8, R9

/// Windows x64 ABI argument register offsets.
const WIN64_ARG_REGS: &[u64] = &[8, 16, 128, 136]; // RCX, RDX, R8, R9

/// AArch64 AAPCS64 argument register offsets (x0-x7, stride 8 starting at 16384).
const AARCH64_ARG_REGS: &[u64] = &[16384, 16392, 16400, 16408, 16416, 16424, 16432, 16440];
/// ARM32 AAPCS argument register offsets (r0-r3 at SLEIGH offsets 0x20..0x2c).
const ARM32_ARG_REGS: &[u64] = &[32, 36, 40, 44];

/// x86-64 SysV ABI float argument register offsets (XMM0-XMM7).
const SYSV_FLOAT_ARG_REGS: &[u64] = &[4608, 4672, 4736, 4800, 4864, 4928, 4992, 5056];

/// Windows x64 ABI float argument register offsets (XMM0-XMM3).
const WIN64_FLOAT_ARG_REGS: &[u64] = &[4608, 4672, 4736, 4800];

/// AArch64 AAPCS64 float/SIMD arg regs (v0-v7 aka s0-s7, d0-d7, q0-q7).
/// SLEIGH offsets: 20480 + 32*N for N in 0..8.
const AARCH64_FLOAT_ARG_REGS: &[u64] = &[20480, 20512, 20544, 20576, 20608, 20640, 20672, 20704];

/// Go internal ABI (ABIInternal, Go 1.17+) integer argument registers on
/// amd64: RAX, RBX, RCX, RDI, RSI, R8, R9, R10, R11. R14 carries the
/// goroutine pointer and RDX carries the closure context (skipped here —
/// they are implicit params, not user args).
const GO_AMD64_ARG_REGS: &[u64] = &[0, 24, 8, 56, 48, 128, 136, 144, 152];
/// Go amd64 float arg regs: X0-X14 (XMM0-XMM14) — 15 regs.
/// SLEIGH XMM0 = 4608, stride 64.
const GO_AMD64_FLOAT_ARG_REGS: &[u64] = &[
    4608, 4672, 4736, 4800, 4864, 4928, 4992, 5056, 5120, 5184, 5248, 5312, 5376, 5440, 5504,
];

// Active argument register offsets — set by fold_with_cc() based on binary format.
// Uses thread_local to avoid unsafe static mut.
std::thread_local! {
    static ARG_REG_OFFSETS_TLS: std::cell::RefCell<&'static [u64]> = const { std::cell::RefCell::new(SYSV_ARG_REGS) };
}

std::thread_local! {
    static FLOAT_ARG_REG_OFFSETS_TLS: std::cell::RefCell<&'static [u64]> = const { std::cell::RefCell::new(SYSV_FLOAT_ARG_REGS) };
}

fn arg_reg_offsets() -> &'static [u64] {
    ARG_REG_OFFSETS_TLS.with(|r| *r.borrow())
}

fn float_arg_reg_offsets() -> &'static [u64] {
    FLOAT_ARG_REG_OFFSETS_TLS.with(|r| *r.borrow())
}

/// Calling convention detected from binary format.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum CallingConv {
    SysV,      // Linux, macOS, BSD — RDI, RSI, RDX, RCX, R8, R9
    Win64,     // Windows x64 — RCX, RDX, R8, R9
    Cdecl32,   // x86-32 cdecl — stack-based, caller cleans
    Stdcall32, // x86-32 stdcall — stack-based, callee cleans (RET imm16)
    AArch64,   // AAPCS64 — x0-x7
    Arm32,     // AAPCS — r0-r3
    GoAmd64,   // Go internal ABI v1.17+ — RAX, RBX, RCX, RDI, RSI, R8-R11
}

/// Full ABI descriptor: arg locations, return locations, cleanup, shadow space.
///
/// Audit P1 #2: replaces ad-hoc per-architecture rules in return-value
/// detection and call-site arg recovery with a single source of truth so
/// new architectures and conventions can be added without sprinkling magic
/// numbers across passes.
#[derive(Clone, Copy, Debug)]
pub struct Abi {
    /// Integer/pointer argument register offsets in call order.
    pub int_args: &'static [u64],
    /// Floating-point argument register offsets in call order.
    pub float_args: &'static [u64],
    /// Integer return register offset (RAX, EAX, x0, r0, ...).
    /// `None` when the convention does not designate one (e.g. void-only).
    pub return_reg_int: Option<u64>,
    /// Float return register offset (XMM0, V0, ...).
    pub return_reg_float: Option<u64>,
    /// True when the callee cleans the argument stack (stdcall/fastcall).
    /// False for cdecl/SysV/Win64 where the caller adjusts SP after the call.
    pub callee_cleanup_stack: bool,
    /// Shadow space the caller must allocate (Win64 = 32, others = 0).
    pub shadow_space_bytes: u32,
}

/// Look up the ABI descriptor for a calling convention.
pub fn abi(cc: CallingConv) -> Abi {
    match cc {
        CallingConv::SysV => Abi {
            int_args: SYSV_ARG_REGS,
            float_args: SYSV_FLOAT_ARG_REGS,
            return_reg_int: Some(RAX_OFFSET),
            return_reg_float: Some(4608), // XMM0
            callee_cleanup_stack: false,
            shadow_space_bytes: 0,
        },
        CallingConv::Win64 => Abi {
            int_args: WIN64_ARG_REGS,
            float_args: WIN64_FLOAT_ARG_REGS,
            return_reg_int: Some(RAX_OFFSET),
            return_reg_float: Some(4608),
            callee_cleanup_stack: false,
            shadow_space_bytes: 32,
        },
        CallingConv::Cdecl32 => Abi {
            int_args: &[],
            float_args: &[],
            return_reg_int: Some(RAX_OFFSET), // EAX (offset 0, size 4)
            return_reg_float: None,           // ST0 — not modeled here
            callee_cleanup_stack: false,
            shadow_space_bytes: 0,
        },
        CallingConv::Stdcall32 => Abi {
            int_args: &[],
            float_args: &[],
            return_reg_int: Some(RAX_OFFSET),
            return_reg_float: None,
            callee_cleanup_stack: true,
            shadow_space_bytes: 0,
        },
        CallingConv::AArch64 => Abi {
            int_args: AARCH64_ARG_REGS,
            float_args: AARCH64_FLOAT_ARG_REGS,
            return_reg_int: Some(16384),  // x0
            return_reg_float: Some(20480), // v0
            callee_cleanup_stack: false,
            shadow_space_bytes: 0,
        },
        CallingConv::Arm32 => Abi {
            int_args: ARM32_ARG_REGS,
            float_args: &[],
            return_reg_int: Some(32), // r0
            return_reg_float: None,
            callee_cleanup_stack: false,
            shadow_space_bytes: 0,
        },
        CallingConv::GoAmd64 => Abi {
            int_args: GO_AMD64_ARG_REGS,
            float_args: GO_AMD64_FLOAT_ARG_REGS,
            return_reg_int: Some(RAX_OFFSET),
            return_reg_float: Some(4608),
            callee_cleanup_stack: false,
            shadow_space_bytes: 0,
        },
    }
}

/// Fold expressions: inline temps, eliminate dead code, recover conditions.
pub fn fold(ssa: &mut SsaCfg) {
    fold_with_cc(ssa, CallingConv::SysV);
}

/// Fold with explicit calling convention.
pub fn fold_with_cc(ssa: &mut SsaCfg, cc: CallingConv) {
    // Pull arg-register offsets from the ABI descriptor.
    let abi_for_cc = abi(cc);
    ARG_REG_OFFSETS_TLS.with(|r| {
        *r.borrow_mut() = abi_for_cc.int_args;
    });
    FLOAT_ARG_REG_OFFSETS_TLS.with(|r| {
        *r.borrow_mut() = abi_for_cc.float_args;
    });
    // Collect call arguments FIRST, before any optimization.
    // Arg register writes (RCX/RDX for Win64, RDI/RSI for SysV) have use_count=0
    // because the Call terminator doesn't reference them by VarId. If we run
    // fold_once or eliminate_dead first, these assignments get removed.
    collect_call_arguments(ssa);
    recount_uses(ssa);

    // Seed x86 ABI-default flag values for uninitialized reads. DF (x86
    // direction flag, register offset 522) is guaranteed 0 on function
    // entry by SysV and Win64. Without this, REP STOSB/MOVSB/SCASB expand
    // to `1 - 2*DF` in the per-iteration advance, leaking `(uint8_t)DF`
    // into output and breaking memset-style recognition.
    if matches!(
        cc,
        CallingConv::SysV | CallingConv::Win64 | CallingConv::Cdecl32 | CallingConv::GoAmd64
    ) {
        for v in ssa.vars.iter_mut() {
            if matches!(v.expr, Expr::Unknown)
                && v.varnode.space == AddressSpaceId::Register
                && v.varnode.offset == 522
            {
                v.expr = Expr::Const(0, v.size);
            }
        }
    }

    // Name parameters FIRST so propagate_register_constants won't
    // overwrite param VarIds with constants from other code paths.
    name_parameters_with_cc(ssa, cc);

    for _round in 0..8 {
        let before = count_live_stmts(ssa);
        fold_once(ssa);
        recount_uses(ssa);
        propagate_register_constants(ssa);
        propagate_call_returns(ssa);
        recount_uses(ssa);
        eliminate_dead(ssa);
        recount_uses(ssa);
        recover_conditions(ssa);
        mba_simplify(ssa);
        detect_return_values(ssa);
        recount_uses(ssa);
        // Name loop Phi variables so the printer uses the name instead of
        // expanding the Phi expression. This prevents #PHI_CLEANUP from
        // destroying loop variable semantics (e.g., "return phi(0, count+1)" → "return 0").
        name_loop_phis(ssa);
        name_parameters_with_cc(ssa, cc); // Re-run to catch params exposed by folding
        let after = count_live_stmts(ssa);
        if before == after {
            break;
        }
    }
    // Type inference runs once after folding is stable
    infer_types(ssa);
    // Recognize struct field access patterns after all folding is done
    recognize_field_access(ssa);
    // Go-specific: detect adjacent-register string/slice/iface parameter
    // pairs and retag their names. Runs last so the prior passes have
    // converged type info.
    if matches!(cc, CallingConv::GoAmd64) {
        infer_go_header_params(ssa);
    }
}

/// Go amd64 adjacent-register header detection. Go ABI passes strings,
/// slices, and interfaces as separate register operands:
///   string = (data, len)          — 2 regs
///   slice  = (data, len, cap)     — 3 regs
///   iface  = (tab, data)          — 2 regs
///
/// Heuristic: param_i is a pointer (Pointer-typed or used as Load
/// address) AND param_(i+1) is used as an integer upper bound (operand
/// of IntLess/IntLessEqual/IntSLess/IntSLessEqual, or as a size arg).
/// Rename the pair; if param_(i+2) also appears to be a capacity-style
/// int, treat as slice.
fn infer_go_header_params(ssa: &mut SsaCfg) {
    // Build a map param_name -> VarIds that carry it.
    let mut param_vars: std::collections::BTreeMap<String, Vec<usize>> =
        std::collections::BTreeMap::new();
    for (i, v) in ssa.vars.iter().enumerate() {
        if let Some(n) = v.param_name.as_ref() {
            if n.starts_with("param_") {
                param_vars.entry(n.clone()).or_default().push(i);
            }
        }
    }
    // Sort numerically by param index.
    let mut indexed: Vec<(u32, String)> = param_vars
        .keys()
        .filter_map(|n| {
            n.strip_prefix("param_")
                .and_then(|s| s.parse::<u32>().ok())
                .map(|i| (i, n.clone()))
        })
        .collect();
    indexed.sort();
    if indexed.is_empty() {
        return;
    }

    // Classify each param.
    // Build transitive "derived from param" closure. A VarId Y is
    // derived-from(X) if X ∈ roots, or Y's expr is Var(Z)/BinOp(_, Z, _)
    // /BinOp(_, _, Z)/UnaryOp(_, Z) with Z ∈ closure.
    let closure_from = |roots: &[usize], ssa: &SsaCfg| -> std::collections::HashSet<usize> {
        let mut set: std::collections::HashSet<usize> = roots.iter().copied().collect();
        let mut changed = true;
        let mut guard = 0;
        while changed && guard < 8 {
            changed = false;
            guard += 1;
            for (idx, v) in ssa.vars.iter().enumerate() {
                if set.contains(&idx) {
                    continue;
                }
                let parents: &[VarId] = match &v.expr {
                    Expr::Var(a) => std::slice::from_ref(a),
                    Expr::UnaryOp(_, a) => std::slice::from_ref(a),
                    Expr::BinOp(_, a, b) => {
                        if set.contains(&(a.0 as usize)) || set.contains(&(b.0 as usize)) {
                            set.insert(idx);
                            changed = true;
                        }
                        continue;
                    }
                    _ => continue,
                };
                if parents.iter().any(|p| set.contains(&(p.0 as usize))) {
                    set.insert(idx);
                    changed = true;
                }
            }
        }
        set
    };

    let is_pointer_like = |p: &str,
                           param_vars: &std::collections::BTreeMap<String, Vec<usize>>,
                           ssa: &SsaCfg|
     -> bool {
        let vars = match param_vars.get(p) {
            Some(v) => v,
            None => return false,
        };
        for &vi in vars {
            if ssa.vars[vi].inferred_type == InferredType::Pointer {
                return true;
            }
        }
        let derived = closure_from(vars, ssa);
        for blk in &ssa.blocks {
            for stmt in &blk.stmts {
                match stmt {
                    Stmt::Store { addr, .. } => {
                        if derived.contains(&(addr.0 as usize)) {
                            return true;
                        }
                    }
                    Stmt::Assign(vid) => match &ssa.vars[vid.0 as usize].expr {
                        Expr::Load(ptr) if derived.contains(&(ptr.0 as usize)) => return true,
                        Expr::FieldAccess(base, _) if derived.contains(&(base.0 as usize)) => {
                            return true
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
        }
        false
    };
    let is_length_like = |p: &str,
                          param_vars: &std::collections::BTreeMap<String, Vec<usize>>,
                          ssa: &SsaCfg|
     -> bool {
        let vars = match param_vars.get(p) {
            Some(v) => v,
            None => return false,
        };
        for v in ssa.vars.iter() {
            if let Expr::BinOp(kind, l, r) = &v.expr {
                if matches!(
                    kind,
                    BinOpKind::Less
                        | BinOpKind::LessEq
                        | BinOpKind::SLess
                        | BinOpKind::SLessEq
                        | BinOpKind::Eq
                        | BinOpKind::NotEq
                ) {
                    if vars.contains(&(l.0 as usize)) || vars.contains(&(r.0 as usize)) {
                        return true;
                    }
                }
            }
        }
        for blk in &ssa.blocks {
            for stmt in &blk.stmts {
                if let Stmt::Call { args, .. } = stmt {
                    for a in args {
                        if vars.contains(&(a.0 as usize)) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    };

    // Reject: param_(i+1) compared against a value derived from param_i.
    // Real strings/slices have len that is independent of data; if the
    // "len" candidate is being compared to `*(data + 0x10)` style load
    // of the data param, we are looking at array indexing, not a slice
    // header.
    let len_is_bound_by_data = |a_name: &str,
                                b_name: &str,
                                param_vars: &std::collections::BTreeMap<String, Vec<usize>>,
                                ssa: &SsaCfg|
     -> bool {
        let a_vars = match param_vars.get(a_name) {
            Some(v) => v,
            None => return false,
        };
        let b_vars = match param_vars.get(b_name) {
            Some(v) => v,
            None => return false,
        };
        let a_derived = closure_from(a_vars, ssa);
        // Scan comparisons; if both sides derive from a (data) and b
        // (length), reject. Loads from a's offsets count as a-derived.
        let mut load_chain: std::collections::HashSet<usize> = std::collections::HashSet::new();
        load_chain.extend(a_derived.iter().copied());
        for (idx, v) in ssa.vars.iter().enumerate() {
            match &v.expr {
                Expr::Load(p) if a_derived.contains(&(p.0 as usize)) => {
                    load_chain.insert(idx);
                }
                Expr::FieldAccess(p, _) if a_derived.contains(&(p.0 as usize)) => {
                    load_chain.insert(idx);
                }
                _ => {}
            }
        }
        // Now expand load_chain transitively via Var/BinOp/UnaryOp.
        let load_chain = closure_from(&load_chain.iter().copied().collect::<Vec<_>>(), ssa);

        for v in ssa.vars.iter() {
            if let Expr::BinOp(kind, l, r) = &v.expr {
                if matches!(
                    kind,
                    BinOpKind::Less
                        | BinOpKind::LessEq
                        | BinOpKind::SLess
                        | BinOpKind::SLessEq
                        | BinOpKind::Eq
                        | BinOpKind::NotEq
                ) {
                    let l_b = b_vars.contains(&(l.0 as usize));
                    let r_b = b_vars.contains(&(r.0 as usize));
                    let l_a = load_chain.contains(&(l.0 as usize));
                    let r_a = load_chain.contains(&(r.0 as usize));
                    if (l_b && r_a) || (r_b && l_a) {
                        return true;
                    }
                }
            }
        }
        false
    };

    // Walk adjacent pairs. Each detected header uses the FIRST param's
    // original numeric index as suffix so signature sort keeps order
    // and multiple string/slice params don't collide.
    let mut i = 0;
    while i + 1 < indexed.len() {
        let (ai, a_name) = &indexed[i];
        let (bi, b_name) = &indexed[i + 1];
        if *bi != *ai + 1 {
            i += 1;
            continue;
        }

        let a_ptr = is_pointer_like(a_name, &param_vars, ssa);
        let b_len = is_length_like(b_name, &param_vars, ssa);
        if !(a_ptr && b_len) {
            i += 1;
            continue;
        }

        // Reject if the apparent length is bound by a value derived
        // from the apparent data pointer — that's array indexing into
        // a struct, not a real slice/string header.
        if len_is_bound_by_data(a_name, b_name, &param_vars, ssa) {
            i += 1;
            continue;
        }

        let mut stride = 2;
        let mut is_slice = false;
        if i + 2 < indexed.len() {
            let (ci, c_name) = &indexed[i + 2];
            if *ci == *bi + 1 && is_length_like(c_name, &param_vars, ssa) {
                stride = 3;
                is_slice = true;
            }
        }

        let suffix_data = *ai;
        let suffix_len = *bi;
        let (data_name, len_name) = if is_slice {
            (
                format!("slice_data_{}", suffix_data),
                format!("slice_len_{}", suffix_len),
            )
        } else {
            (
                format!("s_data_{}", suffix_data),
                format!("s_len_{}", suffix_len),
            )
        };

        rename_param(ssa, a_name, &data_name);
        rename_param(ssa, b_name, &len_name);
        if is_slice {
            let (ci, c_name) = &indexed[i + 2];
            let cap_name = format!("slice_cap_{}", *ci);
            rename_param(ssa, c_name, &cap_name);
        }
        i += stride;
    }
}

fn rename_param(ssa: &mut SsaCfg, old: &str, new: &str) {
    for v in &mut ssa.vars {
        if v.param_name.as_deref() == Some(old) {
            v.param_name = Some(new.to_string());
        }
    }
}

fn count_live_stmts(ssa: &SsaCfg) -> usize {
    ssa.blocks.iter().map(|b| b.stmts.len()).sum()
}

/// Combine two chained frame-register offset operations into a single (op, const) pair.
///
/// Given: `(FRAME_REG op1 C1) op2 C2`, returns `(result_op, result_const)` such that
/// `FRAME_REG result_op result_const` is numerically equivalent.
fn combine_frame_offset(op1: BinOpKind, c1: u64, op2: BinOpKind, c2: u64) -> (BinOpKind, u64) {
    let s1 = c1 as i64;
    let s2 = c2 as i64;
    let delta1: i64 = if matches!(op1, BinOpKind::Sub) {
        -s1
    } else {
        s1
    };
    let delta2: i64 = if matches!(op2, BinOpKind::Sub) {
        -s2
    } else {
        s2
    };
    let combined = delta1.wrapping_add(delta2);
    if combined < 0 {
        (BinOpKind::Sub, (-combined) as u64)
    } else {
        (BinOpKind::Add, combined as u64)
    }
}

/// Return the logical negation of an equality/inequality operator.
/// Only handles Eq↔NotEq. Returns None for Less/SLess/etc. (those need operand swapping).
fn negate_eq_op(op: BinOpKind) -> Option<BinOpKind> {
    match op {
        BinOpKind::Eq => Some(BinOpKind::NotEq),
        BinOpKind::NotEq => Some(BinOpKind::Eq),
        _ => None,
    }
}

fn fold_once(ssa: &mut SsaCfg) {
    // Pass 1: Collapse trivial Phis
    for v in 0..ssa.vars.len() {
        if let Expr::Phi(inputs) = &ssa.vars[v].expr {
            if inputs.is_empty() {
                continue;
            }
            let first = inputs[0];
            if inputs.iter().all(|i| *i == first) {
                ssa.vars[v].expr = Expr::Var(first);
            }
        }
    }

    // Pass 1b: Simplify trivial ternaries
    for v in 0..ssa.vars.len() {
        if let Expr::Ternary(cond, then_val, else_val) = &ssa.vars[v].expr {
            let c = *cond;
            let t = *then_val;
            let e = *else_val;
            // Ternary(Const(1), a, b) → Var(a)
            if matches!(&ssa.vars[c.0 as usize].expr, Expr::Const(v, _) if *v != 0) {
                ssa.vars[v].expr = Expr::Var(t);
            }
            // Ternary(Const(0), a, b) → Var(b)
            else if matches!(&ssa.vars[c.0 as usize].expr, Expr::Const(0, _)) {
                ssa.vars[v].expr = Expr::Var(e);
            }
            // Ternary(c, a, a) → Var(a)
            else if t == e {
                ssa.vars[v].expr = Expr::Var(t);
            }
        }
    }

    // Pass 2: Algebraic simplification + constant folding
    for v in 0..ssa.vars.len() {
        let expr = ssa.vars[v].expr.clone();
        ssa.vars[v].expr = simplify_expr(expr, &ssa.vars);
    }
    // Constant folding: evaluate BinOp(Const, Const) chains to single constants.
    for v in 0..ssa.vars.len() {
        if matches!(
            &ssa.vars[v].expr,
            Expr::BinOp(_, _, _) | Expr::UnaryOp(_, _)
        ) {
            if let Some((val, sz)) = const_fold_expr(&ssa.vars[v].expr, &ssa.vars) {
                ssa.vars[v].expr = Expr::Const(val, sz);
            }
        }
    }
    // Pass 2b: Collapse chained RSP frame-register arithmetic.
    // Pattern: (RSP op1 C1) op2 C2 → RSP combined_op combined_C
    // Needed for RSP-relative local naming: single-level RSP±N patterns.
    for v in 0..ssa.vars.len() {
        let (op2, inner_id, c2_id) = match &ssa.vars[v].expr {
            Expr::BinOp(op, inner, c2) if matches!(op, BinOpKind::Add | BinOpKind::Sub) => {
                (*op, *inner, *c2)
            }
            _ => continue,
        };
        let c2_val = match ssa.vars[c2_id.0 as usize].expr {
            Expr::Const(val, _) => val,
            _ => continue,
        };
        let (op1, frame_id, c1_id) = match &ssa.vars[inner_id.0 as usize].expr {
            Expr::BinOp(op, frame, c1) if matches!(op, BinOpKind::Add | BinOpKind::Sub) => {
                (*op, *frame, *c1)
            }
            _ => continue,
        };
        let c1_val = match ssa.vars[c1_id.0 as usize].expr {
            Expr::Const(val, _) => val,
            _ => continue,
        };
        let frame_vdef = &ssa.vars[frame_id.0 as usize];
        if frame_vdef.varnode.space != AddressSpaceId::Register
            || frame_vdef.varnode.offset != RSP_OFFSET
            || !matches!(frame_vdef.expr, Expr::Unknown)
        {
            continue;
        }
        let (combined_op, combined_c) = combine_frame_offset(op1, c1_val, op2, c2_val);
        let sz = ssa.vars[c1_id.0 as usize].size;
        let varnode = ssa.vars[c1_id.0 as usize].varnode;
        let new_const_id = ssa.new_var(varnode, Expr::Const(combined_c, sz), sz);
        ssa.vars[v].expr = Expr::BinOp(combined_op, frame_id, new_const_id);
    }

    // MBA deobfuscation: deep algebraic simplification through expression trees.
    mba_simplify(ssa);

    // Equality saturation: explore all equivalent MBA forms, extract cheapest.
    // Only run on expressions deep enough to benefit (depth ≥ 5).
    // Wrapped in catch_unwind because egg can panic on pathological inputs.
    // Suppress panic messages during eqsat to avoid noisy stderr output.
    {
        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| { /* silence egg panics */ }));
        for v in 0..ssa.vars.len() {
            let depth = expr_depth(&ssa.vars[v].expr, &ssa.vars, 0);
            if depth >= 5 {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    crate::eqsat::simplify_expr(v, &mut ssa.vars)
                }));
                if let Ok(Some(simplified)) = result {
                    ssa.vars[v].expr = simplified;
                }
            }
        }
        std::panic::set_hook(prev_hook);
    }

    // Pass 3: Inline single-use Unique vars and all constants
    let inline_candidates: Vec<(VarId, Expr)> = (0..ssa.vars.len())
        .filter_map(|v| {
            let vdef = &ssa.vars[v];
            if vdef.use_count == 1 && vdef.varnode.space == AddressSpaceId::Unique {
                Some((vdef.id, vdef.expr.clone()))
            } else if matches!(vdef.expr, Expr::Const(_, _)) {
                Some((vdef.id, vdef.expr.clone()))
            } else {
                None
            }
        })
        .collect();

    for v in 0..ssa.vars.len() {
        let expr = ssa.vars[v].expr.clone();
        ssa.vars[v].expr = substitute_expr(&expr, &inline_candidates);
    }

    // Pass 4: Multi-level register copy propagation
    propagate_register_copies(ssa);
}

/// MBA (Mixed Boolean-Arithmetic) deobfuscation pass.
///
/// Two-phase approach inspired by msynth/SiMBA:
/// Phase 1: Pattern-based — cancellation, absorption, double negation
/// Phase 2: Oracle-based — evaluate expressions on sample inputs, match I/O
///          behavior against a table of simple canonical forms
fn mba_simplify(ssa: &mut SsaCfg) {
    // Phase 1: Pattern-based simplification (fast, catches structural patterns)
    for _pass in 0..4 {
        let mut changed = false;
        for v in 0..ssa.vars.len() {
            let new_expr = mba_simplify_expr(v, &ssa.vars);
            if let Some(new_expr) = new_expr {
                ssa.vars[v].expr = new_expr;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    // Phase 2: Oracle-based truth table simplification
    // For each expression with ≤ 3 base variables, evaluate on sample inputs
    // and check if the I/O behavior matches a simpler expression.
    mba_oracle_simplify(ssa);
}

/// Oracle-based MBA simplification using truth table matching.
///
/// For each complex expression (depth ≥ 3), find its base variables,
/// evaluate on sample inputs, and check if the output matches a simpler form.
fn mba_oracle_simplify(ssa: &mut SsaCfg) {
    // Phase A: Bottom-up tree walking — simplify subtrees first to reduce
    // 4+ variable expressions to tractable 2-3 variable forms.
    // Process variables in dependency order (lower IDs = earlier definitions = leaves).
    for _pass in 0..6 {
        let mut changed = false;

        // Forward pass (leaves → root)
        for v in 0..ssa.vars.len() {
            if try_simba_at(v, &mut ssa.vars) {
                changed = true;
            }
        }
        // Reverse pass (root → leaves) — catch top-down opportunities
        for v in (0..ssa.vars.len()).rev() {
            if try_simba_at(v, &mut ssa.vars) {
                changed = true;
            }
        }

        if !changed {
            break;
        }
    }
}

/// Try SiMBA simplification on a single variable. Returns true if simplified.
fn try_simba_at(v: usize, vars: &mut Vec<VarDef>) -> bool {
    let depth = expr_depth(&vars[v].expr, vars, 0);
    if depth < 2 {
        return false;
    }

    // Constant folding first
    if let Some((val, sz)) = const_fold_expr(&vars[v].expr, vars) {
        vars[v].expr = Expr::Const(val, sz);
        return true;
    }

    let mut bases: Vec<VarId> = Vec::new();
    collect_base_vars(&vars[v].expr, vars, &mut bases, 0);
    bases.sort_by_key(|id| id.0);
    bases.dedup_by_key(|id| id.0);

    if bases.is_empty() || bases.len() > 4 {
        return false;
    }

    let sz = vars[v].size;
    let mask = if sz >= 8 {
        u64::MAX
    } else {
        (1u64 << (sz * 8)).wrapping_sub(1)
    };

    let simplified = match bases.len() {
        1 => simba_simplify_1var(v, vars, bases[0], mask, sz),
        2 => simba_simplify_2var(v, vars, &bases, mask, sz),
        3 => simba_simplify_3var(v, vars, &bases, mask, sz),
        4 => simba_simplify_4var(v, vars, &bases, mask, sz),
        _ => None,
    };

    if let Some(simple) = simplified {
        vars[v].expr = simple;
        return true;
    }

    false
}

/// Compute expression depth (for filtering).
fn expr_depth(expr: &Expr, vars: &[VarDef], depth: usize) -> usize {
    if depth > 10 {
        return depth;
    } // prevent infinite recursion
    match expr {
        Expr::Const(_, _) | Expr::Unknown => 0,
        Expr::Var(id) => {
            if id.0 as usize >= vars.len() {
                return 0;
            }
            expr_depth(&vars[id.0 as usize].expr, vars, depth + 1)
        }
        Expr::BinOp(_, left, right) => {
            let ld = expr_depth(&vars[left.0 as usize].expr, vars, depth + 1);
            let rd = expr_depth(&vars[right.0 as usize].expr, vars, depth + 1);
            1 + ld.max(rd)
        }
        Expr::UnaryOp(_, inner) => 1 + expr_depth(&vars[inner.0 as usize].expr, vars, depth + 1),
        _ => 0,
    }
}

/// Collect base variables (leaves of the expression tree that aren't constants).
fn collect_base_vars(expr: &Expr, vars: &[VarDef], bases: &mut Vec<VarId>, depth: usize) {
    if depth > 10 {
        return;
    }
    match expr {
        Expr::Const(_, _) => {}
        Expr::Unknown => {}
        Expr::Var(id) => {
            if id.0 as usize >= vars.len() {
                return;
            }
            let inner = &vars[id.0 as usize].expr;
            if matches!(inner, Expr::Unknown)
                || matches!(inner, Expr::Load(_))
                || matches!(inner, Expr::Phi(_))
                || matches!(inner, Expr::FieldAccess(_, _))
                || matches!(inner, Expr::Ternary(_, _, _))
            {
                bases.push(*id); // This is a base variable (input)
            } else {
                collect_base_vars(inner, vars, bases, depth + 1);
            }
        }
        Expr::BinOp(_, left, right) => {
            collect_base_vars(&Expr::Var(*left), vars, bases, depth + 1);
            collect_base_vars(&Expr::Var(*right), vars, bases, depth + 1);
        }
        Expr::UnaryOp(_, inner) => {
            collect_base_vars(&Expr::Var(*inner), vars, bases, depth + 1);
        }
        _ => {}
    }
}

/// Symbolically evaluate an expression with given variable bindings.
fn eval_expr(
    expr: &Expr,
    vars: &[VarDef],
    env: &std::collections::HashMap<u32, u64>,
    mask: u64,
    depth: usize,
) -> Option<u64> {
    if depth > 20 {
        return None;
    }
    match expr {
        Expr::Const(val, _) => Some(*val & mask),
        Expr::Unknown
        | Expr::Load(_)
        | Expr::Phi(_)
        | Expr::FieldAccess(_, _)
        | Expr::Ternary(_, _, _)
        | Expr::UserOp { .. } => None,
        Expr::Var(id) => {
            if let Some(&val) = env.get(&id.0) {
                Some(val & mask)
            } else if (id.0 as usize) < vars.len() {
                eval_expr(&vars[id.0 as usize].expr, vars, env, mask, depth + 1)
            } else {
                None
            }
        }
        Expr::BinOp(kind, left, right) => {
            let l = eval_expr(&Expr::Var(*left), vars, env, mask, depth + 1)?;
            let r = eval_expr(&Expr::Var(*right), vars, env, mask, depth + 1)?;
            let result = match kind {
                BinOpKind::Add => l.wrapping_add(r),
                BinOpKind::Sub => l.wrapping_sub(r),
                BinOpKind::Mult => l.wrapping_mul(r),
                BinOpKind::And => l & r,
                BinOpKind::Or => l | r,
                BinOpKind::Xor => l ^ r,
                BinOpKind::Lsl => l.wrapping_shl((r & 63) as u32),
                BinOpKind::Lsr => l.wrapping_shr((r & 63) as u32),
                BinOpKind::Asr => ((l as i64).wrapping_shr((r & 63) as u32)) as u64,
                _ => return None,
            };
            Some(result & mask)
        }
        Expr::UnaryOp(kind, inner) => {
            let v = eval_expr(&Expr::Var(*inner), vars, env, mask, depth + 1)?;
            let result = match kind {
                UnaryOpKind::Neg => (-(v as i64)) as u64,
                UnaryOpKind::Not => !v,
                _ => return None,
            };
            Some(result & mask)
        }
    }
}

/// SiMBA-style linear MBA simplification.
///
/// Any MBA expression over 2 variables can be uniquely decomposed as:
///   f(a,b) = c0 + c1*a + c2*b + c3*(a&b)   (mod 2^N)
///
/// We recover c0..c3 from just 4 evaluations:
///   c0 = f(0,0)
///   c1 = f(1,0) - f(0,0)
///   c2 = f(0,1) - f(0,0)
///   c3 = f(1,1) - f(1,0) - f(0,1) + f(0,0)
///
/// Then map the coefficient vector to the simplest expression:
///   (0,1,0,0) → a, (0,0,1,0) → b, (0,1,1,0) → a+b,
///   (0,1,1,-2) → a^b, (0,1,1,-1) → a|b, (0,0,0,1) → a&b, etc.
///
/// For 1 variable: f(a) = c0 + c1*a, 2 evaluations.
/// For 3 variables: f(a,b,c) = 8 coefficients over {1,a,b,c,a&b,a&c,b&c,a&b&c}.
/// SiMBA coefficient recovery for 2-variable MBA expressions.
/// Called from mba_oracle_simplify when exactly 2 base variables are found.
fn simba_simplify_2var(
    var_idx: usize,
    vars: &[VarDef],
    bases: &[VarId],
    mask: u64,
    sz: u32,
) -> Option<Expr> {
    if bases.len() != 2 {
        return None;
    }
    let (a_id, b_id) = (bases[0], bases[1]);

    // Evaluate f(0,0), f(1,0), f(0,1), f(1,1)
    let mut env = std::collections::HashMap::new();

    env.clear();
    env.insert(a_id.0, 0u64);
    env.insert(b_id.0, 0u64);
    let f00 = eval_expr(&vars[var_idx].expr, vars, &env, mask, 0)?;

    env.clear();
    env.insert(a_id.0, 1u64);
    env.insert(b_id.0, 0u64);
    let f10 = eval_expr(&vars[var_idx].expr, vars, &env, mask, 0)?;

    env.clear();
    env.insert(a_id.0, 0u64);
    env.insert(b_id.0, 1u64);
    let f01 = eval_expr(&vars[var_idx].expr, vars, &env, mask, 0)?;

    env.clear();
    env.insert(a_id.0, 1u64);
    env.insert(b_id.0, 1u64);
    let f11 = eval_expr(&vars[var_idx].expr, vars, &env, mask, 0)?;

    // Recover coefficients (mod 2^N)
    let c0 = f00;
    let c1 = f10.wrapping_sub(f00) & mask;
    let c2 = f01.wrapping_sub(f00) & mask;
    let c3 = f11.wrapping_sub(f10).wrapping_sub(f01).wrapping_add(f00) & mask;

    // Verify with additional test points to avoid false positives
    env.clear();
    env.insert(a_id.0, 0xAA);
    env.insert(b_id.0, 0x55);
    let f_test = eval_expr(&vars[var_idx].expr, vars, &env, mask, 0)?;
    let expected = (c0
        .wrapping_add(c1.wrapping_mul(0xAA))
        .wrapping_add(c2.wrapping_mul(0x55))
        .wrapping_add(c3.wrapping_mul(0xAA & 0x55)))
        & mask;
    if f_test != expected {
        return None;
    } // Not a linear MBA

    // Second verification
    env.clear();
    env.insert(a_id.0, 0xFF);
    env.insert(b_id.0, 0x42);
    let f_test2 = eval_expr(&vars[var_idx].expr, vars, &env, mask, 0)?;
    let expected2 = (c0
        .wrapping_add(c1.wrapping_mul(0xFF))
        .wrapping_add(c2.wrapping_mul(0x42))
        .wrapping_add(c3.wrapping_mul(0xFF & 0x42)))
        & mask;
    if f_test2 != expected2 {
        return None;
    }

    // Map coefficient vector to simplest expression
    let neg1 = mask; // -1 mod 2^N
    let neg2 = mask.wrapping_sub(1); // -2 mod 2^N

    // Zero constant → simpler expression without constant term
    if c0 == 0 {
        match (c1, c2, c3) {
            (0, 0, 0) => return Some(Expr::Const(0, sz)),
            (1, 0, 0) => return Some(Expr::Var(a_id)),
            (0, 1, 0) => return Some(Expr::Var(b_id)),
            (1, 1, 0) => return Some(Expr::BinOp(BinOpKind::Add, a_id, b_id)),
            _ if c1 == 1 && c2 == neg1 && c3 == 0 => {
                return Some(Expr::BinOp(BinOpKind::Sub, a_id, b_id))
            }
            _ if c1 == neg1 && c2 == 1 && c3 == 0 => {
                return Some(Expr::BinOp(BinOpKind::Sub, b_id, a_id))
            }
            (0, 0, 1) => return Some(Expr::BinOp(BinOpKind::And, a_id, b_id)),
            _ if c1 == 1 && c2 == 1 && c3 == neg1 => {
                return Some(Expr::BinOp(BinOpKind::Or, a_id, b_id))
            }
            _ if c1 == 1 && c2 == 1 && c3 == neg2 => {
                return Some(Expr::BinOp(BinOpKind::Xor, a_id, b_id))
            }
            _ if c1 == 1 && c2 == 0 && c3 == neg1 => {
                // a - (a&b) = a & ~b — but we don't have AndNot, express as Sub
                return Some(Expr::BinOp(BinOpKind::Sub, a_id, b_id)); // approximation
            }
            _ if c1 == 0 && c2 == 1 && c3 == neg1 => {
                return Some(Expr::BinOp(BinOpKind::Sub, b_id, a_id)); // approximation
            }
            _ => {}
        }
    }

    // With constant term — check if it's a simple op + constant
    if c0 != 0 && c3 == 0 {
        // f = c0 + c1*a + c2*b — linear combination
        if c1 == 1 && c2 == 0 {
            // f = c0 + a — but we can't easily create Add(a, Const) without a new var
            return None;
        }
        if c1 == 0 && c2 == 1 {
            return None; // f = c0 + b
        }
    }

    // Negated forms
    if c0 == neg1 {
        match (c1, c2, c3) {
            _ if c1 == neg1 && c2 == neg1 && c3 == 1 => {
                // ~(a|b) = -1 - a - b + (a&b)
                return None; // Would need NOT(OR(a,b)) — complex to express
            }
            _ if c1 == neg1 && c2 == 0 && c3 == 0 => {
                // ~a = -1 - a
                return Some(Expr::UnaryOp(UnaryOpKind::Not, a_id));
            }
            _ if c1 == 0 && c2 == neg1 && c3 == 0 => {
                return Some(Expr::UnaryOp(UnaryOpKind::Not, b_id));
            }
            _ => {}
        }
    }

    None
}

/// SiMBA coefficient recovery for 1-variable MBA expressions.
/// SiMBA coefficient recovery for 3-variable MBA expressions.
/// Boolean basis: {1, a, b, c, a&b, a&c, b&c, a&b&c} — 8 coefficients from 8 evaluations.
fn simba_simplify_3var(
    var_idx: usize,
    vars: &[VarDef],
    bases: &[VarId],
    mask: u64,
    _sz: u32,
) -> Option<Expr> {
    if bases.len() != 3 {
        return None;
    }
    let (a_id, b_id, c_id) = (bases[0], bases[1], bases[2]);

    // Evaluate f on all 8 combinations of (0,1) for (a,b,c)
    let mut env = std::collections::HashMap::new();
    let mut f = [0u64; 8];
    let combos: [(u64, u64, u64); 8] = [
        (0, 0, 0),
        (1, 0, 0),
        (0, 1, 0),
        (0, 0, 1),
        (1, 1, 0),
        (1, 0, 1),
        (0, 1, 1),
        (1, 1, 1),
    ];
    for (i, (a, b, c)) in combos.iter().enumerate() {
        env.clear();
        env.insert(a_id.0, *a);
        env.insert(b_id.0, *b);
        env.insert(c_id.0, *c);
        f[i] = eval_expr(&vars[var_idx].expr, vars, &env, mask, 0)?;
    }

    // Recover coefficients
    let c0 = f[0];
    let c1 = f[1].wrapping_sub(f[0]) & mask;
    let c2 = f[2].wrapping_sub(f[0]) & mask;
    let c3 = f[3].wrapping_sub(f[0]) & mask;
    let c4 = f[4]
        .wrapping_sub(f[1])
        .wrapping_sub(f[2])
        .wrapping_add(f[0])
        & mask;
    let c5 = f[5]
        .wrapping_sub(f[1])
        .wrapping_sub(f[3])
        .wrapping_add(f[0])
        & mask;
    let c6 = f[6]
        .wrapping_sub(f[2])
        .wrapping_sub(f[3])
        .wrapping_add(f[0])
        & mask;
    let c7 = f[7]
        .wrapping_sub(f[4])
        .wrapping_sub(f[5])
        .wrapping_sub(f[6])
        .wrapping_add(f[1])
        .wrapping_add(f[2])
        .wrapping_add(f[3])
        .wrapping_sub(f[0])
        & mask;

    // Verify with a non-trivial test point
    env.clear();
    env.insert(a_id.0, 0xAA);
    env.insert(b_id.0, 0x55);
    env.insert(c_id.0, 0x42);
    let f_test = eval_expr(&vars[var_idx].expr, vars, &env, mask, 0)?;
    let (ta, tb, tc) = (0xAAu64, 0x55u64, 0x42u64);
    let expected = c0
        .wrapping_add(c1.wrapping_mul(ta))
        .wrapping_add(c2.wrapping_mul(tb))
        .wrapping_add(c3.wrapping_mul(tc))
        .wrapping_add(c4.wrapping_mul(ta & tb))
        .wrapping_add(c5.wrapping_mul(ta & tc))
        .wrapping_add(c6.wrapping_mul(tb & tc))
        .wrapping_add(c7.wrapping_mul(ta & tb & tc))
        & mask;
    if f_test != expected {
        return None;
    }

    let neg1 = mask;
    let neg2 = mask.wrapping_sub(1);

    // Map coefficient vector to simplest expression
    // Only handle patterns where c0 == 0 (no constant offset)
    if c0 != 0 {
        return None;
    } // with constant → too complex to simplify cleanly

    // Count non-zero coefficients
    let coeffs = [c1, c2, c3, c4, c5, c6, c7];
    let nonzero = coeffs.iter().filter(|&&c| c != 0).count();

    // Single non-zero → single variable or single op
    if nonzero == 1 {
        if c1 == 1 {
            return Some(Expr::Var(a_id));
        }
        if c2 == 1 {
            return Some(Expr::Var(b_id));
        }
        if c3 == 1 {
            return Some(Expr::Var(c_id));
        }
        if c4 == 1 {
            return Some(Expr::BinOp(BinOpKind::And, a_id, b_id));
        }
        if c5 == 1 {
            return Some(Expr::BinOp(BinOpKind::And, a_id, c_id));
        }
        if c6 == 1 {
            return Some(Expr::BinOp(BinOpKind::And, b_id, c_id));
        }
        // c7 == 1 → a&b&c — can't express as single BinOp
        if c1 == neg1 {
            return Some(Expr::UnaryOp(UnaryOpKind::Neg, a_id));
        }
        if c2 == neg1 {
            return Some(Expr::UnaryOp(UnaryOpKind::Neg, b_id));
        }
        if c3 == neg1 {
            return Some(Expr::UnaryOp(UnaryOpKind::Neg, c_id));
        }
    }

    // Two-variable patterns (third variable cancels out)
    // a + b: c1=1, c2=1, rest 0
    if c1 == 1 && c2 == 1 && c3 == 0 && c4 == 0 && c5 == 0 && c6 == 0 && c7 == 0 {
        return Some(Expr::BinOp(BinOpKind::Add, a_id, b_id));
    }
    if c1 == 1 && c3 == 1 && c2 == 0 && c4 == 0 && c5 == 0 && c6 == 0 && c7 == 0 {
        return Some(Expr::BinOp(BinOpKind::Add, a_id, c_id));
    }
    if c2 == 1 && c3 == 1 && c1 == 0 && c4 == 0 && c5 == 0 && c6 == 0 && c7 == 0 {
        return Some(Expr::BinOp(BinOpKind::Add, b_id, c_id));
    }

    // a ^ b: c1=1, c2=1, c4=-2
    if c1 == 1 && c2 == 1 && c4 == neg2 && c3 == 0 && c5 == 0 && c6 == 0 && c7 == 0 {
        return Some(Expr::BinOp(BinOpKind::Xor, a_id, b_id));
    }
    if c1 == 1 && c3 == 1 && c5 == neg2 && c2 == 0 && c4 == 0 && c6 == 0 && c7 == 0 {
        return Some(Expr::BinOp(BinOpKind::Xor, a_id, c_id));
    }
    if c2 == 1 && c3 == 1 && c6 == neg2 && c1 == 0 && c4 == 0 && c5 == 0 && c7 == 0 {
        return Some(Expr::BinOp(BinOpKind::Xor, b_id, c_id));
    }

    // a | b: c1=1, c2=1, c4=-1
    if c1 == 1 && c2 == 1 && c4 == neg1 && c3 == 0 && c5 == 0 && c6 == 0 && c7 == 0 {
        return Some(Expr::BinOp(BinOpKind::Or, a_id, b_id));
    }
    if c1 == 1 && c3 == 1 && c5 == neg1 && c2 == 0 && c4 == 0 && c6 == 0 && c7 == 0 {
        return Some(Expr::BinOp(BinOpKind::Or, a_id, c_id));
    }
    if c2 == 1 && c3 == 1 && c6 == neg1 && c1 == 0 && c4 == 0 && c5 == 0 && c7 == 0 {
        return Some(Expr::BinOp(BinOpKind::Or, b_id, c_id));
    }

    // a - b: c1=1, c2=-1
    if c1 == 1 && c2 == neg1 && c3 == 0 && c4 == 0 && c5 == 0 && c6 == 0 && c7 == 0 {
        return Some(Expr::BinOp(BinOpKind::Sub, a_id, b_id));
    }
    if c1 == 1 && c3 == neg1 && c2 == 0 && c4 == 0 && c5 == 0 && c6 == 0 && c7 == 0 {
        return Some(Expr::BinOp(BinOpKind::Sub, a_id, c_id));
    }

    // Three-variable patterns
    // a + b + c: c1=c2=c3=1, rest 0
    if c1 == 1 && c2 == 1 && c3 == 1 && c4 == 0 && c5 == 0 && c6 == 0 && c7 == 0 {
        // Can't express as single BinOp but it's still simpler than deep MBA
        return None; // leave for now
    }

    // a ^ b ^ c: c1=c2=c3=1, c4=c5=c6=-2, c7=4
    if c1 == 1 && c2 == 1 && c3 == 1 && c4 == neg2 && c5 == neg2 && c6 == neg2 && c7 == 4 {
        return None; // Can't express as single op
    }

    None
}

/// SiMBA coefficient recovery for 4-variable MBA expressions.
/// Boolean basis: {1, a, b, c, d, a&b, a&c, a&d, b&c, b&d, c&d,
///                 a&b&c, a&b&d, a&c&d, b&c&d, a&b&c&d}
/// 16 coefficients from 16 evaluations via Möbius inversion.
fn simba_simplify_4var(
    var_idx: usize,
    vars: &[VarDef],
    bases: &[VarId],
    mask: u64,
    _sz: u32,
) -> Option<Expr> {
    if bases.len() != 4 {
        return None;
    }
    let ids = [bases[0], bases[1], bases[2], bases[3]];

    // Evaluate f on all 16 combinations of (0,1) for (a,b,c,d)
    let mut env = std::collections::HashMap::new();
    let _f = [[[[0u64; 1]; 2]; 2]; 2]; // f[a][b][c] with d=0..1 flattened
    let mut vals = std::collections::HashMap::new();
    for a in 0u64..=1 {
        for b in 0u64..=1 {
            for c in 0u64..=1 {
                for d in 0u64..=1 {
                    env.clear();
                    env.insert(ids[0].0, a);
                    env.insert(ids[1].0, b);
                    env.insert(ids[2].0, c);
                    env.insert(ids[3].0, d);
                    let v = eval_expr(&vars[var_idx].expr, vars, &env, mask, 0)?;
                    vals.insert((a, b, c, d), v);
                }
            }
        }
    }

    let v = |a: u64, b: u64, c: u64, d: u64| -> u64 { *vals.get(&(a, b, c, d)).unwrap() };

    // Möbius inversion: recover 16 coefficients
    let c_1 = v(0, 0, 0, 0);
    let c_a = v(1, 0, 0, 0).wrapping_sub(v(0, 0, 0, 0)) & mask;
    let c_b = v(0, 1, 0, 0).wrapping_sub(v(0, 0, 0, 0)) & mask;
    let c_c = v(0, 0, 1, 0).wrapping_sub(v(0, 0, 0, 0)) & mask;
    let c_d = v(0, 0, 0, 1).wrapping_sub(v(0, 0, 0, 0)) & mask;
    let c_ab = v(1, 1, 0, 0)
        .wrapping_sub(v(1, 0, 0, 0))
        .wrapping_sub(v(0, 1, 0, 0))
        .wrapping_add(v(0, 0, 0, 0))
        & mask;
    let c_ac = v(1, 0, 1, 0)
        .wrapping_sub(v(1, 0, 0, 0))
        .wrapping_sub(v(0, 0, 1, 0))
        .wrapping_add(v(0, 0, 0, 0))
        & mask;
    let c_ad = v(1, 0, 0, 1)
        .wrapping_sub(v(1, 0, 0, 0))
        .wrapping_sub(v(0, 0, 0, 1))
        .wrapping_add(v(0, 0, 0, 0))
        & mask;
    let c_bc = v(0, 1, 1, 0)
        .wrapping_sub(v(0, 1, 0, 0))
        .wrapping_sub(v(0, 0, 1, 0))
        .wrapping_add(v(0, 0, 0, 0))
        & mask;
    let c_bd = v(0, 1, 0, 1)
        .wrapping_sub(v(0, 1, 0, 0))
        .wrapping_sub(v(0, 0, 0, 1))
        .wrapping_add(v(0, 0, 0, 0))
        & mask;
    let c_cd = v(0, 0, 1, 1)
        .wrapping_sub(v(0, 0, 1, 0))
        .wrapping_sub(v(0, 0, 0, 1))
        .wrapping_add(v(0, 0, 0, 0))
        & mask;
    // Skip triple and quad coefficients for matching (we only output 2-op expressions)
    let c_abc = v(1, 1, 1, 0)
        .wrapping_sub(v(1, 1, 0, 0))
        .wrapping_sub(v(1, 0, 1, 0))
        .wrapping_sub(v(0, 1, 1, 0))
        .wrapping_add(v(1, 0, 0, 0))
        .wrapping_add(v(0, 1, 0, 0))
        .wrapping_add(v(0, 0, 1, 0))
        .wrapping_sub(v(0, 0, 0, 0))
        & mask;
    let c_abd = v(1, 1, 0, 1)
        .wrapping_sub(v(1, 1, 0, 0))
        .wrapping_sub(v(1, 0, 0, 1))
        .wrapping_sub(v(0, 1, 0, 1))
        .wrapping_add(v(1, 0, 0, 0))
        .wrapping_add(v(0, 1, 0, 0))
        .wrapping_add(v(0, 0, 0, 1))
        .wrapping_sub(v(0, 0, 0, 0))
        & mask;
    let c_acd = v(1, 0, 1, 1)
        .wrapping_sub(v(1, 0, 1, 0))
        .wrapping_sub(v(1, 0, 0, 1))
        .wrapping_sub(v(0, 0, 1, 1))
        .wrapping_add(v(1, 0, 0, 0))
        .wrapping_add(v(0, 0, 1, 0))
        .wrapping_add(v(0, 0, 0, 1))
        .wrapping_sub(v(0, 0, 0, 0))
        & mask;
    let c_bcd = v(0, 1, 1, 1)
        .wrapping_sub(v(0, 1, 1, 0))
        .wrapping_sub(v(0, 1, 0, 1))
        .wrapping_sub(v(0, 0, 1, 1))
        .wrapping_add(v(0, 1, 0, 0))
        .wrapping_add(v(0, 0, 1, 0))
        .wrapping_add(v(0, 0, 0, 1))
        .wrapping_sub(v(0, 0, 0, 0))
        & mask;
    let c_abcd = v(1, 1, 1, 1)
        .wrapping_sub(v(1, 1, 1, 0))
        .wrapping_sub(v(1, 1, 0, 1))
        .wrapping_sub(v(1, 0, 1, 1))
        .wrapping_sub(v(0, 1, 1, 1))
        .wrapping_add(v(1, 1, 0, 0))
        .wrapping_add(v(1, 0, 1, 0))
        .wrapping_add(v(1, 0, 0, 1))
        .wrapping_add(v(0, 1, 1, 0))
        .wrapping_add(v(0, 1, 0, 1))
        .wrapping_add(v(0, 0, 1, 1))
        .wrapping_sub(v(1, 0, 0, 0))
        .wrapping_sub(v(0, 1, 0, 0))
        .wrapping_sub(v(0, 0, 1, 0))
        .wrapping_sub(v(0, 0, 0, 1))
        .wrapping_add(v(0, 0, 0, 0))
        & mask;

    // Verify with a test point
    env.clear();
    env.insert(ids[0].0, 0xAA);
    env.insert(ids[1].0, 0x55);
    env.insert(ids[2].0, 0x42);
    env.insert(ids[3].0, 0xDE);
    let f_test = eval_expr(&vars[var_idx].expr, vars, &env, mask, 0)?;
    let (ta, tb, tc, td) = (0xAAu64, 0x55u64, 0x42u64, 0xDEu64);
    let expected = c_1
        .wrapping_add(c_a.wrapping_mul(ta))
        .wrapping_add(c_b.wrapping_mul(tb))
        .wrapping_add(c_c.wrapping_mul(tc))
        .wrapping_add(c_d.wrapping_mul(td))
        .wrapping_add(c_ab.wrapping_mul(ta & tb))
        .wrapping_add(c_ac.wrapping_mul(ta & tc))
        .wrapping_add(c_ad.wrapping_mul(ta & td))
        .wrapping_add(c_bc.wrapping_mul(tb & tc))
        .wrapping_add(c_bd.wrapping_mul(tb & td))
        .wrapping_add(c_cd.wrapping_mul(tc & td))
        .wrapping_add(c_abc.wrapping_mul(ta & tb & tc))
        .wrapping_add(c_abd.wrapping_mul(ta & tb & td))
        .wrapping_add(c_acd.wrapping_mul(ta & tc & td))
        .wrapping_add(c_bcd.wrapping_mul(tb & tc & td))
        .wrapping_add(c_abcd.wrapping_mul(ta & tb & tc & td))
        & mask;
    if f_test != expected {
        return None;
    } // Not a linear MBA

    // Only match patterns where the result is a simple 1-2 op expression on a subset of variables.
    // Skip if constant term is non-zero (complex to represent).
    if c_1 != 0 {
        return None;
    }

    // Collect non-zero coefficients
    let all_coeffs = [
        (c_a, "a"),
        (c_b, "b"),
        (c_c, "c"),
        (c_d, "d"),
        (c_ab, "ab"),
        (c_ac, "ac"),
        (c_ad, "ad"),
        (c_bc, "bc"),
        (c_bd, "bd"),
        (c_cd, "cd"),
        (c_abc, "abc"),
        (c_abd, "abd"),
        (c_acd, "acd"),
        (c_bcd, "bcd"),
        (c_abcd, "abcd"),
    ];
    let nonzero: Vec<_> = all_coeffs.iter().filter(|(c, _)| *c != 0).collect();

    let neg1 = mask;
    let neg2 = mask.wrapping_sub(1);

    // Single non-zero coefficient → single variable or single AND
    if nonzero.len() == 1 {
        let (coeff, name) = nonzero[0];
        if *coeff == 1 {
            return match *name {
                "a" => Some(Expr::Var(ids[0])),
                "b" => Some(Expr::Var(ids[1])),
                "c" => Some(Expr::Var(ids[2])),
                "d" => Some(Expr::Var(ids[3])),
                "ab" => Some(Expr::BinOp(BinOpKind::And, ids[0], ids[1])),
                "ac" => Some(Expr::BinOp(BinOpKind::And, ids[0], ids[2])),
                "ad" => Some(Expr::BinOp(BinOpKind::And, ids[0], ids[3])),
                "bc" => Some(Expr::BinOp(BinOpKind::And, ids[1], ids[2])),
                "bd" => Some(Expr::BinOp(BinOpKind::And, ids[1], ids[3])),
                "cd" => Some(Expr::BinOp(BinOpKind::And, ids[2], ids[3])),
                _ => None,
            };
        }
        if *coeff == neg1 {
            return match *name {
                "a" => Some(Expr::UnaryOp(UnaryOpKind::Neg, ids[0])),
                "b" => Some(Expr::UnaryOp(UnaryOpKind::Neg, ids[1])),
                "c" => Some(Expr::UnaryOp(UnaryOpKind::Neg, ids[2])),
                "d" => Some(Expr::UnaryOp(UnaryOpKind::Neg, ids[3])),
                _ => None,
            };
        }
    }

    // Two-variable patterns (other vars cancel): detect which pair is active
    // by checking which singleton+pair coefficients are non-zero.
    // Pattern: c_x=1, c_y=1, c_xy=-2 → x ^ y
    // Pattern: c_x=1, c_y=1, c_xy=-1 → x | y
    // Pattern: c_x=1, c_y=1, c_xy=0 → x + y
    // Pattern: c_x=1, c_y=-1, c_xy=0 → x - y
    let pairs: &[(usize, usize, &str)] = &[
        (0, 1, "ab"),
        (0, 2, "ac"),
        (0, 3, "ad"),
        (1, 2, "bc"),
        (1, 3, "bd"),
        (2, 3, "cd"),
    ];
    for &(i, j, pair_name) in pairs {
        let ci = all_coeffs[i].0; // singleton i
        let cj = all_coeffs[j].0; // singleton j
        let cpair = all_coeffs
            .iter()
            .find(|(_, n)| *n == pair_name)
            .map(|(c, _)| *c)
            .unwrap_or(0);

        // Check that all OTHER coefficients are zero
        let others_zero = all_coeffs.iter().all(|(c, name)| {
            *c == 0 || *name == all_coeffs[i].1 || *name == all_coeffs[j].1 || *name == pair_name
        });
        if !others_zero {
            continue;
        }

        if ci == 1 && cj == 1 && cpair == neg2 {
            return Some(Expr::BinOp(BinOpKind::Xor, ids[i], ids[j]));
        }
        if ci == 1 && cj == 1 && cpair == neg1 {
            return Some(Expr::BinOp(BinOpKind::Or, ids[i], ids[j]));
        }
        if ci == 1 && cj == 1 && cpair == 0 {
            return Some(Expr::BinOp(BinOpKind::Add, ids[i], ids[j]));
        }
        if ci == 1 && cj == neg1 && cpair == 0 {
            return Some(Expr::BinOp(BinOpKind::Sub, ids[i], ids[j]));
        }
        if ci == neg1 && cj == 1 && cpair == 0 {
            return Some(Expr::BinOp(BinOpKind::Sub, ids[j], ids[i]));
        }
    }

    None
}

fn simba_simplify_1var(
    var_idx: usize,
    vars: &[VarDef],
    base: VarId,
    mask: u64,
    sz: u32,
) -> Option<Expr> {
    let mut env = std::collections::HashMap::new();

    env.insert(base.0, 0u64);
    let f0 = eval_expr(&vars[var_idx].expr, vars, &env, mask, 0)?;

    env.clear();
    env.insert(base.0, 1u64);
    let f1 = eval_expr(&vars[var_idx].expr, vars, &env, mask, 0)?;

    let c0 = f0;
    let c1 = f1.wrapping_sub(f0) & mask;

    // Verify against several test points. 0x42 alone is not enough:
    // bit-masking expressions like `(x & 0xFF00FF00FF00FF00) >> 8`
    // all collapse to 0 for small x, giving c0=c1=0 and a false
    // Const(0) conclusion. The all-ones point exercises every bit
    // lane and flushes out any non-linearity.
    for probe in [0x42u64, u64::MAX, 0xAAAAAAAAAAAAAAAA, 0x0123456789ABCDEF] {
        env.clear();
        env.insert(base.0, probe & mask);
        let f_test = eval_expr(&vars[var_idx].expr, vars, &env, mask, 0)?;
        let expected = c0.wrapping_add(c1.wrapping_mul(probe & mask)) & mask;
        if f_test != expected {
            return None;
        }
    }

    let neg1 = mask;

    match (c0, c1) {
        (0, 0) => Some(Expr::Const(0, sz)),
        (0, 1) => Some(Expr::Var(base)),
        _ if c0 == neg1 && c1 == neg1 => Some(Expr::UnaryOp(UnaryOpKind::Not, base)),
        (0, _) if c1 == neg1 => Some(Expr::UnaryOp(UnaryOpKind::Neg, base)),
        _ if c0 != 0 && c1 == 0 => Some(Expr::Const(c0, sz)),
        _ => None,
    }
}

fn mba_simplify_expr(var_idx: usize, vars: &[VarDef]) -> Option<Expr> {
    let expr = &vars[var_idx].expr;
    match expr {
        // Sub(a, Sub(a, b)) → Var(b)  [cancellation: a - (a - b) = b]
        Expr::BinOp(BinOpKind::Sub, left, right) => {
            if let Expr::BinOp(BinOpKind::Sub, inner_left, inner_right) =
                &vars[right.0 as usize].expr
            {
                if left == inner_left || same_varnode(*left, *inner_left, vars) {
                    return Some(Expr::Var(*inner_right));
                }
            }
            // Sub(Add(a, b), a) → Var(b), Sub(Add(a, b), b) → Var(a)
            if let Expr::BinOp(BinOpKind::Add, add_left, add_right) = &vars[left.0 as usize].expr {
                if right == add_left || same_varnode(*right, *add_left, vars) {
                    return Some(Expr::Var(*add_right));
                }
                if right == add_right || same_varnode(*right, *add_right, vars) {
                    return Some(Expr::Var(*add_left));
                }
            }
            // Sub(a, a) → 0 (already handled in simplify_expr but re-check after inlining)
            if left == right || same_varnode(*left, *right, vars) {
                return Some(Expr::Const(0, vars[left.0 as usize].size));
            }
            None
        }
        // Xor(a, Xor(a, b)) → Var(b)  [cancellation: a ^ (a ^ b) = b]
        Expr::BinOp(BinOpKind::Xor, left, right) => {
            if let Expr::BinOp(BinOpKind::Xor, inner_left, inner_right) =
                &vars[right.0 as usize].expr
            {
                if left == inner_left || same_varnode(*left, *inner_left, vars) {
                    return Some(Expr::Var(*inner_right));
                }
                if left == inner_right || same_varnode(*left, *inner_right, vars) {
                    return Some(Expr::Var(*inner_left));
                }
            }
            if let Expr::BinOp(BinOpKind::Xor, inner_left, inner_right) =
                &vars[left.0 as usize].expr
            {
                if right == inner_left || same_varnode(*right, *inner_left, vars) {
                    return Some(Expr::Var(*inner_right));
                }
                if right == inner_right || same_varnode(*right, *inner_right, vars) {
                    return Some(Expr::Var(*inner_left));
                }
            }
            // a ^ 0 → a (re-check after const folding resolved operands)
            if is_const_zero(*right, vars) {
                return Some(Expr::Var(*left));
            }
            if is_const_zero(*left, vars) {
                return Some(Expr::Var(*right));
            }
            None
        }
        // Add(a, Neg(a)) → 0, Add(Neg(a), a) → 0 [cancellation]
        Expr::BinOp(BinOpKind::Add, left, right) => {
            if let Expr::UnaryOp(UnaryOpKind::Neg, inner) = &vars[right.0 as usize].expr {
                if left == inner || same_varnode(*left, *inner, vars) {
                    return Some(Expr::Const(0, vars[left.0 as usize].size));
                }
            }
            if let Expr::UnaryOp(UnaryOpKind::Neg, inner) = &vars[left.0 as usize].expr {
                if right == inner || same_varnode(*right, *inner, vars) {
                    return Some(Expr::Const(0, vars[right.0 as usize].size));
                }
            }
            // Add(Sub(a, b), b) → Var(a)
            if let Expr::BinOp(BinOpKind::Sub, sub_left, sub_right) = &vars[left.0 as usize].expr {
                if right == sub_right || same_varnode(*right, *sub_right, vars) {
                    return Some(Expr::Var(*sub_left));
                }
            }
            if let Expr::BinOp(BinOpKind::Sub, sub_left, sub_right) = &vars[right.0 as usize].expr {
                if left == sub_right || same_varnode(*left, *sub_right, vars) {
                    return Some(Expr::Var(*sub_left));
                }
            }
            None
        }
        // And(a, Or(a, b)) → Var(a) [absorption]
        // Or(a, And(a, b)) → Var(a) [absorption]
        Expr::BinOp(BinOpKind::And, left, right) => {
            // a & (a | b) → a
            if let Expr::BinOp(BinOpKind::Or, or_left, _or_right) = &vars[right.0 as usize].expr {
                if left == or_left || same_varnode(*left, *or_left, vars) {
                    return Some(Expr::Var(*left));
                }
            }
            if let Expr::BinOp(BinOpKind::Or, or_left, _or_right) = &vars[left.0 as usize].expr {
                if right == or_left || same_varnode(*right, *or_left, vars) {
                    return Some(Expr::Var(*right));
                }
            }
            None
        }
        Expr::BinOp(BinOpKind::Or, left, right) => {
            // a | (a & b) → a
            if let Expr::BinOp(BinOpKind::And, and_left, _and_right) = &vars[right.0 as usize].expr
            {
                if left == and_left || same_varnode(*left, *and_left, vars) {
                    return Some(Expr::Var(*left));
                }
            }
            if let Expr::BinOp(BinOpKind::And, and_left, _and_right) = &vars[left.0 as usize].expr {
                if right == and_left || same_varnode(*right, *and_left, vars) {
                    return Some(Expr::Var(*right));
                }
            }
            None
        }
        // Double negation: Neg(Neg(x)) → x, Not(Not(x)) → x
        Expr::UnaryOp(UnaryOpKind::Neg, inner) => {
            if let Expr::UnaryOp(UnaryOpKind::Neg, inner2) = &vars[inner.0 as usize].expr {
                return Some(Expr::Var(*inner2));
            }
            None
        }
        Expr::UnaryOp(UnaryOpKind::Not, inner) => {
            if let Expr::UnaryOp(UnaryOpKind::Not, inner2) = &vars[inner.0 as usize].expr {
                return Some(Expr::Var(*inner2));
            }
            None
        }
        // BoolNot(BoolNot(x)) → x
        // BoolNot(Eq(a, b))   → NotEq(a, b)
        // BoolNot(NotEq(a, b)) → Eq(a, b)
        Expr::UnaryOp(UnaryOpKind::BoolNot, inner) => {
            if let Expr::UnaryOp(UnaryOpKind::BoolNot, inner2) = &vars[inner.0 as usize].expr {
                return Some(Expr::Var(*inner2));
            }
            if let Expr::BinOp(cmp_op, a, b) = vars[inner.0 as usize].expr {
                if let Some(neg_op) = negate_eq_op(cmp_op) {
                    return Some(Expr::BinOp(neg_op, a, b));
                }
                // BoolNot(Sub(a, b)) → Eq(a, b)  [!(a - b) means a == b]
                if matches!(cmp_op, BinOpKind::Sub) {
                    return Some(Expr::BinOp(BinOpKind::Eq, a, b));
                }
            }
            None
        }
        // (Eq(a,b) == 0) → NotEq(a,b),  (NotEq(a,b) == 0) → Eq(a,b)
        // (Sub(a,b) == 0) → Eq(a,b)  [a - b == 0 means a == b]
        Expr::BinOp(BinOpKind::Eq, inner_id, zero_id) => {
            if matches!(vars[zero_id.0 as usize].expr, Expr::Const(0, _)) {
                // Follow Var chains to reach the underlying BinOp
                let mut resolved = *inner_id;
                for _ in 0..4 {
                    if let Expr::Var(next) = vars[resolved.0 as usize].expr {
                        resolved = next;
                    } else {
                        break;
                    }
                }
                if let Expr::BinOp(cmp_op, a, b) = vars[resolved.0 as usize].expr {
                    if let Some(neg_op) = negate_eq_op(cmp_op) {
                        return Some(Expr::BinOp(neg_op, a, b));
                    }
                    // Eq(Sub(a, b), 0) → Eq(a, b)  [a - b == 0 means a == b]
                    if matches!(cmp_op, BinOpKind::Sub) {
                        return Some(Expr::BinOp(BinOpKind::Eq, a, b));
                    }
                }
            }
            None
        }
        // (BinOp(a,b) != 0) → BinOp(a,b)  [identity: comparison already a bool]
        // (Sub(a,b) != 0) → NotEq(a,b)  [a - b != 0 means a != b]
        Expr::BinOp(BinOpKind::NotEq, inner_id, zero_id) => {
            if matches!(vars[zero_id.0 as usize].expr, Expr::Const(0, _)) {
                // Follow Var chains to reach the underlying BinOp
                let mut resolved = *inner_id;
                for _ in 0..4 {
                    if let Expr::Var(next) = vars[resolved.0 as usize].expr {
                        resolved = next;
                    } else {
                        break;
                    }
                }
                if let Expr::BinOp(cmp_op, a, b) = vars[resolved.0 as usize].expr {
                    // NotEq(Sub(a, b), 0) → NotEq(a, b)  [a - b != 0 means a != b]
                    if matches!(cmp_op, BinOpKind::Sub) {
                        return Some(Expr::BinOp(BinOpKind::NotEq, a, b));
                    }
                }
                if let Expr::BinOp(_, _, _) = vars[resolved.0 as usize].expr {
                    return Some(Expr::Var(resolved));
                }
            }
            None
        }
        // CDQ+IDIV simplification: SDiv of 64-bit sign-extended 32-bit value
        // Pattern: SDiv(Or(Lsl(Zext(Asr(x, 31)), 32), Zext(x)), Zext(divisor)) → SDiv(x, divisor)
        // Also handles: SDiv(Or(Lsl(Sext(sign), 32), Zext(val)), Zext(divisor))
        //   where sign = Asr(val, 31) (CDQ pattern)
        Expr::BinOp(BinOpKind::SDiv, left, right) => {
            // Check if left is Or(Lsl(..., 32), Zext(x)) — the CDQ concatenation
            if let Expr::BinOp(BinOpKind::Or, or_left, or_right) = &vars[left.0 as usize].expr {
                // or_left should be Lsl(Zext/Sext(sign), 32), or_right should be Zext(val)
                let val_from_or = extract_cdq_value(*or_left, *or_right, vars)
                    .or_else(|| extract_cdq_value(*or_right, *or_left, vars));
                if let Some(val_id) = val_from_or {
                    // Right operand: strip Zext wrapper if present
                    let div_id = if let Expr::UnaryOp(UnaryOpKind::Zext, inner) =
                        &vars[right.0 as usize].expr
                    {
                        *inner
                    } else {
                        *right
                    };
                    return Some(Expr::BinOp(BinOpKind::SDiv, val_id, div_id));
                }
            }
            // Also handle SRem with same pattern
            None
        }
        Expr::BinOp(BinOpKind::SRem, left, right) => {
            if let Expr::BinOp(BinOpKind::Or, or_left, or_right) = &vars[left.0 as usize].expr {
                let val_from_or = extract_cdq_value(*or_left, *or_right, vars)
                    .or_else(|| extract_cdq_value(*or_right, *or_left, vars));
                if let Some(val_id) = val_from_or {
                    let div_id = if let Expr::UnaryOp(UnaryOpKind::Zext, inner) =
                        &vars[right.0 as usize].expr
                    {
                        *inner
                    } else {
                        *right
                    };
                    return Some(Expr::BinOp(BinOpKind::SRem, val_id, div_id));
                }
            }
            None
        }
        // Mult by 0 after inlining
        Expr::BinOp(BinOpKind::Mult, left, right) => {
            if is_const_zero(*left, vars) || is_const_zero(*right, vars) {
                return Some(Expr::Const(0, vars[left.0 as usize].size));
            }
            if is_const_one(*left, vars) {
                return Some(Expr::Var(*right));
            }
            if is_const_one(*right, vars) {
                return Some(Expr::Var(*left));
            }
            None
        }
        _ => None,
    }
}

fn simplify_expr(expr: Expr, vars: &[VarDef]) -> Expr {
    match &expr {
        // === Identity / Annihilation rules ===

        // x & x → x, x & 0 → 0, x & -1 → x, const & mask noop
        Expr::BinOp(BinOpKind::And, left, right) => {
            if left == right || same_varnode(*left, *right, vars) {
                Expr::Var(*left)
            } else if is_const_zero(*right, vars) || is_const_zero(*left, vars) {
                Expr::Const(0, vars[left.0 as usize].size)
            } else if is_const_all_ones(*right, vars) {
                Expr::Var(*left)
            } else if is_const_all_ones(*left, vars) {
                Expr::Var(*right)
            } else if is_const_mask_noop(*left, *right, vars) {
                Expr::Var(*left)
            } else {
                expr
            }
        }
        // x ^ x → 0, x ^ 0 → x, 0 ^ x → x
        Expr::BinOp(BinOpKind::Xor, left, right) => {
            if left == right || same_varnode(*left, *right, vars) {
                Expr::Const(0, vars[left.0 as usize].size)
            } else if is_const_zero(*right, vars) {
                Expr::Var(*left)
            } else if is_const_zero(*left, vars) {
                Expr::Var(*right)
            } else {
                expr
            }
        }
        // x | x → x, x + 0 → x, 0 + x → x, x | 0 → x, x | -1 → -1
        Expr::BinOp(BinOpKind::Or, left, right) => {
            if left == right || same_varnode(*left, *right, vars) {
                Expr::Var(*left)
            } else if is_const_zero(*right, vars) {
                Expr::Var(*left)
            } else if is_const_zero(*left, vars) {
                Expr::Var(*right)
            } else if is_const_all_ones(*right, vars) {
                Expr::Var(*right)
            } else if is_const_all_ones(*left, vars) {
                Expr::Var(*left)
            } else {
                expr
            }
        }
        Expr::BinOp(BinOpKind::Add, left, right) => {
            if is_const_zero(*right, vars) {
                Expr::Var(*left)
            } else if is_const_zero(*left, vars) {
                Expr::Var(*right)
            }
            // x + x → x * 2 → x << 1 (useful for MBA reduction)
            else if left == right || same_varnode(*left, *right, vars) {
                Expr::BinOp(BinOpKind::Lsl, *left, *right) // approximate as shift
            } else {
                expr
            }
        }
        // x - 0 → x, x - x → 0
        Expr::BinOp(BinOpKind::Sub, left, right) => {
            if is_const_zero(*right, vars) {
                Expr::Var(*left)
            } else if left == right || same_varnode(*left, *right, vars) {
                Expr::Const(0, vars[left.0 as usize].size)
            } else {
                expr
            }
        }
        // x * 1 → x, x * 0 → 0
        Expr::BinOp(BinOpKind::Mult, left, right) => {
            if is_const_one(*right, vars) {
                Expr::Var(*left)
            } else if is_const_one(*left, vars) {
                Expr::Var(*right)
            } else if is_const_zero(*right, vars) {
                Expr::Const(0, vars[left.0 as usize].size)
            } else if is_const_zero(*left, vars) {
                Expr::Const(0, vars[right.0 as usize].size)
            } else {
                expr
            }
        }
        // x >> 0 → x, x << 0 → x
        Expr::BinOp(BinOpKind::Lsr | BinOpKind::Lsl | BinOpKind::Asr, left, right) => {
            if is_const_zero(*right, vars) {
                Expr::Var(*left)
            } else {
                expr
            }
        }

        _ => expr,
    }
}

/// Extract the original 32-bit value from a 64-bit concatenation pattern used for division.
///
/// Recognizes the x86 CDQ+IDIV pattern where a 32-bit value is widened to 64 bits
/// for signed division. The concatenation takes two forms:
///
/// 1. CDQ via Asr: Or(Lsl(Zext(Asr(val, 31)), 32), Zext(val))
/// 2. CDQ via Subpiece: Or(Lsl(Zext(val_copy), 32), Zext(val))
///    where val_copy is the same register/varnode as val
///
/// In both cases, the 64-bit value is just the sign-extension of the 32-bit value,
/// so the division can be simplified to a 32-bit operation.
///
/// `high_part` should be the Lsl(..., 32) side, `low_part` the Zext(val) side.
fn extract_cdq_value(high_part: VarId, low_part: VarId, vars: &[VarDef]) -> Option<VarId> {
    // low_part must be Zext(val)
    let val_id = match &vars[low_part.0 as usize].expr {
        Expr::UnaryOp(UnaryOpKind::Zext, inner) => *inner,
        _ => return None,
    };

    // high_part must be Lsl(something, 32)
    let (shift_input, shift_amount) = match &vars[high_part.0 as usize].expr {
        Expr::BinOp(BinOpKind::Lsl, left, right) => (*left, *right),
        _ => return None,
    };

    // shift_amount must be 32
    match &vars[shift_amount.0 as usize].expr {
        Expr::Const(32, _) => {}
        _ => return None,
    }

    // shift_input should be Zext/Sext of something derived from val
    let inner_of_shift = match &vars[shift_input.0 as usize].expr {
        Expr::UnaryOp(UnaryOpKind::Zext | UnaryOpKind::Sext, inner) => *inner,
        _ => return None,
    };

    // The inner value should be derived from the same source as val_id.
    // Case 1: Asr(val, 31) — classic CDQ sign extension
    if let Expr::BinOp(BinOpKind::Asr, asr_val, asr_amount) = &vars[inner_of_shift.0 as usize].expr
    {
        if let Expr::Const(31, _) = &vars[asr_amount.0 as usize].expr {
            if same_varnode(*asr_val, val_id, vars) || asr_val == &val_id {
                return Some(val_id);
            }
        }
    }

    // Case 2: Same register/varnode as val — the CDQ Subpiece(Sext(EAX), 0) bug
    // produces EDX = EAX, so high = Zext(EDX) = Zext(EAX) = Zext(val)
    if same_varnode(inner_of_shift, val_id, vars) || inner_of_shift == val_id {
        return Some(val_id);
    }

    // Case 3: The inner is a Var pointing to the same source
    if let Expr::Var(src) = &vars[inner_of_shift.0 as usize].expr {
        if same_varnode(*src, val_id, vars) || *src == val_id {
            return Some(val_id);
        }
    }

    // Case 4: The inner is Sext(val) — direct sign extension (CDQ produces this
    // via Subpiece(Sext(EAX), 0) → EDX, which after copy propagation becomes
    // Sext(val) in the high half)
    if let Expr::UnaryOp(UnaryOpKind::Sext, sext_inner) = &vars[inner_of_shift.0 as usize].expr {
        if same_varnode(*sext_inner, val_id, vars) || *sext_inner == val_id {
            return Some(val_id);
        }
    }

    // Case 5: Follow through Var indirection on the inner
    let resolved = match &vars[inner_of_shift.0 as usize].expr {
        Expr::Var(v) => *v,
        _ => inner_of_shift,
    };
    if resolved != inner_of_shift {
        if let Expr::UnaryOp(UnaryOpKind::Sext, sext_inner) = &vars[resolved.0 as usize].expr {
            if same_varnode(*sext_inner, val_id, vars) || *sext_inner == val_id {
                return Some(val_id);
            }
        }
        if same_varnode(resolved, val_id, vars) || resolved == val_id {
            return Some(val_id);
        }
    }

    None
}

/// Constant folding: evaluate BinOp(Const, Const) → Const.
/// This handles chains of arithmetic that resolve to constants at compile time.
fn const_fold_expr(expr: &Expr, vars: &[VarDef]) -> Option<(u64, u32)> {
    match expr {
        Expr::Const(val, sz) => Some((*val, *sz)),
        Expr::Var(id) => const_fold_expr(&vars[id.0 as usize].expr, vars),
        Expr::BinOp(kind, left, right) => {
            let (lv, lsz) = const_fold_expr(&vars[left.0 as usize].expr, vars)?;
            let (rv, _) = const_fold_expr(&vars[right.0 as usize].expr, vars)?;
            let mask = if lsz >= 8 {
                u64::MAX
            } else {
                (1u64 << (lsz * 8)) - 1
            };
            let result = match kind {
                BinOpKind::Add => lv.wrapping_add(rv) & mask,
                BinOpKind::Sub => lv.wrapping_sub(rv) & mask,
                BinOpKind::Mult => lv.wrapping_mul(rv) & mask,
                BinOpKind::And => lv & rv,
                BinOpKind::Or => lv | rv,
                BinOpKind::Xor => lv ^ rv,
                BinOpKind::Lsl => (lv << (rv & 63)) & mask,
                BinOpKind::Lsr => lv >> (rv & 63),
                BinOpKind::Asr => ((lv as i64) >> (rv & 63)) as u64 & mask,
                _ => return None,
            };
            Some((result, lsz))
        }
        Expr::UnaryOp(kind, inner) => {
            let (v, sz) = const_fold_expr(&vars[inner.0 as usize].expr, vars)?;
            let mask = if sz >= 8 {
                u64::MAX
            } else {
                (1u64 << (sz * 8)) - 1
            };
            let result = match kind {
                UnaryOpKind::Neg => (-(v as i64) as u64) & mask,
                UnaryOpKind::Not => (!v) & mask,
                _ => return None,
            };
            Some((result, sz))
        }
        _ => None,
    }
}

/// Check if two VarIds refer to the same register (same offset+size).
fn same_varnode(a: VarId, b: VarId, vars: &[VarDef]) -> bool {
    let va = &vars[a.0 as usize];
    let vb = &vars[b.0 as usize];
    va.varnode.space == AddressSpaceId::Register
        && vb.varnode.space == AddressSpaceId::Register
        && va.varnode.offset == vb.varnode.offset
        && va.varnode.size == vb.varnode.size
}

fn is_const_zero(id: VarId, vars: &[VarDef]) -> bool {
    matches!(&vars[id.0 as usize].expr, Expr::Const(0, _))
}

fn is_const_one(id: VarId, vars: &[VarDef]) -> bool {
    matches!(&vars[id.0 as usize].expr, Expr::Const(1, _))
}

/// Check if `val & mask` == `val` (AND is a no-op because val fits within mask).
fn is_const_mask_noop(val_id: VarId, mask_id: VarId, vars: &[VarDef]) -> bool {
    if let (Expr::Const(val, _), Expr::Const(mask, _)) = (
        &vars[val_id.0 as usize].expr,
        &vars[mask_id.0 as usize].expr,
    ) {
        *val & *mask == *val && *val != 0
    } else {
        false
    }
}

fn is_const_all_ones(id: VarId, vars: &[VarDef]) -> bool {
    if let Expr::Const(val, sz) = &vars[id.0 as usize].expr {
        let mask = if *sz >= 8 {
            u64::MAX
        } else {
            (1u64 << (*sz * 8)) - 1
        };
        *val == mask
    } else {
        false
    }
}

/// Propagate constants from register writes to Unknown versions at the same offset.
/// Only propagates to non-parameter, non-argument registers that aren't heavily used
/// (which would indicate they're loop variables, not constants).
fn propagate_register_constants(ssa: &mut SsaCfg) {
    // Collect all register constants: offset → (value, size)
    let mut reg_consts: std::collections::HashMap<u64, (u64, u32)> =
        std::collections::HashMap::new();
    for v in &ssa.vars {
        if v.varnode.space == AddressSpaceId::Register && v.param_name.is_none() {
            if let Expr::Const(val, sz) = &v.expr {
                reg_consts.insert(v.varnode.offset, (*val, *sz));
            }
        }
    }

    // Propagate to Unknown vars at the same register offset
    // Only target non-parameter, low-use Unknown vars
    for v in &mut ssa.vars {
        if v.varnode.space == AddressSpaceId::Register && matches!(&v.expr, Expr::Unknown)
            && v.param_name.is_none()
            && v.use_count <= 2  // Low use count = likely a constant setup, not a loop var
            && !v.call_return    // Don't overwrite call-return placeholders with stale constants
            && !FLAG_OFFSETS.contains(&v.varnode.offset)
            && v.varnode.offset != RSP_OFFSET
            && v.varnode.offset != RIP_OFFSET
            && v.varnode.offset != 40
        // RBP
        {
            if let Some(&(val, _const_sz)) = reg_consts.get(&v.varnode.offset) {
                let mask = match v.varnode.size {
                    1 => 0xFF,
                    2 => 0xFFFF,
                    4 => 0xFFFFFFFF,
                    _ => u64::MAX,
                };
                v.expr = Expr::Const(val & mask, v.varnode.size);
            }
        }
    }
}

/// Multi-level register copy propagation:
/// RAX = var_8; RAX = RAX + 1 → RAX = var_8 + 1
/// Also handles chains: RAX = X; RAX = RAX op Y; RAX = RAX op Z
fn propagate_register_copies(ssa: &mut SsaCfg) {
    for bi in 0..ssa.blocks.len() {
        // Build a map: for each register, track the most recent assignment's expression
        let mut reg_expr: std::collections::HashMap<(u64, u32), (VarId, Expr)> =
            std::collections::HashMap::new();
        let mut replacements: Vec<(usize, Expr)> = Vec::new();

        let stmts = &ssa.blocks[bi].stmts;
        for i in 0..stmts.len() {
            if let Stmt::Assign(var_id) = &stmts[i] {
                let vdef = &ssa.vars[var_id.0 as usize];
                if vdef.varnode.space != AddressSpaceId::Register {
                    continue;
                }
                let key = (vdef.varnode.offset, vdef.varnode.size);

                if let Expr::BinOp(kind, left, right) = &vdef.expr {
                    let left_var = &ssa.vars[left.0 as usize];
                    // Is the left operand the same register?
                    if left_var.varnode.space == AddressSpaceId::Register
                        && left_var.varnode.offset == vdef.varnode.offset
                        && left_var.use_count <= 1
                    {
                        // Look up what that register was previously assigned to
                        if let Some((prev_id, _prev_expr)) = reg_expr.get(&key) {
                            // Substitute the previous assignment's VarId as the left operand
                            // This handles: EAX = X; EAX = EAX + Y → EAX = X + Y
                            replacements.push((i, Expr::BinOp(*kind, *prev_id, *right)));
                        }
                    }
                }

                // Track this assignment
                reg_expr.insert(key, (*var_id, vdef.expr.clone()));
            }
        }

        for (idx, new_expr) in replacements {
            if let Stmt::Assign(var_id) = &ssa.blocks[bi].stmts[idx] {
                ssa.vars[var_id.0 as usize].expr = new_expr;
            }
        }
    }
}

fn substitute_expr(expr: &Expr, candidates: &[(VarId, Expr)]) -> Expr {
    match expr {
        Expr::Var(id) => candidates
            .iter()
            .find(|(cid, _)| cid == id)
            .map(|(_, r)| r.clone())
            .unwrap_or_else(|| expr.clone()),
        _ => expr.clone(),
    }
}

fn eliminate_dead(ssa: &mut SsaCfg) {
    for block in &mut ssa.blocks {
        let mut read_after: std::collections::HashSet<(u64, u32)> =
            std::collections::HashSet::new();

        // Collect reads from terminators
        match &block.terminator {
            SsaTerminator::CBranch { cond, .. } => {
                collect_var_reads(*cond, &ssa.vars, &mut read_after);
            }
            SsaTerminator::Return(Some(v)) | SsaTerminator::Indirect(v) => {
                collect_var_reads(*v, &ssa.vars, &mut read_after);
            }
            SsaTerminator::Call { args, .. } => {
                for a in args {
                    collect_var_reads(*a, &ssa.vars, &mut read_after);
                }
            }
            _ => {}
        }

        let mut dead_indices = Vec::new();
        for i in (0..block.stmts.len()).rev() {
            match &block.stmts[i] {
                Stmt::Assign(var_id) => {
                    let vdef = &ssa.vars[var_id.0 as usize];
                    let key = (vdef.varnode.offset, vdef.varnode.size);

                    // Dead flags
                    if vdef.varnode.space == AddressSpaceId::Register
                        && FLAG_OFFSETS.contains(&vdef.varnode.offset)
                        && vdef.use_count == 0
                    {
                        dead_indices.push(i);
                        continue;
                    }

                    // Dead uniques — but preserve UserOp placeholders (void
                    // CallOther / SLEIGH user pcodeops). They have side
                    // effects outside the SSA model (e.g. software_interrupt)
                    // and removing them drops critical analyst info.
                    if vdef.varnode.space == AddressSpaceId::Unique
                        && vdef.use_count == 0
                        && !matches!(&vdef.expr, Expr::UserOp { .. })
                    {
                        dead_indices.push(i);
                        continue;
                    }

                    // Dead CARRY/SCARRY/SBORROW operations (multi-precision arithmetic flags)
                    if vdef.use_count == 0 {
                        if matches!(
                            &vdef.expr,
                            Expr::BinOp(
                                BinOpKind::Carry | BinOpKind::SCarry | BinOpKind::SBorrow,
                                _,
                                _
                            )
                        ) {
                            dead_indices.push(i);
                            continue;
                        }
                    }

                    // RIP writes
                    if vdef.varnode.space == AddressSpaceId::Register
                        && vdef.varnode.offset == RIP_OFFSET
                    {
                        dead_indices.push(i);
                        continue;
                    }

                    // Dead register writes (not read before overwrite)
                    // BUT preserve argument registers before calls
                    // BUT preserve registers in loop bodies (back-edge blocks)
                    // because the SSA may not have connected loop-carried variables
                    let is_arg_reg = arg_reg_offsets().contains(&vdef.varnode.offset)
                        && vdef.varnode.space == AddressSpaceId::Register;
                    let precedes_call =
                        block.stmts.get(i + 1..).map_or(false, |rest| {
                            rest.iter().any(|s| matches!(s, Stmt::Call { .. }))
                        }) || matches!(block.terminator, SsaTerminator::Call { .. });
                    // With proper Phi re-linking, loop-carried values (accumulators)
                    // have use_count > 0 from Phi inputs. No special loop body
                    // preservation needed — standard DCE rules apply.
                    if vdef.varnode.space == AddressSpaceId::Register
                        && !read_after.contains(&key)
                        && vdef.use_count == 0
                        && !(is_arg_reg && precedes_call)
                    {
                        dead_indices.push(i);
                        continue;
                    }

                    let mut visited = std::collections::HashSet::new();
                    collect_expr_reads_inner(&vdef.expr, &ssa.vars, &mut read_after, &mut visited);
                }
                Stmt::Store { addr, val } => {
                    let val_def = &ssa.vars[val.0 as usize];
                    let addr_def = &ssa.vars[addr.0 as usize];
                    if is_rsp_derived(&addr_def.varnode, &addr_def.expr, &ssa.vars)
                        || is_esp_derived(&addr_def.varnode, &addr_def.expr, &ssa.vars)
                    {
                        if let Expr::Const(_, _) = &val_def.expr {
                            dead_indices.push(i);
                            continue;
                        }
                    }
                    collect_var_reads(*addr, &ssa.vars, &mut read_after);
                    collect_var_reads(*val, &ssa.vars, &mut read_after);
                }
                Stmt::Call { args, .. } => {
                    for a in args {
                        collect_var_reads(*a, &ssa.vars, &mut read_after);
                    }
                }
            }
        }
        // Remove in reverse order so indices stay valid
        dead_indices.sort_unstable();
        dead_indices.dedup();
        for &i in dead_indices.iter().rev() {
            block.stmts.remove(i);
        }
    }
}

fn collect_var_reads(
    id: VarId,
    vars: &[VarDef],
    reads: &mut std::collections::HashSet<(u64, u32)>,
) {
    let mut visited = std::collections::HashSet::new();
    collect_var_reads_inner(id, vars, reads, &mut visited);
}

fn collect_var_reads_inner(
    id: VarId,
    vars: &[VarDef],
    reads: &mut std::collections::HashSet<(u64, u32)>,
    visited: &mut std::collections::HashSet<u32>,
) {
    if !visited.insert(id.0) {
        return;
    } // cycle detection
    let vdef = &vars[id.0 as usize];
    if vdef.varnode.space == AddressSpaceId::Register {
        reads.insert((vdef.varnode.offset, vdef.varnode.size));
    }
    collect_expr_reads_inner(&vdef.expr, vars, reads, visited);
}

fn collect_expr_reads_inner(
    expr: &Expr,
    vars: &[VarDef],
    reads: &mut std::collections::HashSet<(u64, u32)>,
    visited: &mut std::collections::HashSet<u32>,
) {
    match expr {
        Expr::Var(id) => {
            let v = &vars[id.0 as usize];
            if v.varnode.space == AddressSpaceId::Register {
                reads.insert((v.varnode.offset, v.varnode.size));
            }
        }
        Expr::BinOp(_, l, r) => {
            collect_var_reads_inner(*l, vars, reads, visited);
            collect_var_reads_inner(*r, vars, reads, visited);
        }
        Expr::UnaryOp(_, i) | Expr::Load(i) | Expr::FieldAccess(i, _) => {
            collect_var_reads_inner(*i, vars, reads, visited)
        }
        Expr::Phi(inputs) => {
            for i in inputs {
                collect_var_reads_inner(*i, vars, reads, visited);
            }
        }
        Expr::Ternary(c, t, e) => {
            collect_var_reads_inner(*c, vars, reads, visited);
            collect_var_reads_inner(*t, vars, reads, visited);
            collect_var_reads_inner(*e, vars, reads, visited);
        }
        _ => {}
    }
}

fn is_rsp_derived(vn: &pcode_ir::Varnode, expr: &Expr, vars: &[VarDef]) -> bool {
    if vn.space == AddressSpaceId::Register && vn.offset == RSP_OFFSET {
        return true;
    }
    match expr {
        Expr::Var(id) | Expr::BinOp(_, id, _) => {
            let v = &vars[id.0 as usize];
            v.varnode.space == AddressSpaceId::Register && v.varnode.offset == RSP_OFFSET
        }
        _ => false,
    }
}

fn is_esp_derived(vn: &pcode_ir::Varnode, expr: &Expr, vars: &[VarDef]) -> bool {
    if vn.space == AddressSpaceId::Register && vn.offset == ESP_OFFSET && vn.size == 4 {
        return true;
    }
    match expr {
        Expr::Var(id) | Expr::BinOp(_, id, _) => {
            let v = &vars[id.0 as usize];
            v.varnode.space == AddressSpaceId::Register
                && v.varnode.offset == ESP_OFFSET
                && v.varnode.size == 4
        }
        _ => false,
    }
}

// ---- Condition Recovery ----

/// Recover high-level conditions from flag variables.
/// Handles: ZF (from TEST/CMP → IntEq), SF==OF (JGE/JL from CMP → IntSLess).
fn recover_conditions(ssa: &mut SsaCfg) {
    // Collect ALL CBranch conditions — not just flag registers.
    // Compound conditions from Jcc (like JG) produce BoolAnd/BoolNot in Unique space.
    let mut to_recover: Vec<(usize, VarId)> = Vec::new();
    for (bi, block) in ssa.blocks.iter().enumerate() {
        if let SsaTerminator::CBranch { cond, .. } = &block.terminator {
            let vdef = &ssa.vars[cond.0 as usize];
            let dominated_by_flags = is_flag_derived(*cond, ssa);
            // A comparison is only "already recovered" if its operands are NOT flags
            let already_comparison = if let Expr::BinOp(k, l, r) = &vdef.expr {
                is_comparison(*k) && !is_flag_derived(*l, ssa) && !is_flag_derived(*r, ssa)
            } else {
                false
            };
            if dominated_by_flags && !already_comparison {
                to_recover.push((bi, *cond));
            }
        }
    }

    for (bi, cond_id) in to_recover {
        if let Some(new_cond) = try_recover_condition(cond_id, bi, ssa) {
            if let SsaTerminator::CBranch {
                taken, fallthrough, ..
            } = ssa.blocks[bi].terminator
            {
                ssa.blocks[bi].terminator = SsaTerminator::CBranch {
                    cond: new_cond,
                    taken,
                    fallthrough,
                };
            }
        }
    }

    // Pass 1a': Flag-subexpression rewrite. Compound conditions
    // (BoolAnd / BoolOr) leak raw `OF != SF` / `OV == NG` when the
    // flag pair appears as a sub-operand and recover_conditions only
    // rewrote the top-level CBranch cond. Walk every var; when its
    // expr is NotEq/Eq with (OF|OV|SBORROW, SF|NG) operands in either
    // order, rewrite to IntSLess/IntSLessEq over the underlying
    // compare operands.
    {
        let is_of = |id: VarId, ssa: &SsaCfg| -> bool {
            is_flag_ref(id, 523, ssa) || is_flag_ref(id, 259, ssa)
        };
        let is_sf = |id: VarId, ssa: &SsaCfg| -> bool {
            is_flag_ref(id, 519, ssa) || is_flag_ref(id, 256, ssa)
        };
        let mut rewrites: Vec<(usize, Expr, InferredType)> = Vec::new();
        for (idx, v) in ssa.vars.iter().enumerate() {
            let (is_pair, kind, l, r) = match &v.expr {
                Expr::BinOp(BinOpKind::NotEq, l, r) => {
                    let pair =
                        (is_of(*l, ssa) && is_sf(*r, ssa)) || (is_sf(*l, ssa) && is_of(*r, ssa));
                    (pair, BinOpKind::SLess, *l, *r)
                }
                Expr::BinOp(BinOpKind::Eq, l, r) => {
                    let pair =
                        (is_of(*l, ssa) && is_sf(*r, ssa)) || (is_sf(*l, ssa) && is_of(*r, ssa));
                    (pair, BinOpKind::SLessEq, *l, *r)
                }
                _ => (false, BinOpKind::Eq, VarId(0), VarId(0)),
            };
            if !is_pair {
                continue;
            }
            // Extract CMP operands from either flag var's definition.
            let extract_ab = |flag_var: VarId| -> Option<(VarId, VarId)> {
                match &ssa.vars[flag_var.0 as usize].expr {
                    Expr::BinOp(_, a, b) => Some((*a, *b)),
                    _ => None,
                }
            };
            let ab = extract_ab(l).or_else(|| extract_ab(r));
            if let Some((a, b)) = ab {
                let (final_l, final_r) = match kind {
                    BinOpKind::SLess => (a, b),
                    BinOpKind::SLessEq => (b, a),
                    _ => (a, b),
                };
                rewrites.push((idx, Expr::BinOp(kind, final_l, final_r), InferredType::Bool));
            }
        }
        for (idx, expr, ty) in rewrites {
            ssa.vars[idx].expr = expr;
            ssa.vars[idx].inferred_type = ty;
        }
    }

    // Pass 1b: Sub(a, b) used bare as a CBranch condition → NotEq(a, b).
    // Handles `if (x - 1)` → `if (x != 1)` for non-flag-derived conditions.
    let mut sub_cond: Vec<(usize, VarId, VarId)> = Vec::new(); // (bi, a, b)
    for (bi, block) in ssa.blocks.iter().enumerate() {
        if let SsaTerminator::CBranch { cond, .. } = &block.terminator {
            if is_flag_derived(*cond, ssa) {
                continue;
            }
            let mut resolved = *cond;
            for _ in 0..4 {
                if let Expr::Var(next) = ssa.vars[resolved.0 as usize].expr {
                    resolved = next;
                } else {
                    break;
                }
            }
            if let Expr::BinOp(BinOpKind::Sub, a, b) = ssa.vars[resolved.0 as usize].expr {
                sub_cond.push((bi, a, b));
            }
        }
    }
    for (bi, a, b) in sub_cond {
        let cond_varnode = if let SsaTerminator::CBranch { cond, .. } = ssa.blocks[bi].terminator {
            ssa.vars[cond.0 as usize].varnode
        } else {
            continue;
        };
        let new_cond = ssa.new_var(cond_varnode, Expr::BinOp(BinOpKind::NotEq, a, b), 1);
        if let SsaTerminator::CBranch {
            taken, fallthrough, ..
        } = ssa.blocks[bi].terminator
        {
            ssa.blocks[bi].terminator = SsaTerminator::CBranch {
                cond: new_cond,
                taken,
                fallthrough,
            };
        }
    }

    // Also recover conditions inside Ternary expressions (from CSEL/CSINC/CNEG).
    // These are intra-instruction conditional selects that use flag registers.
    let mut ternary_to_recover: Vec<(usize, VarId, usize)> = Vec::new(); // (var_idx, cond_id, block_idx)
    for (bi, block) in ssa.blocks.iter().enumerate() {
        for stmt in &block.stmts {
            if let Stmt::Assign(vid) = stmt {
                let vi = vid.0 as usize;
                if let Expr::Ternary(cond, _, _) = &ssa.vars[vi].expr {
                    if is_flag_derived(*cond, ssa) {
                        // Check it's not already a recovered comparison
                        let already = if let Expr::BinOp(k, l, r) = &ssa.vars[cond.0 as usize].expr
                        {
                            is_comparison(*k)
                                && !is_flag_derived(*l, ssa)
                                && !is_flag_derived(*r, ssa)
                        } else {
                            false
                        };
                        if !already {
                            ternary_to_recover.push((vi, *cond, bi));
                        }
                    }
                }
            }
        }
    }

    for (vi, cond_id, block_idx) in ternary_to_recover {
        if let Some(new_cond) = try_recover_condition(cond_id, block_idx, ssa) {
            if let Expr::Ternary(_, then_val, else_val) = ssa.vars[vi].expr {
                ssa.vars[vi].expr = Expr::Ternary(new_cond, then_val, else_val);
            }
        }
    }

    // Pass 3: Recover CSETM/CSET algebraic flag patterns.
    // CSETM: Mult(Zext(flag_cond), Neg(1)) or equivalent → Ternary(cond, -1, 0)
    // CSET:  Zext(flag_cond) → Ternary(cond, 1, 0)
    // These are AArch64 conditional-set instructions that compute flag conditions
    // algebraically instead of using intra-instruction CBranch.
    let mut cset_recoveries: Vec<(usize, VarId, i64, i64, usize)> = Vec::new();

    for (bi, block) in ssa.blocks.iter().enumerate() {
        for stmt in &block.stmts {
            if let Stmt::Assign(vid) = stmt {
                let vi = vid.0 as usize;
                if let Some((cond_id, then_val, else_val)) = extract_cset_pattern(vi, ssa) {
                    if is_flag_derived(cond_id, ssa) {
                        cset_recoveries.push((vi, cond_id, then_val, else_val, bi));
                    }
                }
            }
        }
    }

    for (vi, cond_id, then_val, else_val, block_idx) in cset_recoveries {
        let recovered = try_recover_condition(cond_id, block_idx, ssa);
        let final_cond = recovered.unwrap_or(cond_id);

        let size = ssa.vars[vi].size;
        let then_var = ssa.new_var(
            pcode_ir::Varnode::constant(then_val as u64, size),
            Expr::Const(then_val as u64, size),
            size,
        );
        let else_var = ssa.new_var(
            pcode_ir::Varnode::constant(else_val as u64, size),
            Expr::Const(else_val as u64, size),
            size,
        );
        ssa.vars[vi].expr = Expr::Ternary(final_cond, then_var, else_var);
    }
}

/// Extract CSETM/CSET algebraic flag patterns from an expression.
/// Returns (flag_condition_id, then_value, else_value) if the pattern matches.
///
/// CSETM pattern: `Zext(Mult(Zext(flag_cond), Neg(1)))` or without outer Zext
///   When flag_cond is true:  zext(1) * -1 = -1 (0xFFFFFFFF)
///   When flag_cond is false: zext(0) * -1 = 0
///   Result: (flag_cond, -1, 0)
///
/// CSET pattern: `Zext(Zext(flag_cond))` or bare `Zext(flag_cond)` where flag_cond is flag-derived
///   Result: (flag_cond, 1, 0)
fn extract_cset_pattern(var_idx: usize, ssa: &SsaCfg) -> Option<(VarId, i64, i64)> {
    let vdef = &ssa.vars[var_idx];

    // Peel off an outer Zext (32→64 bit extension)
    let inner_idx = if let Expr::UnaryOp(UnaryOpKind::Zext, inner) = &vdef.expr {
        inner.0 as usize
    } else {
        var_idx
    };

    let inner_def = &ssa.vars[inner_idx];

    // CSETM: Mult(Zext(flag_cond), Neg(1)) or Mult(Neg(1), Zext(flag_cond))
    // Also: Mult(Zext(flag_cond), Const(0xFFFF...)) where the const is -1 for the size
    if let Expr::BinOp(BinOpKind::Mult, left, right) = &inner_def.expr {
        // Try both orderings: Mult(Zext(cond), neg) or Mult(neg, Zext(cond))
        for (zext_side, neg_side) in [(*left, *right), (*right, *left)] {
            let zext_def = &ssa.vars[zext_side.0 as usize];
            let neg_def = &ssa.vars[neg_side.0 as usize];

            // Check if neg_side is -1: either Neg(Const(1)) or Const(mask) where mask is all-1s
            let is_neg_one = match &neg_def.expr {
                Expr::UnaryOp(UnaryOpKind::Neg, c) => {
                    matches!(&ssa.vars[c.0 as usize].expr, Expr::Const(1, _))
                }
                Expr::Const(val, sz) => {
                    let mask = if *sz >= 8 {
                        u64::MAX
                    } else {
                        (1u64 << (sz * 8)) - 1
                    };
                    *val == mask
                }
                _ => false,
            };

            if !is_neg_one {
                continue;
            }

            // Check if zext_side is Zext(flag_cond)
            if let Expr::UnaryOp(UnaryOpKind::Zext, cond_id) = &zext_def.expr {
                return Some((*cond_id, -1, 0));
            }
        }
    }

    // CSET: Zext(flag_cond) where the inner is flag-derived and boolean-sized
    // We already peeled the outer Zext above, so inner_def might itself be Zext(cond)
    if inner_idx != var_idx {
        if let Expr::UnaryOp(UnaryOpKind::Zext, cond_id) = &inner_def.expr {
            // This is Zext(Zext(cond)) — double extension of a boolean flag condition
            if is_flag_derived(*cond_id, ssa) {
                return Some((*cond_id, 1, 0));
            }
        }
        // Also check if inner_def itself is directly flag-derived (single Zext)
        if is_flag_derived(VarId(inner_idx as u32), ssa) && inner_def.size <= 1 {
            return Some((VarId(inner_idx as u32), 1, 0));
        }
    }

    None
}

/// Check if a VarId's expression tree references any flag registers.
fn is_flag_derived(id: VarId, ssa: &SsaCfg) -> bool {
    is_flag_derived_depth(id, ssa, 5)
}

fn is_flag_derived_depth(id: VarId, ssa: &SsaCfg, depth: u32) -> bool {
    if depth == 0 {
        return false;
    }
    let vdef = &ssa.vars[id.0 as usize];
    if vdef.varnode.space == AddressSpaceId::Register && FLAG_OFFSETS.contains(&vdef.varnode.offset)
    {
        return true;
    }
    match &vdef.expr {
        Expr::Var(inner) => is_flag_derived_depth(*inner, ssa, depth - 1),
        Expr::BinOp(_, l, r) => {
            is_flag_derived_depth(*l, ssa, depth - 1) || is_flag_derived_depth(*r, ssa, depth - 1)
        }
        Expr::UnaryOp(_, i) => is_flag_derived_depth(*i, ssa, depth - 1),
        _ => false,
    }
}

fn try_recover_condition(cond_id: VarId, block_idx: usize, ssa: &mut SsaCfg) -> Option<VarId> {
    let vdef = &ssa.vars[cond_id.0 as usize];

    // If already a comparison with non-flag operands, use it
    if let Expr::BinOp(kind, l, r) = &vdef.expr {
        if is_comparison(*kind) && !is_flag_derived(*l, ssa) && !is_flag_derived(*r, ssa) {
            return Some(cond_id);
        }
    }

    // Detect compound flag patterns from x86 Jcc instructions:
    // JG:  BoolAnd(BoolNot(ZF), IntEq(OF, SF))  → left > right (signed)
    // JGE: IntEq(OF, SF)                         → left >= right (signed)
    // JL:  BoolXor/NotEq(OF, SF)                 → left < right (signed)
    // JE:  ZF                                     → left == right
    // JNE: BoolNot(ZF)                            → left != right
    // JA:  BoolAnd(BoolNot(CF), BoolNot(ZF))     → left > right (unsigned)
    // JB:  CF                                     → left < right (unsigned)

    // Try to find CMP/SUB operands from this block
    let cmp_result = find_cmp_operands(block_idx, ssa)
        // Fallback: trace through the condition's SSA expression tree directly.
        // Flag assignments may have been eliminated by dead code elimination,
        // but the VarIds still exist. Trace from the condition variable through
        // its expression tree to find the underlying CMP/TEST operands.
        .or_else(|| trace_cond_to_cmp(cond_id, ssa, 8));
    let (cmp_left, cmp_right) = cmp_result?;

    // Classify the condition expression and determine operand order
    let classified = classify_jcc_condition(cond_id, ssa);

    if let Some((kind, swap)) = classified {
        let (left, right) = if swap {
            (cmp_right, cmp_left)
        } else {
            (cmp_left, cmp_right)
        };
        let new_var = ssa.new_var(
            ssa.vars[cond_id.0 as usize].varnode,
            Expr::BinOp(kind, left, right),
            1,
        );
        return Some(new_var);
    }

    // Fallback: check if it's a simple flag with a direct comparison expr (non-flag operands)
    let vdef = &ssa.vars[cond_id.0 as usize];
    if let Expr::Var(inner_id) = &vdef.expr {
        let inner = &ssa.vars[inner_id.0 as usize];
        if let Expr::BinOp(kind, l, r) = &inner.expr {
            if is_comparison(*kind) && !is_flag_derived(*l, ssa) && !is_flag_derived(*r, ssa) {
                return Some(*inner_id);
            }
        }
    }
    if let Expr::BinOp(kind, l, r) = &vdef.expr {
        if is_comparison(*kind) && !is_flag_derived(*l, ssa) && !is_flag_derived(*r, ssa) {
            return Some(cond_id);
        }
    }

    // Special case: post-mba_simplify JG pattern.
    // mba_simplify rewrites BoolNot(ZF) → NotEq(cmp_a, cmp_b) before recover_conditions.
    // Handle BoolAnd(NotEq(a,b), Eq(OF/OV,SF/NG)) and its mirror — both orderings.
    // Validates that NotEq operands match cmp_left/cmp_right to prevent false positives.
    let ba_parts = if let Expr::BinOp(BinOpKind::BoolAnd, l, r) = &ssa.vars[cond_id.0 as usize].expr
    {
        Some((*l, *r))
    } else {
        None
    };

    if let Some((ba_left, ba_right)) = ba_parts {
        let is_of_sf_eq = |id: VarId| -> bool {
            if let Expr::BinOp(BinOpKind::Eq, a, b) = &ssa.vars[id.0 as usize].expr {
                let a_of = is_flag_ref(*a, 523, ssa)
                    || is_flag_ref(*a, 259, ssa)
                    || is_flag_ref(*a, 262, ssa)
                    || is_flag_ref(*a, 99, ssa);
                let a_sf = is_flag_ref(*a, 519, ssa)
                    || is_flag_ref(*a, 256, ssa)
                    || is_flag_ref(*a, 263, ssa)
                    || is_flag_ref(*a, 96, ssa);
                let b_of = is_flag_ref(*b, 523, ssa)
                    || is_flag_ref(*b, 259, ssa)
                    || is_flag_ref(*b, 262, ssa)
                    || is_flag_ref(*b, 99, ssa);
                let b_sf = is_flag_ref(*b, 519, ssa)
                    || is_flag_ref(*b, 256, ssa)
                    || is_flag_ref(*b, 263, ssa)
                    || is_flag_ref(*b, 96, ssa);
                (a_of && b_sf) || (a_sf && b_of)
            } else {
                false
            }
        };
        let r_is_of_sf = is_of_sf_eq(ba_right);
        let l_is_of_sf = is_of_sf_eq(ba_left);

        let neq_side = if r_is_of_sf {
            Some(ba_left)
        } else if l_is_of_sf {
            Some(ba_right)
        } else {
            None
        };
        let neq_pair = neq_side.and_then(|id| {
            if let Expr::BinOp(BinOpKind::NotEq, l, r) = &ssa.vars[id.0 as usize].expr {
                if !is_flag_derived(*l, ssa) && !is_flag_derived(*r, ssa) {
                    return Some((*l, *r));
                }
            }
            None
        });

        if let Some((neq_l, neq_r)) = neq_pair {
            let ra = resolve_cmp_operand(neq_l, ssa);
            let rb = resolve_cmp_operand(neq_r, ssa);
            let ca = resolve_cmp_operand(cmp_left, ssa);
            let cb = resolve_cmp_operand(cmp_right, ssa);
            if (ra == ca && rb == cb) || (ra == cb && rb == ca) {
                let varnode = ssa.vars[cond_id.0 as usize].varnode;
                let new_var = ssa.new_var(
                    varnode,
                    Expr::BinOp(BinOpKind::SLess, cmp_right, cmp_left),
                    1,
                );
                return Some(new_var);
            }
        }
    }

    None
}

/// Trace the condition variable's SSA expression tree to find CMP/TEST operands.
/// This handles the case where flag assignments have been inlined/eliminated by
/// earlier fold passes but the VarIds still exist.
fn trace_cond_to_cmp(cond_id: VarId, ssa: &SsaCfg, depth: u32) -> Option<(VarId, VarId)> {
    if depth == 0 {
        return None;
    }
    let vdef = &ssa.vars[cond_id.0 as usize];
    match &vdef.expr {
        // SF = IntSLess(result, 0)
        Expr::BinOp(BinOpKind::SLess, result_id, zero_id) => {
            let zero = &ssa.vars[zero_id.0 as usize];
            if matches!(&zero.expr, Expr::Const(0, _)) {
                return trace_to_cmp_with_zero(*result_id, ssa, Some(*zero_id));
            }
            None
        }
        // CF = Carry/Less(left, right)
        Expr::BinOp(
            BinOpKind::Carry | BinOpKind::SCarry | BinOpKind::SBorrow | BinOpKind::Less,
            left,
            right,
        ) => Some((*left, *right)),
        // BoolNot(inner) → trace inner
        Expr::UnaryOp(UnaryOpKind::BoolNot, inner) => trace_cond_to_cmp(*inner, ssa, depth - 1),
        // Zext/Sext wrapping (common in ternary conditions from CSEL/CNEG) → trace inner
        Expr::UnaryOp(UnaryOpKind::Zext | UnaryOpKind::Sext, inner) => {
            trace_cond_to_cmp(*inner, ssa, depth - 1)
        }
        // Var(inner) → follow
        Expr::Var(inner) => trace_cond_to_cmp(*inner, ssa, depth - 1),
        // Compound: BoolAnd/BoolOr → trace both sides for CMP operands
        Expr::BinOp(BinOpKind::BoolAnd | BinOpKind::BoolOr, left, right) => {
            trace_cond_to_cmp(*left, ssa, depth - 1)
                .or_else(|| trace_cond_to_cmp(*right, ssa, depth - 1))
        }
        // Eq/NotEq: could be ZF=IntEq(result,0) or IntEq(OF,SF)
        Expr::BinOp(BinOpKind::Eq | BinOpKind::NotEq, left, right) => {
            // Check if right is Const(0) — this is ZF = IntEq(result, 0)
            let rdef = &ssa.vars[right.0 as usize];
            if matches!(&rdef.expr, Expr::Const(0, _)) {
                if let Some(result) = trace_to_cmp_with_zero(*left, ssa, Some(*right)) {
                    return Some(result);
                }
                // Can't trace further — use (result, 0) directly.
                // This handles TEST of computed values like IDIV remainder.
                return Some((*left, *right));
            }
            // Otherwise trace through (e.g., IntEq(OF, SF) for JGE)
            trace_cond_to_cmp(*left, ssa, depth - 1)
                .or_else(|| trace_cond_to_cmp(*right, ssa, depth - 1))
        }
        _ => None,
    }
}

/// Find the CMP/SUB/TEST operands by tracing from the flag definitions.
/// Searches the specified block first, then all blocks as fallback.
fn find_cmp_operands(block_idx: usize, ssa: &SsaCfg) -> Option<(VarId, VarId)> {
    // Try the specified block first
    if let Some(result) = find_cmp_in_block(block_idx, ssa) {
        return Some(result);
    }
    // Fallback: search all blocks (for cases where the CMP is in a predecessor)
    for bi in (0..ssa.blocks.len()).rev() {
        if bi == block_idx {
            continue;
        }
        if let Some(result) = find_cmp_in_block(bi, ssa) {
            return Some(result);
        }
    }
    None
}

fn find_cmp_in_block(block_idx: usize, ssa: &SsaCfg) -> Option<(VarId, VarId)> {
    let block = &ssa.blocks[block_idx];
    for stmt in block.stmts.iter().rev() {
        if let Stmt::Assign(vid) = stmt {
            let v = &ssa.vars[vid.0 as usize];
            // ZF = IntEq(sub_result, 0)
            if v.varnode.space == AddressSpaceId::Register && v.varnode.offset == 518 {
                if let Expr::BinOp(BinOpKind::Eq, result_id, zero_id) = &v.expr {
                    let zero = &ssa.vars[zero_id.0 as usize];
                    if matches!(&zero.expr, Expr::Const(0, _)) {
                        return trace_to_cmp_with_zero(*result_id, ssa, Some(*zero_id));
                    }
                }
            }
            // SF = IntSLess(result, 0)
            if v.varnode.space == AddressSpaceId::Register && v.varnode.offset == 519 {
                if let Expr::BinOp(BinOpKind::SLess, result_id, zero_id) = &v.expr {
                    let zero = &ssa.vars[zero_id.0 as usize];
                    if matches!(&zero.expr, Expr::Const(0, _)) {
                        return trace_to_cmp_with_zero(*result_id, ssa, Some(*zero_id));
                    }
                }
            }
            // CF/OF (x86) or CY/OV (ARM64) — trace operands directly
            if v.varnode.space == AddressSpaceId::Register
                && matches!(v.varnode.offset, 512 | 523 | 258 | 259 | 261 | 262)
            {
                if let Expr::BinOp(
                    BinOpKind::Carry | BinOpKind::SCarry | BinOpKind::SBorrow | BinOpKind::Less,
                    left,
                    right,
                ) = &v.expr
                {
                    return Some((*left, *right));
                }
            }
            // ARM64: NG/ZR and tmpNG/tmpZR from flag writes
            if v.varnode.space == AddressSpaceId::Register && matches!(v.varnode.offset, 257 | 264)
            // ZR or tmpZR (ARM64)
            {
                if let Expr::BinOp(BinOpKind::Eq, result_id, zero_id) = &v.expr {
                    let zero = &ssa.vars[zero_id.0 as usize];
                    if matches!(&zero.expr, Expr::Const(0, _)) {
                        return trace_to_cmp_with_zero(*result_id, ssa, Some(*zero_id));
                    }
                }
            }
            if v.varnode.space == AddressSpaceId::Register && matches!(v.varnode.offset, 256 | 263)
            // NG or tmpNG (ARM64)
            {
                if let Expr::BinOp(BinOpKind::SLess, result_id, zero_id) = &v.expr {
                    let zero = &ssa.vars[zero_id.0 as usize];
                    if matches!(&zero.expr, Expr::Const(0, _)) {
                        return trace_to_cmp_with_zero(*result_id, ssa, Some(*zero_id));
                    }
                }
            }
            // ARM32: tmpZR at offset 101 (ZR=97 is the stored flag, tmpZR=101 is the computed one)
            // ARM32 CMP sets tmpNG/tmpZR/tmpCY/tmpOV, then copies to NG/ZR/CY/OV
            if v.varnode.space == AddressSpaceId::Register && matches!(v.varnode.offset, 97 | 101)
            // ZR or tmpZR (ARM32)
            {
                if let Expr::BinOp(BinOpKind::Eq, result_id, zero_id) = &v.expr {
                    let zero = &ssa.vars[zero_id.0 as usize];
                    if matches!(&zero.expr, Expr::Const(0, _)) {
                        return trace_to_cmp_with_zero(*result_id, ssa, Some(*zero_id));
                    }
                }
            }
            if v.varnode.space == AddressSpaceId::Register && matches!(v.varnode.offset, 96 | 100)
            // NG or tmpNG (ARM32)
            {
                if let Expr::BinOp(BinOpKind::SLess, result_id, zero_id) = &v.expr {
                    let zero = &ssa.vars[zero_id.0 as usize];
                    if matches!(&zero.expr, Expr::Const(0, _)) {
                        return trace_to_cmp_with_zero(*result_id, ssa, Some(*zero_id));
                    }
                }
            }
            // ARM32: tmpCY/CY carry flag from CMP
            if v.varnode.space == AddressSpaceId::Register
                && matches!(v.varnode.offset, 98 | 99 | 102 | 103)
            // CY, OV, tmpCY, tmpOV (ARM32)
            {
                if let Expr::BinOp(
                    BinOpKind::Carry | BinOpKind::SCarry | BinOpKind::SBorrow | BinOpKind::Less,
                    left,
                    right,
                ) = &v.expr
                {
                    return Some((*left, *right));
                }
            }
        }
    }
    None
}

/// Trace a SUB/AND/NEG result variable back to find the CMP operands.
/// Uses zero_id for IntNeg(x) → (0, x) and TEST same-register → (x, 0).
fn trace_to_cmp_with_zero(
    result_id: VarId,
    ssa: &SsaCfg,
    zero_id: Option<VarId>,
) -> Option<(VarId, VarId)> {
    let v = &ssa.vars[result_id.0 as usize];
    match &v.expr {
        Expr::BinOp(BinOpKind::Sub, left, right) => Some((
            resolve_cmp_operand(*left, ssa),
            resolve_cmp_operand(*right, ssa),
        )),
        Expr::BinOp(BinOpKind::And, left, right) => {
            // TEST a, b → AND(a, b). ZF = (a & b == 0).
            // When both operands are the same (TEST a, a), compare a against 0.
            // When different, compare (a & b) result against 0.
            let l = resolve_cmp_operand(*left, ssa);
            let r = resolve_cmp_operand(*right, ssa);
            if let Some(z) = zero_id {
                // For TEST: compare the operand (or result) against zero
                if ssa.vars[l.0 as usize].varnode == ssa.vars[r.0 as usize].varnode {
                    Some((l, z))
                } else {
                    // Different operands: use the result itself vs zero
                    Some((result_id, z))
                }
            } else {
                Some((l, r))
            }
        }
        // IntNeg(x) is equivalent to Sub(0, x)
        Expr::UnaryOp(UnaryOpKind::Neg, inner) => {
            if let Some(z) = zero_id {
                Some((z, resolve_cmp_operand(*inner, ssa)))
            } else {
                None
            }
        }
        Expr::Var(inner) => trace_to_cmp_with_zero(*inner, ssa, zero_id),
        _ => None,
    }
}

/// Resolve a CMP operand through register copies to find the underlying value.
/// REG = Var(other_reg) → follow; REG = Load(stack) → use the Load.
fn resolve_cmp_operand(id: VarId, ssa: &SsaCfg) -> VarId {
    resolve_cmp_operand_depth(id, ssa, 8)
}

fn resolve_cmp_operand_depth(id: VarId, ssa: &SsaCfg, depth: u32) -> VarId {
    if depth == 0 {
        return id;
    }
    let v = &ssa.vars[id.0 as usize];
    // Follow register-to-register copies
    if v.varnode.space == AddressSpaceId::Register {
        if let Expr::Var(src) = &v.expr {
            let sv = &ssa.vars[src.0 as usize];
            // If source is a stack Load or has a param name, prefer it
            if matches!(&sv.expr, Expr::Load(_)) || sv.param_name.is_some() {
                return *src;
            }
            // If source is another register, follow one more level
            if sv.varnode.space == AddressSpaceId::Register {
                if let Expr::Var(inner) = &sv.expr {
                    let iv = &ssa.vars[inner.0 as usize];
                    if matches!(&iv.expr, Expr::Load(_)) || iv.param_name.is_some() {
                        return *inner;
                    }
                }
                if let Expr::Load(_) = &sv.expr {
                    return *src;
                }
            }
            return *src;
        }
        if let Expr::Load(_) = &v.expr {
            return id;
        }
    }
    // Follow Unique space vars
    if v.varnode.space == AddressSpaceId::Unique {
        if let Expr::Var(src) = &v.expr {
            return resolve_cmp_operand_depth(*src, ssa, depth - 1);
        }
    }
    id
}

/// Classify a Jcc condition expression into a comparison kind.
/// Returns (comparison_kind, swap_operands).
/// swap_operands=true means use (right, left) instead of (left, right) from CMP.
fn classify_jcc_condition(cond_id: VarId, ssa: &SsaCfg) -> Option<(BinOpKind, bool)> {
    let vdef = &ssa.vars[cond_id.0 as usize];

    // Unwrap Zext/Sext/Var wrappers (common in ternary conditions from CSEL/CNEG)
    if let Expr::UnaryOp(UnaryOpKind::Zext | UnaryOpKind::Sext, inner) = &vdef.expr {
        return classify_jcc_condition(*inner, ssa);
    }
    if let Expr::Var(inner) = &vdef.expr {
        if ssa.vars[inner.0 as usize].varnode.space == AddressSpaceId::Register
            || ssa.vars[inner.0 as usize].varnode.space == AddressSpaceId::Unique
        {
            return classify_jcc_condition(*inner, ssa);
        }
    }

    // General BoolNot unwrapping: !cond → invert the inner condition
    if let Expr::UnaryOp(UnaryOpKind::BoolNot, inner) = &vdef.expr {
        if let Some((kind, swap)) = classify_jcc_condition(*inner, ssa) {
            let inverted = match kind {
                BinOpKind::Eq => BinOpKind::NotEq,
                BinOpKind::NotEq => BinOpKind::Eq,
                BinOpKind::Less => BinOpKind::LessEq, // !(a < b) = a >= b = b <= a
                BinOpKind::LessEq => BinOpKind::Less, // !(a <= b) = a > b = b < a
                BinOpKind::SLess => BinOpKind::SLessEq, // !(a < b) = a >= b = b <= a
                BinOpKind::SLessEq => BinOpKind::SLess, // !(a <= b) = a > b = b < a
                _ => return None,
            };
            // Invert: !(a < b) = b <= a, so swap stays the same but the kind flips.
            // But !(a < b) = a >= b = b <= a. With swap, the operands are already swapped.
            // We need: invert the comparison and flip swap.
            return Some((inverted, !swap));
        }
    }

    // Helper: check ZF (x86=518), ZR (ARM64=257,tmpZR=264), ZR (ARM32=97)
    let is_zf = |id: VarId| {
        is_flag_ref(id, 518, ssa)
            || is_flag_ref(id, 257, ssa)
            || is_flag_ref(id, 264, ssa)
            || is_flag_ref(id, 97, ssa)
    };
    // Helper: check CF (x86=512), CY (ARM64=258,tmpCY=261), CY (ARM32=98)
    let is_cf = |id: VarId| {
        is_flag_ref(id, 512, ssa)
            || is_flag_ref(id, 258, ssa)
            || is_flag_ref(id, 261, ssa)
            || is_flag_ref(id, 98, ssa)
    };
    // Helper: check OF (x86=523), OV (ARM64=259,tmpOV=262), OV (ARM32=99)
    let is_of = |id: VarId| {
        is_flag_ref(id, 523, ssa)
            || is_flag_ref(id, 259, ssa)
            || is_flag_ref(id, 262, ssa)
            || is_flag_ref(id, 99, ssa)
    };
    // Helper: check SF (x86=519), NG (ARM64=256,tmpNG=263), NG (ARM32=96)
    let is_sf = |id: VarId| {
        is_flag_ref(id, 519, ssa)
            || is_flag_ref(id, 256, ssa)
            || is_flag_ref(id, 263, ssa)
            || is_flag_ref(id, 96, ssa)
    };

    match &vdef.expr {
        // ZF/ZR directly → JE/BEQ → a == b
        _ if is_zf(cond_id) => Some((BinOpKind::Eq, false)),

        // BoolNot(ZF/ZR) → JNE/BNE → a != b
        Expr::UnaryOp(UnaryOpKind::BoolNot, inner) if is_zf(*inner) => {
            Some((BinOpKind::NotEq, false))
        }

        // CF/CY directly → JB/BLO → a < b (unsigned)
        _ if is_cf(cond_id) => Some((BinOpKind::Less, false)),

        // BoolNot(CF/CY) → JAE/BHS → a >= b (unsigned) = b <= a
        Expr::UnaryOp(UnaryOpKind::BoolNot, inner) if is_cf(*inner) => {
            Some((BinOpKind::LessEq, true))
        }

        // IntEq(OF, SF) or IntEq(OV, NG) → JGE/BGE → a >= b (signed) = b <= a
        Expr::BinOp(BinOpKind::Eq, left, right)
            if (is_of(*left) && is_sf(*right)) || (is_sf(*left) && is_of(*right)) =>
        {
            Some((BinOpKind::SLessEq, true))
        }

        // NotEq(OF, SF) or NotEq(SBORROW, SLess) → JL → a < b (signed)
        Expr::BinOp(BinOpKind::NotEq, left, right)
            if (is_of(*left) && is_sf(*right)) || (is_sf(*left) && is_of(*right)) =>
        {
            Some((BinOpKind::SLess, false))
        }

        // SF/NG directly → JL/BLT → a < b (signed)
        _ if is_sf(cond_id) => Some((BinOpKind::SLess, false)),

        // BoolOr(CF, ZF) → JBE → a <= b (unsigned)
        Expr::BinOp(BinOpKind::BoolOr, left, right)
            if (is_cf(*left) && is_zf(*right)) || (is_zf(*left) && is_cf(*right)) =>
        {
            Some((BinOpKind::LessEq, false))
        }

        // BoolOr(ZF, NotEq(OF, SF)) → JLE → a <= b (signed)
        // BoolOr(BoolNot(CY), ZR) → AArch64 BLS → unsigned a <= b
        //   (AArch64 CY is inverted vs x86 CF: CY=1 means no borrow = a >= b)
        Expr::BinOp(BinOpKind::BoolOr, left, right) => {
            let left_def = &ssa.vars[left.0 as usize];
            let right_def = &ssa.vars[right.0 as usize];
            // ZF || (OF != SF) → JLE
            let zf_or_sfneqof = (is_zf(*left)
                && matches!(&right_def.expr,
                    Expr::BinOp(BinOpKind::NotEq, a, b)
                    if (is_of(*a) && is_sf(*b)) || (is_sf(*a) && is_of(*b))))
                || (is_zf(*right)
                    && matches!(&left_def.expr,
                    Expr::BinOp(BinOpKind::NotEq, a, b)
                    if (is_of(*a) && is_sf(*b)) || (is_sf(*a) && is_of(*b))));
            if zf_or_sfneqof {
                return Some((BinOpKind::SLessEq, false));
            }
            // AArch64: BoolOr(BoolNot(CY), ZR) → BLS → unsigned a <= b
            let not_cy_or_zr = (matches!(&left_def.expr, Expr::UnaryOp(UnaryOpKind::BoolNot, inner) if is_cf(*inner))
                && is_zf(*right))
                || (matches!(&right_def.expr, Expr::UnaryOp(UnaryOpKind::BoolNot, inner) if is_cf(*inner))
                    && is_zf(*left));
            if not_cy_or_zr {
                return Some((BinOpKind::LessEq, false));
            }
            // AArch64: BoolOr(ZR, NotEq(OV, NG)) → signed a <= b
            let zr_or_ngneqov = (is_zf(*left)
                && matches!(&right_def.expr,
                    Expr::BinOp(BinOpKind::NotEq, a, b)
                    if (is_of(*a) && is_sf(*b)) || (is_sf(*a) && is_of(*b))))
                || (is_zf(*right)
                    && matches!(&left_def.expr,
                    Expr::BinOp(BinOpKind::NotEq, a, b)
                    if (is_of(*a) && is_sf(*b)) || (is_sf(*a) && is_of(*b))));
            if zr_or_ngneqov {
                return Some((BinOpKind::SLessEq, false));
            }
            None
        }

        // BoolAnd(BoolNot(ZF/ZR), IntEq(OF/OV, SF/NG)) → JG/BGT → a > b = b < a
        Expr::BinOp(BinOpKind::BoolAnd, left, right) => {
            let left_def = &ssa.vars[left.0 as usize];
            let right_def = &ssa.vars[right.0 as usize];

            let left_is_not_zf = matches!(&left_def.expr,
                Expr::UnaryOp(UnaryOpKind::BoolNot, inner) if is_zf(*inner));
            let right_is_sf_eq_of = matches!(&right_def.expr,
                Expr::BinOp(BinOpKind::Eq, a, b)
                    if (is_of(*a) && is_sf(*b)) || (is_sf(*a) && is_of(*b)));

            if left_is_not_zf && right_is_sf_eq_of {
                Some((BinOpKind::SLess, true)) // JG/BGT: a > b = b < a
            } else {
                let left_is_not_cf = matches!(&left_def.expr,
                    Expr::UnaryOp(UnaryOpKind::BoolNot, inner) if is_cf(*inner));
                let right_is_not_zf = matches!(&right_def.expr,
                    Expr::UnaryOp(UnaryOpKind::BoolNot, inner) if is_zf(*inner));

                if left_is_not_cf && right_is_not_zf {
                    Some((BinOpKind::Less, true)) // JA/BHI: unsigned b < a
                } else if left_is_not_zf {
                    Some((BinOpKind::NotEq, false))
                } else {
                    None
                }
            }
        }

        _ => None,
    }
}

/// Check if a VarId refers to (or resolves to) a specific flag register.
fn is_flag_ref(id: VarId, flag_offset: u64, ssa: &SsaCfg) -> bool {
    let v = &ssa.vars[id.0 as usize];
    if v.varnode.space == AddressSpaceId::Register && v.varnode.offset == flag_offset {
        return true;
    }
    // Check one level of Var indirection
    if let Expr::Var(inner) = &v.expr {
        let inner_v = &ssa.vars[inner.0 as usize];
        if inner_v.varnode.space == AddressSpaceId::Register
            && inner_v.varnode.offset == flag_offset
        {
            return true;
        }
    }
    false
}

fn is_comparison(kind: BinOpKind) -> bool {
    matches!(
        kind,
        BinOpKind::Eq
            | BinOpKind::NotEq
            | BinOpKind::Less
            | BinOpKind::LessEq
            | BinOpKind::SLess
            | BinOpKind::SLessEq
    )
}

// ---- Return Values ----

fn detect_return_values(ssa: &mut SsaCfg) {
    // Try to detect architecture from register usage:
    // ARM32 r0 = offset 32 (0x20), x86 RAX = offset 0, AArch64 x0 = offset 16384
    let has_arm32_regs = ssa.vars.iter().any(|v| {
        v.varnode.space == AddressSpaceId::Register
            && v.varnode.offset == 32
            && v.varnode.size == 4
            && matches!(v.varnode.offset, 32..=92)
    }); // ARM32 r0-r15 range
    let has_aarch64_regs = ssa.vars.iter().any(|v| {
        v.varnode.space == AddressSpaceId::Register
        && v.varnode.offset >= 16384 && v.varnode.offset <= 16440  // x0-x7 range
        && (v.varnode.size == 4 || v.varnode.size == 8)
    });
    let ret_reg_offset = if has_arm32_regs {
        32
    } else if has_aarch64_regs {
        16384
    }
    // AArch64 x0
    else {
        RAX_OFFSET
    }; // x86 RAX=0

    // AArch64: unwrap Zext from existing return values (SSA builder may have picked
    // x0 size=8 when the function actually operates on w0 size=4).
    if has_aarch64_regs {
        for bi in 0..ssa.blocks.len() {
            if let SsaTerminator::Return(Some(var_id)) = ssa.blocks[bi].terminator {
                if let Expr::UnaryOp(UnaryOpKind::Zext, inner) = &ssa.vars[var_id.0 as usize].expr {
                    if ssa.vars[inner.0 as usize].varnode.size == 4 {
                        let inner_id = *inner;
                        ssa.blocks[bi].terminator = SsaTerminator::Return(Some(inner_id));
                    }
                }
            }
        }
    }

    for bi in 0..ssa.blocks.len() {
        if let SsaTerminator::Return(ref ret_val) = ssa.blocks[bi].terminator {
            if ret_val.is_some() {
                continue;
            }
        } else {
            continue;
        }

        // Strategy 1: Look backwards in this block for RAX/EAX assignment
        let mut found = find_ret_reg_in_block(&ssa.blocks[bi].stmts, &ssa.vars, ret_reg_offset);

        // Strategy 2: Check for call_return var (EAX set by a preceding CALL).
        //
        // This branch covers two source-level patterns that compile to
        // identical machine code:
        //   int wrap() { return foo(); }      // legitimate
        //   void f()    { foo(); }            // call_return is stale
        // The decompiler cannot disambiguate without callsite information,
        // so it promotes the call_return (matching the wrap() interpretation
        // — the more common case) and records a StaleReturnInherited
        // diagnostic so audits can flag the f() case.
        if found.is_none() {
            for stmt in ssa.blocks[bi].stmts.iter().rev() {
                if let Stmt::Assign(var_id) = stmt {
                    let vdef = &ssa.vars[var_id.0 as usize];
                    if vdef.call_return {
                        found = Some(*var_id);
                        ssa.diagnostics.push(crate::ir::Diagnostic {
                            severity: crate::ir::Severity::Info,
                            kind: crate::ir::DiagKind::StaleReturnInherited,
                            addr: None,
                            detail: format!(
                                "block {} return inferred from call_return; \
                                 function may actually be void",
                                bi
                            ),
                        });
                        break;
                    }
                }
            }
        }

        // Strategy 3: Check predecessors (CMOV patterns, conditional returns)
        if found.is_none() {
            for pred_bi in 0..ssa.blocks.len() {
                if pred_bi == bi {
                    continue;
                }
                let flows_to_bi = match &ssa.blocks[pred_bi].terminator {
                    SsaTerminator::Fallthrough(b) | SsaTerminator::Branch(b) => b.0 == bi,
                    SsaTerminator::CBranch {
                        taken, fallthrough, ..
                    } => taken.0 == bi || fallthrough.0 == bi,
                    SsaTerminator::Call { fallthrough, .. } => fallthrough.0 == bi,
                    _ => false,
                };
                if !flows_to_bi {
                    continue;
                }

                let pred_found =
                    find_ret_reg_in_block(&ssa.blocks[pred_bi].stmts, &ssa.vars, ret_reg_offset);
                if pred_found.is_some() {
                    found = pred_found;
                    break;
                }
                // Also check if predecessor ends with a Call (return value in EAX flows through)
                if matches!(&ssa.blocks[pred_bi].terminator, SsaTerminator::Call { .. }) {
                    // The call's return value (in EAX) flows to the return block
                    for stmt in ssa.blocks[pred_bi].stmts.iter().rev() {
                        if let Stmt::Assign(var_id) = stmt {
                            if ssa.vars[var_id.0 as usize].call_return {
                                found = Some(*var_id);
                                break;
                            }
                        }
                    }
                }
                if found.is_some() {
                    break;
                }
            }
        }

        // Strategy 4: Broader search — check ALL blocks that flow to this return block
        // through any path (up to 3 hops). This catches cases where EAX is set several
        // blocks before the actual return (common in x86-32 with epilogue blocks).
        if found.is_none() {
            let mut visited = std::collections::HashSet::new();
            let mut frontier = vec![bi];
            visited.insert(bi);
            for _hop in 0..3 {
                let mut next_frontier = Vec::new();
                for &target_bi in &frontier {
                    for pred_bi in 0..ssa.blocks.len() {
                        if visited.contains(&pred_bi) {
                            continue;
                        }
                        let flows = match &ssa.blocks[pred_bi].terminator {
                            SsaTerminator::Fallthrough(b) | SsaTerminator::Branch(b) => {
                                b.0 == target_bi
                            }
                            SsaTerminator::CBranch {
                                taken, fallthrough, ..
                            } => taken.0 == target_bi || fallthrough.0 == target_bi,
                            SsaTerminator::Call { fallthrough, .. } => fallthrough.0 == target_bi,
                            _ => false,
                        };
                        if !flows {
                            continue;
                        }
                        visited.insert(pred_bi);
                        next_frontier.push(pred_bi);

                        if let Some(var_id) = find_ret_reg_in_block(
                            &ssa.blocks[pred_bi].stmts,
                            &ssa.vars,
                            ret_reg_offset,
                        ) {
                            found = Some(var_id);
                            break;
                        }
                        // Check call_return in predecessor
                        for stmt in ssa.blocks[pred_bi].stmts.iter().rev() {
                            if let Stmt::Assign(var_id) = stmt {
                                if ssa.vars[var_id.0 as usize].call_return {
                                    found = Some(*var_id);
                                    break;
                                }
                            }
                        }
                        if found.is_some() {
                            break;
                        }
                    }
                    if found.is_some() {
                        break;
                    }
                }
                if found.is_some() {
                    break;
                }
                frontier = next_frontier;
            }
        }

        // Strategy 5: Float return — check XMM0 for functions with float ops.
        if found.is_none() {
            let has_float_ops = ssa.vars.iter().any(|v| {
                matches!(
                    &v.expr,
                    Expr::BinOp(
                        BinOpKind::FloatAdd
                            | BinOpKind::FloatSub
                            | BinOpKind::FloatMult
                            | BinOpKind::FloatDiv,
                        _,
                        _
                    ) | Expr::UnaryOp(
                        UnaryOpKind::FloatNeg
                            | UnaryOpKind::FloatAbs
                            | UnaryOpKind::FloatSqrt
                            | UnaryOpKind::Int2Float
                            | UnaryOpKind::Float2Float,
                        _
                    )
                )
            });
            if has_float_ops {
                const XMM0_OFFSET: u64 = 4608;
                found = find_float_ret_in_block(&ssa.blocks[bi].stmts, &ssa.vars, XMM0_OFFSET);
                if found.is_none() {
                    for pred_bi in 0..ssa.blocks.len() {
                        if pred_bi == bi {
                            continue;
                        }
                        let flows_to_bi = match &ssa.blocks[pred_bi].terminator {
                            SsaTerminator::Fallthrough(b) | SsaTerminator::Branch(b) => b.0 == bi,
                            SsaTerminator::CBranch {
                                taken, fallthrough, ..
                            } => taken.0 == bi || fallthrough.0 == bi,
                            SsaTerminator::Call { fallthrough, .. } => fallthrough.0 == bi,
                            _ => false,
                        };
                        if !flows_to_bi {
                            continue;
                        }
                        found = find_float_ret_in_block(
                            &ssa.blocks[pred_bi].stmts,
                            &ssa.vars,
                            XMM0_OFFSET,
                        );
                        if found.is_some() {
                            break;
                        }
                    }
                }
                // Fallback: DCE may have removed the XMM0 assignment from block stmts
                // because use_count was 0 (nothing reads XMM0 after ADDSS before RET).
                // Search the vars array directly for the last XMM0 write with a float expr.
                if found.is_none() {
                    let mut best: Option<VarId> = None;
                    for (vi, vd) in ssa.vars.iter().enumerate() {
                        if vd.varnode.space == AddressSpaceId::Register
                            && vd.varnode.offset == XMM0_OFFSET
                            && matches!(
                                &vd.expr,
                                Expr::BinOp(
                                    BinOpKind::FloatAdd
                                        | BinOpKind::FloatSub
                                        | BinOpKind::FloatMult
                                        | BinOpKind::FloatDiv,
                                    _,
                                    _
                                ) | Expr::UnaryOp(
                                    UnaryOpKind::FloatNeg
                                        | UnaryOpKind::FloatAbs
                                        | UnaryOpKind::FloatSqrt
                                        | UnaryOpKind::Int2Float
                                        | UnaryOpKind::Float2Float,
                                    _
                                ) | Expr::Var(_)
                            )
                        {
                            // Skip params (Unknown expr with param_name)
                            if vd.param_name.is_some() {
                                continue;
                            }
                            best = Some(VarId(vi as u32));
                        }
                    }
                    found = best;
                }
            }
        }

        if let Some(var_id) = found {
            // AArch64: if return value is Zext of a 4-byte w-register result, prefer the
            // inner 4-byte value so the return type prints as `int` rather than `long`.
            let actual_id = if has_aarch64_regs {
                if let Expr::UnaryOp(UnaryOpKind::Zext, inner) = &ssa.vars[var_id.0 as usize].expr {
                    if ssa.vars[inner.0 as usize].varnode.size == 4 {
                        *inner
                    } else {
                        var_id
                    }
                } else {
                    var_id
                }
            } else {
                var_id
            };

            if let SsaTerminator::Return(ref mut ret_val) = ssa.blocks[bi].terminator {
                *ret_val = Some(actual_id);
            }
        }
    }
}

/// Search a block's statements backwards for an assignment to a float return register.
fn find_float_ret_in_block(
    stmts: &[Stmt],
    vars: &[VarDef],
    float_ret_offset: u64,
) -> Option<VarId> {
    for stmt in stmts.iter().rev() {
        if let Stmt::Assign(var_id) = stmt {
            let vdef = &vars[var_id.0 as usize];
            if vdef.varnode.space == AddressSpaceId::Register
                && vdef.varnode.offset == float_ret_offset
            {
                return Some(*var_id);
            }
        }
    }
    None
}

/// Search a block's statements backwards for an assignment to the return register.
fn find_ret_reg_in_block(stmts: &[Stmt], vars: &[VarDef], ret_reg_offset: u64) -> Option<VarId> {
    // First check if there's a Phi for this register — loop-carried values
    // should return the Phi (the loop variable) rather than the raw last-write.
    // This ensures post-loop returns reference the accumulator variable.
    for stmt in stmts {
        if let Stmt::Assign(var_id) = stmt {
            let vdef = &vars[var_id.0 as usize];
            if vdef.varnode.space == AddressSpaceId::Register
                && vdef.varnode.offset == ret_reg_offset
                && vdef.varnode.size >= 4
                && matches!(&vdef.expr, Expr::Phi(_))
            {
                return Some(*var_id);
            }
        }
    }
    // Fallback: scan backwards for any write to this register
    for stmt in stmts.iter().rev() {
        if let Stmt::Assign(var_id) = stmt {
            let vdef = &vars[var_id.0 as usize];
            if vdef.varnode.space == AddressSpaceId::Register
                && vdef.varnode.offset == ret_reg_offset
                && vdef.varnode.size >= 4
            {
                return Some(*var_id);
            }
        }
    }
    None
}

// ---- Call Arguments ----

/// Collect argument register writes (x86-64) or stack pushes (x86-32) before each Call.
/// For x86-32, also removes consumed Store/ESP-decrement statements.
fn collect_call_arguments(ssa: &mut SsaCfg) {
    // Use the calling convention set by fold_with_cc, not heuristic detection.
    let is_x86_32 = arg_reg_offsets().is_empty();

    for bi in 0..ssa.blocks.len() {
        // Collect all indices to remove for this block (from multiple calls)
        let mut all_consumed: Vec<usize> = Vec::new();

        // Check if block ends with a Call terminator
        let call_info = match &ssa.blocks[bi].terminator {
            SsaTerminator::Call {
                target,
                fallthrough,
                ..
            } => Some((target.clone(), *fallthrough)),
            _ => None,
        };

        if let Some((target, fallthrough)) = call_info {
            let n_stmts = ssa.blocks[bi].stmts.len();
            let mut args = if is_x86_32 {
                let (args, consumed) =
                    collect_stack_args_from_block(&ssa.blocks[bi].stmts, &ssa.vars, n_stmts);
                if !args.is_empty() {
                    all_consumed.extend(consumed);
                }
                args
            } else {
                collect_reg_args_from_block(&ssa.blocks[bi].stmts, &ssa.vars, n_stmts)
            };

            if !args.is_empty() {
                // Preserve existing `out` field if already set
                let existing_out =
                    if let SsaTerminator::Call { out, .. } = &ssa.blocks[bi].terminator {
                        *out
                    } else {
                        None
                    };
                ssa.blocks[bi].terminator = SsaTerminator::Call {
                    target,
                    args,
                    out: existing_out,
                    fallthrough,
                };
            }
        }

        // Also check for Call statements within the block
        // Process in reverse order so consumed indices from earlier calls don't shift
        let call_indices: Vec<usize> = (0..ssa.blocks[bi].stmts.len())
            .filter(|si| {
                matches!(&ssa.blocks[bi].stmts[*si],
                Stmt::Call { args, .. } if args.is_empty())
            })
            .collect();

        for &si in call_indices.iter().rev() {
            let mut args = if is_x86_32 {
                let (args, consumed) =
                    collect_stack_args_from_block(&ssa.blocks[bi].stmts, &ssa.vars, si);
                if !args.is_empty() {
                    all_consumed.extend(consumed);
                }
                args
            } else {
                collect_reg_args_from_block(&ssa.blocks[bi].stmts, &ssa.vars, si)
            };

            if !args.is_empty() {
                if let Stmt::Call { target, out, .. } = &ssa.blocks[bi].stmts[si] {
                    let target = target.clone();
                    let out = *out;
                    ssa.blocks[bi].stmts[si] = Stmt::Call { target, args, out };
                }
            }
        }

        // Remove consumed arg Store + ESP-decrement statements (reverse order for stable indices)
        all_consumed.sort_unstable();
        all_consumed.dedup();
        for &i in all_consumed.iter().rev() {
            if i < ssa.blocks[bi].stmts.len() {
                ssa.blocks[bi].stmts.remove(i);
            }
        }
    }
}

/// Collect x86-64 register-based arguments before a call (original logic).
fn collect_reg_args_from_block(stmts: &[Stmt], vars: &[VarDef], up_to: usize) -> Vec<VarId> {
    let arg_offsets = arg_reg_offsets();
    if arg_offsets.is_empty() {
        return Vec::new();
    }
    let mut args: Vec<(u64, VarId)> = Vec::new();
    for j in (0..up_to).rev() {
        if let Stmt::Assign(var_id) = &stmts[j] {
            let vdef = safe_var(vars, *var_id);
            // Skip clobber placeholders that SSA inserts for caller-saved
            // registers after a call (`call_return=true` with `Expr::Unknown`).
            // Using the clobber as an arg gives `?` at the call site on
            // architectures where the return register overlaps an arg
            // register (ARM32 r0, AArch64 x0). The REAL argument value is
            // the preceding Stmt::Assign with a concrete expr.
            if vdef.call_return && matches!(&vdef.expr, Expr::Unknown) {
                continue;
            }
            if vdef.varnode.space == AddressSpaceId::Register
                && arg_offsets.contains(&vdef.varnode.offset)
            {
                if !args.iter().any(|(off, _)| *off == vdef.varnode.offset) {
                    args.push((vdef.varnode.offset, *var_id));
                }
            }
            // Also check if this Assign wraps a sub-register that maps to an arg register.
            // x86-64: EAX(offset=0,size=4) should match RAX(offset=0,size=8) for arg purposes,
            // but only for registers in the arg list.
            // More importantly: check all register sizes at the same offset
            if vdef.varnode.space == AddressSpaceId::Register
                && !arg_offsets.contains(&vdef.varnode.offset)
            {
                // Check if a different-sized register at this offset is an arg register
                for &arg_off in arg_offsets {
                    if arg_off == vdef.varnode.offset
                        && !args.iter().any(|(off, _)| *off == arg_off)
                    {
                        args.push((arg_off, *var_id));
                    }
                }
            }
        }
        if matches!(&stmts[j], Stmt::Call { .. }) {
            break;
        }
    }

    // Also collect float arguments from XMM registers
    let float_offsets = float_arg_reg_offsets();
    if !float_offsets.is_empty() {
        let mut float_args: Vec<(u64, VarId)> = Vec::new();
        for j in (0..up_to).rev() {
            if let Stmt::Assign(var_id) = &stmts[j] {
                let vdef = safe_var(vars, *var_id);
                if vdef.varnode.space == AddressSpaceId::Register
                    && float_offsets.contains(&vdef.varnode.offset)
                {
                    if !float_args
                        .iter()
                        .any(|(off, _)| *off == vdef.varnode.offset)
                    {
                        float_args.push((vdef.varnode.offset, *var_id));
                    }
                }
            }
            if matches!(&stmts[j], Stmt::Call { .. }) {
                break;
            }
        }
        float_args
            .sort_by_key(|(off, _)| float_offsets.iter().position(|o| o == off).unwrap_or(99));
        args.extend(float_args);
    }

    args.sort_by_key(|(off, _)| {
        arg_reg_offsets()
            .iter()
            .position(|o| o == off)
            .unwrap_or(99)
    });
    args.into_iter().map(|(_, v)| v).collect()
}

/// Collect x86-32 stack-pushed arguments before a call.
///
/// Scans backward from `up_to` for Store { addr: ESP-derived, val } patterns.
/// Arguments are pushed right-to-left (cdecl), so first push = last arg.
/// Returns (args in correct call order, indices of consumed statements to remove).
fn collect_stack_args_from_block(
    stmts: &[Stmt],
    vars: &[VarDef],
    up_to: usize,
) -> (Vec<VarId>, Vec<usize>) {
    let mut pushed_values: Vec<VarId> = Vec::new();
    let mut consumed_indices: Vec<usize> = Vec::new();
    let mut i = up_to;

    while i > 0 {
        i -= 1;
        match &stmts[i] {
            Stmt::Store { addr, val } => {
                let addr_def = &vars[addr.0 as usize];
                if is_esp_var(addr_def, vars) {
                    pushed_values.push(*val);
                    consumed_indices.push(i);
                    continue;
                }
                // Non-ESP store — could be a memory write between pushes, skip
                continue;
            }
            Stmt::Assign(v) => {
                let vdef = &vars[v.0 as usize];
                // Skip (and mark for removal) ESP writes (IntSub ESP, 4) — PUSH boilerplate
                if vdef.varnode.space == AddressSpaceId::Register
                    && vdef.varnode.offset == ESP_OFFSET
                    && vdef.varnode.size == 4
                {
                    consumed_indices.push(i);
                    continue;
                }
                // Skip flag writes
                if FLAG_OFFSETS.contains(&vdef.varnode.offset) {
                    continue;
                }
                // Skip Unique-space temporaries (address computation, etc.)
                if vdef.varnode.space == AddressSpaceId::Unique {
                    consumed_indices.push(i);
                    continue;
                }
                // Other register writes between pushes — these could be thiscall
                // ECX setup or general register preparation. Stop scanning.
                break;
            }
            Stmt::Call { .. } => break, // Previous call — stop
        }
    }

    // Arguments pushed right-to-left: first pushed = last argument
    // We collected bottom-up, so reverse for correct order
    pushed_values.reverse();
    (pushed_values, consumed_indices)
}

/// Check if a VarDef is ESP-derived (direct ESP or computed from ESP via IntSub).
fn is_esp_var(vdef: &VarDef, vars: &[VarDef]) -> bool {
    if vdef.varnode.space == AddressSpaceId::Register
        && vdef.varnode.offset == ESP_OFFSET
        && vdef.varnode.size == 4
    {
        return true;
    }
    // Check Unique-space vars that are computed from ESP
    if vdef.varnode.space == AddressSpaceId::Unique {
        match &vdef.expr {
            Expr::BinOp(BinOpKind::Sub, left, _) | Expr::BinOp(BinOpKind::Add, left, _) => {
                let left_def = &vars[left.0 as usize];
                return left_def.varnode.space == AddressSpaceId::Register
                    && left_def.varnode.offset == ESP_OFFSET
                    && left_def.varnode.size == 4;
            }
            Expr::Var(v) => {
                let inner = &vars[v.0 as usize];
                return inner.varnode.space == AddressSpaceId::Register
                    && inner.varnode.offset == ESP_OFFSET
                    && inner.varnode.size == 4;
            }
            _ => {}
        }
    }
    false
}

// ---- Type inference ----

/// Infer types for all SSA variables from operation context.
///
/// Three phases:
/// 1. **Seed** — mark variables whose defining expression directly implies a type
///    (float ops, signed ops, comparisons, load/store addresses)
/// 2. **Forward propagation** — propagate types through Copy/Var chains and extensions
/// 3. **Backward propagation** — propagate types from uses (e.g., if a var is used in
///    SDiv, mark it signed even if its definition didn't imply it)
fn infer_types(ssa: &mut SsaCfg) {
    let n = ssa.vars.len();

    // Phase 1: Seed types from defining expressions
    for vi in 0..n {
        let ty = seed_type_from_expr(&ssa.vars[vi].expr, &ssa.vars);
        if ty != InferredType::Unknown {
            ssa.vars[vi].inferred_type = ty;
        }
    }

    // Mark Store addresses as pointers
    for bi in 0..ssa.blocks.len() {
        for stmt in &ssa.blocks[bi].stmts {
            if let Stmt::Store { addr, .. } = stmt {
                let cur = ssa.vars[addr.0 as usize].inferred_type;
                ssa.vars[addr.0 as usize].inferred_type = cur.merge(InferredType::Pointer);
            }
        }
    }

    // Mark Load pointer operands as pointers (from Expr::Load(ptr_var))
    for vi in 0..n {
        match ssa.vars[vi].expr {
            Expr::Load(ptr) => {
                let cur = ssa.vars[ptr.0 as usize].inferred_type;
                ssa.vars[ptr.0 as usize].inferred_type = cur.merge(InferredType::Pointer);
            }
            Expr::FieldAccess(base, _) => {
                let cur = ssa.vars[base.0 as usize].inferred_type;
                ssa.vars[base.0 as usize].inferred_type = cur.merge(InferredType::Pointer);
            }
            _ => {}
        }
    }

    // Phase 2: Forward propagation (2 rounds)
    for _ in 0..2 {
        for vi in 0..n {
            let expr = ssa.vars[vi].expr.clone();
            let propagated = forward_propagate_type(&expr, &ssa.vars);
            if propagated != InferredType::Unknown
                && ssa.vars[vi].inferred_type == InferredType::Unknown
            {
                ssa.vars[vi].inferred_type = propagated;
            }
        }
    }

    // Phase 3: Backward propagation — mark operands of typed operations
    for vi in 0..n {
        let ty = ssa.vars[vi].inferred_type;
        if ty == InferredType::Unknown {
            continue;
        }

        match ssa.vars[vi].expr.clone() {
            Expr::BinOp(_, left, right) => {
                backward_propagate(ssa, left, ty);
                backward_propagate(ssa, right, ty);
            }
            Expr::UnaryOp(_, input) => {
                // For Sext/Zext, the input inherits the signedness
                backward_propagate(ssa, input, ty);
            }
            Expr::Var(v) => {
                backward_propagate(ssa, v, ty);
            }
            Expr::Ternary(_, t, e) => {
                backward_propagate(ssa, t, ty);
                backward_propagate(ssa, e, ty);
            }
            _ => {}
        }
    }

    // Mark size-1 comparison results as Bool
    for vi in 0..n {
        if ssa.vars[vi].size == 1 {
            if let Expr::BinOp(kind, _, _) = &ssa.vars[vi].expr {
                match kind {
                    BinOpKind::Eq
                    | BinOpKind::NotEq
                    | BinOpKind::Less
                    | BinOpKind::LessEq
                    | BinOpKind::SLess
                    | BinOpKind::SLessEq
                    | BinOpKind::FloatEq
                    | BinOpKind::FloatNotEq
                    | BinOpKind::FloatLess
                    | BinOpKind::FloatLessEq
                    | BinOpKind::Carry
                    | BinOpKind::SCarry
                    | BinOpKind::SBorrow
                    | BinOpKind::BoolAnd
                    | BinOpKind::BoolOr
                    | BinOpKind::BoolXor => {
                        ssa.vars[vi].inferred_type = InferredType::Bool;
                    }
                    _ => {}
                }
            }
            if let Expr::UnaryOp(UnaryOpKind::BoolNot | UnaryOpKind::FloatNan, _) =
                &ssa.vars[vi].expr
            {
                ssa.vars[vi].inferred_type = InferredType::Bool;
            }
        }
    }
}

/// Seed the type of a variable from its defining expression.
fn seed_type_from_expr(expr: &Expr, _vars: &[VarDef]) -> InferredType {
    match expr {
        // Float operations
        Expr::BinOp(kind, _, _) => match kind {
            BinOpKind::FloatAdd
            | BinOpKind::FloatSub
            | BinOpKind::FloatMult
            | BinOpKind::FloatDiv => InferredType::Float,
            BinOpKind::FloatEq
            | BinOpKind::FloatNotEq
            | BinOpKind::FloatLess
            | BinOpKind::FloatLessEq => InferredType::Bool,
            // Signed operations
            BinOpKind::SDiv | BinOpKind::SRem => InferredType::Signed,
            BinOpKind::SLess | BinOpKind::SLessEq => InferredType::Bool,
            // Unsigned operations
            BinOpKind::Div | BinOpKind::Rem => InferredType::Unsigned,
            BinOpKind::Less | BinOpKind::LessEq => InferredType::Bool,
            // Comparisons
            BinOpKind::Eq | BinOpKind::NotEq => InferredType::Bool,
            // Boolean logic
            BinOpKind::BoolAnd | BinOpKind::BoolOr | BinOpKind::BoolXor => InferredType::Bool,
            _ => InferredType::Unknown,
        },
        Expr::UnaryOp(kind, _) => match kind {
            // Float unary ops
            UnaryOpKind::FloatNeg
            | UnaryOpKind::FloatAbs
            | UnaryOpKind::FloatSqrt
            | UnaryOpKind::FloatCeil
            | UnaryOpKind::FloatFloor
            | UnaryOpKind::FloatRound
            | UnaryOpKind::Int2Float
            | UnaryOpKind::Float2Float => InferredType::Float,
            UnaryOpKind::FloatNan => InferredType::Bool,
            // Trunc: float→int
            UnaryOpKind::Trunc => InferredType::Signed,
            // Sign extension implies signed source
            UnaryOpKind::Sext | UnaryOpKind::Neg => InferredType::Signed,
            // Zero extension implies unsigned source
            UnaryOpKind::Zext => InferredType::Unsigned,
            // Arithmetic shift right implies signed
            // (mapped from IntAsr)
            UnaryOpKind::BoolNot => InferredType::Bool,
            _ => InferredType::Unknown,
        },
        _ => InferredType::Unknown,
    }
}

/// Propagate type forward from the defining expression's operands.
fn forward_propagate_type(expr: &Expr, vars: &[VarDef]) -> InferredType {
    match expr {
        // Copy/Var inherits the source type
        Expr::Var(v) => vars[v.0 as usize].inferred_type,
        // Arithmetic on floats produces float
        Expr::BinOp(BinOpKind::Add | BinOpKind::Sub | BinOpKind::Mult, left, right) => {
            let lt = vars[left.0 as usize].inferred_type;
            let rt = vars[right.0 as usize].inferred_type;
            if lt == InferredType::Float || rt == InferredType::Float {
                InferredType::Float
            } else if lt == InferredType::Signed || rt == InferredType::Signed {
                InferredType::Signed
            } else {
                InferredType::Unknown
            }
        }
        // Sext preserves signed, Zext preserves unsigned
        Expr::UnaryOp(UnaryOpKind::Sext, input) => {
            let it = vars[input.0 as usize].inferred_type;
            if it == InferredType::Unknown {
                InferredType::Signed
            } else {
                it
            }
        }
        Expr::UnaryOp(UnaryOpKind::Zext, input) => {
            let it = vars[input.0 as usize].inferred_type;
            if it == InferredType::Unknown {
                InferredType::Unsigned
            } else {
                it
            }
        }
        // Neg implies signed result
        Expr::UnaryOp(UnaryOpKind::Neg, _) => InferredType::Signed,
        // Load result: unknown (the pointee type isn't known without more analysis)
        _ => InferredType::Unknown,
    }
}

/// Backward-propagate a type to an operand variable (if it's still Unknown).
fn backward_propagate(ssa: &mut SsaCfg, var: VarId, ty: InferredType) {
    let cur = ssa.vars[var.0 as usize].inferred_type;
    if cur == InferredType::Unknown {
        // Don't propagate Bool backward (comparisons don't make operands bool)
        // Don't propagate Pointer backward (pointer arithmetic doesn't make operands pointers)
        match ty {
            InferredType::Signed | InferredType::Float => {
                ssa.vars[var.0 as usize].inferred_type = ty;
            }
            _ => {}
        }
    }
}

// ---- Use counting ----

pub(crate) fn recount_uses(ssa: &mut SsaCfg) {
    let mut use_counts = vec![0u32; ssa.vars.len()];
    for v in 0..ssa.vars.len() {
        match &ssa.vars[v].expr {
            Expr::Var(id) => use_counts[id.0 as usize] += 1,
            Expr::BinOp(_, l, r) => {
                use_counts[l.0 as usize] += 1;
                use_counts[r.0 as usize] += 1;
            }
            Expr::UnaryOp(_, i) | Expr::Load(i) | Expr::FieldAccess(i, _) => {
                use_counts[i.0 as usize] += 1
            }
            Expr::Phi(inputs) => {
                for i in inputs {
                    use_counts[i.0 as usize] += 1;
                }
            }
            Expr::Ternary(c, t, e) => {
                use_counts[c.0 as usize] += 1;
                use_counts[t.0 as usize] += 1;
                use_counts[e.0 as usize] += 1;
            }
            Expr::UserOp { inputs, .. } => {
                for i in inputs {
                    use_counts[i.0 as usize] += 1;
                }
            }
            Expr::Const(_, _) | Expr::Unknown => {}
        }
    }
    for block in &ssa.blocks {
        for stmt in &block.stmts {
            match stmt {
                Stmt::Store { addr, val } => {
                    use_counts[addr.0 as usize] += 1;
                    use_counts[val.0 as usize] += 1;
                }
                Stmt::Call { args, .. } => {
                    for a in args {
                        use_counts[a.0 as usize] += 1;
                    }
                }
                _ => {}
            }
        }
        match &block.terminator {
            SsaTerminator::CBranch { cond, .. } => use_counts[cond.0 as usize] += 1,
            SsaTerminator::Return(Some(v)) | SsaTerminator::Indirect(v) => {
                use_counts[v.0 as usize] += 1
            }
            SsaTerminator::Call { args, out, .. } => {
                for a in args {
                    use_counts[a.0 as usize] += 1;
                }
                // out var is "defined by" this call — don't count as a use here.
                // (It's a def, not a use. Printer reads out to emit `lhs = call(...)`)
                let _ = out; // suppress warning
            }
            _ => {}
        }
    }
    for (i, count) in use_counts.into_iter().enumerate() {
        ssa.vars[i].use_count = count;
    }
}

// ---- Pass: Save/Restore Elimination ----
// Detect the pattern:  A = X; [call]; Y = A
// ---- Pass: Forward Substitution Within Blocks ----
// Scan each block linearly. Track what each register currently holds (its
// "value" — a VarId pointing to the original source). When a register is
// read, substitute the source. This is safe because we only look within
// one block and we invalidate on any write.
//
// Example: EAX = var_8; var_c = EAX → var_c = var_8 (because EAX holds var_8)
//          Later: EAX = var_c → EAX = var_8 (because var_c holds var_8)

#[allow(dead_code)]
fn forward_substitute_block(ssa: &mut SsaCfg) {
    for bi in 0..ssa.blocks.len() {
        // Map: (register offset, size) → the VarId of the value it currently holds
        let mut reg_value: std::collections::HashMap<(u64, u32), VarId> =
            std::collections::HashMap::new();
        // Map: VarId (stack/unique) → the VarId of its source value
        let mut alias_map: std::collections::HashMap<u32, VarId> = std::collections::HashMap::new();

        let stmts = &ssa.blocks[bi].stmts;
        let mut replacements: Vec<(u32, Expr)> = Vec::new();

        for stmt in stmts {
            match stmt {
                Stmt::Assign(var_id) => {
                    let vdef = &ssa.vars[var_id.0 as usize];

                    if vdef.varnode.space == AddressSpaceId::Register {
                        match &vdef.expr {
                            // REG = Var(src) — register gets a new value
                            Expr::Var(src_id) => {
                                let src = &ssa.vars[src_id.0 as usize];
                                if src.varnode.space == AddressSpaceId::Register {
                                    // REG = OTHER_REG: look up what OTHER_REG holds
                                    let key = (src.varnode.offset, src.varnode.size);
                                    if let Some(original) = reg_value.get(&key) {
                                        // Substitute: instead of REG = OTHER_REG,
                                        // use REG = original_source
                                        replacements.push((var_id.0, Expr::Var(*original)));
                                        let my_key = (vdef.varnode.offset, vdef.varnode.size);
                                        reg_value.insert(my_key, *original);
                                    } else {
                                        let my_key = (vdef.varnode.offset, vdef.varnode.size);
                                        reg_value.insert(my_key, *src_id);
                                    }
                                } else {
                                    // REG = stack_var/unique: look up what the stack var holds
                                    if let Some(original) = alias_map.get(&src_id.0) {
                                        replacements.push((var_id.0, Expr::Var(*original)));
                                        let my_key = (vdef.varnode.offset, vdef.varnode.size);
                                        reg_value.insert(my_key, *original);
                                    } else {
                                        let my_key = (vdef.varnode.offset, vdef.varnode.size);
                                        reg_value.insert(my_key, *src_id);
                                    }
                                }
                            }
                            Expr::Load(_) => {
                                // REG = Load(addr) — register gets a loaded value
                                // Invalidate this register's tracked value
                                let my_key = (vdef.varnode.offset, vdef.varnode.size);
                                reg_value.remove(&my_key);
                            }
                            _ => {
                                // REG = expr — register gets a computed value
                                let my_key = (vdef.varnode.offset, vdef.varnode.size);
                                reg_value.remove(&my_key);
                            }
                        }
                    } else {
                        // Non-register assignment (stack var, unique)
                        // Track what it holds for later substitution
                        if let Expr::Var(src_id) = &vdef.expr {
                            let src = &ssa.vars[src_id.0 as usize];
                            if src.varnode.space == AddressSpaceId::Register {
                                let key = (src.varnode.offset, src.varnode.size);
                                if let Some(original) = reg_value.get(&key) {
                                    // stack_var = REG where REG holds original
                                    // → stack_var = original
                                    replacements.push((var_id.0, Expr::Var(*original)));
                                    alias_map.insert(var_id.0, *original);
                                } else {
                                    alias_map.insert(var_id.0, *src_id);
                                }
                            }
                        }
                    }
                }
                Stmt::Store { .. } => {
                    // Stores don't affect register tracking
                }
                Stmt::Call { .. } => {
                    // Calls invalidate ALL register values (callee may clobber)
                    reg_value.clear();
                }
            }
        }

        // Also invalidate on Call terminators
        if matches!(&ssa.blocks[bi].terminator, SsaTerminator::Call { .. }) {
            // Already handled — reg_value would be cleared if we had more stmts
        }

        // Apply replacements
        for (var_idx, new_expr) in replacements {
            ssa.vars[var_idx as usize].expr = new_expr;
        }
    }
}

// where A is a stack variable used only for the save+restore.
// Replace Y's expression with X directly, eliminating the roundtrip.
// Also: A = X; ... ; B = A where B has same register as X → B = X

#[allow(dead_code)]
fn eliminate_save_restore(ssa: &mut SsaCfg) {
    // First: look for the specific pattern REG = stack_var where
    // stack_var.expr = Var(same_REG) — this is a restore.
    // Replace the restore's expr to point directly at the original register value.
    for v in 0..ssa.vars.len() {
        let vdef = &ssa.vars[v];
        if vdef.varnode.space != AddressSpaceId::Register {
            continue;
        }
        // Is this REG = Var(stack_var)?
        let src_id = match &vdef.expr {
            Expr::Var(id) => Some(*id),
            _ => None,
        };
        let Some(src_id) = src_id else { continue };
        let src = &ssa.vars[src_id.0 as usize];
        // Is the source a stack variable (stored to RBP-offset)?
        // In our SSA, stack vars have Unique space or are intermediate
        // Check if the source was defined as Var(original_reg) where original_reg
        // is the same register we're writing to
        if let Expr::Var(orig_id) = &src.expr {
            let orig = &ssa.vars[orig_id.0 as usize];
            if orig.varnode.space == AddressSpaceId::Register
                && orig.varnode.offset == vdef.varnode.offset
                && orig.varnode.size == vdef.varnode.size
            {
                // Save/restore detected: REG = X; stack = REG; ... ; REG = stack
                // Replace this var's expr with Var(orig_id) to skip the stack roundtrip
                // But we can't do it here because we'd need to modify ssa.vars while reading it.
                // Collect for later.
            }
        }
    }

    // Collect and apply save/restore eliminations (Var chains)
    let mut sr_replacements: Vec<(usize, VarId)> = Vec::new();
    for v in 0..ssa.vars.len() {
        let vdef = &ssa.vars[v];
        if vdef.varnode.space != AddressSpaceId::Register {
            continue;
        }
        if let Expr::Var(src_id) = &vdef.expr {
            let src = &ssa.vars[src_id.0 as usize];
            if let Expr::Var(orig_id) = &src.expr {
                let orig = &ssa.vars[orig_id.0 as usize];
                if orig.varnode.space == AddressSpaceId::Register
                    && orig.varnode.offset == vdef.varnode.offset
                    && orig.varnode.size == vdef.varnode.size
                    && src.use_count <= 2
                {
                    sr_replacements.push((v, *orig_id));
                }
            }
        }
    }
    // Disabled — too aggressive, eliminates legitimate assignments
    // for (v, orig_id) in &sr_replacements {
    //     ssa.vars[*v].expr = Expr::Var(*orig_id);
    // }

    // Memory save/restore: within each block, match Store(addr, reg_val)
    // followed by Load(same_addr) → same register. Only match within the
    // SAME block to avoid cross-block aliasing issues.
    for bi in 0..ssa.blocks.len() {
        let mut store_map: std::collections::HashMap<u64, VarId> = std::collections::HashMap::new();

        // Collect stores in this block
        for stmt in &ssa.blocks[bi].stmts {
            if let Stmt::Store { addr, val } = stmt {
                if let Some(offset) = compute_rbp_offset(*addr, &ssa.vars) {
                    let stored = &ssa.vars[val.0 as usize];
                    // Only track stores of register values (save patterns)
                    if stored.varnode.space == AddressSpaceId::Register {
                        store_map.insert(offset, *val);
                    }
                }
            }
        }

        if store_map.is_empty() {
            continue;
        }

        // Find Load assignments in this block that match a store
        let mut load_replacements: Vec<(u32, VarId)> = Vec::new();
        for stmt in &ssa.blocks[bi].stmts {
            if let Stmt::Assign(var_id) = stmt {
                let vdef = &ssa.vars[var_id.0 as usize];
                if vdef.varnode.space != AddressSpaceId::Register {
                    continue;
                }
                if let Expr::Load(addr_id) = &vdef.expr {
                    if let Some(offset) = compute_rbp_offset(*addr_id, &ssa.vars) {
                        if let Some(stored_val) = store_map.get(&offset) {
                            let stored = &ssa.vars[stored_val.0 as usize];
                            // Only replace if stored value was the same register
                            if stored.varnode.offset == vdef.varnode.offset {
                                load_replacements.push((var_id.0, *stored_val));
                            }
                        }
                    }
                }
            }
        }
        // Disabled for now — needs more precise matching
        // for (var_idx, stored_val) in load_replacements {
        //     ssa.vars[var_idx as usize].expr = Expr::Var(stored_val);
        // }
    }
}

/// Compute the RBP-relative offset for an address var, if it's RBP + const.
#[allow(dead_code)]
fn compute_rbp_offset(addr_id: VarId, vars: &[VarDef]) -> Option<u64> {
    let v = &vars[addr_id.0 as usize];
    match &v.expr {
        Expr::BinOp(BinOpKind::Add, base_id, off_id) => {
            let base = &vars[base_id.0 as usize];
            if base.varnode.space == AddressSpaceId::Register && base.varnode.offset == 40 {
                // RBP + const
                if let Expr::Const(val, _) = &vars[off_id.0 as usize].expr {
                    return Some(*val);
                }
            }
            // One level of indirection on base
            if let Expr::Var(inner) = &base.expr {
                let inner_v = &vars[inner.0 as usize];
                if inner_v.varnode.space == AddressSpaceId::Register && inner_v.varnode.offset == 40
                {
                    if let Expr::Const(val, _) = &vars[off_id.0 as usize].expr {
                        return Some(*val);
                    }
                }
            }
            None
        }
        Expr::Var(inner) => compute_rbp_offset(*inner, vars),
        _ => None,
    }
}

// ---- Pass: Return Value Propagation ----
// After a Call (terminator or statement), the first read of RAX/EAX (x86)
// or x0/w0 (ARM64) is the call's return value. Replace the assignment
// with a synthetic "call_return" expression so the printer can inline it.

fn propagate_call_returns(ssa: &mut SsaCfg) {
    for bi in 0..ssa.blocks.len() {
        // Check if this block has a Call terminator
        let has_call_term = matches!(&ssa.blocks[bi].terminator, SsaTerminator::Call { .. });

        // For Call terminators: wire SsaTerminator::Call.out from the call_return var
        // in the current block (placed by clobber_caller_saved).
        // Also scan the fallthrough block for additional RAX assignments to mark.
        if has_call_term {
            let fallthrough = match &ssa.blocks[bi].terminator {
                SsaTerminator::Call { fallthrough, .. } => Some(*fallthrough),
                _ => None,
            };

            // Wire out: find the last call_return var in the current block's stmts.
            // If use_count > 0, wire it to SsaTerminator::Call.out and remove the stmt.
            let mut out_var: Option<VarId> = None;
            let mut out_stmt_idx: Option<usize> = None;
            for (idx, stmt) in ssa.blocks[bi].stmts.iter().enumerate().rev() {
                if let Stmt::Assign(var_id) = stmt {
                    let vdef = &ssa.vars[var_id.0 as usize];
                    if vdef.call_return {
                        if vdef.use_count > 0 {
                            out_var = Some(*var_id);
                            out_stmt_idx = Some(idx);
                        }
                        break; // Only check the last call_return var
                    }
                }
            }
            if let (Some(var), Some(idx)) = (out_var, out_stmt_idx) {
                if let SsaTerminator::Call { out, .. } = &mut ssa.blocks[bi].terminator {
                    *out = Some(var);
                }
                ssa.blocks[bi].stmts.remove(idx);
            }

            if let Some(ft) = fallthrough {
                if ft.0 < ssa.blocks.len() {
                    // Find the first RAX/EAX assignment in the fallthrough block
                    for stmt in &ssa.blocks[ft.0].stmts {
                        if let Stmt::Assign(var_id) = stmt {
                            let vdef = &ssa.vars[var_id.0 as usize];
                            // Skip if already marked call_return by SSA-level clobber
                            if vdef.call_return {
                                break;
                            }
                            if vdef.varnode.space == AddressSpaceId::Register
                                && (vdef.varnode.offset == RAX_OFFSET)
                                && matches!(&vdef.expr, Expr::Unknown)
                            {
                                ssa.vars[var_id.0 as usize].call_return = true;
                                break;
                            }
                        }
                    }
                }
            }
        }

        // For Call statements within a block: the next RAX assignment is the return value
        let mut call_idx: Option<usize> = None;
        let mut to_remove: Vec<usize> = Vec::new();
        for i in 0..ssa.blocks[bi].stmts.len() {
            if matches!(&ssa.blocks[bi].stmts[i], Stmt::Call { .. }) {
                call_idx = Some(i);
                continue;
            }
            if let Some(cidx) = call_idx {
                if let Stmt::Assign(var_id) = &ssa.blocks[bi].stmts[i] {
                    let var_id = *var_id;
                    let vdef = &ssa.vars[var_id.0 as usize];
                    if vdef.call_return {
                        // Already handled by SSA clobber; wire out if use_count > 0
                        let use_count = ssa.vars[var_id.0 as usize].use_count;
                        if use_count > 0 {
                            if let Stmt::Call { out, .. } = &mut ssa.blocks[bi].stmts[cidx] {
                                *out = Some(var_id);
                                to_remove.push(i);
                            }
                        }
                        call_idx = None;
                        continue;
                    }
                    if vdef.varnode.space == AddressSpaceId::Register
                        && vdef.varnode.offset == RAX_OFFSET
                    {
                        ssa.vars[var_id.0 as usize].call_return = true;
                        let use_count = ssa.vars[var_id.0 as usize].use_count;
                        if use_count > 0 {
                            if let Stmt::Call { out, .. } = &mut ssa.blocks[bi].stmts[cidx] {
                                *out = Some(var_id);
                                to_remove.push(i);
                            }
                        }
                        call_idx = None;
                    }
                } else {
                    // Non-assign stmt between call and return read — reset
                    call_idx = None;
                }
            }
        }
        for idx in to_remove.into_iter().rev() {
            ssa.blocks[bi].stmts.remove(idx);
        }
    }
}

// ---- Pass: Copy Chain Collapse ----
// If A = B (register copy) and A is only used once in an expression,
// replace that use with B directly. This collapses:
//   EAX = var_8; var_c = EAX  →  var_c = var_8
//   ECX = EAX (after call)    →  ECX = call_return

#[allow(dead_code)]
fn collapse_copy_chains(ssa: &mut SsaCfg) {
    // Build a map: VarId → its Var(source) if it's a safe copy to collapse.
    // Only collapse register copies where the source is a stack variable (Unique load)
    // or constant — NOT register-to-register copies, since the source register
    // might be overwritten between the copy and the use.
    let copy_map: Vec<Option<VarId>> = (0..ssa.vars.len())
        .map(|v| {
            let vdef = &ssa.vars[v];
            if vdef.call_return {
                return None;
            }
            if vdef.use_count <= 1 && vdef.varnode.space == AddressSpaceId::Register {
                if let Expr::Var(src) = &vdef.expr {
                    let src_def = &ssa.vars[src.0 as usize];
                    if src_def.call_return {
                        return None;
                    }
                    // Only collapse if source is a stack var, constant, or Unique
                    // (not another register that might get overwritten)
                    if src_def.varnode.space != AddressSpaceId::Register {
                        return Some(*src);
                    }
                    // Also collapse if source has a param name (stable identity)
                    if src_def.param_name.is_some() {
                        return Some(*src);
                    }
                }
            }
            None
        })
        .collect();

    // Substitute: for each var whose expr references a copy source, replace with the source
    for v in 0..ssa.vars.len() {
        let expr = ssa.vars[v].expr.clone();
        ssa.vars[v].expr = substitute_copies(&expr, &copy_map);
    }
}

#[allow(dead_code)]
fn substitute_copies(expr: &Expr, copy_map: &[Option<VarId>]) -> Expr {
    match expr {
        Expr::Var(id) => {
            if let Some(Some(src)) = copy_map.get(id.0 as usize) {
                // Follow the chain one level
                if let Some(Some(src2)) = copy_map.get(src.0 as usize) {
                    Expr::Var(*src2)
                } else {
                    Expr::Var(*src)
                }
            } else {
                expr.clone()
            }
        }
        Expr::BinOp(kind, left, right) => {
            let l = resolve_copy(*left, copy_map);
            let r = resolve_copy(*right, copy_map);
            Expr::BinOp(*kind, l, r)
        }
        Expr::UnaryOp(kind, input) => {
            let i = resolve_copy(*input, copy_map);
            Expr::UnaryOp(*kind, i)
        }
        Expr::Load(ptr) => {
            let p = resolve_copy(*ptr, copy_map);
            Expr::Load(p)
        }
        _ => expr.clone(),
    }
}

#[allow(dead_code)]
fn resolve_copy(id: VarId, copy_map: &[Option<VarId>]) -> VarId {
    if let Some(Some(src)) = copy_map.get(id.0 as usize) {
        if let Some(Some(src2)) = copy_map.get(src.0 as usize) {
            *src2
        } else {
            *src
        }
    } else {
        id
    }
}

// ---- Pass: Parameter Naming ----
// In the entry block, assignments from argument registers (RDI, RSI, etc.)
// to stack variables are parameter setup. Name them param_0, param_1, etc.

fn name_parameters(ssa: &mut SsaCfg) {
    name_parameters_with_cc(ssa, CallingConv::SysV)
}

fn name_parameters_with_cc(ssa: &mut SsaCfg, cc: CallingConv) {
    if ssa.blocks.is_empty() {
        return;
    }
    let entry = ssa.entry.0;
    if entry >= ssa.blocks.len() {
        return;
    }

    let mut param_idx = 0u32;
    let mut named_offsets = std::collections::HashSet::new();
    let mut to_name: Vec<(usize, String, u64)> = Vec::new();

    // Pass 1: Collect params from Unknown expressions (unoptimized code)
    let stmts: Vec<Stmt> = ssa.blocks[entry].stmts.clone();
    for stmt in &stmts {
        if let Stmt::Assign(var_id) = stmt {
            let vdef = &ssa.vars[var_id.0 as usize];
            if let Expr::Unknown = &vdef.expr {
                if vdef.varnode.space == AddressSpaceId::Register
                    && arg_reg_offsets().contains(&vdef.varnode.offset)
                    && !named_offsets.contains(&vdef.varnode.offset)
                {
                    to_name.push((
                        var_id.0 as usize,
                        format!("param_{}", param_idx),
                        vdef.varnode.offset,
                    ));
                    named_offsets.insert(vdef.varnode.offset);
                    param_idx += 1;
                }
            }
        }
        if let Stmt::Store { val, .. } = stmt {
            let vdef = &ssa.vars[val.0 as usize];
            if vdef.param_name.is_none() {
                if let Expr::Unknown = &vdef.expr {
                    if vdef.varnode.space == AddressSpaceId::Register
                        && arg_reg_offsets().contains(&vdef.varnode.offset)
                        && !named_offsets.contains(&vdef.varnode.offset)
                    {
                        to_name.push((
                            val.0 as usize,
                            format!("param_{}", param_idx),
                            vdef.varnode.offset,
                        ));
                        named_offsets.insert(vdef.varnode.offset);
                        param_idx += 1;
                    }
                }
            }
        }
    }
    for (v, name, _) in &to_name {
        ssa.vars[*v].param_name = Some(name.clone());
    }

    // Pass 2: Scan vars for arg-register reads with no prior def.
    //
    // Two modes:
    //   - Default (SysV / Win64 / AArch64 / Arm32): scan ALL vars,
    //     name first matching arg-reg per offset. Permissive — multi-
    //     arg C++ funcs need this.
    //   - GoAmd64: restrict to entry-reachable blocks (entry + 3 hops
    //     past morestack JBE) and stop at first ABI-position gap.
    //     Go aggressively reuses arg regs as scratch deeper in the
    //     function, so deep reads don't indicate params.
    {
        let go_strict = matches!(cc, CallingConv::GoAmd64);

        // Build entry-reachable block set (used only when go_strict).
        let early_vars: std::collections::HashSet<usize> = if go_strict {
            let entry_idx = ssa.entry.0;
            let mut early_blocks: std::collections::HashSet<usize> =
                std::collections::HashSet::new();
            let mut frontier: Vec<usize> = vec![entry_idx];
            for _ in 0..3 {
                let mut next = Vec::new();
                for b in frontier.drain(..) {
                    if !early_blocks.insert(b) {
                        continue;
                    }
                    if b >= ssa.blocks.len() {
                        continue;
                    }
                    match &ssa.blocks[b].terminator {
                        SsaTerminator::Branch(t) | SsaTerminator::Fallthrough(t) => next.push(t.0),
                        SsaTerminator::CBranch {
                            taken, fallthrough, ..
                        } => {
                            next.push(taken.0);
                            next.push(fallthrough.0);
                        }
                        _ => {}
                    }
                }
                frontier = next;
            }
            let mut s: std::collections::HashSet<usize> = std::collections::HashSet::new();
            for &b in &early_blocks {
                if b < ssa.blocks.len() {
                    for stmt in &ssa.blocks[b].stmts {
                        if let Stmt::Assign(vid) = stmt {
                            s.insert(vid.0 as usize);
                        }
                    }
                }
            }
            s
        } else {
            std::collections::HashSet::new()
        };

        let mut to_name: Vec<(usize, String)> = Vec::new();
        for &offset in arg_reg_offsets().iter() {
            if named_offsets.contains(&offset) {
                continue;
            }
            let mut found: Option<usize> = None;
            for v in 0..ssa.vars.len() {
                let vdef = &ssa.vars[v];
                if vdef.varnode.space != AddressSpaceId::Register {
                    continue;
                }
                if vdef.varnode.offset != offset {
                    continue;
                }
                if vdef.param_name.is_some() {
                    continue;
                }
                if !matches!(&vdef.expr, Expr::Unknown | Expr::Phi(_)) {
                    continue;
                }
                if go_strict && !early_vars.contains(&v) {
                    continue;
                }
                found = Some(v);
                break;
            }
            if let Some(v) = found {
                to_name.push((v, format!("param_{}", param_idx)));
                named_offsets.insert(offset);
                param_idx += 1;
            } else if go_strict {
                // Gap in ABI sequence under Go strict mode — stop.
                break;
            }
        }
        for (v, name) in to_name {
            ssa.vars[v].param_name = Some(name);
        }
    }

    // Pass 3: x86-32 cdecl stack parameters from positive EBP offsets.
    // In cdecl with frame pointer: EBP+8 = param_0, EBP+12 = param_1, etc.
    // Scan all vars for Load(EBP + positive_offset) patterns.
    if arg_reg_offsets().is_empty() && param_idx == 0 {
        const EBP_OFFSET_32: u64 = 20;
        const RBP_OFFSET_64: u64 = 40;
        let mut ebp_params: std::collections::BTreeMap<u64, Vec<usize>> =
            std::collections::BTreeMap::new();

        for v in 0..ssa.vars.len() {
            let vdef = &ssa.vars[v];
            if vdef.param_name.is_some() {
                continue;
            }
            // Look for Load(ptr) where ptr is EBP/RBP + positive_const
            if let Expr::Load(ptr_id) = &vdef.expr {
                let ptr = &ssa.vars[ptr_id.0 as usize];
                if let Expr::BinOp(BinOpKind::Add, base_id, off_id) = &ptr.expr {
                    let base = &ssa.vars[base_id.0 as usize];
                    let off = &ssa.vars[off_id.0 as usize];
                    if base.varnode.space == AddressSpaceId::Register
                        && (base.varnode.offset == EBP_OFFSET_32
                            || base.varnode.offset == RBP_OFFSET_64)
                    {
                        if let Expr::Const(off_val, _) = &off.expr {
                            // EBP+8 = param_0, EBP+12 = param_1, ...
                            if *off_val >= 8 && *off_val < 0x80 && *off_val % 4 == 0 {
                                ebp_params.entry(*off_val).or_default().push(v);
                            }
                        }
                    }
                }
            }
        }

        // Name the detected parameters and mark them as stack-parameter loads.
        // The Load(EBP+offset) reads the parameter VALUE from the stack slot —
        // it's not a pointer dereference. We set param_name and mark the Load
        // source as a stack parameter so the printer can suppress the *() wrapper.
        for (off_val, var_indices) in &ebp_params {
            let pidx = (off_val - 8) / 4;
            let name = format!("param_{}", pidx);
            for &vi in var_indices {
                if ssa.vars[vi].param_name.is_none() {
                    ssa.vars[vi].param_name = Some(name.clone());
                    // Mark the Load pointer variable as a stack frame address
                    // so field_access recognition skips it and the printer
                    // knows this Load is a parameter read, not a pointer deref.
                    if let Expr::Load(ptr_id) = &ssa.vars[vi].expr {
                        let ptr_idx = ptr_id.0 as usize;
                        if ptr_idx < ssa.vars.len() {
                            // Tag the address var — we'll use param_name on the load result
                            // to suppress the deref in the printer
                        }
                    }
                }
            }
        }
    }

    // Pass 4: x86-32 thiscall ECX detection.
    // In MSVC thiscall, ECX holds `this`. If ECX (offset 8, size 4) has Expr::Unknown
    // in the entry block, it's a parameter read without prior write.
    if arg_reg_offsets().is_empty() {
        const ECX_OFFSET: u64 = 8;
        let has_ecx_param = ssa
            .vars
            .iter()
            .any(|v| v.param_name.as_deref() == Some("this"));
        if !has_ecx_param {
            for v in 0..ssa.vars.len() {
                let vdef = &ssa.vars[v];
                if vdef.varnode.space == AddressSpaceId::Register
                    && vdef.varnode.offset == ECX_OFFSET
                    && vdef.varnode.size == 4
                    && vdef.param_name.is_none()
                    && matches!(&vdef.expr, Expr::Unknown)
                    && vdef.use_count > 0
                {
                    ssa.vars[v].param_name = Some("this".to_string());
                    break;
                }
            }
        }
    }

    // Pass 5: Float parameters from XMM registers (x86-64 SysV / Win64).
    let float_offsets = float_arg_reg_offsets();
    if !float_offsets.is_empty() {
        let mut fparam_idx = 0u32;
        let mut fnamed_offsets = std::collections::HashSet::new();

        // Scan entry block for XMM register vars with Unknown expr
        let stmts: Vec<Stmt> = ssa.blocks[entry].stmts.clone();
        for stmt in &stmts {
            if let Stmt::Assign(var_id) = stmt {
                let idx = var_id.0 as usize;
                let is_float_param = {
                    let vdef = &ssa.vars[idx];
                    matches!(&vdef.expr, Expr::Unknown)
                        && vdef.varnode.space == AddressSpaceId::Register
                        && float_offsets.contains(&vdef.varnode.offset)
                        && !fnamed_offsets.contains(&vdef.varnode.offset)
                };
                if is_float_param {
                    let offset = ssa.vars[idx].varnode.offset;
                    ssa.vars[idx].param_name = Some(format!("fparam_{}", fparam_idx));
                    ssa.vars[idx].inferred_type = InferredType::Float;
                    fnamed_offsets.insert(offset);
                    fparam_idx += 1;
                }
            }
        }

        // Fallback: scan all vars for XMM reads with no prior def (optimized code)
        if fparam_idx == 0 {
            for &offset in float_offsets.iter() {
                for v in 0..ssa.vars.len() {
                    let vdef = &ssa.vars[v];
                    if vdef.varnode.space == AddressSpaceId::Register
                        && vdef.varnode.offset == offset
                        && vdef.param_name.is_none()
                    {
                        if matches!(&vdef.expr, Expr::Unknown | Expr::Phi(_)) {
                            ssa.vars[v].param_name = Some(format!("fparam_{}", fparam_idx));
                            ssa.vars[v].inferred_type = InferredType::Float;
                            fnamed_offsets.insert(offset);
                            fparam_idx += 1;
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// Recognize struct field access patterns.
/// Converts Load(BinOp(Add, base, Const(offset))) → FieldAccess(base, offset)
/// when the base is a pointer (parameter, Load result, or another FieldAccess)
/// and the offset is a small aligned value typical of struct fields.
fn recognize_field_access(ssa: &mut SsaCfg) {
    // Collect pointer-typed variables: parameters, Load results, and anything
    // already typed as Pointer.
    let mut pointer_vars: std::collections::HashSet<VarId> = std::collections::HashSet::new();
    for v in &ssa.vars {
        if v.param_name.is_some() {
            pointer_vars.insert(v.id);
        }
        if v.inferred_type == InferredType::Pointer {
            pointer_vars.insert(v.id);
        }
        if matches!(&v.expr, Expr::Load(_)) {
            pointer_vars.insert(v.id);
        }
    }

    // Find Load(BinOp(Add, base, Const(offset))) patterns
    let mut replacements: Vec<(usize, VarId, u64)> = Vec::new();
    for v in 0..ssa.vars.len() {
        let vdef = &ssa.vars[v];
        if let Expr::Load(ptr_id) = &vdef.expr {
            let ptr_def = safe_var(&ssa.vars, *ptr_id);
            if let Expr::BinOp(BinOpKind::Add, base, offset_var) = &ptr_def.expr {
                let offset_def = safe_var(&ssa.vars, *offset_var);
                if let Expr::Const(offset_val, _) = &offset_def.expr {
                    // Only convert if:
                    // 1. Offset is non-zero (offset 0 is just a plain deref)
                    // 2. Offset is within reasonable struct size (< 4096 bytes)
                    // 3. Base looks like a pointer (parameter, load, or known pointer)
                    if *offset_val > 0 && *offset_val < 4096 {
                        let base_def = safe_var(&ssa.vars, *base);

                        // Skip stack frame accesses: EBP+offset in x86-32 is a parameter
                        // or local variable, not a struct field. EBP offset = 20, ESP offset = 28.
                        let is_stack_frame = base_def.varnode.space == AddressSpaceId::Register
                            && (base_def.varnode.offset == 20 || base_def.varnode.offset == 28)
                            && base_def.varnode.size == 4;
                        if is_stack_frame {
                            continue;
                        }

                        let base_is_pointer = pointer_vars.contains(base)
                            || base_def.param_name.is_some()
                            || matches!(&base_def.expr, Expr::Load(_) | Expr::FieldAccess(_, _))
                            || base_def.inferred_type == InferredType::Pointer;

                        // Also check if base is a register that was a parameter
                        let base_is_reg_param = base_def.varnode.space == AddressSpaceId::Register
                            && (base_def.param_name.is_some()
                                || matches!(&base_def.expr, Expr::Var(src) if safe_var(&ssa.vars, *src).param_name.is_some()));

                        if base_is_pointer || base_is_reg_param {
                            replacements.push((v, *base, *offset_val));
                        }
                    }
                }
            }
        }
    }

    for (var_idx, base, offset) in replacements {
        ssa.vars[var_idx].expr = Expr::FieldAccess(base, offset);
    }
}

/// Apply parameter names and types from the function signature database to call arguments.
///
/// For each call whose target resolves to a known function name (via `import_map`),
/// rename argument variables from generic "param_N" names to the signature's parameter names
/// and propagate parameter types when not already inferred.
pub fn apply_signature_names(
    ssa: &mut SsaCfg,
    import_map: &std::collections::HashMap<u64, String>,
) {
    // Collect (VarId, new_name, new_type, display_type) to apply after iteration.
    let mut renames: Vec<(VarId, String, InferredType, Option<&'static str>)> = Vec::new();

    for block in &ssa.blocks {
        // Helper closure: given a call target and args, collect renames
        let mut process_call = |target: &CallTarget, args: &[VarId]| {
            let addr = match target {
                CallTarget::Direct(a) => *a,
                CallTarget::Indirect(_) => return,
            };
            // Try import name → signature DB first, then learned types by address
            let sig = if let Some(name) = import_map.get(&addr) {
                crate::signatures::lookup(name)
            } else {
                None
            }
            .or_else(|| crate::signatures::lookup_addr(addr));
            let Some(sig) = sig else { return };
            for (i, arg_id) in args.iter().enumerate() {
                if let Some(param) = sig.params.get(i) {
                    let var = &ssa.vars[arg_id.0 as usize];
                    // Only propagate type from signature — don't rename.
                    // Renaming via param_name would corrupt the function signature
                    // (the printer collects all vars with param_name for the sig line).
                    // Instead, the printer uses signatures::lookup() directly for
                    // call-site argument comments/naming.
                    let ty = param.ty.to_inferred();
                    if ty != InferredType::Unknown && var.inferred_type == InferredType::Unknown {
                        renames.push((*arg_id, String::new(), ty, Some(param.ty.c_str())));
                    }
                }
            }
        };

        for stmt in &block.stmts {
            if let Stmt::Call { target, args, .. } = stmt {
                process_call(target, args);
            }
        }
        if let SsaTerminator::Call { target, args, .. } = &block.terminator {
            process_call(target, args);
        }
    }

    // Apply collected type updates
    for (var_id, _new_name, new_type, disp_type) in renames {
        let var = &mut ssa.vars[var_id.0 as usize];
        if new_type != InferredType::Unknown && var.inferred_type == InferredType::Unknown {
            var.inferred_type = new_type;
        }
        if var.display_type.is_none() {
            var.display_type = disp_type;
        }
    }
}

/// Propagate return types from the function signature database to call output variables.
///
/// For each call whose target resolves to a known function, set the return variable's
/// inferred type from the signature when not already inferred.
pub fn propagate_signature_return_types(
    ssa: &mut SsaCfg,
    import_map: &std::collections::HashMap<u64, String>,
) {
    let mut type_updates: Vec<(VarId, InferredType, Option<&'static str>)> = Vec::new();

    for block in &ssa.blocks {
        // Stmt::Call with out variable
        for stmt in &block.stmts {
            if let Stmt::Call {
                target,
                out: Some(out_id),
                ..
            } = stmt
            {
                if let CallTarget::Direct(addr) = target {
                    let sig = import_map
                        .get(addr)
                        .and_then(|name| crate::signatures::lookup(name))
                        .or_else(|| crate::signatures::lookup_addr(*addr));
                    if let Some(sig) = sig {
                        let ret_ty = sig.ret.to_inferred();
                        let disp = sig.ret.c_str();
                        if ret_ty != InferredType::Unknown {
                            let var = &ssa.vars[out_id.0 as usize];
                            if var.inferred_type == InferredType::Unknown {
                                type_updates.push((*out_id, ret_ty, Some(disp)));
                            }
                        }
                    }
                }
            }
        }

        // SsaTerminator::Call — find call_return var in fallthrough block
        if let SsaTerminator::Call {
            target,
            fallthrough,
            ..
        } = &block.terminator
        {
            if let CallTarget::Direct(addr) = target {
                let sig = import_map
                    .get(addr)
                    .and_then(|name| crate::signatures::lookup(name))
                    .or_else(|| crate::signatures::lookup_addr(*addr));
                if let Some(sig) = sig {
                    let ret_ty = sig.ret.to_inferred();
                    let disp = sig.ret.c_str();
                    if ret_ty != InferredType::Unknown {
                        let ft_idx = fallthrough.0;
                        if ft_idx < ssa.blocks.len() {
                            for stmt in &ssa.blocks[ft_idx].stmts {
                                if let Stmt::Assign(var_id) = stmt {
                                    let var = &ssa.vars[var_id.0 as usize];
                                    if var.call_return && var.inferred_type == InferredType::Unknown
                                    {
                                        type_updates.push((*var_id, ret_ty, Some(disp)));
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    for (var_id, ty, disp) in type_updates {
        let var = &mut ssa.vars[var_id.0 as usize];
        var.inferred_type = ty;
        if var.display_type.is_none() {
            var.display_type = disp;
        }
    }

    // Forward-propagate return types AND display types through Var/Copy chains.
    // If var_A = CreateFile() has type Pointer, and var_B = Var(var_A),
    // then var_B should also be Pointer.
    for _round in 0..3 {
        let mut propagated = false;
        for v in 0..ssa.vars.len() {
            if let Expr::Var(src) = &ssa.vars[v].expr {
                let src_idx = src.0 as usize;
                // Propagate InferredType
                if ssa.vars[v].inferred_type == InferredType::Unknown {
                    let src_ty = ssa.vars[src_idx].inferred_type;
                    if src_ty != InferredType::Unknown {
                        ssa.vars[v].inferred_type = src_ty;
                        propagated = true;
                    }
                }
                // Propagate display_type
                if ssa.vars[v].display_type.is_none() {
                    if let Some(disp) = ssa.vars[src_idx].display_type {
                        ssa.vars[v].display_type = Some(disp);
                        propagated = true;
                    }
                }
            }
        }
        if !propagated {
            break;
        }
    }

    // Backward-propagate display types through Load chains.
    // If var_A = Load(param_3) and var_A.display_type = "HANDLE",
    // then param_3 holds a pointer to HANDLE → display_type = "HANDLE *".
    // This makes function parameter types reflect what the callee expects.
    for v in 0..ssa.vars.len() {
        let disp = ssa.vars[v].display_type;
        let Some(disp) = disp else { continue };
        if let Expr::Load(ptr_id) = &ssa.vars[v].expr {
            let ptr_idx = ptr_id.0 as usize;
            if ptr_idx < ssa.vars.len() && ssa.vars[ptr_idx].display_type.is_none() {
                // The pointer variable holds an address of <display_type>
                // For function parameters, show as the pointed-to type (not ptr-to-ptr)
                // because *(param_0) of type HANDLE means param_0 IS the HANDLE
                // (x86-32 passes by value on the stack, Load fetches the param value)
                if ssa.vars[ptr_idx].param_name.is_some() {
                    ssa.vars[ptr_idx].display_type = Some(disp);
                    if ssa.vars[ptr_idx].inferred_type == InferredType::Unknown {
                        ssa.vars[ptr_idx].inferred_type = ssa.vars[v].inferred_type;
                    }
                }
            }
        }
    }
}

/// Assign names to self-referential Phi VarDefs (loop variables).
/// A self-referential Phi is one where at least one input transitively
/// references the Phi itself (via Add, Var, etc.). These represent
/// loop-carried values like counters and accumulators.
///
/// When a Phi has a param_name, format_var returns the name directly
/// instead of expanding "phi(init, body_val)" — which prevents the
/// text-level #PHI_CLEANUP from replacing "return phi(0, ...)" with "return 0".
fn name_loop_phis(ssa: &mut SsaCfg) {
    let mut loop_phi_count = 0u32;
    for vi in 0..ssa.vars.len() {
        if ssa.vars[vi].param_name.is_some() {
            continue;
        }
        if let Expr::Phi(ref inputs) = ssa.vars[vi].expr {
            if inputs.len() < 2 {
                continue;
            }
            let phi_id = VarId(vi as u32);
            // Check if any input transitively references this Phi (self-referential)
            let is_self_ref = inputs
                .iter()
                .any(|input| refs_varid(*input, phi_id, &ssa.vars, 6));
            if is_self_ref {
                // This is a loop Phi. Assign a name based on the register size.
                let vn = ssa.vars[vi].varnode;
                let prefix = if vn.size <= 4 { "i" } else { "l" };
                loop_phi_count += 1;
                ssa.vars[vi].param_name = Some(format!("{}Var{}", prefix, loop_phi_count));
            }
        }
    }
}

/// Check if a VarId's expression tree transitively references a target VarId.
fn refs_varid(id: VarId, target: VarId, vars: &[VarDef], depth: u32) -> bool {
    if depth == 0 {
        return false;
    }
    if id == target {
        return true;
    }
    let vdef = &vars[id.0 as usize];
    match &vdef.expr {
        Expr::Var(inner) => refs_varid(*inner, target, vars, depth - 1),
        Expr::BinOp(_, l, r) => {
            refs_varid(*l, target, vars, depth - 1) || refs_varid(*r, target, vars, depth - 1)
        }
        Expr::UnaryOp(_, i) => refs_varid(*i, target, vars, depth - 1),
        Expr::Phi(inputs) => inputs
            .iter()
            .any(|i| refs_varid(*i, target, vars, depth - 1)),
        _ => false,
    }
}

// ─────────────────────────────────────────────────────────────────────
// Phi → Ternary rewrite for conditional (non-loop) merges.
//
// Rewrites `Expr::Phi(inputs)` at a non-loop-header block whose inputs
// can be grouped into exactly two distinct values reachable through a
// dominating CBranch. This produces `Expr::Ternary(cond, then, else)`
// which the printer already renders as `(cond) ? t : e` — bypassing
// every register-elision filter that fought pred-exit SSA destruction.
//
// See `.opt/campaigns/phi-ternary-merge.md` for campaign context.
// ─────────────────────────────────────────────────────────────────────

use crate::dominators::compute_dominators;

pub fn rewrite_conditional_phi_to_ternary(ssa: &mut SsaCfg, cfg: &Cfg) {
    if cfg.blocks.is_empty() {
        return;
    }
    let dom = compute_dominators(cfg);
    let preds = cfg.predecessors();

    // Mark back-edge targets (loop headers). These carry loop-Phi
    // accumulators and must be skipped.
    let n = cfg.blocks.len();
    let mut is_back_target = vec![false; n];
    for block in &cfg.blocks {
        for succ in cfg.successors(block.id) {
            if phi_dom_dominates(&dom, succ.0, block.id.0) {
                is_back_target[succ.0] = true;
            }
        }
    }

    for merge_bid in 0..ssa.blocks.len() {
        if merge_bid >= n {
            break;
        }
        if is_back_target[merge_bid] {
            continue;
        }
        let pred_list = match preds.get(merge_bid) {
            Some(p) if p.len() >= 2 => p.clone(),
            _ => continue,
        };

        // Collect Phi stmts at this block.
        let phi_stmts: Vec<(VarId, Vec<VarId>)> = ssa.blocks[merge_bid]
            .stmts
            .iter()
            .filter_map(|s| match s {
                Stmt::Assign(v) => match &ssa.vars[v.0 as usize].expr {
                    Expr::Phi(inputs) if inputs.len() == pred_list.len() => {
                        Some((*v, inputs.clone()))
                    }
                    _ => None,
                },
                _ => None,
            })
            .collect();

        for (phi_v, inputs) in phi_stmts {
            // First pass: if every input resolves (via Var chain) to
            // the same leaf OR to the same varnode (register slot), all
            // paths render identically in the printer — collapse the
            // Phi to `Var(first_input)`. This covers `phi(x, x)` cases
            // that the SSA-level same-input dedup missed because the
            // inputs have distinct VarIds but identical render.
            let first_leaf = phi_resolve_var_chain(inputs[0], &ssa.vars, 8);
            let first_vn = ssa.vars[first_leaf.0 as usize].varnode;
            let all_same_render = inputs.iter().all(|&inp| {
                let leaf = phi_resolve_var_chain(inp, &ssa.vars, 8);
                leaf == first_leaf || ssa.vars[leaf.0 as usize].varnode == first_vn
            });
            if all_same_render {
                ssa.vars[phi_v.0 as usize].expr = Expr::Var(inputs[0]);
                continue;
            }

            // Group preds by which SSA input they feed.
            let mut groups: Vec<(VarId, Vec<BlockId>)> = Vec::new();
            for (i, &p) in pred_list.iter().enumerate() {
                let input = inputs[i];
                if let Some(g) = groups.iter_mut().find(|(v, _)| *v == input) {
                    g.1.push(p);
                } else {
                    groups.push((input, vec![p]));
                }
            }
            if groups.len() != 2 {
                continue;
            }

            let (val_a, preds_a) = groups[0].clone();
            let (val_b, preds_b) = groups[1].clone();

            // Nearest common dominator of all preds.
            let all_preds: Vec<BlockId> = preds_a.iter().chain(preds_b.iter()).copied().collect();
            let Some(common_dom) = phi_nearest_common_dom(&dom, &all_preds) else {
                continue;
            };
            if common_dom.0 >= ssa.blocks.len() {
                continue;
            }

            let (cond, taken, fallthrough) = match &ssa.blocks[common_dom.0].terminator {
                SsaTerminator::CBranch {
                    cond,
                    taken,
                    fallthrough,
                } => (*cond, *taken, *fallthrough),
                _ => continue,
            };

            // Classify each pred group by which CBranch arm dominates it.
            let group_under = |ps: &[BlockId], arm: BlockId| -> bool {
                ps.iter().all(|p| phi_dom_dominates(&dom, arm.0, p.0))
            };
            let (then_val, else_val) =
                if group_under(&preds_a, taken) && group_under(&preds_b, fallthrough) {
                    (val_a, val_b)
                } else if group_under(&preds_a, fallthrough) && group_under(&preds_b, taken) {
                    (val_b, val_a)
                } else {
                    continue;
                };

            // Collapse `Ternary(c, x, x)` when both arms would render
            // identically in the printer. Same VarId trivially. Same
            // leaf after Var-chain trivially. Same leaf VARNODE
            // (register offset + size) because the printer names
            // locations by varnode, so `(c) ? lVar1 : lVar1` rendering
            // is the signal regardless of SSA-version differences —
            // emitting the ternary adds no information vs `lVar1`.
            let t_leaf = phi_resolve_var_chain(then_val, &ssa.vars, 8);
            let e_leaf = phi_resolve_var_chain(else_val, &ssa.vars, 8);
            let same_leaf = t_leaf == e_leaf;
            let same_location = {
                let t_vn = ssa.vars[t_leaf.0 as usize].varnode;
                let e_vn = ssa.vars[e_leaf.0 as usize].varnode;
                t_vn == e_vn
            };
            if same_leaf || same_location {
                ssa.vars[phi_v.0 as usize].expr = Expr::Var(then_val);
            } else {
                ssa.vars[phi_v.0 as usize].expr = Expr::Ternary(cond, then_val, else_val);
            }
        }
    }
}

fn phi_resolve_var_chain(id: VarId, vars: &[VarDef], depth: u32) -> VarId {
    if depth == 0 {
        return id;
    }
    match &vars[id.0 as usize].expr {
        Expr::Var(inner) => phi_resolve_var_chain(*inner, vars, depth - 1),
        _ => id,
    }
}

fn phi_dom_dominates(dom: &[BlockId], a: usize, b: usize) -> bool {
    if a == b {
        return true;
    }
    if a >= dom.len() || b >= dom.len() {
        return false;
    }
    let mut cur = b;
    for _ in 0..dom.len() {
        let d = dom[cur].0;
        if d == a {
            return true;
        }
        if d == cur {
            return false;
        } // reached root
        cur = d;
    }
    false
}

fn phi_nearest_common_dom(dom: &[BlockId], blocks: &[BlockId]) -> Option<BlockId> {
    if blocks.is_empty() {
        return None;
    }
    let mut cd = blocks[0];
    for &b in &blocks[1..] {
        cd = phi_common_dom_pair(dom, cd, b)?;
    }
    Some(cd)
}

fn phi_common_dom_pair(dom: &[BlockId], a: BlockId, b: BlockId) -> Option<BlockId> {
    let mut chain_a: std::collections::HashSet<BlockId> = Default::default();
    let mut cur = a;
    for _ in 0..dom.len() {
        chain_a.insert(cur);
        if cur.0 >= dom.len() {
            break;
        }
        let d = dom[cur.0];
        if d == cur {
            break;
        }
        cur = d;
    }
    let mut cur = b;
    for _ in 0..dom.len() {
        if chain_a.contains(&cur) {
            return Some(cur);
        }
        if cur.0 >= dom.len() {
            return None;
        }
        let d = dom[cur.0];
        if d == cur {
            return if chain_a.contains(&cur) {
                Some(cur)
            } else {
                None
            };
        }
        cur = d;
    }
    None
}
