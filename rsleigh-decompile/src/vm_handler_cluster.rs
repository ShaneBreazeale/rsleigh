//! VM-handler equivalence clusterer.
//!
//! Protector-style virtualizers (VMProtect, Themida, Code Virtualizer,
//! PyVMProtect) emit semantically-equivalent handler variants —
//! permuted instruction order, junk inserted between live ops, dummy
//! prefixes, register renaming. Signature-based heuristics
//! (`vm_handler_classify`) miss those clones.
//!
//! Approach: hash a *canonical* form of each handler's SSA. The canonical
//! form abstracts away VarIds (alpha-renamed in DFS post-order) and the
//! exact instruction interleaving (we only emit the sequence of
//! side-effecting ops: Stores, Calls, the terminator, the Return value).
//! Handlers that produce identical canonical forms cluster together.
//!
//! Two-pass MVP:
//! 1. `canonicalize(&SsaCfg) -> String` — DFS post-order rewrite of the
//!    side-effect skeleton.
//! 2. `cluster(handlers) -> Vec<HandlerCluster>` — group by canonical
//!    string; one cluster per equivalence class.

use crate::ir::{BinOpKind, Expr, SsaCfg, SsaTerminator, Stmt, UnaryOpKind, VarDef, VarId};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct HandlerCluster {
    /// One representative handler — the lowest-VA member.
    pub representative: u64,
    /// All addresses sharing the same canonical form.
    pub members: Vec<u64>,
    /// Canonical hash (FNV-1a 64-bit) of the shared shape.
    pub canonical_hash: u64,
}

/// Bucket handlers by canonical SSA shape.
pub fn cluster(handlers: &[(u64, SsaCfg)]) -> Vec<HandlerCluster> {
    let mut buckets: HashMap<String, Vec<u64>> = HashMap::new();
    for (va, ssa) in handlers {
        let canon = canonicalize(ssa);
        buckets.entry(canon).or_default().push(*va);
    }
    let mut out: Vec<HandlerCluster> = buckets
        .into_iter()
        .map(|(canon, mut members)| {
            members.sort_unstable();
            HandlerCluster {
                representative: members[0],
                canonical_hash: fnv1a64(canon.as_bytes()),
                members,
            }
        })
        .collect();
    out.sort_by_key(|c| c.representative);
    out
}

/// Produce a deterministic textual canonicalisation of an SSA cfg.
/// Two SSA cfgs that differ only by VarId renaming and irrelevant
/// dead vars produce the same canonical string.
pub fn canonicalize(ssa: &SsaCfg) -> String {
    let mut out = String::with_capacity(256);
    let mut renamer = Renamer::default();
    for blk in &ssa.blocks {
        out.push_str("BLK{");
        for stmt in &blk.stmts {
            match stmt {
                Stmt::Assign(_) => {} // pure dataflow, side-effect-free
                Stmt::Store { addr, val } => {
                    out.push_str("ST(");
                    emit(&mut out, *addr, &ssa.vars, &mut renamer, 0);
                    out.push(',');
                    emit(&mut out, *val, &ssa.vars, &mut renamer, 0);
                    out.push_str(");");
                }
                Stmt::Call {
                    target, args, out: _,
                } => {
                    out.push_str("CALL(");
                    out.push_str(&format!("{:?}:", target));
                    for a in args {
                        emit(&mut out, *a, &ssa.vars, &mut renamer, 0);
                        out.push(',');
                    }
                    out.push_str(");");
                }
            }
        }
        match &blk.terminator {
            SsaTerminator::Return(Some(v)) => {
                out.push_str("RET(");
                emit(&mut out, *v, &ssa.vars, &mut renamer, 0);
                out.push_str(")");
            }
            SsaTerminator::Return(None) => out.push_str("RET()"),
            SsaTerminator::CBranch { cond, .. } => {
                out.push_str("CBR(");
                emit(&mut out, *cond, &ssa.vars, &mut renamer, 0);
                out.push(')');
            }
            SsaTerminator::Branch(_) | SsaTerminator::Fallthrough(_) => out.push_str("JMP"),
            SsaTerminator::Call { target, .. } => {
                out.push_str(&format!("TCALL({:?})", target));
            }
            SsaTerminator::Indirect(v) => {
                out.push_str("IND(");
                emit(&mut out, *v, &ssa.vars, &mut renamer, 0);
                out.push(')');
            }
        }
        out.push('}');
    }
    out
}

const MAX_DEPTH: usize = 16;

fn emit(out: &mut String, v: VarId, vars: &[VarDef], r: &mut Renamer, depth: usize) {
    if depth > MAX_DEPTH {
        out.push('…');
        return;
    }
    let Some(def) = vars.get(v.0 as usize) else {
        out.push_str("?");
        return;
    };
    match &def.expr {
        Expr::Const(c, _) => {
            out.push_str(&format!("#{:x}", c));
        }
        Expr::Var(inner) => emit(out, *inner, vars, r, depth + 1),
        Expr::BinOp(kind, l, r2) => {
            out.push_str(binop_token(*kind));
            out.push('(');
            // Commutative ops get sorted operands so XOR(a,b) == XOR(b,a).
            if is_commutative(*kind) {
                let mut la = String::new();
                let mut ra = String::new();
                emit(&mut la, *l, vars, r, depth + 1);
                emit(&mut ra, *r2, vars, r, depth + 1);
                if la <= ra {
                    out.push_str(&la);
                    out.push(',');
                    out.push_str(&ra);
                } else {
                    out.push_str(&ra);
                    out.push(',');
                    out.push_str(&la);
                }
            } else {
                emit(out, *l, vars, r, depth + 1);
                out.push(',');
                emit(out, *r2, vars, r, depth + 1);
            }
            out.push(')');
        }
        Expr::UnaryOp(kind, inner) => {
            out.push_str(unop_token(*kind));
            out.push('(');
            emit(out, *inner, vars, r, depth + 1);
            out.push(')');
        }
        Expr::Load(addr) => {
            out.push_str("LD(");
            emit(out, *addr, vars, r, depth + 1);
            out.push(')');
        }
        Expr::FieldAccess(base, off) => {
            out.push_str("FLD(");
            emit(out, *base, vars, r, depth + 1);
            out.push_str(&format!(",{:#x})", off));
        }
        Expr::Phi(_) => out.push_str("PHI"),
        Expr::Ternary(c, t, e) => {
            out.push_str("TERN(");
            emit(out, *c, vars, r, depth + 1);
            out.push(',');
            emit(out, *t, vars, r, depth + 1);
            out.push(',');
            emit(out, *e, vars, r, depth + 1);
            out.push(')');
        }
        Expr::UserOp { func_id, inputs } => {
            out.push_str(&format!("UOP{}(", func_id));
            for i in inputs {
                emit(out, *i, vars, r, depth + 1);
                out.push(',');
            }
            out.push(')');
        }
        Expr::Unknown => {
            // Free variable — alpha-rename to dense id so two handlers
            // with different VarId numbering still match.
            out.push_str(&format!("$x{}", r.intern(v.0)));
        }
    }
}

#[derive(Default)]
struct Renamer {
    map: HashMap<u32, u32>,
    next: u32,
}
impl Renamer {
    fn intern(&mut self, id: u32) -> u32 {
        if let Some(&v) = self.map.get(&id) {
            return v;
        }
        let v = self.next;
        self.map.insert(id, v);
        self.next += 1;
        v
    }
}

fn is_commutative(k: BinOpKind) -> bool {
    matches!(
        k,
        BinOpKind::Add
            | BinOpKind::Mult
            | BinOpKind::And
            | BinOpKind::Or
            | BinOpKind::Xor
            | BinOpKind::Eq
            | BinOpKind::NotEq
            | BinOpKind::BoolAnd
            | BinOpKind::BoolOr
            | BinOpKind::BoolXor
    )
}

fn binop_token(k: BinOpKind) -> &'static str {
    match k {
        BinOpKind::Add => "+",
        BinOpKind::Sub => "-",
        BinOpKind::Mult => "*",
        BinOpKind::Div => "/u",
        BinOpKind::SDiv => "/s",
        BinOpKind::Rem => "%u",
        BinOpKind::SRem => "%s",
        BinOpKind::And => "&",
        BinOpKind::Or => "|",
        BinOpKind::Xor => "^",
        BinOpKind::Lsl => "<<",
        BinOpKind::Lsr => ">>u",
        BinOpKind::Asr => ">>s",
        BinOpKind::Eq => "==",
        BinOpKind::NotEq => "!=",
        BinOpKind::Less => "<u",
        BinOpKind::LessEq => "<=u",
        BinOpKind::SLess => "<s",
        BinOpKind::SLessEq => "<=s",
        BinOpKind::Carry => "C",
        BinOpKind::SCarry => "Sc",
        BinOpKind::SBorrow => "Sb",
        BinOpKind::BoolAnd => "&&",
        BinOpKind::BoolOr => "||",
        BinOpKind::BoolXor => "^^",
        BinOpKind::FloatAdd => "f+",
        BinOpKind::FloatSub => "f-",
        BinOpKind::FloatMult => "f*",
        BinOpKind::FloatDiv => "f/",
        BinOpKind::FloatEq => "f==",
        BinOpKind::FloatNotEq => "f!=",
        BinOpKind::FloatLess => "f<",
        BinOpKind::FloatLessEq => "f<=",
    }
}

fn unop_token(k: UnaryOpKind) -> &'static str {
    match k {
        UnaryOpKind::Neg => "neg",
        UnaryOpKind::Not => "~",
        UnaryOpKind::Zext => "zx",
        UnaryOpKind::Sext => "sx",
        UnaryOpKind::BoolNot => "!",
        UnaryOpKind::FloatNeg => "fneg",
        UnaryOpKind::FloatAbs => "fabs",
        UnaryOpKind::FloatSqrt => "fsqrt",
        UnaryOpKind::FloatNan => "fnan",
        UnaryOpKind::Int2Float => "i2f",
        UnaryOpKind::Float2Float => "f2f",
        UnaryOpKind::Trunc => "tr",
        UnaryOpKind::FloatCeil => "fceil",
        UnaryOpKind::FloatFloor => "ffloor",
        UnaryOpKind::FloatRound => "fround",
        UnaryOpKind::Popcount => "pop",
        UnaryOpKind::Lzcount => "lz",
    }
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{BlockId, InferredType, SsaBlock, SsaCfg, SsaTerminator, VarDef};
    use pcode_ir::Varnode;

    fn mk_var(id: u32, expr: Expr, size: u32) -> VarDef {
        VarDef {
            id: VarId(id),
            varnode: Varnode::constant(0, size),
            expr,
            size,
            use_count: 1,
            param_name: None,
            call_return: false,
            inferred_type: InferredType::Unknown,
            display_type: None,
            memory: None,
            origins: Default::default(),
        }
    }

    fn mk_ssa(vars: Vec<VarDef>, ret: VarId) -> SsaCfg {
        SsaCfg {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                addr: 0x1000,
                stmts: vec![],
                terminator: SsaTerminator::Return(Some(ret)),
            }],
            vars,
            entry: BlockId(0),
            diagnostics: vec![],
        }
    }

    #[test]
    fn xor_handlers_with_swapped_operands_cluster() {
        // Handler A: ret = a ^ b
        let a = mk_ssa(
            vec![
                mk_var(0, Expr::Unknown, 8),
                mk_var(1, Expr::Unknown, 8),
                mk_var(2, Expr::BinOp(BinOpKind::Xor, VarId(0), VarId(1)), 8),
            ],
            VarId(2),
        );
        // Handler B: ret = b ^ a — same semantics, swapped operand order
        let b = mk_ssa(
            vec![
                mk_var(0, Expr::Unknown, 8),
                mk_var(1, Expr::Unknown, 8),
                mk_var(2, Expr::BinOp(BinOpKind::Xor, VarId(1), VarId(0)), 8),
            ],
            VarId(2),
        );
        let groups = cluster(&[(0x1000, a), (0x2000, b)]);
        assert_eq!(groups.len(), 1, "expected one cluster, got {:?}", groups);
        assert_eq!(groups[0].members, vec![0x1000, 0x2000]);
    }

    #[test]
    fn distinct_handlers_dont_cluster() {
        // Handler A: ret = a ^ b
        let a = mk_ssa(
            vec![
                mk_var(0, Expr::Unknown, 8),
                mk_var(1, Expr::Unknown, 8),
                mk_var(2, Expr::BinOp(BinOpKind::Xor, VarId(0), VarId(1)), 8),
            ],
            VarId(2),
        );
        // Handler C: ret = a + b — different op
        let c = mk_ssa(
            vec![
                mk_var(0, Expr::Unknown, 8),
                mk_var(1, Expr::Unknown, 8),
                mk_var(2, Expr::BinOp(BinOpKind::Add, VarId(0), VarId(1)), 8),
            ],
            VarId(2),
        );
        let groups = cluster(&[(0x1000, a), (0x3000, c)]);
        assert_eq!(groups.len(), 2);
    }
}
