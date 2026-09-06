//! Equality saturation for MBA deobfuscation using the `egg` crate.
//!
//! Defines a simple arithmetic language, MBA rewrite rules, and a cost model
//! that prefers fewer operations. The e-graph explores all equivalent forms
//! simultaneously, then extracts the cheapest one.

use egg::{define_language, rewrite, CostFunction, Id, Language, RecExpr, Rewrite, Runner};

// Define the expression language for MBA simplification.
// This is a standalone language (not our SSA IR) — we convert to/from it.
define_language! {
    pub enum Mba {
        // Constants
        Num(i64),
        // Variable references (index into a base-variable array)
        "var" = Var(Id),

        // Arithmetic
        "+" = Add([Id; 2]),
        "-" = Sub([Id; 2]),
        "*" = Mul([Id; 2]),
        "neg" = Neg(Id),

        // Bitwise
        "&" = And([Id; 2]),
        "|" = Or([Id; 2]),
        "^" = Xor([Id; 2]),
        "~" = Not(Id),

        // Shifts
        "<<" = Shl([Id; 2]),
        ">>" = Shr([Id; 2]),
    }
}

/// Cost model: prefer expressions with fewer nodes and simpler operations.
pub struct MbaCost;

impl CostFunction<Mba> for MbaCost {
    type Cost = usize;

    fn cost<C>(&mut self, enode: &Mba, mut costs: C) -> usize
    where
        C: FnMut(Id) -> usize,
    {
        let op_cost = match enode {
            Mba::Num(_) => 0,
            Mba::Var(_) => 1,
            Mba::Add(_) | Mba::Sub(_) => 2,
            Mba::And(_) | Mba::Or(_) | Mba::Xor(_) => 2,
            Mba::Neg(_) | Mba::Not(_) => 1,
            Mba::Mul(_) => 3,
            Mba::Shl(_) | Mba::Shr(_) => 2,
        };
        enode.fold(op_cost, |sum, id| sum + costs(id))
    }
}

/// Build the MBA rewrite rules.
pub fn mba_rules() -> Vec<Rewrite<Mba, ()>> {
    vec![
        // === Identity / Annihilation ===
        rewrite!("add-0-r"; "(+ ?a 0)" => "?a"),
        rewrite!("add-0-l"; "(+ 0 ?a)" => "?a"),
        rewrite!("sub-0";   "(- ?a 0)" => "?a"),
        rewrite!("mul-1-r"; "(* ?a 1)" => "?a"),
        rewrite!("mul-1-l"; "(* 1 ?a)" => "?a"),
        rewrite!("mul-0-r"; "(* ?a 0)" => "0"),
        rewrite!("mul-0-l"; "(* 0 ?a)" => "0"),
        rewrite!("and-0-r"; "(& ?a 0)" => "0"),
        rewrite!("and-0-l"; "(& 0 ?a)" => "0"),
        rewrite!("or-0-r";  "(| ?a 0)" => "?a"),
        rewrite!("or-0-l";  "(| 0 ?a)" => "?a"),
        rewrite!("xor-0-r"; "(^ ?a 0)" => "?a"),
        rewrite!("xor-0-l"; "(^ 0 ?a)" => "?a"),
        // === Self-operations ===
        rewrite!("sub-self"; "(- ?a ?a)" => "0"),
        rewrite!("xor-self"; "(^ ?a ?a)" => "0"),
        rewrite!("and-self"; "(& ?a ?a)" => "?a"),
        rewrite!("or-self";  "(| ?a ?a)" => "?a"),
        // === Double negation ===
        rewrite!("neg-neg"; "(neg (neg ?a))" => "?a"),
        rewrite!("not-not"; "(~ (~ ?a))" => "?a"),
        // === Commutativity ===
        rewrite!("add-comm"; "(+ ?a ?b)" => "(+ ?b ?a)"),
        rewrite!("mul-comm"; "(* ?a ?b)" => "(* ?b ?a)"),
        rewrite!("and-comm"; "(& ?a ?b)" => "(& ?b ?a)"),
        rewrite!("or-comm";  "(| ?a ?b)" => "(| ?b ?a)"),
        rewrite!("xor-comm"; "(^ ?a ?b)" => "(^ ?b ?a)"),
        // === MBA identities (the key deobfuscation rules) ===
        // (a + b) - 2*(a & b) = a ^ b
        rewrite!("mba-xor-1"; "(- (+ ?a ?b) (* 2 (& ?a ?b)))" => "(^ ?a ?b)"),
        rewrite!("mba-xor-2"; "(- (+ ?a ?b) (+ (& ?a ?b) (& ?a ?b)))" => "(^ ?a ?b)"),
        // (a ^ b) + 2*(a & b) = a + b
        rewrite!("mba-add-1"; "(+ (^ ?a ?b) (* 2 (& ?a ?b)))" => "(+ ?a ?b)"),
        rewrite!("mba-add-2"; "(+ (^ ?a ?b) (+ (& ?a ?b) (& ?a ?b)))" => "(+ ?a ?b)"),
        // (a | b) - (a & b) = a ^ b
        rewrite!("mba-xor-3"; "(- (| ?a ?b) (& ?a ?b))" => "(^ ?a ?b)"),
        // (a ^ b) + (a & b) = a | b
        rewrite!("mba-or-1"; "(+ (^ ?a ?b) (& ?a ?b))" => "(| ?a ?b)"),
        // (a & b) + (a | b) = a + b
        rewrite!("mba-add-3"; "(+ (& ?a ?b) (| ?a ?b))" => "(+ ?a ?b)"),
        // === Absorption ===
        rewrite!("absorb-and-or"; "(& ?a (| ?a ?b))" => "?a"),
        rewrite!("absorb-or-and"; "(| ?a (& ?a ?b))" => "?a"),
        // === Cancellation ===
        // a - (a - b) = b
        rewrite!("cancel-sub"; "(- ?a (- ?a ?b))" => "?b"),
        // a ^ (a ^ b) = b
        rewrite!("cancel-xor"; "(^ ?a (^ ?a ?b))" => "?b"),
        // (a + b) - b = a
        rewrite!("cancel-add-sub-r"; "(- (+ ?a ?b) ?b)" => "?a"),
        rewrite!("cancel-add-sub-l"; "(- (+ ?a ?b) ?a)" => "?b"),
        // (a - b) + b = a
        rewrite!("cancel-sub-add"; "(+ (- ?a ?b) ?b)" => "?a"),
        // === Distributivity ===
        // a * (b + c) = a*b + a*c
        rewrite!("dist-mul-add"; "(* ?a (+ ?b ?c))" => "(+ (* ?a ?b) (* ?a ?c))"),
        // Factor: a*b + a*c = a * (b + c)
        rewrite!("factor-mul-add"; "(+ (* ?a ?b) (* ?a ?c))" => "(* ?a (+ ?b ?c))"),
        // === Negation / complement ===
        // -a = ~a + 1  (two's complement)
        rewrite!("neg-as-not"; "(neg ?a)" => "(+ (~ ?a) 1)"),
        // a + (-b) = a - b
        rewrite!("add-neg"; "(+ ?a (neg ?b))" => "(- ?a ?b)"),
        // -1 * a = neg a
        rewrite!("mul-neg1"; "(* -1 ?a)" => "(neg ?a)"),
        // === De Morgan's laws ===
        rewrite!("demorgan-and"; "(~ (& ?a ?b))" => "(| (~ ?a) (~ ?b))"),
        rewrite!("demorgan-or"; "(~ (| ?a ?b))" => "(& (~ ?a) (~ ?b))"),
        // Reverse De Morgan (prefer AND/OR over NOT-of-NOT)
        rewrite!("demorgan-and-rev"; "(| (~ ?a) (~ ?b))" => "(~ (& ?a ?b))"),
        rewrite!("demorgan-or-rev"; "(& (~ ?a) (~ ?b))" => "(~ (| ?a ?b))"),
        // === Shift identities ===
        rewrite!("shl-0"; "(<< ?a 0)" => "?a"),
        rewrite!("shr-0"; "(>> ?a 0)" => "?a"),
        // a << 1 = a + a
        rewrite!("shl-1"; "(<< ?a 1)" => "(+ ?a ?a)"),
        // a * 2 = a + a
        rewrite!("mul-2"; "(* 2 ?a)" => "(+ ?a ?a)"),
        rewrite!("mul-2-r"; "(* ?a 2)" => "(+ ?a ?a)"),
    ]
}

/// Convert a sub-expression from our SSA VarDef tree into the egg Mba language.
/// Returns (RecExpr, mapping from egg Var indices to VarIds).
pub fn ssa_to_egg(
    var_idx: usize,
    vars: &[crate::ir::VarDef],
    max_depth: usize,
) -> Option<(RecExpr<Mba>, Vec<crate::ir::VarId>)> {
    use crate::ir::{BinOpKind, Expr, UnaryOpKind, VarId};

    let mut expr = RecExpr::default();
    let mut var_map: Vec<VarId> = Vec::new(); // egg var index → SSA VarId

    fn convert(
        v: usize,
        vars: &[crate::ir::VarDef],
        expr: &mut RecExpr<Mba>,
        var_map: &mut Vec<VarId>,
        depth: usize,
        max_depth: usize,
    ) -> Option<Id> {
        if depth > max_depth {
            return None;
        }
        if v >= vars.len() {
            return None;
        }

        let vdef = &vars[v];
        match &vdef.expr {
            Expr::Const(val, _) => Some(expr.add(Mba::Num(*val as i64))),
            Expr::Unknown
            | Expr::Load(_)
            | Expr::Phi(_)
            | Expr::FieldAccess(_, _)
            | Expr::Ternary(_, _, _)
            | Expr::UserOp { .. } => {
                // Base variable — assign an index
                let idx = var_map.len();
                var_map.push(VarId(v as u32));
                let idx_id = expr.add(Mba::Num(idx as i64));
                Some(expr.add(Mba::Var(idx_id)))
            }
            Expr::Var(inner) => {
                convert(inner.0 as usize, vars, expr, var_map, depth + 1, max_depth)
            }
            Expr::BinOp(kind, left, right) => {
                let l = convert(left.0 as usize, vars, expr, var_map, depth + 1, max_depth)?;
                let r = convert(right.0 as usize, vars, expr, var_map, depth + 1, max_depth)?;
                let node = match kind {
                    BinOpKind::Add => Mba::Add([l, r]),
                    BinOpKind::Sub => Mba::Sub([l, r]),
                    BinOpKind::Mult => Mba::Mul([l, r]),
                    BinOpKind::And => Mba::And([l, r]),
                    BinOpKind::Or => Mba::Or([l, r]),
                    BinOpKind::Xor => Mba::Xor([l, r]),
                    BinOpKind::Lsl => Mba::Shl([l, r]),
                    BinOpKind::Lsr | BinOpKind::Asr => Mba::Shr([l, r]),
                    _ => return None,
                };
                Some(expr.add(node))
            }
            Expr::UnaryOp(kind, inner) => {
                let i = convert(inner.0 as usize, vars, expr, var_map, depth + 1, max_depth)?;
                let node = match kind {
                    UnaryOpKind::Neg => Mba::Neg(i),
                    UnaryOpKind::Not => Mba::Not(i),
                    _ => return None,
                };
                Some(expr.add(node))
            }
        }
    }

    convert(var_idx, vars, &mut expr, &mut var_map, 0, max_depth)?;
    Some((expr, var_map))
}

/// Convert an egg RecExpr back to our SSA Expr, creating new VarDefs as needed.
pub fn egg_to_ssa(
    best: &RecExpr<Mba>,
    var_map: &[crate::ir::VarId],
    vars: &mut Vec<crate::ir::VarDef>,
    sz: u32,
) -> Option<crate::ir::Expr> {
    use crate::ir::{BinOpKind, Expr, UnaryOpKind, VarId};

    fn convert(
        id: Id,
        best: &RecExpr<Mba>,
        var_map: &[VarId],
        vars: &mut Vec<crate::ir::VarDef>,
        sz: u32,
    ) -> Option<Expr> {
        let node = &best[id];
        match node {
            Mba::Num(val) => Some(Expr::Const(*val as u64, sz)),
            Mba::Var(idx_id) => {
                if let Mba::Num(idx) = &best[*idx_id] {
                    var_map.get(*idx as usize).map(|vid| Expr::Var(*vid))
                } else {
                    None
                }
            }
            Mba::Add([l, r]) => {
                let le = convert(*l, best, var_map, vars, sz)?;
                let re = convert(*r, best, var_map, vars, sz)?;
                Some(make_binop(BinOpKind::Add, le, re, vars, sz))
            }
            Mba::Sub([l, r]) => {
                let le = convert(*l, best, var_map, vars, sz)?;
                let re = convert(*r, best, var_map, vars, sz)?;
                Some(make_binop(BinOpKind::Sub, le, re, vars, sz))
            }
            Mba::Mul([l, r]) => {
                let le = convert(*l, best, var_map, vars, sz)?;
                let re = convert(*r, best, var_map, vars, sz)?;
                Some(make_binop(BinOpKind::Mult, le, re, vars, sz))
            }
            Mba::And([l, r]) => {
                let le = convert(*l, best, var_map, vars, sz)?;
                let re = convert(*r, best, var_map, vars, sz)?;
                Some(make_binop(BinOpKind::And, le, re, vars, sz))
            }
            Mba::Or([l, r]) => {
                let le = convert(*l, best, var_map, vars, sz)?;
                let re = convert(*r, best, var_map, vars, sz)?;
                Some(make_binop(BinOpKind::Or, le, re, vars, sz))
            }
            Mba::Xor([l, r]) => {
                let le = convert(*l, best, var_map, vars, sz)?;
                let re = convert(*r, best, var_map, vars, sz)?;
                Some(make_binop(BinOpKind::Xor, le, re, vars, sz))
            }
            Mba::Shl([l, r]) => {
                let le = convert(*l, best, var_map, vars, sz)?;
                let re = convert(*r, best, var_map, vars, sz)?;
                Some(make_binop(BinOpKind::Lsl, le, re, vars, sz))
            }
            Mba::Shr([l, r]) => {
                let le = convert(*l, best, var_map, vars, sz)?;
                let re = convert(*r, best, var_map, vars, sz)?;
                Some(make_binop(BinOpKind::Lsr, le, re, vars, sz))
            }
            Mba::Neg(inner) => {
                let ie = convert(*inner, best, var_map, vars, sz)?;
                Some(make_unaryop(UnaryOpKind::Neg, ie, vars, sz))
            }
            Mba::Not(inner) => {
                let ie = convert(*inner, best, var_map, vars, sz)?;
                Some(make_unaryop(UnaryOpKind::Not, ie, vars, sz))
            }
        }
    }

    let root = Id::from(best.as_ref().len() - 1);
    convert(root, best, var_map, vars, sz)
}

/// Helper: create a BinOp by allocating intermediate SSA vars if needed.
fn make_binop(
    kind: crate::ir::BinOpKind,
    left: crate::ir::Expr,
    right: crate::ir::Expr,
    vars: &mut Vec<crate::ir::VarDef>,
    sz: u32,
) -> crate::ir::Expr {
    let left_id = match left {
        crate::ir::Expr::Var(id) => id,
        crate::ir::Expr::Const(_, _) => {
            let id = crate::ir::VarId(vars.len() as u32);
            vars.push(crate::ir::VarDef {
                id,
                varnode: pcode_ir::Varnode {
                    space: pcode_ir::AddressSpaceId::Unique,
                    offset: 0xE000_0000 + id.0 as u64,
                    size: sz,
                },
                expr: left,
                size: sz,
                use_count: 1,
                param_name: None,
                call_return: false,
                inferred_type: crate::ir::InferredType::Unknown,
                display_type: None,
                memory: None,
                origins: Default::default(),
            });
            id
        }
        other => {
            let id = crate::ir::VarId(vars.len() as u32);
            vars.push(crate::ir::VarDef {
                id,
                varnode: pcode_ir::Varnode {
                    space: pcode_ir::AddressSpaceId::Unique,
                    offset: 0xE000_0000 + id.0 as u64,
                    size: sz,
                },
                expr: other,
                size: sz,
                use_count: 1,
                param_name: None,
                call_return: false,
                inferred_type: crate::ir::InferredType::Unknown,
                display_type: None,
                memory: None,
                origins: Default::default(),
            });
            id
        }
    };
    let right_id = match right {
        crate::ir::Expr::Var(id) => id,
        crate::ir::Expr::Const(_, _) => {
            let id = crate::ir::VarId(vars.len() as u32);
            vars.push(crate::ir::VarDef {
                id,
                varnode: pcode_ir::Varnode {
                    space: pcode_ir::AddressSpaceId::Unique,
                    offset: 0xE000_0000 + id.0 as u64,
                    size: sz,
                },
                expr: right,
                size: sz,
                use_count: 1,
                param_name: None,
                call_return: false,
                inferred_type: crate::ir::InferredType::Unknown,
                display_type: None,
                memory: None,
                origins: Default::default(),
            });
            id
        }
        other => {
            let id = crate::ir::VarId(vars.len() as u32);
            vars.push(crate::ir::VarDef {
                id,
                varnode: pcode_ir::Varnode {
                    space: pcode_ir::AddressSpaceId::Unique,
                    offset: 0xE000_0000 + id.0 as u64,
                    size: sz,
                },
                expr: other,
                size: sz,
                use_count: 1,
                param_name: None,
                call_return: false,
                inferred_type: crate::ir::InferredType::Unknown,
                display_type: None,
                memory: None,
                origins: Default::default(),
            });
            id
        }
    };
    crate::ir::Expr::BinOp(kind, left_id, right_id)
}

fn make_unaryop(
    kind: crate::ir::UnaryOpKind,
    inner: crate::ir::Expr,
    vars: &mut Vec<crate::ir::VarDef>,
    sz: u32,
) -> crate::ir::Expr {
    let inner_id = match inner {
        crate::ir::Expr::Var(id) => id,
        other => {
            let id = crate::ir::VarId(vars.len() as u32);
            vars.push(crate::ir::VarDef {
                id,
                varnode: pcode_ir::Varnode {
                    space: pcode_ir::AddressSpaceId::Unique,
                    offset: 0xE000_0000 + id.0 as u64,
                    size: sz,
                },
                expr: other,
                size: sz,
                use_count: 1,
                param_name: None,
                call_return: false,
                inferred_type: crate::ir::InferredType::Unknown,
                display_type: None,
                memory: None,
                origins: Default::default(),
            });
            id
        }
    };
    crate::ir::Expr::UnaryOp(kind, inner_id)
}

/// Run equality saturation on a single expression and return the simplified form.
/// Returns None if the expression can't be simplified or conversion fails.
pub fn simplify_expr(var_idx: usize, vars: &mut Vec<crate::ir::VarDef>) -> Option<crate::ir::Expr> {
    let sz = vars[var_idx].size;

    // Convert SSA → egg (max depth 15 to avoid huge expressions)
    let (egg_expr, var_map) = ssa_to_egg(var_idx, vars, 15)?;

    let expr_len = egg_expr.as_ref().len();

    // Skip tiny expressions (not worth the overhead)
    if expr_len < 5 {
        return None;
    }

    // Skip very large expressions — egg's union-find can panic on pathological
    // inputs with deep expression trees and commutativity rules
    if expr_len > 500 {
        return None;
    }

    let original_cost = {
        let root = Id::from(expr_len - 1);
        let mut egraph = egg::EGraph::<Mba, ()>::default();
        egraph.add_expr(&egg_expr);
        egg::Extractor::new(&egraph, MbaCost).find_best(root).0
    };

    // Run equality saturation with conservative limits
    let rules = mba_rules();
    let runner = Runner::<Mba, (), ()>::default()
        .with_expr(&egg_expr)
        .with_iter_limit(20) // limit iterations (reduced from 30)
        .with_node_limit(5_000) // limit e-graph size (reduced from 10K)
        .with_time_limit(std::time::Duration::from_millis(50))
        .run(&rules);

    // Extract the cheapest equivalent expression
    let root = runner.roots[0];
    let extractor = egg::Extractor::new(&runner.egraph, MbaCost);
    let (best_cost, best_expr) = extractor.find_best(root);

    // Only accept if it's actually simpler
    if best_cost >= original_cost {
        return None;
    }
    if best_expr.as_ref().len() >= expr_len {
        return None;
    }

    // Convert egg → SSA
    egg_to_ssa(&best_expr, &var_map, vars, sz)
}
