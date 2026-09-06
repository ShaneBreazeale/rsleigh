//! Semantic roots resolved against the exact post-fold SSA used by slicing.
use crate::fold::{abi, CallingConv};
use crate::ir::{SsaCfg, SsaTerminator, VarId};
use pcode_ir::{AddressSpaceId, Instruction, PcodeOp};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Selector {
    Variable { var_id: u32 },
    CallArgument { address: u64, index: usize },
    Return { address: Option<u64> },
    Condition { address: u64 },
}

#[derive(Debug, Serialize)]
pub struct Selection {
    pub selector: Selector,
    pub root: u32,
    pub instruction_address: Option<String>,
    pub calling_convention: String,
    pub interpretation: &'static str,
}

#[derive(Debug, Serialize)]
pub struct SelectionError {
    pub code: &'static str,
    pub message: String,
    pub candidates: Vec<String>,
}

fn error(code: &'static str, message: impl Into<String>) -> SelectionError {
    SelectionError {
        code,
        message: message.into(),
        candidates: vec![],
    }
}

/// Resolve only real control-flow instruction sites. Implicit returns at the
/// end of truncated decoding and instructions inside a block are not sites.
/// Multiple return instructions require a site even if their roots agree.
pub fn resolve(
    ssa: &SsaCfg,
    instructions: &[(u64, Instruction)],
    selector: Selector,
    cc: CallingConv,
) -> Result<Selection, SelectionError> {
    let operations: Vec<_> = instructions
        .iter()
        .map(|(address, inst)| (*address, inst.ops.as_slice()))
        .collect();
    resolve_operations(ssa, &operations, selector, cc)
}

/// Resolve a restored snapshot without re-decoding instructions. The address
/// and typed operations must belong to the same snapshot as `ssa`.
pub fn resolve_operations(
    ssa: &SsaCfg,
    instructions: &[(u64, &[PcodeOp])],
    selector: Selector,
    cc: CallingConv,
) -> Result<Selection, SelectionError> {
    let selected = |root: VarId, address: Option<u64>, interpretation| Selection {
        selector: selector.clone(),
        root: root.0,
        instruction_address: address.map(|a| format!("0x{a:x}")),
        calling_convention: format!("{cc:?}"),
        interpretation,
    };
    if let Selector::Variable { var_id } = &selector {
        return if (*var_id as usize) < ssa.vars.len() {
            Ok(selected(
                VarId(*var_id),
                None,
                "snapshot-local SSA variable",
            ))
        } else {
            Err(error(
                "missing_target",
                format!("SSA variable {var_id} does not exist"),
            ))
        };
    }
    let address = match &selector {
        Selector::CallArgument { address, .. } | Selector::Condition { address } => Some(*address),
        Selector::Return { address } => *address,
        _ => unreachable!(),
    };
    if let Some(address) = address {
        if !instructions.iter().any(|(a, _)| *a == address) {
            return Err(error(
                "missing_target",
                format!("instruction 0x{address:x} is absent from this snapshot"),
            ));
        }
    }
    let mut blocks: Vec<_> = ssa.blocks.iter().collect();
    blocks.sort_by_key(|b| b.addr);
    let mut candidates = Vec::new();
    for (index, block) in blocks.iter().enumerate() {
        let end = blocks.get(index + 1).map(|b| b.addr);
        let Some((site, inst)) = instructions
            .iter()
            .filter(|(a, _)| *a >= block.addr && end.is_none_or(|end| *a < end))
            .max_by_key(|(a, _)| *a)
        else {
            continue;
        };
        if address.is_some_and(|a| a != *site) {
            continue;
        }
        let compatible = match (&selector, &block.terminator) {
            (Selector::CallArgument { .. }, SsaTerminator::Call { .. }) => inst
                .iter()
                .any(|op| matches!(op, PcodeOp::Call { .. } | PcodeOp::CallInd { .. })),
            (Selector::Return { .. }, SsaTerminator::Return(_)) => inst
                .iter()
                .any(|op| matches!(op, PcodeOp::Return { .. } | PcodeOp::BranchInd { .. })),
            (Selector::Condition { .. }, SsaTerminator::CBranch { .. }) => inst.iter().any(
                |op| matches!(op, PcodeOp::CBranch {dest,..} if dest.space == AddressSpaceId::Ram),
            ),
            _ => false,
        };
        if compatible {
            candidates.push((*site, *block));
        }
    }
    if candidates.is_empty() {
        return Err(error(
            if address.is_some() {
                "unsupported_root"
            } else {
                "missing_target"
            },
            "no matching call, return, or conditional-branch root at the requested site",
        ));
    }
    if candidates.len() > 1 {
        return Err(SelectionError {
            code: "ambiguous_target",
            message: "multiple return sites; select one with --at ADDRESS".into(),
            candidates: candidates.iter().map(|(a, _)| format!("0x{a:x}")).collect(),
        });
    }
    let (site, block) = candidates[0];
    match (&selector, &block.terminator) {
        (Selector::CallArgument {index,..}, SsaTerminator::Call {args,..}) => {
            let registers = abi(cc).int_args;
            let root = if registers.is_empty() {
                args.get(*index).copied()
            } else {
                // Use the ABI register slot, never the compacted recovered-args
                // position: a missing arg zero must not shift arg one to zero.
                let offset = registers.get(*index).ok_or_else(|| error("unsupported_root", "argument is outside supported integer register slots"))?;
                args.iter().copied().find(|v| ssa.vars.get(v.0 as usize).is_some_and(|v|
                    v.varnode.space == AddressSpaceId::Register && v.varnode.offset == *offset))
            }.ok_or_else(|| error("unsupported_root", format!("argument {index} was not recovered under {cc:?}")))?;
            Ok(selected(root, Some(site), "zero-based integer/pointer ABI argument; recovery is not a callee signature proof"))
        }
        (Selector::Return {..}, SsaTerminator::Return(root)) => {
            let root = root.ok_or_else(|| error("unsupported_root", "return site has no recovered value (void or unknown return convention)"))?;
            Ok(selected(root, Some(site), "recovered return value at the selected instruction; does not establish reachability"))
        }
        (Selector::Condition {..}, SsaTerminator::CBranch {cond,..}) =>
            Ok(selected(*cond, Some(site), "nonzero condition selects the taken edge; expression dependence, not control dependence")),
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{BlockId, CallTarget, Expr, SsaBlock};
    use pcode_ir::Varnode;

    #[test]
    fn missing_integer_register_slot_does_not_shift_other_arguments() {
        let mut ssa = SsaCfg {
            blocks: vec![],
            vars: vec![],
            entry: BlockId(0),
            diagnostics: vec![],
        };
        let second = ssa.new_var(Varnode::register(48, 8), Expr::Const(22, 8), 8); // RSI, SysV arg 1
        ssa.blocks.push(SsaBlock {
            id: BlockId(0),
            addr: 0x1000,
            stmts: vec![],
            terminator: SsaTerminator::Call {
                target: CallTarget::Direct(0x2000),
                args: vec![second],
                out: None,
                fallthrough: BlockId(0),
            },
        });
        let instructions = vec![(
            0x1000,
            Instruction::new(
                5,
                "call".into(),
                vec![PcodeOp::Call {
                    dest: Varnode::ram(0x2000, 8),
                }],
            ),
        )];
        assert_eq!(
            resolve(
                &ssa,
                &instructions,
                Selector::CallArgument {
                    address: 0x1000,
                    index: 0
                },
                CallingConv::SysV
            )
            .unwrap_err()
            .code,
            "unsupported_root"
        );
        assert_eq!(
            resolve(
                &ssa,
                &instructions,
                Selector::CallArgument {
                    address: 0x1000,
                    index: 1
                },
                CallingConv::SysV
            )
            .unwrap()
            .root,
            second.0
        );
    }

    #[test]
    fn implicit_end_of_input_is_not_a_real_return_site() {
        let mut ssa = SsaCfg {
            blocks: vec![],
            vars: vec![],
            entry: BlockId(0),
            diagnostics: vec![],
        };
        let value = ssa.new_var(Varnode::register(0, 4), Expr::Const(7, 4), 4);
        ssa.blocks.push(SsaBlock {
            id: BlockId(0),
            addr: 0x1000,
            stmts: vec![],
            terminator: SsaTerminator::Return(Some(value)),
        });
        let instructions = vec![(
            0x1000,
            Instruction::new(
                5,
                "mov eax,7".into(),
                vec![PcodeOp::Copy {
                    out: Varnode::register(0, 4),
                    input: Varnode::constant(7, 4),
                }],
            ),
        )];
        assert_eq!(
            resolve(
                &ssa,
                &instructions,
                Selector::Return { address: None },
                CallingConv::Cdecl32
            )
            .unwrap_err()
            .code,
            "missing_target"
        );
    }
}
