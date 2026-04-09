use std::collections::BTreeMap;

use pcode_ir::{optimize, AddressSpaceId, PcodeOp, Varnode};
use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct FixtureInstruction {
    pub name: String,
    pub bytes: Vec<u8>,
    pub length: u64,
    pub pcode: Option<Vec<PcodeOp>>,
    pub pcode_count: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct FixtureFile {
    cases: Vec<FixtureCase>,
}

#[derive(Debug, Deserialize)]
struct FixtureCase {
    name: String,
    bytes: Vec<u8>,
    length: u64,
    #[serde(default)]
    pcode: Option<Vec<FixturePcodeOp>>,
    #[serde(default)]
    pcode_count: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct FixturePcodeOp {
    op: String,
    #[serde(default)]
    output: Option<FixtureVarnode>,
    #[serde(default)]
    inputs: Vec<FixtureVarnode>,
}

#[derive(Debug, Deserialize)]
struct FixtureVarnode {
    space: String,
    offset: u64,
    size: u32,
}

pub fn x86_fixture() -> Result<Vec<FixtureInstruction>, String> {
    parse_json_fixture(include_str!("../ghidra_x86.json"))
}

pub fn aarch64_fixture() -> Result<Vec<FixtureInstruction>, String> {
    parse_json_fixture(include_str!("../ghidra_aarch64.json"))
}

fn parse_json_fixture(input: &str) -> Result<Vec<FixtureInstruction>, String> {
    let file: FixtureFile =
        serde_json::from_str(input).map_err(|err| format!("invalid fixture json: {err}"))?;

    file.cases
        .into_iter()
        .map(|case| {
            let pcode = case
                .pcode
                .map(|ops| {
                    ops.into_iter()
                        .map(fixture_op_to_pcode)
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()?;

            Ok(FixtureInstruction {
                name: case.name,
                bytes: case.bytes,
                length: case.length,
                pcode,
                pcode_count: case.pcode_count,
            })
        })
        .collect()
}

fn fixture_op_to_pcode(op: FixturePcodeOp) -> Result<PcodeOp, String> {
    match op.op.as_str() {
        "COPY" => Ok(PcodeOp::Copy {
            out: require_output(&op)?,
            input: require_input(&op, 0)?,
        }),
        "LOAD" => Ok(PcodeOp::Load {
            out: require_output(&op)?,
            space: AddressSpaceId::Ram,
            ptr: require_input(&op, 1)?,
        }),
        "STORE" => Ok(PcodeOp::Store {
            space: AddressSpaceId::Ram,
            ptr: require_input(&op, 1)?,
            val: require_input(&op, 2)?,
        }),
        "RETURN" => Ok(PcodeOp::Return {
            dest: require_input(&op, 0)?,
        }),
        "INT_ADD" => Ok(PcodeOp::IntAdd {
            out: require_output(&op)?,
            left: require_input(&op, 0)?,
            right: require_input(&op, 1)?,
        }),
        "INT_SUB" => Ok(PcodeOp::IntSub {
            out: require_output(&op)?,
            left: require_input(&op, 0)?,
            right: require_input(&op, 1)?,
        }),
        "INT_MULT" => Ok(PcodeOp::IntMult {
            out: require_output(&op)?,
            left: require_input(&op, 0)?,
            right: require_input(&op, 1)?,
        }),
        "INT_AND" => Ok(PcodeOp::IntAnd {
            out: require_output(&op)?,
            left: require_input(&op, 0)?,
            right: require_input(&op, 1)?,
        }),
        "INT_OR" => Ok(PcodeOp::IntOr {
            out: require_output(&op)?,
            left: require_input(&op, 0)?,
            right: require_input(&op, 1)?,
        }),
        "INT_XOR" => Ok(PcodeOp::IntXor {
            out: require_output(&op)?,
            left: require_input(&op, 0)?,
            right: require_input(&op, 1)?,
        }),
        "INT_EQUAL" => Ok(PcodeOp::IntEq {
            out: require_output(&op)?,
            left: require_input(&op, 0)?,
            right: require_input(&op, 1)?,
        }),
        "INT_LESSEQUAL" => Ok(PcodeOp::IntLessEq {
            out: require_output(&op)?,
            left: require_input(&op, 0)?,
            right: require_input(&op, 1)?,
        }),
        "INT_SLESS" => Ok(PcodeOp::IntSLess {
            out: require_output(&op)?,
            left: require_input(&op, 0)?,
            right: require_input(&op, 1)?,
        }),
        "INT_CARRY" => Ok(PcodeOp::IntCarry {
            out: require_output(&op)?,
            left: require_input(&op, 0)?,
            right: require_input(&op, 1)?,
        }),
        "INT_SCARRY" => Ok(PcodeOp::IntSCarry {
            out: require_output(&op)?,
            left: require_input(&op, 0)?,
            right: require_input(&op, 1)?,
        }),
        "INT_SBORROW" => Ok(PcodeOp::IntSBorrow {
            out: require_output(&op)?,
            left: require_input(&op, 0)?,
            right: require_input(&op, 1)?,
        }),
        "POPCOUNT" => Ok(PcodeOp::Popcount {
            out: require_output(&op)?,
            input: require_input(&op, 0)?,
        }),
        other => Err(format!("unsupported fixture pcode op '{other}'")),
    }
}

fn require_output(op: &FixturePcodeOp) -> Result<Varnode, String> {
    op.output
        .as_ref()
        .ok_or_else(|| format!("missing output for '{}'", op.op))
        .and_then(fixture_varnode_to_pcode)
}

fn require_input(op: &FixturePcodeOp, idx: usize) -> Result<Varnode, String> {
    op.inputs
        .get(idx)
        .ok_or_else(|| format!("missing input {idx} for '{}'", op.op))
        .and_then(fixture_varnode_to_pcode)
}

fn fixture_varnode_to_pcode(varnode: &FixtureVarnode) -> Result<Varnode, String> {
    let space = match varnode.space.as_str() {
        "register" => AddressSpaceId::Register,
        "ram" => AddressSpaceId::Ram,
        "unique" => AddressSpaceId::Unique,
        "const" => AddressSpaceId::Const,
        other => return Err(format!("unsupported fixture varnode space '{other}'")),
    };

    Ok(Varnode {
        space,
        offset: varnode.offset,
        size: varnode.size,
    })
}

pub fn optimize_fixture_pcode(ops: &[PcodeOp]) -> Vec<PcodeOp> {
    let mut ops = ops.to_vec();
    optimize(&mut ops);
    ops
}

pub fn canonicalize_pcode(ops: &[PcodeOp]) -> Vec<String> {
    let mut uniques = BTreeMap::<(u64, u32), usize>::new();
    let mut next_unique = 0usize;

    ops.iter()
        .map(|op| canonicalize_op(op, &mut uniques, &mut next_unique))
        .collect()
}

fn canonicalize_op(
    op: &PcodeOp,
    uniques: &mut BTreeMap<(u64, u32), usize>,
    next_unique: &mut usize,
) -> String {
    fn unique_label(
        varnode: &Varnode,
        uniques: &mut BTreeMap<(u64, u32), usize>,
        next_unique: &mut usize,
    ) -> String {
        let id = uniques
            .entry((varnode.offset, varnode.size))
            .or_insert_with(|| {
                let id = *next_unique;
                *next_unique += 1;
                id
            });
        format!("unique:u{}:{}", id, varnode.size)
    }

    fn fmt_varnode(
        varnode: &Varnode,
        uniques: &mut BTreeMap<(u64, u32), usize>,
        next_unique: &mut usize,
    ) -> String {
        match varnode.space {
            AddressSpaceId::Unique => unique_label(varnode, uniques, next_unique),
            AddressSpaceId::Register => format!("register:0x{:x}:{}", varnode.offset, varnode.size),
            AddressSpaceId::Ram => format!("ram:0x{:x}:{}", varnode.offset, varnode.size),
            AddressSpaceId::Const => format!("const:0x{:x}:{}", varnode.offset, varnode.size),
        }
    }

    match op {
        PcodeOp::Copy { out, input } => format!(
            "COPY {} <- {}",
            fmt_varnode(out, uniques, next_unique),
            fmt_varnode(input, uniques, next_unique)
        ),
        PcodeOp::Load { out, space, ptr } => format!(
            "LOAD {:?} {} <- {}",
            space,
            fmt_varnode(out, uniques, next_unique),
            fmt_varnode(ptr, uniques, next_unique)
        ),
        PcodeOp::Store { space, ptr, val } => format!(
            "STORE {:?} {} <- {}",
            space,
            fmt_varnode(ptr, uniques, next_unique),
            fmt_varnode(val, uniques, next_unique)
        ),
        PcodeOp::Return { dest } => format!("RETURN {}", fmt_varnode(dest, uniques, next_unique)),
        PcodeOp::IntAdd { out, left, right } => format!(
            "INT_ADD {} <- {}, {}",
            fmt_varnode(out, uniques, next_unique),
            fmt_varnode(left, uniques, next_unique),
            fmt_varnode(right, uniques, next_unique)
        ),
        PcodeOp::IntSub { out, left, right } => format!(
            "INT_SUB {} <- {}, {}",
            fmt_varnode(out, uniques, next_unique),
            fmt_varnode(left, uniques, next_unique),
            fmt_varnode(right, uniques, next_unique)
        ),
        PcodeOp::IntMult { out, left, right } => format!(
            "INT_MULT {} <- {}, {}",
            fmt_varnode(out, uniques, next_unique),
            fmt_varnode(left, uniques, next_unique),
            fmt_varnode(right, uniques, next_unique)
        ),
        PcodeOp::IntAnd { out, left, right } => format!(
            "INT_AND {} <- {}, {}",
            fmt_varnode(out, uniques, next_unique),
            fmt_varnode(left, uniques, next_unique),
            fmt_varnode(right, uniques, next_unique)
        ),
        PcodeOp::IntOr { out, left, right } => format!(
            "INT_OR {} <- {}, {}",
            fmt_varnode(out, uniques, next_unique),
            fmt_varnode(left, uniques, next_unique),
            fmt_varnode(right, uniques, next_unique)
        ),
        PcodeOp::IntXor { out, left, right } => format!(
            "INT_XOR {} <- {}, {}",
            fmt_varnode(out, uniques, next_unique),
            fmt_varnode(left, uniques, next_unique),
            fmt_varnode(right, uniques, next_unique)
        ),
        PcodeOp::IntEq { out, left, right } => format!(
            "INT_EQUAL {} <- {}, {}",
            fmt_varnode(out, uniques, next_unique),
            fmt_varnode(left, uniques, next_unique),
            fmt_varnode(right, uniques, next_unique)
        ),
        PcodeOp::IntLessEq { out, left, right } => format!(
            "INT_LESSEQUAL {} <- {}, {}",
            fmt_varnode(out, uniques, next_unique),
            fmt_varnode(left, uniques, next_unique),
            fmt_varnode(right, uniques, next_unique)
        ),
        PcodeOp::IntSLess { out, left, right } => format!(
            "INT_SLESS {} <- {}, {}",
            fmt_varnode(out, uniques, next_unique),
            fmt_varnode(left, uniques, next_unique),
            fmt_varnode(right, uniques, next_unique)
        ),
        PcodeOp::IntCarry { out, left, right } => format!(
            "INT_CARRY {} <- {}, {}",
            fmt_varnode(out, uniques, next_unique),
            fmt_varnode(left, uniques, next_unique),
            fmt_varnode(right, uniques, next_unique)
        ),
        PcodeOp::IntSCarry { out, left, right } => format!(
            "INT_SCARRY {} <- {}, {}",
            fmt_varnode(out, uniques, next_unique),
            fmt_varnode(left, uniques, next_unique),
            fmt_varnode(right, uniques, next_unique)
        ),
        PcodeOp::IntSBorrow { out, left, right } => format!(
            "INT_SBORROW {} <- {}, {}",
            fmt_varnode(out, uniques, next_unique),
            fmt_varnode(left, uniques, next_unique),
            fmt_varnode(right, uniques, next_unique)
        ),
        PcodeOp::Popcount { out, input } => format!(
            "POPCOUNT {} <- {}",
            fmt_varnode(out, uniques, next_unique),
            fmt_varnode(input, uniques, next_unique)
        ),
        other => format!("{other:?}"),
    }
}
