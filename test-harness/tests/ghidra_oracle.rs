//! Ghidra P-code oracle parity tests.
//!
//! Loads JSON exported by `scripts/ExportRsleighOracle.java`, decodes the same
//! bytes through rsleigh, and asserts a strict subset of P-code facts match.
//!
//! Comparison policy is documented in `test-harness/fixtures/oracle/README.md`.
//!
//! Skips silently if no fixtures are present so the test is no-op until a
//! Ghidra install regenerates oracle JSONs.

use pcode_ir::{AddressSpaceId, PcodeOp, Varnode};
use rsleigh_api::{Architecture, Decoder};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
struct Oracle {
    schema_version: u32,
    arch: String,
    functions: Vec<OracleFunction>,
}

#[derive(Debug, Deserialize)]
struct OracleFunction {
    entry: u64,
    instructions: Vec<OracleInstr>,
}

#[derive(Debug, Deserialize)]
struct OracleInstr {
    addr: u64,
    len: u32,
    bytes: String,
    pcode: Vec<OracleOp>,
}

#[derive(Debug, Deserialize)]
struct OracleOp {
    op: String,
    out: Option<OracleVarnode>,
    inputs: Vec<OracleVarnode>,
}

#[derive(Debug, Deserialize, Clone)]
struct OracleVarnode {
    space: String,
    offset: u64,
    size: u32,
}

fn arch_from_string(s: &str) -> Option<Architecture> {
    match s {
        "x86:LE:64:default" => Some(Architecture::X86_64),
        "AARCH64:LE:64:v8A" | "AARCH64:LE:64:AppleSilicon" => Some(Architecture::AArch64),
        _ => None,
    }
}

fn space_from_ghidra(s: &str) -> Option<AddressSpaceId> {
    match s {
        "register" => Some(AddressSpaceId::Register),
        "ram" => Some(AddressSpaceId::Ram),
        "unique" => Some(AddressSpaceId::Unique),
        "const" => Some(AddressSpaceId::Const),
        _ => None,
    }
}

/// Canonical (mnemonic, output, inputs) view of a single P-code op.
/// Side-by-side comparable across Ghidra and rsleigh after unique-id remap.
#[derive(Debug, PartialEq, Eq)]
struct NormOp {
    mnemonic: &'static str,
    out: Option<NormVar>,
    inputs: Vec<NormVar>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct NormVar {
    space: AddressSpaceId,
    offset: u64,
    size: u32,
}

impl NormVar {
    fn from_pcode(v: &Varnode) -> Self {
        Self {
            space: v.space,
            offset: v.offset,
            size: v.size,
        }
    }

    fn from_oracle(v: &OracleVarnode) -> Option<Self> {
        Some(Self {
            space: space_from_ghidra(&v.space)?,
            offset: v.offset,
            size: v.size,
        })
    }
}

fn ghidra_mnemonic_to_rsleigh(s: &str) -> Option<&'static str> {
    Some(match s {
        "COPY" => "Copy",
        "LOAD" => "Load",
        "STORE" => "Store",
        "BRANCH" => "Branch",
        "CBRANCH" => "CBranch",
        "BRANCHIND" => "BranchInd",
        "CALL" => "Call",
        "CALLIND" => "CallInd",
        "RETURN" => "Return",
        "INT_ADD" => "IntAdd",
        "INT_SUB" => "IntSub",
        "INT_MULT" => "IntMult",
        "INT_DIV" => "IntDiv",
        "INT_SDIV" => "IntSDiv",
        "INT_REM" => "IntRem",
        "INT_SREM" => "IntSRem",
        "INT_NEGATE" => "IntNeg",
        "INT_EQUAL" => "IntEq",
        "INT_NOTEQUAL" => "IntNotEq",
        "INT_LESS" => "IntLess",
        "INT_LESSEQUAL" => "IntLessEq",
        "INT_SLESS" => "IntSLess",
        "INT_SLESSEQUAL" => "IntSLessEq",
        "INT_AND" => "IntAnd",
        "INT_OR" => "IntOr",
        "INT_XOR" => "IntXor",
        "INT_2COMP" => "IntNeg",
        "INT_LEFT" => "IntLsl",
        "INT_RIGHT" => "IntLsr",
        "INT_SRIGHT" => "IntAsr",
        "INT_ZEXT" => "IntZext",
        "INT_SEXT" => "IntSext",
        "SUBPIECE" => "Subpiece",
        "INT_CARRY" => "IntCarry",
        "INT_SCARRY" => "IntSCarry",
        "INT_SBORROW" => "IntSBorrow",
        "BOOL_AND" => "BoolAnd",
        "BOOL_OR" => "BoolOr",
        "BOOL_XOR" => "BoolXor",
        "BOOL_NEGATE" => "BoolNot",
        "FLOAT_ADD" => "FloatAdd",
        "FLOAT_SUB" => "FloatSub",
        "FLOAT_MULT" => "FloatMult",
        "FLOAT_DIV" => "FloatDiv",
        "FLOAT_NEG" => "FloatNeg",
        "FLOAT_ABS" => "FloatAbs",
        "FLOAT_SQRT" => "FloatSqrt",
        "FLOAT_EQUAL" => "FloatEq",
        "FLOAT_NOTEQUAL" => "FloatNotEq",
        "FLOAT_LESS" => "FloatLess",
        "FLOAT_LESSEQUAL" => "FloatLessEq",
        "FLOAT_NAN" => "FloatNan",
        "INT2FLOAT" => "Int2Float",
        "FLOAT2FLOAT" => "Float2Float",
        "TRUNC" => "Trunc",
        "FLOAT_CEIL" => "FloatCeil",
        "FLOAT_FLOOR" => "FloatFloor",
        "FLOAT_ROUND" => "FloatRound",
        "POPCOUNT" => "Popcount",
        "LZCOUNT" => "Lzcount",
        "CALLOTHER" => "CallOther",
        _ => return None,
    })
}

fn rsleigh_op_to_norm(op: &PcodeOp) -> NormOp {
    use PcodeOp::*;
    let v = NormVar::from_pcode;
    macro_rules! n {
        ($name:expr, $out:expr, $ins:expr) => {
            NormOp {
                mnemonic: $name,
                out: $out,
                inputs: $ins,
            }
        };
    }
    match op {
        Copy { out, input } => n!("Copy", Some(v(out)), vec![v(input)]),
        Load { out, space: _, ptr } => n!("Load", Some(v(out)), vec![v(ptr)]),
        Store { space: _, ptr, val } => n!("Store", None, vec![v(ptr), v(val)]),
        Branch { dest } => n!("Branch", None, vec![v(dest)]),
        CBranch { dest, cond } => n!("CBranch", None, vec![v(dest), v(cond)]),
        BranchInd { dest } => n!("BranchInd", None, vec![v(dest)]),
        Call { dest } => n!("Call", None, vec![v(dest)]),
        CallInd { dest } => n!("CallInd", None, vec![v(dest)]),
        Return { dest } => n!("Return", None, vec![v(dest)]),
        IntAdd { out, left, right } => n!("IntAdd", Some(v(out)), vec![v(left), v(right)]),
        IntSub { out, left, right } => n!("IntSub", Some(v(out)), vec![v(left), v(right)]),
        IntMult { out, left, right } => n!("IntMult", Some(v(out)), vec![v(left), v(right)]),
        IntDiv { out, left, right } => n!("IntDiv", Some(v(out)), vec![v(left), v(right)]),
        IntSDiv { out, left, right } => n!("IntSDiv", Some(v(out)), vec![v(left), v(right)]),
        IntRem { out, left, right } => n!("IntRem", Some(v(out)), vec![v(left), v(right)]),
        IntSRem { out, left, right } => n!("IntSRem", Some(v(out)), vec![v(left), v(right)]),
        IntNeg { out, input } => n!("IntNeg", Some(v(out)), vec![v(input)]),
        IntEq { out, left, right } => n!("IntEq", Some(v(out)), vec![v(left), v(right)]),
        IntNotEq { out, left, right } => n!("IntNotEq", Some(v(out)), vec![v(left), v(right)]),
        IntLess { out, left, right } => n!("IntLess", Some(v(out)), vec![v(left), v(right)]),
        IntLessEq { out, left, right } => n!("IntLessEq", Some(v(out)), vec![v(left), v(right)]),
        IntSLess { out, left, right } => n!("IntSLess", Some(v(out)), vec![v(left), v(right)]),
        IntSLessEq { out, left, right } => {
            n!("IntSLessEq", Some(v(out)), vec![v(left), v(right)])
        }
        IntAnd { out, left, right } => n!("IntAnd", Some(v(out)), vec![v(left), v(right)]),
        IntOr { out, left, right } => n!("IntOr", Some(v(out)), vec![v(left), v(right)]),
        IntXor { out, left, right } => n!("IntXor", Some(v(out)), vec![v(left), v(right)]),
        IntNot { out, input } => n!("IntNot", Some(v(out)), vec![v(input)]),
        IntLsl { out, left, right } => n!("IntLsl", Some(v(out)), vec![v(left), v(right)]),
        IntLsr { out, left, right } => n!("IntLsr", Some(v(out)), vec![v(left), v(right)]),
        IntAsr { out, left, right } => n!("IntAsr", Some(v(out)), vec![v(left), v(right)]),
        IntZext { out, input } => n!("IntZext", Some(v(out)), vec![v(input)]),
        IntSext { out, input } => n!("IntSext", Some(v(out)), vec![v(input)]),
        Subpiece { out, input, lsb } => n!(
            "Subpiece",
            Some(v(out)),
            vec![
                v(input),
                NormVar { space: AddressSpaceId::Const, offset: *lsb as u64, size: 4 },
            ]
        ),
        IntCarry { out, left, right } => n!("IntCarry", Some(v(out)), vec![v(left), v(right)]),
        IntSCarry { out, left, right } => n!("IntSCarry", Some(v(out)), vec![v(left), v(right)]),
        IntSBorrow { out, left, right } => n!("IntSBorrow", Some(v(out)), vec![v(left), v(right)]),
        BoolAnd { out, left, right } => n!("BoolAnd", Some(v(out)), vec![v(left), v(right)]),
        BoolOr { out, left, right } => n!("BoolOr", Some(v(out)), vec![v(left), v(right)]),
        BoolXor { out, left, right } => n!("BoolXor", Some(v(out)), vec![v(left), v(right)]),
        BoolNot { out, input } => n!("BoolNot", Some(v(out)), vec![v(input)]),
        FloatAdd { out, left, right } => n!("FloatAdd", Some(v(out)), vec![v(left), v(right)]),
        FloatSub { out, left, right } => n!("FloatSub", Some(v(out)), vec![v(left), v(right)]),
        FloatMult { out, left, right } => n!("FloatMult", Some(v(out)), vec![v(left), v(right)]),
        FloatDiv { out, left, right } => n!("FloatDiv", Some(v(out)), vec![v(left), v(right)]),
        FloatNeg { out, input } => n!("FloatNeg", Some(v(out)), vec![v(input)]),
        FloatAbs { out, input } => n!("FloatAbs", Some(v(out)), vec![v(input)]),
        FloatSqrt { out, input } => n!("FloatSqrt", Some(v(out)), vec![v(input)]),
        FloatEq { out, left, right } => n!("FloatEq", Some(v(out)), vec![v(left), v(right)]),
        FloatNotEq { out, left, right } => n!("FloatNotEq", Some(v(out)), vec![v(left), v(right)]),
        FloatLess { out, left, right } => n!("FloatLess", Some(v(out)), vec![v(left), v(right)]),
        FloatLessEq { out, left, right } => {
            n!("FloatLessEq", Some(v(out)), vec![v(left), v(right)])
        }
        FloatNan { out, input } => n!("FloatNan", Some(v(out)), vec![v(input)]),
        Int2Float { out, input } => n!("Int2Float", Some(v(out)), vec![v(input)]),
        Float2Float { out, input } => n!("Float2Float", Some(v(out)), vec![v(input)]),
        Trunc { out, input } => n!("Trunc", Some(v(out)), vec![v(input)]),
        FloatCeil { out, input } => n!("FloatCeil", Some(v(out)), vec![v(input)]),
        FloatFloor { out, input } => n!("FloatFloor", Some(v(out)), vec![v(input)]),
        FloatRound { out, input } => n!("FloatRound", Some(v(out)), vec![v(input)]),
        Popcount { out, input } => n!("Popcount", Some(v(out)), vec![v(input)]),
        Lzcount { out, input } => n!("Lzcount", Some(v(out)), vec![v(input)]),
        CallOther { out, func_id, inputs } => {
            let mut v_inputs = vec![NormVar {
                space: AddressSpaceId::Const,
                offset: *func_id,
                size: 8,
            }];
            v_inputs.extend(inputs.iter().map(v));
            NormOp {
                mnemonic: "CallOther",
                out: out.as_ref().map(v),
                inputs: v_inputs,
            }
        }
    }
}

fn oracle_op_to_norm(op: &OracleOp) -> Option<NormOp> {
    let mnemonic = ghidra_mnemonic_to_rsleigh(&op.op)?;
    let out = op.out.as_ref().and_then(NormVar::from_oracle);
    let inputs: Option<Vec<_>> = op.inputs.iter().map(NormVar::from_oracle).collect();
    let mut inputs = inputs?;
    // LOAD/STORE first input is an opaque address-space ID const that Ghidra
    // and rsleigh encode differently (Ghidra: numeric Ghidra-space-id, rsleigh:
    // enum discriminant). Strip on both sides; the operand semantics are
    // recovered by the strict space-tag on the pointer/value varnode itself.
    if matches!(mnemonic, "Load" | "Store") && !inputs.is_empty() {
        inputs.remove(0);
    }
    Some(NormOp {
        mnemonic,
        out,
        inputs,
    })
}

/// Remap `unique` offsets to first-def order (per instruction). Ghidra and
/// rsleigh assign arbitrary unique offsets; only definition order is comparable.
fn normalize_uniques(ops: &mut [NormOp]) {
    let mut map: HashMap<u64, u64> = HashMap::new();
    let mut next: u64 = 0;
    let mut canon = |v: &mut NormVar| {
        if v.space == AddressSpaceId::Unique {
            let id = *map.entry(v.offset).or_insert_with(|| {
                let i = next;
                next += 1;
                i
            });
            v.offset = id;
        }
    };
    for op in ops.iter_mut() {
        if let Some(out) = op.out.as_mut() {
            canon(out);
        }
        for inp in op.inputs.iter_mut() {
            canon(inp);
        }
    }
}

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("oracle")
}

fn discover_oracles() -> Vec<PathBuf> {
    let root = fixtures_root();
    let mut out = Vec::new();
    if !root.exists() {
        return out;
    }
    for arch_dir in std::fs::read_dir(&root).into_iter().flatten().flatten() {
        let p = arch_dir.path();
        if !p.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(&p).into_iter().flatten().flatten() {
            let f = entry.path();
            if f.extension().and_then(|s| s.to_str()) == Some("json")
                && f.to_string_lossy().ends_with(".ghidra.json")
            {
                out.push(f);
            }
        }
    }
    out
}

fn parse_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("oracle hex bytes"))
        .collect()
}

fn check_oracle(path: &Path) {
    let raw = std::fs::read_to_string(path).expect("read oracle json");
    let oracle: Oracle = serde_json::from_str(&raw).expect("parse oracle json");
    assert_eq!(oracle.schema_version, 1, "{}", path.display());

    let arch = arch_from_string(&oracle.arch).unwrap_or_else(|| {
        panic!("unmapped Ghidra arch in {}: {}", path.display(), oracle.arch)
    });

    assert!(
        !oracle.functions.is_empty(),
        "{}: oracle has zero functions — Ghidra import didn't disassemble. \
         Check that ExportRsleighOracle.java forced disassembly + function creation.",
        path.display()
    );
    let mut total_instructions = 0usize;

    let mut decoder = Decoder::new(arch);

    for func in &oracle.functions {
        total_instructions += func.instructions.len();
        for ins in &func.instructions {
            let bytes = parse_hex(&ins.bytes);
            let decoded = decoder
                .decode(&bytes, ins.addr)
                .unwrap_or_else(|e| panic!("rsleigh decode failed at {:#x}: {:?}", ins.addr, e));

            assert_eq!(
                decoded.len as u32, ins.len,
                "{}@{:#x}: instruction length mismatch (rsleigh={} ghidra={})",
                path.display(),
                ins.addr,
                decoded.len,
                ins.len
            );

            let mut rs_norm: Vec<NormOp> = decoded.ops.iter().map(rsleigh_op_to_norm).collect();
            let mut gh_norm: Vec<NormOp> = ins
                .pcode
                .iter()
                .filter_map(oracle_op_to_norm)
                .collect();
            normalize_uniques(&mut rs_norm);
            normalize_uniques(&mut gh_norm);

            assert_eq!(
                rs_norm.len(),
                gh_norm.len(),
                "{}@{:#x}: pcode op count mismatch\n  rsleigh: {:#?}\n  ghidra:  {:#?}",
                path.display(),
                ins.addr,
                rs_norm,
                gh_norm
            );

            for (i, (r, g)) in rs_norm.iter().zip(gh_norm.iter()).enumerate() {
                assert_eq!(
                    r,
                    g,
                    "{}@{:#x}[op {}]: pcode mismatch\n  rsleigh: {:#?}\n  ghidra:  {:#?}\n  func entry={:#x}",
                    path.display(),
                    ins.addr,
                    i,
                    r,
                    g,
                    func.entry
                );
            }
        }
    }
    assert!(
        total_instructions > 0,
        "{}: oracle has functions but zero instructions",
        path.display()
    );
}

#[test]
fn ghidra_oracle_parity() {
    let oracles = discover_oracles();
    if oracles.is_empty() {
        eprintln!(
            "no oracle fixtures present under {}; skipping",
            fixtures_root().display()
        );
        return;
    }
    for path in oracles {
        eprintln!("checking {}", path.display());
        check_oracle(&path);
    }
}

#[test]
fn unique_normalization_is_stable() {
    use AddressSpaceId::*;
    let mut ops = vec![
        NormOp {
            mnemonic: "Copy",
            out: Some(NormVar { space: Unique, offset: 0xdeadbeef, size: 8 }),
            inputs: vec![NormVar { space: Register, offset: 0, size: 8 }],
        },
        NormOp {
            mnemonic: "Copy",
            out: Some(NormVar { space: Register, offset: 24, size: 8 }),
            inputs: vec![NormVar { space: Unique, offset: 0xdeadbeef, size: 8 }],
        },
    ];
    normalize_uniques(&mut ops);
    assert_eq!(ops[0].out.as_ref().unwrap().offset, 0);
    assert_eq!(ops[1].inputs[0].offset, 0);
}
