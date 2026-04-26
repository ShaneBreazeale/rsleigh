//! Custom-VM bytecode disassembler.
//!
//! Given a bytecode region (base VA + size) and a handler table that
//! maps opcodes to (mnemonic, operand_size), walk the bytecode and emit
//! one line per VM instruction. Works for any byte-indexed VM where the
//! analyst has already classified the handlers.
//!
//! Companion to:
//!   - `xor_vtable` / `vm_dispatch_extract` — locate the dispatcher
//!     and recover the handler table
//!   - `vm_handler_classify` — derive operand-size per handler
//!   - `handler_summary` — name handlers from their API call surface
//!
//! Real-world use: malware VMs (VMProtect-style, Themida, Stantinko,
//! Trickbot Anchor, etc.) where the C2 URL / decryption key / behaviour
//! is hidden behind a bytecode interpreter. Once you have the handler
//! map, this module emits the actual program logic.
//!
//! Input handler-JSON format — array indexed by opcode byte:
//!   [
//!     {"name": "CALL_FN",     "operand_size": 2},
//!     {"name": "STORE_DICT",  "operand_size": 4, "handler_va": "0x180017750"},
//!     ...
//!   ]
//! Missing entries (sparse vtable) are rendered as `OP_<hex>` with
//! `operand_size: 0` — the analyst can fill them in later.

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Handler {
    pub name: String,
    pub operand_size: u8,
    pub handler_va: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct Instr {
    pub bc_va: u64,
    pub opcode: u8,
    pub mnemonic: String,
    pub operands: Vec<u8>,
    pub handler_va: Option<u64>,
}

/// Parse a JSON handlers file. Accepts either an array (opcode = index)
/// or an object whose keys are decimal/hex opcode strings.
pub fn parse_handlers_json(json: &str) -> Result<HashMap<u8, Handler>, String> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let mut out = HashMap::new();
    let entry_to_handler = |e: &serde_json::Value| -> Option<Handler> {
        let name = e.get("name")?.as_str()?.to_string();
        let operand_size = e
            .get("operand_size")
            .and_then(|x| x.as_u64())
            .unwrap_or(0) as u8;
        let handler_va = e.get("handler_va").and_then(|x| match x {
            serde_json::Value::String(s) => {
                let s = s.trim_start_matches("0x").trim_start_matches("0X");
                u64::from_str_radix(s, 16).ok()
            }
            serde_json::Value::Number(n) => n.as_u64(),
            _ => None,
        });
        Some(Handler {
            name,
            operand_size,
            handler_va,
        })
    };
    if let Some(arr) = v.as_array() {
        for (i, e) in arr.iter().enumerate() {
            if i > 255 {
                break;
            }
            if e.is_null() {
                continue;
            }
            if let Some(h) = entry_to_handler(e) {
                out.insert(i as u8, h);
            }
        }
    } else if let Some(obj) = v.as_object() {
        for (k, e) in obj {
            let key = if let Some(stripped) = k.strip_prefix("0x").or_else(|| k.strip_prefix("0X")) {
                u8::from_str_radix(stripped, 16).ok()
            } else {
                k.parse::<u8>().ok()
            };
            if let (Some(op), Some(h)) = (key, entry_to_handler(e)) {
                out.insert(op, h);
            }
        }
    } else {
        return Err("handlers JSON must be an array or object".to_string());
    }
    Ok(out)
}

pub fn disassemble(bytecode: &[u8], bc_base_va: u64, vtable: &HashMap<u8, Handler>) -> Vec<Instr> {
    let mut out = Vec::new();
    let mut pc = 0usize;
    while pc < bytecode.len() {
        let opcode = bytecode[pc];
        let bc_va = bc_base_va + pc as u64;
        if let Some(h) = vtable.get(&opcode) {
            let osz = h.operand_size as usize;
            let end = (pc + 1 + osz).min(bytecode.len());
            let operands = bytecode[pc + 1..end].to_vec();
            out.push(Instr {
                bc_va,
                opcode,
                mnemonic: h.name.clone(),
                operands,
                handler_va: h.handler_va,
            });
            // If we ran past the end mid-operand, stop — the bytecode
            // size was too small for the declared operand_size.
            if end < pc + 1 + osz {
                break;
            }
            pc = end;
        } else {
            // Unknown opcode — emit as `OP_<hex>` with zero operands.
            // We can't safely advance past unknowns since operand size
            // is unknown; advance 1 and let the analyst notice the
            // sequence of `OP_xx` lines.
            out.push(Instr {
                bc_va,
                opcode,
                mnemonic: format!("OP_{:02X}", opcode),
                operands: Vec::new(),
                handler_va: None,
            });
            pc += 1;
        }
    }
    out
}

pub fn render(insts: &[Instr]) -> Vec<String> {
    insts
        .iter()
        .map(|i| {
            let ops: String = i
                .operands
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");
            let suffix = match i.handler_va {
                Some(va) => format!("    ; handler={:#x}", va),
                None => String::new(),
            };
            if ops.is_empty() {
                format!("{:#010x}: {:02x}        {}{}", i.bc_va, i.opcode, i.mnemonic, suffix)
            } else {
                format!(
                    "{:#010x}: {:02x}  {:<14} {}{}",
                    i.bc_va, i.opcode, i.mnemonic, ops, suffix
                )
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vt_from_pairs(pairs: &[(u8, &str, u8)]) -> HashMap<u8, Handler> {
        pairs
            .iter()
            .map(|(op, name, sz)| {
                (
                    *op,
                    Handler {
                        name: (*name).to_string(),
                        operand_size: *sz,
                        handler_va: None,
                    },
                )
            })
            .collect()
    }

    #[test]
    fn parse_array_form() {
        let json = r#"[{"name":"NOP","operand_size":0},{"name":"PUSH","operand_size":1}]"#;
        let m = parse_handlers_json(json).unwrap();
        assert_eq!(m[&0].name, "NOP");
        assert_eq!(m[&1].name, "PUSH");
        assert_eq!(m[&1].operand_size, 1);
    }

    #[test]
    fn parse_object_form_hex_key() {
        let json = r#"{"0x42":{"name":"CALL","operand_size":4,"handler_va":"0x180018960"}}"#;
        let m = parse_handlers_json(json).unwrap();
        let h = &m[&0x42];
        assert_eq!(h.name, "CALL");
        assert_eq!(h.operand_size, 4);
        assert_eq!(h.handler_va, Some(0x180018960));
    }

    #[test]
    fn disasm_walks_bytecode() {
        // 0x00 = NOP (no operand), 0x01 = PUSH (1-byte operand)
        let vt = vt_from_pairs(&[(0x00, "NOP", 0), (0x01, "PUSH", 1)]);
        let bc = [0x00, 0x01, 0x42, 0x00];
        let insts = disassemble(&bc, 0x1000, &vt);
        assert_eq!(insts.len(), 3);
        assert_eq!(insts[0].mnemonic, "NOP");
        assert_eq!(insts[1].mnemonic, "PUSH");
        assert_eq!(insts[1].operands, vec![0x42]);
        assert_eq!(insts[2].bc_va, 0x1003);
    }

    #[test]
    fn disasm_unknown_opcode_renders_OP_hex() {
        let vt: HashMap<u8, Handler> = HashMap::new();
        let bc = [0x99];
        let insts = disassemble(&bc, 0x2000, &vt);
        assert_eq!(insts.len(), 1);
        assert_eq!(insts[0].mnemonic, "OP_99");
    }

    #[test]
    fn render_includes_va_and_operands() {
        let vt = vt_from_pairs(&[(0x05, "CALL", 2)]);
        let bc = [0x05, 0xaa, 0xbb];
        let insts = disassemble(&bc, 0x180018000, &vt);
        let lines = render(&insts);
        assert!(lines[0].contains("0x180018000"));
        assert!(lines[0].contains("CALL"));
        assert!(lines[0].contains("aa bb"));
    }

    #[test]
    fn truncated_operand_stops_disasm() {
        // Bytecode declares 4-byte operand but only 2 bytes left.
        let vt = vt_from_pairs(&[(0x10, "WIDE", 4)]);
        let bc = [0x10, 0xaa, 0xbb];
        let insts = disassemble(&bc, 0x3000, &vt);
        // Should emit one (truncated) instruction then stop.
        assert_eq!(insts.len(), 1);
        assert_eq!(insts[0].operands.len(), 2);
    }
}
