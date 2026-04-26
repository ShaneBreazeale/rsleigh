//! Classify VM-handler instruction encoding.
//!
//! Given a handler address (one of the 47-handler dispatch table from
//! a PyVMProtect-style VM), determine how many bytes of operand the
//! handler consumes from the bytecode buffer. The encoding pattern is
//! a sequence of `MOVZX ?, byte ptr [bc_ptr + pc_reg + N]` reads
//! followed by a `LEA RAX, [pc_reg + K]; MOV [ctx + 0x10], RAX` PC
//! advance.
//!
//! Output: a `HandlerEncoding` per address giving the operand-byte
//! offsets read and the resulting instruction length.
//!
//! Use case: a single VM may have a mix of 1-byte / 2-byte / 4-byte /
//! 7-byte handlers. Without this classifier, a custom VM disassembler
//! mis-aligns at the first variable-width opcode. We extracted this by
//! hand in the v5 RE session; this module automates it.

use goblin::Object;

/// Encoding info for a single handler.
#[derive(Debug, Clone)]
pub struct HandlerEncoding {
    /// Handler entry VA.
    pub addr: u64,
    /// Sorted operand byte offsets the handler reads (relative to the
    /// post-dispatch PC, i.e., 0 = first byte after the opcode).
    pub operand_offsets: Vec<u32>,
    /// Total instruction length in bytes (1 = opcode-only, 4 = opcode +
    /// 3-byte operand, etc.).
    pub instr_len: u32,
}

/// Find the byte offset within `data` corresponding to a virtual
/// address. Returns None if the VA is outside any executable section.
fn va_to_file_offset(obj: &Object<'_>, va: u64) -> Option<usize> {
    if let Object::PE(pe) = obj {
        for sec in &pe.sections {
            let svaddr = pe.image_base as u64 + sec.virtual_address as u64;
            let sv = sec.virtual_size as u64;
            if va >= svaddr && va < svaddr + sv {
                let raddr = sec.pointer_to_raw_data as usize;
                let rsize = sec.size_of_raw_data as usize;
                let off_in_section = (va - svaddr) as usize;
                if off_in_section < rsize {
                    return Some(raddr + off_in_section);
                }
            }
        }
    }
    None
}

/// Classify a handler. We disassemble the first ~256 bytes of the
/// handler body and pattern-match on common shapes. The technique is
/// byte-oriented (no full decoder dependency) and accurate for the
/// PyVMProtect-style register conventions where R8/RAX/RCX/RDX hold
/// the bytecode-buffer pointer or the post-dispatch PC.
///
/// Pattern fragments we recognize:
///
///   - `MOVZX r32, byte ptr [Rb + Ri*1 + disp8]`  → operand byte read.
///     Encoding: `0F B6 ModRM SIB disp8` (5 bytes) when SIB present.
///     We also accept simpler forms with no SIB.
///
///   - `LEA r64, [r64 + disp8]` → PC-advance candidate.
///     Encoding: `48 8D modRM disp8` (4 bytes).
pub fn classify_handler(obj: &Object<'_>, data: &[u8], addr: u64) -> Option<HandlerEncoding> {
    let off = va_to_file_offset(obj, addr)?;
    let scan_len = 0x100.min(data.len() - off);
    let body = &data[off..off + scan_len];

    let mut operand_offsets: Vec<u32> = Vec::new();
    let mut pc_advance: Option<u32> = None;

    let mut k = 0;
    while k + 4 <= body.len() {
        // MOVZX r32/r64, byte ptr [...] — 0F B6 modRM
        // Forms we accept:
        //   0F B6 mod=00 r/m=100 SIB disp8       (5 bytes total)
        //   0F B6 mod=01 r/m=100 SIB disp8       (5 bytes)
        //   0F B6 mod=01 r/m=??? disp8           (4 bytes, no SIB)
        //   48 0F B6 ... (REX prefix; +1 byte)
        //   44 0F B6 ... (REX.R for R8..R15)
        let rex = if (body[k] == 0x48
            || body[k] == 0x44
            || body[k] == 0x4c
            || body[k] == 0x4d
            || body[k] == 0x41
            || body[k] == 0x45)
            && k + 1 < body.len()
            && body[k + 1] == 0x0f
        {
            1
        } else {
            0
        };
        if k + rex + 3 < body.len() && body[k + rex] == 0x0f && body[k + rex + 1] == 0xb6 {
            let modrm = body[k + rex + 2];
            let mod_field = modrm >> 6;
            let rm = modrm & 0x07;
            let mut disp_off = 0i32;
            let mut consumed = 3 + rex;
            // mod=00 r/m=100 → SIB, no disp (or disp32 if SIB.base==101)
            // mod=01 → 8-bit displacement
            // mod=10 → 32-bit displacement
            if rm == 0x04 {
                // SIB present
                if k + consumed >= body.len() {
                    break;
                }
                consumed += 1; // SIB byte
            }
            if mod_field == 0x01 {
                if k + consumed >= body.len() {
                    break;
                }
                disp_off = body[k + consumed] as i8 as i32;
                consumed += 1;
                operand_offsets.push(disp_off as u32);
            } else if mod_field == 0x02 {
                if k + consumed + 4 > body.len() {
                    break;
                }
                disp_off = i32::from_le_bytes([
                    body[k + consumed],
                    body[k + consumed + 1],
                    body[k + consumed + 2],
                    body[k + consumed + 3],
                ]);
                consumed += 4;
                if disp_off >= 0 && disp_off < 64 {
                    operand_offsets.push(disp_off as u32);
                }
            } else if mod_field == 0x00 && rm == 0x04 {
                // disp 0
                operand_offsets.push(0);
            }
            k += consumed;
            continue;
        }
        // LEA r64, [r64 + disp8]  →  48 8D modRM disp8
        if body[k] == 0x48 && body[k + 1] == 0x8d {
            let modrm = body[k + 2];
            let mod_field = modrm >> 6;
            let rm = modrm & 0x07;
            if mod_field == 0x01 && rm != 0x04 {
                // 4-byte form: 48 8D modRM disp8
                if k + 4 <= body.len() {
                    let disp = body[k + 3] as i8 as i32;
                    if disp > 0 && disp < 16 {
                        // Take the FIRST PC advance we see; if there are
                        // multiple (rare), keep the largest.
                        let v = disp as u32;
                        pc_advance = Some(match pc_advance {
                            Some(prev) => prev.max(v),
                            None => v,
                        });
                    }
                    k += 4;
                    continue;
                }
            }
        }
        // RET — stop scanning, we're past the prologue.
        if body[k] == 0xc3 {
            break;
        }
        k += 1;
    }

    let max_op = operand_offsets.iter().copied().max();
    operand_offsets.sort();
    operand_offsets.dedup();

    // Compute total instruction length.
    // Opcode byte is consumed by dispatcher (+1). Handler advances PC
    // by `pc_advance` bytes (the operand portion).
    let instr_len = if let Some(adv) = pc_advance {
        1 + adv
    } else if let Some(maxo) = max_op {
        1 + maxo + 1
    } else {
        1
    };

    Some(HandlerEncoding {
        addr,
        operand_offsets,
        instr_len,
    })
}

/// Batch classify a list of handlers.
pub fn classify_all(obj: &Object<'_>, data: &[u8], addrs: &[u64]) -> Vec<HandlerEncoding> {
    addrs
        .iter()
        .filter_map(|a| classify_handler(obj, data, *a))
        .collect()
}

/// Render results as one-line-per-handler.
pub fn render(encs: &[HandlerEncoding]) -> Vec<String> {
    encs.iter()
        .map(|e| {
            format!(
                "{:#x}  instr_len={}  operand_offsets={:?}",
                e.addr, e.instr_len, e.operand_offsets
            )
        })
        .collect()
}
