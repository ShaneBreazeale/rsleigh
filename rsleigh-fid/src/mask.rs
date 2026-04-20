//! Per-architecture operand masking.
//!
//! Given decoded instruction bytes, produce a canonical form with
//! scalar operand slots zeroed. Goal: two structurally identical funcs
//! with different register allocations or different branch targets
//! hash the same.
//!
//! MVP strategy per arch:
//! - Fixed-width ISAs (ARM64/RISC-V/MIPS32/ARM32): `AND` each 32-bit word
//!   against an opcode-class mask returned by a per-ISA classifier.
//! - Variable-width (x86/x64): keep opcode + ModR/M structural bits,
//!   zero SIB displacement + immediate bytes using instruction length.

use rsleigh_api::{Architecture, Instruction};

/// Produce masked bytes for one instruction.
pub fn mask_instruction(arch: Architecture, inst: &Instruction, raw: &[u8]) -> Vec<u8> {
    match arch {
        Architecture::X86_64 | Architecture::X86_32 => mask_x86(inst, raw),
        Architecture::AArch64 => mask_fixed32(raw, aarch64_mask),
        Architecture::ARM32 => mask_fixed32(raw, arm32_mask),
        Architecture::MIPS32 => mask_fixed32(raw, mips_mask),
        Architecture::RiscV64 => mask_riscv(raw),
    }
}

// --- x86 / x64 -------------------------------------------------------------

fn mask_x86(inst: &Instruction, raw: &[u8]) -> Vec<u8> {
    let len = inst.len as usize;
    let bytes = &raw[..len.min(raw.len())];
    let mut out = bytes.to_vec();

    // Skip legacy/REX prefixes.
    let mut i = 0;
    while i < out.len() {
        match out[i] {
            0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 | 0x66 | 0x67
            | 0xF0 | 0xF2 | 0xF3 => i += 1,
            0x40..=0x4F => { i += 1; } // REX
            _ => break,
        }
    }
    let op_idx = i;
    // Two-byte opcode escape.
    if op_idx < out.len() && out[op_idx] == 0x0F {
        i = op_idx + 1;
        if i < out.len() && (out[i] == 0x38 || out[i] == 0x3A) {
            i += 1;
        }
        i += 1;
    } else if op_idx < out.len() {
        i += 1;
    }

    // Remaining bytes = ModR/M + SIB + disp + imm. Zero disp/imm tail
    // but keep ModR/M + SIB structural bytes so reg encoding still
    // distinguishes instruction shape (approximate).
    // Conservative: keep first 2 post-opcode bytes, zero the rest.
    let keep_after_op = 2usize.min(out.len().saturating_sub(i));
    let zero_start = i + keep_after_op;
    for b in &mut out[zero_start..] {
        *b = 0;
    }
    out
}

// --- ARM64 -----------------------------------------------------------------

fn mask_fixed32(raw: &[u8], mask_fn: fn(u32) -> u32) -> Vec<u8> {
    if raw.len() < 4 {
        return raw.to_vec();
    }
    let w = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let m = mask_fn(w);
    (w & m).to_le_bytes().to_vec()
}

/// Returns the set of bits to KEEP for this AArch64 instruction class.
fn aarch64_mask(w: u32) -> u32 {
    let top = (w >> 25) & 0xF;
    match top {
        // Data processing — immediate
        0x8 | 0x9 => 0xFF80_0000,
        // Branches, exception, system
        0xA | 0xB => 0xFC00_0000,
        // Loads and stores
        0x4 | 0x6 | 0xC | 0xE => 0xFFC0_0000,
        // Data processing — register
        0x5 | 0xD => 0xFFE0_0000,
        // Data processing — SIMD/FP
        0x7 | 0xF => 0xFFE0_0000,
        _ => 0xFC00_0000,
    }
}

/// ARM32 — top 4 cond + opcode class bits.
fn arm32_mask(_w: u32) -> u32 {
    0xFFF0_0000
}

/// MIPS32 — top 6 opcode + (for R-type) low 6 funct.
fn mips_mask(w: u32) -> u32 {
    let op = (w >> 26) & 0x3F;
    match op {
        0 | 0x1C => 0xFC00_003F, // SPECIAL / SPECIAL2 — keep funct
        1 => 0xFC1F_0000,        // REGIMM — keep rt field selector
        _ => 0xFC00_0000,
    }
}

// --- RISC-V ----------------------------------------------------------------

fn mask_riscv(raw: &[u8]) -> Vec<u8> {
    // Compressed 16-bit or standard 32-bit? low 2 bits == 0b11 → 32-bit.
    if raw.len() >= 4 && (raw[0] & 0x3) == 0x3 {
        let w = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let opcode = w & 0x7F;
        let m = match opcode {
            0x33 | 0x3B => 0xFE00_707F, // OP / OP-32: opcode + funct3 + funct7
            0x13 | 0x1B => 0x0000_707F, // OP-IMM / OP-IMM-32: opcode + funct3
            0x03 | 0x23 | 0x67 => 0x0000_707F, // LOAD / STORE / JALR
            0x63 => 0x0000_707F, // BRANCH
            _ => 0x0000_007F,
        };
        (w & m).to_le_bytes().to_vec()
    } else if raw.len() >= 2 {
        let h = u16::from_le_bytes([raw[0], raw[1]]);
        // C-ext: opcode (low 2) + funct3 (high 3)
        let m: u16 = 0xE003;
        (h & m).to_le_bytes().to_vec()
    } else {
        raw.to_vec()
    }
}
