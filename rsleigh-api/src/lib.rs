//! Spectra integration API for rsleigh.
//!
//! Provides a unified `Decoder` interface across all supported architectures,
//! managing context/global-set lifecycle and returning optimized P-code.
//!
//! # Usage
//!
//! ```no_run
//! use rsleigh_api::{Decoder, Architecture};
//!
//! let mut decoder = Decoder::new(Architecture::X86_64);
//! let inst = decoder.decode(&[0x48, 0x89, 0xd8], 0x1000).unwrap();
//! assert_eq!(inst.disassembly, "MOV RAX,RBX");
//! assert_eq!(inst.len, 3);
//! ```
//!
//! # Stability
//!
//! This crate is the **stable** entry point for embedding rsleigh as a
//! decoder/lifter. Audit P2 #2: the surface listed below is covered by
//! semver and changes go through deprecation; everything outside this
//! list (the `rsleigh-decompile` analysis crate, the `rsleigh-cli`
//! binary, signature/FID heuristics, printer text rewrites) is
//! experimental and may change without notice.
//!
//! Stable surface:
//!
//! - [`Decoder`], [`Decoder::new`], [`Decoder::decode`],
//!   [`Decoder::architecture`]
//! - [`Architecture`] (variants may be added; existing variants stay)
//! - [`Architecture::addr_size`], [`Architecture::register_name`]
//! - Re-exports from `pcode-ir`: `Instruction`, `PcodeOp`, `Varnode`,
//!   `AddressSpaceId`, `DecodeError`
//!
//! Anything else in this crate (helper functions, internal context
//! types, generated-crate re-exports) is implementation detail.
//! `rsleigh_decompile::*`, `rsleigh_decompile::printer::*`,
//! `rsleigh_decompile::fold::*`, etc. are **not** covered by this
//! stability promise — pin a specific patch version if you depend on
//! their shape.

pub use pcode_ir::{AddressSpaceId, DecodeError, Instruction, PcodeOp, Varnode};

/// Supported CPU architectures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Architecture {
    /// x86-64 (AMD64 / Intel 64), 64-bit mode.
    X86_64,
    /// x86-32 (IA-32), 32-bit protected mode.
    X86_32,
    /// AArch64 (ARMv8-A, 64-bit).
    AArch64,
    /// ARM32 (ARMv7 + Thumb).
    ARM32,
    /// MIPS32 (big-endian).
    MIPS32,
    /// RISC-V 64-bit (RV64GC).
    RiscV64,
}

impl Architecture {
    /// Address size in bytes for this architecture.
    pub fn addr_size(&self) -> u32 {
        match self {
            Architecture::X86_64 | Architecture::AArch64 | Architecture::RiscV64 => 8,
            Architecture::X86_32 | Architecture::ARM32 | Architecture::MIPS32 => 4,
        }
    }

    /// Look up a register name by its Ghidra offset and size.
    ///
    /// Returns `None` if no register matches the given (offset, size) pair.
    pub fn register_name(&self, offset: u64, size: u32) -> Option<&'static str> {
        match self {
            Architecture::X86_64 => x86_root::register_name(offset, size),
            Architecture::X86_32 => x86_32_root::register_name(offset, size),
            Architecture::AArch64 => aarch64_root::register_name(offset, size),
            Architecture::ARM32 => arm32_root::register_name(offset, size),
            Architecture::MIPS32 => mips_root::register_name(offset, size),
            Architecture::RiscV64 => riscv_root::register_name(offset, size),
        }
    }
}

/// Unified instruction decoder.
///
/// Manages the per-architecture context memory and global set. Create one
/// `Decoder` per architecture, reuse it across many `decode()` calls.
pub struct Decoder {
    arch: Architecture,
    inner: DecoderInner,
}

enum DecoderInner {
    X86_64 {
        context: x86_root::ContextMemory,
        global_set: x86_root::GlobalSet,
    },
    X86_32 {
        context: x86_32_root::ContextMemory,
        global_set: x86_32_root::GlobalSet,
    },
    AArch64 {
        context: aarch64_root::ContextMemory,
        global_set: aarch64_root::GlobalSet,
    },
    ARM32 {
        context: arm32_root::ContextMemory,
        global_set: arm32_root::GlobalSet,
    },
    MIPS32 {
        context: mips_root::ContextMemory,
        global_set: mips_root::GlobalSet,
    },
    RiscV64 {
        context: riscv_root::ContextMemory,
        global_set: riscv_root::GlobalSet,
    },
}

impl Decoder {
    /// Create a new decoder for the given architecture with default context.
    pub fn new(arch: Architecture) -> Self {
        let inner = match arch {
            Architecture::X86_64 => {
                let mut ctx = x86_root::ContextMemory::default();
                // Default to 64-bit mode
                ctx.write_longMode(1);
                ctx.write_addrsize(2);
                ctx.write_opsize(1);
                let gs = x86_root::GlobalSet::new({
                    let mut c = x86_root::ContextMemory::default();
                    c.write_longMode(1);
                    c.write_addrsize(2);
                    c.write_opsize(1);
                    c
                });
                DecoderInner::X86_64 {
                    context: ctx,
                    global_set: gs,
                }
            }
            Architecture::X86_32 => {
                // x86-32 uses its own slaspec with native 32-bit registers (ESP not RSP)
                // Default: 32-bit protected mode (addrsize=1, opsize=1)
                let mut ctx = x86_32_root::ContextMemory::default();
                ctx.write_addrsize(1);
                ctx.write_opsize(1);
                let gs = x86_32_root::GlobalSet::new({
                    let mut c = x86_32_root::ContextMemory::default();
                    c.write_addrsize(1);
                    c.write_opsize(1);
                    c
                });
                DecoderInner::X86_32 {
                    context: ctx,
                    global_set: gs,
                }
            }
            Architecture::AArch64 => DecoderInner::AArch64 {
                context: aarch64_root::ContextMemory::default(),
                global_set: aarch64_root::GlobalSet::new(aarch64_root::ContextMemory::default()),
            },
            Architecture::ARM32 => DecoderInner::ARM32 {
                context: arm32_root::ContextMemory::default(),
                global_set: arm32_root::GlobalSet::new(arm32_root::ContextMemory::default()),
            },
            Architecture::MIPS32 => DecoderInner::MIPS32 {
                context: mips_root::ContextMemory::default(),
                global_set: mips_root::GlobalSet::new(mips_root::ContextMemory::default()),
            },
            Architecture::RiscV64 => DecoderInner::RiscV64 {
                context: riscv_root::ContextMemory::default(),
                global_set: riscv_root::GlobalSet::new(riscv_root::ContextMemory::default()),
            },
        };
        Self { arch, inner }
    }

    /// The architecture this decoder is configured for.
    pub fn architecture(&self) -> Architecture {
        self.arch
    }

    /// For ARM32: set the Thumb-mode context bit before decoding.
    /// Cortex-M is Thumb-only; classic ARM uses LSB of branch target to
    /// indicate Thumb. Caller passes `addr & 1 == 1` to switch to Thumb.
    /// No-op for non-ARM32 decoders.
    pub fn set_arm_thumb(&mut self, thumb: bool) {
        if let DecoderInner::ARM32 {
            context,
            global_set,
        } = &mut self.inner
        {
            context.write_TMode(if thumb { 1 } else { 0 });
            *global_set = arm32_root::GlobalSet::new(*context);
        }
    }

    /// Decode a single instruction from `bytes` at virtual address `addr`.
    ///
    /// Returns the decoded instruction with optimized P-code, or an error
    /// if the bytes don't match any known encoding.
    ///
    /// The `bytes` slice should contain at least enough bytes for the longest
    /// possible instruction (15 for x86, 4 for fixed-width ISAs). Extra bytes
    /// are ignored.
    pub fn decode(&mut self, bytes: &[u8], addr: u64) -> Result<Instruction, DecodeError> {
        // Each instruction gets a fresh copy of context. SLEIGH context changes
        // during pattern matching (e.g. REX prefix bits) are local to each
        // instruction and must not leak to the next decode call. Only globalset
        // changes (stored in GlobalSet, not ContextMemory) persist across instructions.
        match &mut self.inner {
            DecoderInner::X86_64 {
                context,
                global_set,
            } => {
                if let Some(inst) = fallback_x86_64_mov_from_rsp_sib(bytes, addr) {
                    return Ok(inst);
                }

                let mut ctx = *context;
                if let Some((inst_next, display, mut ops)) =
                    x86_root::parse_instruction(bytes, &mut ctx, addr, global_set)
                {
                    pcode_ir::optimize(&mut ops);
                    Ok(Instruction {
                        len: inst_next - addr,
                        disassembly: format_display(&display),
                        ops,
                        constructor: None,
                    })
                } else {
                    Err(DecodeError::UnknownInstruction)
                }
            }
            DecoderInner::X86_32 {
                context,
                global_set,
            } => {
                let mut ctx = *context;
                let addr32 = addr as u32;
                let (inst_next, display, mut ops) =
                    x86_32_root::parse_instruction(bytes, &mut ctx, addr32, global_set)
                        .ok_or(DecodeError::UnknownInstruction)?;
                pcode_ir::optimize(&mut ops);
                Ok(Instruction {
                    len: (inst_next - addr32) as u64,
                    disassembly: format_display(&display),
                    ops,
                    constructor: None,
                })
            }
            DecoderInner::AArch64 {
                context,
                global_set,
            } => {
                let mut ctx = *context;
                let (inst_next, display, mut ops) =
                    aarch64_root::parse_instruction(bytes, &mut ctx, addr, global_set)
                        .ok_or(DecodeError::UnknownInstruction)?;
                pcode_ir::optimize(&mut ops);
                Ok(Instruction {
                    len: inst_next - addr,
                    disassembly: format_display(&display),
                    ops,
                    constructor: None,
                })
            }
            DecoderInner::ARM32 {
                context,
                global_set,
            } => {
                let mut ctx = *context;
                let addr32 = addr as u32;
                let (inst_next, display, mut ops) =
                    arm32_root::parse_instruction(bytes, &mut ctx, addr32, global_set)
                        .ok_or(DecodeError::UnknownInstruction)?;
                pcode_ir::optimize(&mut ops);
                Ok(Instruction {
                    len: (inst_next - addr32) as u64,
                    disassembly: format_display(&display),
                    ops,
                    constructor: None,
                })
            }
            DecoderInner::MIPS32 {
                context,
                global_set,
            } => {
                let mut ctx = *context;
                let addr32 = addr as u32;
                let (inst_next, display, mut ops) =
                    mips_root::parse_instruction(bytes, &mut ctx, addr32, global_set)
                        .ok_or(DecodeError::UnknownInstruction)?;
                pcode_ir::optimize(&mut ops);
                Ok(Instruction {
                    len: (inst_next - addr32) as u64,
                    disassembly: format_display(&display),
                    ops,
                    constructor: None,
                })
            }
            DecoderInner::RiscV64 {
                context,
                global_set,
            } => {
                let mut ctx = *context;
                let (inst_next, display, mut ops) =
                    riscv_root::parse_instruction(bytes, &mut ctx, addr, global_set)
                        .ok_or(DecodeError::UnknownInstruction)?;
                pcode_ir::optimize(&mut ops);
                Ok(Instruction {
                    len: inst_next - addr,
                    disassembly: format_display(&display),
                    ops,
                    constructor: None,
                })
            }
        }
    }
}

fn fallback_x86_64_mov_from_rsp_sib(bytes: &[u8], addr: u64) -> Option<Instruction> {
    let mut pos = 0usize;
    let mut rex = 0u8;
    if bytes
        .first()
        .copied()
        .is_some_and(|b| (0x40..=0x4f).contains(&b))
    {
        rex = bytes[0];
        pos += 1;
    }
    if bytes.get(pos).copied()? != 0x8b {
        return None;
    }
    pos += 1;

    let modrm = bytes.get(pos).copied()?;
    pos += 1;
    let mode = modrm >> 6;
    let reg = ((modrm >> 3) & 7) | ((rex & 0x04) << 1);
    let rm = modrm & 7;
    if rm != 4 || !matches!(mode, 1 | 2) {
        return None;
    }

    let sib = bytes.get(pos).copied()?;
    pos += 1;
    let index = (sib >> 3) & 7;
    let base = (sib & 7) | ((rex & 0x01) << 3);
    if index != 4 || (rex & 0x02) != 0 || !matches!(base, 4 | 12) {
        return None;
    }

    let disp = match mode {
        1 => {
            let d = *bytes.get(pos)? as i8 as i64;
            pos += 1;
            d
        }
        2 => {
            let raw = bytes.get(pos..pos + 4)?;
            pos += 4;
            i32::from_le_bytes(raw.try_into().ok()?) as i64
        }
        _ => return None,
    };

    let size = if rex & 0x08 != 0 { 8 } else { 4 };
    let dest = x86_reg_varnode(reg, size)?;
    let base_vn = x86_reg_varnode(base, 8)?;
    let size_name = if size == 8 { "qword" } else { "dword" };
    let disassembly = if disp == 0 {
        format!(
            "MOV {},{} ptr [{}]",
            x86_reg_name(reg, size)?,
            size_name,
            x86_reg_name(base, 8)?,
        )
    } else {
        format!(
            "MOV {},{} ptr [{} {} {:#x}]",
            x86_reg_name(reg, size)?,
            size_name,
            x86_reg_name(base, 8)?,
            if disp < 0 { "-" } else { "+" },
            disp.unsigned_abs()
        )
    };

    let mut ops = Vec::new();
    let ptr = if disp == 0 {
        base_vn
    } else {
        let ptr = Varnode::unique((addr << 16).wrapping_add(0x8000), 8);
        ops.push(PcodeOp::IntAdd {
            out: ptr,
            left: base_vn,
            right: Varnode::constant(disp as u64, 8),
        });
        ptr
    };
    ops.push(PcodeOp::Load {
        out: dest,
        space: pcode_ir::AddressSpaceId::Ram,
        ptr,
    });

    Some(Instruction {
        len: pos as u64,
        disassembly,
        ops,
        constructor: None,
    })
}

fn x86_reg_varnode(reg: u8, size: u32) -> Option<Varnode> {
    let offset = match reg {
        0..=7 => u64::from(reg) * 8,
        8..=15 => 0x80 + (u64::from(reg) - 8) * 8,
        _ => return None,
    };
    Some(Varnode::register(offset, size))
}

fn x86_reg_name(reg: u8, size: u32) -> Option<&'static str> {
    const R32: [&str; 16] = [
        "EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI", "R8D", "R9D", "R10D", "R11D",
        "R12D", "R13D", "R14D", "R15D",
    ];
    const R64: [&str; 16] = [
        "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12",
        "R13", "R14", "R15",
    ];
    match size {
        4 => R32.get(reg as usize).copied(),
        8 => R64.get(reg as usize).copied(),
        _ => None,
    }
}

/// Format display elements into a disassembly string.
fn format_display(elements: &[impl core::fmt::Display]) -> String {
    elements.iter().map(|d| format!("{}", d)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_64_fallback_decodes_mov_r12d_rsp_disp32() {
        let mut dec = Decoder::new(Architecture::X86_64);
        let inst = dec
            .decode(&[0x44, 0x8b, 0xa4, 0x24, 0x88, 0x00, 0x00, 0x00], 0x1000)
            .expect("decode MOV R12D,[RSP+0x88]");

        assert_eq!(inst.len, 8);
        assert!(inst.disassembly.contains("R12D"), "{}", inst.disassembly);
        assert!(inst.ops.iter().any(|op| {
            matches!(
                op,
                PcodeOp::Load {
                    out,
                    space: pcode_ir::AddressSpaceId::Ram,
                    ..
                } if *out == Varnode::register(0xa0, 4)
            )
        }));
    }
}
