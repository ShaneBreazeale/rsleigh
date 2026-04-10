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

pub use pcode_ir::{AddressSpaceId, DecodeError, Instruction, PcodeOp, Varnode};

/// Supported CPU architectures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Architecture {
    /// x86-64 (AMD64 / Intel 64), 64-bit mode.
    X86_64,
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
            Architecture::ARM32 | Architecture::MIPS32 => 4,
        }
    }

    /// Look up a register name by its Ghidra offset and size.
    ///
    /// Returns `None` if no register matches the given (offset, size) pair.
    pub fn register_name(&self, offset: u64, size: u32) -> Option<&'static str> {
        match self {
            Architecture::X86_64 => x86_root::register_name(offset, size),
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
            Architecture::AArch64 => DecoderInner::AArch64 {
                context: aarch64_root::ContextMemory::default(),
                global_set: aarch64_root::GlobalSet::new(
                    aarch64_root::ContextMemory::default(),
                ),
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
                let mut ctx = *context;
                let (inst_next, display, mut ops) =
                    x86_root::parse_instruction(bytes, &mut ctx, addr, global_set)
                        .ok_or(DecodeError::UnknownInstruction)?;
                pcode_ir::optimize(&mut ops);
                Ok(Instruction {
                    len: inst_next - addr,
                    disassembly: format_display(&display),
                    ops,
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
                })
            }
        }
    }
}

/// Format display elements into a disassembly string.
fn format_display(elements: &[impl core::fmt::Display]) -> String {
    elements.iter().map(|d| format!("{}", d)).collect()
}
