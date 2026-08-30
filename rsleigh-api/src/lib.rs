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
//!   `ConstructorSpan`, `AddressSpaceId`, `DecodeError`
//!
//! Anything else in this crate (helper functions, internal context
//! types, generated-crate re-exports) is implementation detail.
//! `rsleigh_decompile::*`, `rsleigh_decompile::printer::*`,
//! `rsleigh_decompile::fold::*`, etc. are **not** covered by this
//! stability promise — pin a specific patch version if you depend on
//! their shape.

pub use pcode_ir::{AddressSpaceId, ConstructorSpan, DecodeError, Instruction, PcodeOp, Varnode};

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
        let mut instruction = self.decode_unoptimized(bytes, addr)?;
        pcode_ir::optimize(&mut instruction.ops);
        Ok(instruction)
    }

    /// Decode a single instruction without the P-code peephole optimizer.
    ///
    /// This diagnostic API lets oracle tooling distinguish generated-lifter
    /// differences from intentional optimizer folds. It is not part of the
    /// crate's stable embedding surface; normal consumers should use
    /// [`Decoder::decode`].
    pub fn decode_unoptimized(
        &mut self,
        bytes: &[u8],
        addr: u64,
    ) -> Result<Instruction, DecodeError> {
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
                if let Some((inst_next, display, ops, constructor)) =
                    x86_root::parse_instruction_with_constructor(bytes, &mut ctx, addr, global_set)
                {
                    Ok(Instruction {
                        len: inst_next - addr,
                        disassembly: format_display(&display),
                        ops,
                        constructor: Some(constructor),
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
                let (inst_next, display, ops, constructor) =
                    x86_32_root::parse_instruction_with_constructor(
                        bytes, &mut ctx, addr32, global_set,
                    )
                    .ok_or(DecodeError::UnknownInstruction)?;
                Ok(Instruction {
                    len: (inst_next - addr32) as u64,
                    disassembly: format_display(&display),
                    ops,
                    constructor: Some(constructor),
                })
            }
            DecoderInner::AArch64 {
                context,
                global_set,
            } => {
                let mut ctx = *context;
                let (inst_next, display, ops, constructor) =
                    aarch64_root::parse_instruction_with_constructor(
                        bytes, &mut ctx, addr, global_set,
                    )
                    .ok_or(DecodeError::UnknownInstruction)?;
                Ok(Instruction {
                    len: inst_next - addr,
                    disassembly: format_display(&display),
                    ops,
                    constructor: Some(constructor),
                })
            }
            DecoderInner::ARM32 {
                context,
                global_set,
            } => {
                let mut ctx = *context;
                let addr32 = addr as u32;
                let (inst_next, display, ops, constructor) =
                    arm32_root::parse_instruction_with_constructor(
                        bytes, &mut ctx, addr32, global_set,
                    )
                    .ok_or(DecodeError::UnknownInstruction)?;
                Ok(Instruction {
                    len: (inst_next - addr32) as u64,
                    disassembly: format_display(&display),
                    ops,
                    constructor: Some(constructor),
                })
            }
            DecoderInner::MIPS32 {
                context,
                global_set,
            } => {
                let mut ctx = *context;
                let addr32 = addr as u32;
                let (inst_next, display, ops, constructor) =
                    mips_root::parse_instruction_with_constructor(
                        bytes, &mut ctx, addr32, global_set,
                    )
                    .ok_or(DecodeError::UnknownInstruction)?;
                Ok(Instruction {
                    len: (inst_next - addr32) as u64,
                    disassembly: format_display(&display),
                    ops,
                    constructor: Some(constructor),
                })
            }
            DecoderInner::RiscV64 {
                context,
                global_set,
            } => {
                let mut ctx = *context;
                let (inst_next, display, ops, constructor) =
                    riscv_root::parse_instruction_with_constructor(
                        bytes, &mut ctx, addr, global_set,
                    )
                    .ok_or(DecodeError::UnknownInstruction)?;
                Ok(Instruction {
                    len: inst_next - addr,
                    disassembly: format_display(&display),
                    ops,
                    constructor: Some(constructor),
                })
            }
        }
    }
}

/// Format display elements into a disassembly string.
fn format_display(elements: &[impl core::fmt::Display]) -> String {
    elements.iter().map(|d| format!("{}", d)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_decoder_stack(test: impl FnOnce() + Send + 'static) {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(test)
            .expect("spawn decoder test")
            .join()
            .expect("decoder test panicked");
    }

    #[test]
    fn generated_x86_64_decodes_mov_r12d_rsp_disp32() {
        // This SIB encoding must be handled by the generated matcher. There is
        // intentionally no hand-written Rust fallback for [RSP+disp32].
        with_decoder_stack(|| {
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
            let span = inst.constructor.expect("generated constructor provenance");
            assert!(span.source.contains("slaspec/x86/"), "{}", span.source);
        });
    }

    #[test]
    fn diagnostic_decode_preserves_pre_optimization_pcode() {
        with_decoder_stack(|| {
            let bytes = [0xc2, 0x08, 0x00]; // RET 8
            let raw = Decoder::new(Architecture::X86_64)
                .decode_unoptimized(&bytes, 0x1000)
                .expect("raw decode RET 8");
            let optimized = Decoder::new(Architecture::X86_64)
                .decode(&bytes, 0x1000)
                .expect("optimized decode RET 8");

            assert!(
                raw.ops.len() > optimized.ops.len(),
                "raw={:?} optimized={:?}",
                raw.ops,
                optimized.ops
            );
        });
    }

    #[test]
    fn arm32_backward_bl_has_no_spurious_call_tag() {
        with_decoder_stack(|| {
            let mut dec = Decoder::new(Architecture::ARM32);
            let inst = dec
                .decode(&[0xfe, 0xff, 0xff, 0xeb], 0x1000)
                .expect("decode ARM32 BL to self");

            assert!(
                inst.ops.iter().any(|op| {
                    matches!(
                        op,
                        PcodeOp::Call { dest }
                            if dest.space == AddressSpaceId::Ram && dest.offset == 0x1000
                    )
                }),
                "{:?}",
                inst.ops
            );
            assert!(inst.constructor.is_some());
        });
    }
}
