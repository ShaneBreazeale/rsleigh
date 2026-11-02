//! Jump-table recovery for computed indirect jumps (`switch` dispatch).
//!
//! Recognized shapes, traced backwards through the P-code of the dispatch
//! instructions:
//! - relative entries (x86-64 PIC): `jmp table + sext(*(i32 *)(table + idx * 4))`
//! - image-relative entries (MSVC, clang-cl): `jmp base + zext(*(u32 *)(base +
//!   disp + idx * 4))`, where `base` is the image base
//! - absolute entries: `jmp *(table + idx * 4|8)`, directly or through a register
//!
//! The entry count comes from the bounds check before the dispatch
//! (`CMP idx, N` then `JA`/`JAE`); without one, entries are read while they
//! name decoded instructions, also below the table when the index is
//! sign-extended. Every target must be a decoded instruction.
//!
//! The table base is traced through up to `WINDOW` earlier instructions,
//! since compilers hoist its `lea` out of the switch.

use pcode_ir::{AddressSpaceId, Instruction, PcodeOp, Varnode};
use std::collections::HashSet;

/// Reads `len` bytes of the loaded image at a virtual address.
pub type Memory<'a> = &'a dyn Fn(u64, usize) -> Option<Vec<u8>>;

/// A recovered jump table.
#[derive(Debug, Clone)]
pub struct JumpTable {
    /// Address of the instruction that ends in the computed jump.
    pub jump: u64,
    /// A varnode that still holds the table index at the jump: the scaled
    /// register itself, or the register it was copied or extended from when
    /// the scaled one is overwritten by the table load.
    pub index: Varnode,
    /// When no such varnode exists, the address of the instruction that
    /// scales `index` and overwrites it: the caller copies `index` into a
    /// temporary just before that instruction and tests the temporary.
    pub copy_before: Option<u64>,
    /// Case targets in table order: entry `k` is taken when the index is
    /// `first + k`.
    pub targets: Vec<u64>,
    /// Index value of the first entry: negative when an unchecked,
    /// sign-extended index reaches entries below the table address.
    pub first: i64,
}

/// Entries read from a table with no bounds check.
const MAX_ENTRIES: usize = 256;
/// Largest table a bounds check may declare. Every entry must still name a
/// decoded instruction and lie inside the image, so a wrong count fails; this
/// caps the `idx == k` chain built from a right one.
const MAX_GUARDED_ENTRIES: usize = 4096;
/// Contiguous instructions before the jump whose ops are searched.
const WINDOW: usize = 512;

/// One operation of the dispatch window.
struct Op<'a> {
    op: &'a PcodeOp,
    /// Address of the instruction the op belongs to.
    address: u64,
}

enum Entries {
    /// `base + sext(i32 entry)` or `base + zext(u32 entry)`. `base` is the
    /// table itself (PIC) or the image base (MSVC).
    Relative { base: u64, signed: bool },
    /// Absolute addresses of the given byte width.
    Absolute(usize),
}

/// Find jump tables among `instructions` (any order; the entry is first).
pub fn find(instructions: &[(u64, Instruction)], memory: Memory) -> Vec<JumpTable> {
    let mut sorted: Vec<&(u64, Instruction)> = instructions.iter().collect();
    sorted.sort_by_key(|(a, _)| *a);
    let starts: HashSet<u64> = sorted.iter().map(|(a, _)| *a).collect();
    let mut found = Vec::new();
    for (i, (address, inst)) in sorted.iter().enumerate() {
        let Some(PcodeOp::BranchInd { dest }) = inst.ops.last() else {
            continue;
        };
        // Contiguous instructions leading to the jump.
        let mut first = i;
        while first > 0
            && i - first < WINDOW
            && sorted[first - 1].0 + sorted[first - 1].1.len == sorted[first].0
        {
            first -= 1;
        }
        let window: Vec<Op> = sorted[first..=i]
            .iter()
            .flat_map(|(address, inst)| {
                inst.ops.iter().map(|op| Op {
                    op,
                    address: *address,
                })
            })
            .collect();
        let end = window.len() - 1;
        let Some((table, entries, index_pos, index)) = dispatch(&window, end, *dest) else {
            continue;
        };
        let floor = signed_floor(&window, index_pos, index);
        let Some((index, copy_before)) = stable_index(&window, index_pos, index, *address) else {
            continue;
        };
        let bound = guard_count(&sorted[i.saturating_sub(16)..i])
            .filter(|count| *count <= MAX_GUARDED_ENTRIES);
        let width = match entries {
            Entries::Relative { .. } => 4,
            Entries::Absolute(w) => w,
        };
        // Target of entry `k` (relative to the table address); `None` when
        // it is not a decoded instruction or lies outside the image.
        let entry = |k: i64| -> Option<u64> {
            let bytes = memory(table.wrapping_add((k * width as i64) as u64), width)?;
            let raw = bytes
                .iter()
                .rev()
                .fold(0u64, |acc, b| (acc << 8) | *b as u64);
            let target = match entries {
                Entries::Relative { base, signed: true } => {
                    base.wrapping_add(raw as u32 as i32 as i64 as u64)
                }
                Entries::Relative {
                    base,
                    signed: false,
                } => base.wrapping_add(raw as u32 as u64),
                Entries::Absolute(_) => raw,
            };
            starts.contains(&target).then_some(target)
        };
        let mut targets = Vec::new();
        for k in 0..bound.unwrap_or(MAX_ENTRIES) {
            let Some(target) = entry(k as i64) else {
                // A declared table that runs off the image or names
                // non-code is not a table.
                if bound.is_some() {
                    targets.clear();
                }
                break;
            };
            targets.push(target);
        }
        if targets.is_empty() {
            continue;
        }
        // An unchecked sign-extended index also reaches entries below the
        // table: take them while they name code, down to the index's minimum.
        let mut first = 0i64;
        if let (None, Some(floor)) = (bound, floor) {
            while first > floor && targets.len() < MAX_ENTRIES {
                let Some(target) = entry(first - 1) else {
                    break;
                };
                targets.insert(0, target);
                first -= 1;
            }
        }
        found.push(JumpTable {
            jump: *address,
            index,
            copy_before,
            targets,
            first,
        });
    }
    found
}

/// A varnode holding the value `vn` has at `pos` that no later op in the
/// window overwrites, following copies and extensions back to their source.
/// When none exists (`add eax, 0x83` built the index and the table load
/// overwrites it), the value itself with the address of the instruction
/// that reads it: the caller copies it aside just before that instruction.
fn stable_index(
    window: &[Op],
    start: usize,
    start_vn: Varnode,
    jump: u64,
) -> Option<(Varnode, Option<u64>)> {
    let (mut pos, mut vn) = (start, start_vn);
    for _ in 0..6 {
        let overwritten = window[pos..].iter().any(|o| writes(o.op, vn));
        // Unique temporaries are per instruction, so one that is never
        // rewritten (the value a global index was loaded into) is stable too.
        if !overwritten && vn.space != AddressSpaceId::Const {
            return Some((vn, None));
        }
        let Some(d) = def(window, pos, vn) else { break };
        match window[d].op {
            PcodeOp::Copy { input, .. }
            | PcodeOp::IntZext { input, .. }
            | PcodeOp::Subpiece { input, lsb: 0, .. } => (vn, pos) = (*input, d),
            _ => break,
        }
    }
    // The copy goes in front of the reading instruction, so none of its
    // earlier ops may have changed the value. The caller checks that the
    // instruction is in the jump's block.
    let at = window[start].address;
    let changed_first = window[..start]
        .iter()
        .any(|o| o.address == at && writes(o.op, start_vn));
    (start_vn.space == AddressSpaceId::Register && at != jump && !changed_first)
        .then_some((start_vn, Some(at)))
}

/// Lowest value of the index `vn` at `pos` when it is a sign extension of a
/// narrower value (`movsx rax, byte [...]`), followed through copies.
fn signed_floor(window: &[Op], pos: usize, vn: Varnode) -> Option<i64> {
    let (mut at, mut vn) = (pos, vn);
    for _ in 0..6 {
        let d = def(window, at, vn)?;
        match window[d].op {
            PcodeOp::Copy { input, .. } => (vn, at) = (*input, d),
            PcodeOp::IntSext { input, out } if input.size < out.size && input.size <= 4 => {
                return Some(-(1i64 << (input.size * 8 - 1)));
            }
            _ => return None,
        }
    }
    None
}

/// True when `op` writes `vn`.
fn writes(op: &PcodeOp, vn: Varnode) -> bool {
    pcode_ir::get_output(op).is_some_and(|out| out.space == vn.space && out.offset == vn.offset)
}

/// Index of the last op before `end` that writes `vn`.
fn def(window: &[Op], end: usize, vn: Varnode) -> Option<usize> {
    window[..end].iter().rposition(|o| {
        pcode_ir::get_output(o.op)
            .is_some_and(|out| out.space == vn.space && out.offset == vn.offset)
    })
}

/// Value of a constant-derived varnode.
fn constant(window: &[Op], end: usize, vn: Varnode, depth: u32) -> Option<u64> {
    if vn.space == AddressSpaceId::Const {
        return Some(vn.offset);
    }
    if depth == 0 {
        return None;
    }
    let d = def(window, end, vn)?;
    match window[d].op {
        PcodeOp::Copy { input, .. }
        | PcodeOp::IntZext { input, .. }
        | PcodeOp::IntSext { input, .. }
        | PcodeOp::Subpiece { input, lsb: 0, .. } => constant(window, d, *input, depth - 1),
        PcodeOp::IntAdd { left, right, .. } => Some(
            constant(window, d, *left, depth - 1)?.wrapping_add(constant(
                window,
                d,
                *right,
                depth - 1,
            )?),
        ),
        _ => None,
    }
}

/// (index varnode, op position, scale) for `idx * scale` or `idx << n`.
fn scaled(window: &[Op], end: usize, vn: Varnode, depth: u32) -> Option<(Varnode, usize, u64)> {
    if depth == 0 {
        return None;
    }
    let d = def(window, end, vn)?;
    match window[d].op {
        PcodeOp::IntMult { left, right, .. } => {
            let scale = constant(window, d, *right, 4)?;
            Some((*left, d, scale))
        }
        PcodeOp::IntLsl { left, right, .. } => {
            let shift = constant(window, d, *right, 4)?;
            (shift < 4).then(|| (*left, d, 1 << shift))
        }
        PcodeOp::Copy { input, .. }
        | PcodeOp::IntZext { input, .. }
        | PcodeOp::IntSext { input, .. } => scaled(window, d, *input, depth - 1),
        _ => None,
    }
}

/// (table, index varnode, op position, scale) for `table + idx * scale`.
/// The table may be a sum of constants around the scaled index, as in
/// `[r8 + rax*4 + disp]` with `r8` holding the image base.
fn table_address(
    window: &[Op],
    end: usize,
    vn: Varnode,
    depth: u32,
) -> Option<(u64, Varnode, usize, u64)> {
    if depth == 0 {
        return None;
    }
    let d = def(window, end, vn)?;
    match window[d].op {
        PcodeOp::IntAdd { left, right, .. } => [(*left, *right), (*right, *left)]
            .into_iter()
            .find_map(|(base, offset)| {
                let table = constant(window, d, base, 6)?;
                if let Some((index, pos, scale)) = scaled(window, d, offset, 4) {
                    return Some((table, index, pos, scale));
                }
                let (rest, index, pos, scale) = table_address(window, d, offset, depth - 1)?;
                Some((table.wrapping_add(rest), index, pos, scale))
            }),
        PcodeOp::Copy { input, .. } => table_address(window, d, *input, depth - 1),
        _ => None,
    }
}

/// The table, entry kind, and index of the computed jump to `dest`.
fn dispatch(window: &[Op], end: usize, dest: Varnode) -> Option<(u64, Entries, usize, Varnode)> {
    // `jmp [table + idx*w]`: the destination names the computed address.
    if dest.space == AddressSpaceId::Ram {
        let address = Varnode {
            space: AddressSpaceId::Unique,
            ..dest
        };
        let (table, index, pos, scale) = table_address(window, end, address, 4)?;
        return matches!(scale, 4 | 8)
            .then(|| (table, Entries::Absolute(scale as usize), pos, index));
    }
    let (mut vn, mut at) = (dest, end);
    for _ in 0..8 {
        let d = def(window, at, vn)?;
        match window[d].op {
            PcodeOp::Copy { input, .. } => (vn, at) = (*input, d),
            // `mov reg, [table + idx*w]; jmp reg`
            PcodeOp::Load { ptr, out, .. } => {
                let (table, index, pos, scale) = table_address(window, d, *ptr, 4)?;
                let width = out.size as u64;
                return (scale == width && matches!(width, 4 | 8))
                    .then(|| (table, Entries::Absolute(width as usize), pos, index));
            }
            // `movsxd reg, [table + idx*4]; add reg, table; jmp reg`, or
            // `mov eax, [base + disp + idx*4]; add rax, base; jmp rax`
            PcodeOp::IntAdd { left, right, .. } => {
                return [(*left, *right), (*right, *left)]
                    .into_iter()
                    .find_map(|(base, entry)| {
                        let base = constant(window, d, base, 6)?;
                        let (mut ev, mut eat, mut signed) = (entry, d, true);
                        for _ in 0..6 {
                            let ed = def(window, eat, ev)?;
                            match window[ed].op {
                                PcodeOp::IntSext { input, .. } | PcodeOp::Copy { input, .. } => {
                                    (ev, eat) = (*input, ed)
                                }
                                PcodeOp::IntZext { input, .. } => {
                                    (ev, eat, signed) = (*input, ed, false)
                                }
                                PcodeOp::Load { ptr, out, .. } if out.size == 4 => {
                                    let (table, index, pos, scale) =
                                        table_address(window, ed, *ptr, 4)?;
                                    return (scale == 4).then_some((
                                        table,
                                        Entries::Relative { base, signed },
                                        pos,
                                        index,
                                    ));
                                }
                                _ => return None,
                            }
                        }
                        None
                    });
            }
            _ => return None,
        }
    }
    None
}

/// Entry count from `CMP reg, N` followed by `JA` (N + 1) or `JAE` (N).
fn guard_count(before: &[&(u64, Instruction)]) -> Option<usize> {
    let mut inclusive = None;
    for (_, inst) in before.iter().rev() {
        let text = inst.disassembly.trim().to_ascii_uppercase();
        let mnemonic = text.split_whitespace().next().unwrap_or("");
        if inclusive.is_none() {
            inclusive = match mnemonic {
                "JA" | "JNBE" => Some(true),
                "JAE" | "JNB" | "JNC" => Some(false),
                _ => continue,
            };
            continue;
        }
        if mnemonic == "CMP" {
            let imm = text.rsplit(',').next()?.trim();
            let n = match imm.strip_prefix("0X") {
                Some(hex) => u64::from_str_radix(hex, 16).ok()?,
                None => imm.parse().ok()?,
            };
            let count = if inclusive? { n + 1 } else { n };
            return usize::try_from(count).ok().filter(|c| *c >= 1);
        }
    }
    None
}

/// Loaded-image bytes by virtual address (ELF segments, PE sections,
/// Mach-O segments), mapped once per binary.
pub struct ImageMemory<'a> {
    data: &'a [u8],
    /// (virtual address, size in file, file offset)
    ranges: Vec<(u64, u64, u64)>,
}

impl<'a> ImageMemory<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        let ranges = match goblin::Object::parse(data) {
            Ok(goblin::Object::Elf(elf)) => elf
                .program_headers
                .iter()
                .filter(|ph| ph.p_type == goblin::elf::program_header::PT_LOAD)
                .map(|ph| (ph.p_vaddr, ph.p_filesz, ph.p_offset))
                .collect(),
            Ok(goblin::Object::PE(pe)) => pe
                .sections
                .iter()
                .map(|s| {
                    (
                        pe.image_base as u64 + s.virtual_address as u64,
                        s.size_of_raw_data
                            .min(s.virtual_size.max(s.size_of_raw_data))
                            as u64,
                        s.pointer_to_raw_data as u64,
                    )
                })
                .collect(),
            Ok(goblin::Object::Mach(goblin::mach::Mach::Binary(macho))) => macho
                .segments
                .iter()
                .map(|seg| (seg.vmaddr, seg.filesize, seg.fileoff))
                .collect(),
            _ => Vec::new(),
        };
        Self { data, ranges }
    }

    pub fn read(&self, va: u64, len: usize) -> Option<Vec<u8>> {
        let (start, _, offset) = self
            .ranges
            .iter()
            .find(|(start, size, _)| va >= *start && va + len as u64 <= start + size)?;
        let from = usize::try_from(offset + (va - start)).ok()?;
        self.data
            .get(from..from.checked_add(len)?)
            .map(<[u8]>::to_vec)
    }
}
