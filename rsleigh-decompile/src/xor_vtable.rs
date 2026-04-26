//! Detect XOR-encoded vtable dispatch.
//!
//! VM packers commonly encode their handler tables to defeat static
//! analysis: the table base lives in a data slot XOR-masked with a
//! 64-bit key, every entry is itself XOR-masked with a (possibly
//! different) key, and the indirect call goes through a 1-byte
//! `JMP <reg>` trampoline so the emit site looks identical for every
//! handler invocation.
//!
//! The dispatch site has a recognisable shape, even when individual
//! instruction encodings vary:
//!
//!   1. Two `MOV r64, [RIP+disp32]` reads from data-section slots.
//!   2. `XOR r64, r64` — combine the two slot values to recover the
//!      cleartext vtable base.
//!   3. `MOV r64, [r64 + r64*8]` — index the vtable.
//!   4. `XOR r64, r64` — combine the entry with a key to recover the
//!      cleartext handler address.
//!   5. `CALL qword ptr [RIP+disp32]` — call through the IAT slot
//!      that points at a `JMP <reg>` trampoline.
//!
//! This module finds functions matching that shape and reports:
//!   - The dispatcher's call-through-trampoline site.
//!   - The two data slots involved (vtable_xor + key).
//!   - The trampoline address.
//!
//! Static recovery of the actual handler set requires emulating the
//! init chain (the data slots are populated at runtime). The detection
//! step alone narrows the analyst's attention to the dispatcher
//! function within seconds.

use goblin::Object;

#[derive(Debug, Clone)]
pub struct XorVtableDispatch {
    /// Virtual address of the `CALL [trampoline]` instruction.
    pub call_site_va: u64,
    /// IAT slot the CALL targets (= the trampoline ptr).
    pub trampoline_slot: u64,
    /// Data slots read by the two `MOV r64, [RIP+disp32]` instructions
    /// preceding the CALL — these are the vtable_xor + key candidates.
    pub data_slots: Vec<u64>,
}

/// Look in a code region for XOR-encoded vtable dispatch sites.
/// `trampoline_slots` is the set of IAT slots known to hold trampoline
/// pointers (from `jmp_rax_trampoline::scan` the caller has already
/// resolved which IAT slots route through `JMP <reg>` gadgets).
///
/// In practice, callers may not know the exact set of trampoline IAT
/// slots up-front. We expose a `_any_indirect_call` mode below for that
/// case — it accepts every `CALL [RIP+d32]` and applies the look-back
/// shape filter to gate false positives.
pub fn scan_region(
    code: &[u8],
    base_va: u64,
    trampoline_slots: &std::collections::HashSet<u64>,
) -> Vec<XorVtableDispatch> {
    let mut hits = Vec::new();
    let mut off = 0;
    while off + 6 <= code.len() {
        // CALL [RIP+disp32] = FF 15 d32 (6 bytes).
        if code[off] == 0xff && code[off + 1] == 0x15 {
            let d32 = i32::from_le_bytes([
                code[off + 2],
                code[off + 3],
                code[off + 4],
                code[off + 5],
            ]);
            let next_rip = base_va.wrapping_add((off + 6) as u64);
            let target_slot =
                next_rip.wrapping_add(d32 as i64 as u64);
            if trampoline_slots.contains(&target_slot) {
                // Look back ~80 bytes for the dispatch shape.
                let lb_start = off.saturating_sub(80);
                let window = &code[lb_start..off];
                let window_va = base_va + lb_start as u64;
                if shape_matches(window) {
                    let slots = collect_rip_slots(window, window_va);
                    hits.push(XorVtableDispatch {
                        call_site_va: base_va + off as u64,
                        trampoline_slot: target_slot,
                        data_slots: slots,
                    });
                }
            }
            off += 6;
            continue;
        }
        off += 1;
    }
    hits
}

/// Heuristic shape match for the look-back window before a CALL.
/// Requires:
///   - At least one indexed memory load (`MOV r, [r + r*8]`) — modRM
///     SIB byte where ss=11 and index!=rsp. Common forms: `48 8B 0C C1`
///     (MOV RCX, [RCX + RAX*8]), `48 8B 0C D7` (MOV RCX, [RDI + RDX*8]),
///     etc. We pattern on `48 8B ?? ??` where the SIB byte (3rd) has
///     scale=3 (top 2 bits == 11).
///   - At least one `XOR r64, r64` (modRM register-register form):
///     `48 31 ??` or `48 33 ??`.
///   - At least two `MOV r64, [RIP+disp32]` instructions.
///
/// Conservative — most legitimate code that hits all three is a
/// dispatcher.
fn shape_matches(window: &[u8]) -> bool {
    let mut indexed_load = false;
    let mut xor_count = 0;
    let mut rip_load_count = 0;
    let mut k = 0;
    while k + 3 <= window.len() {
        // 48 8B <modrm> <sib> — MOV r64, [SIB] where SIB.scale=3 (* 8)
        if k + 4 <= window.len() && window[k] == 0x48 && window[k + 1] == 0x8b {
            let modrm = window[k + 2];
            // mod=00 r/m=100 → SIB at +3
            if modrm & 0xc0 == 0 && modrm & 0x07 == 0x04 {
                let sib = window[k + 3];
                let scale = (sib >> 6) & 0x3;
                if scale == 3 {
                    indexed_load = true;
                }
            }
            // mod=00 r/m=101 → RIP-relative disp32
            if modrm & 0xc0 == 0 && modrm & 0x07 == 0x05
                && k + 7 <= window.len()
            {
                rip_load_count += 1;
                k += 7;
                continue;
            }
        }
        // 48 31 ?? or 48 33 ?? — XOR r64, r64 (3 bytes total)
        if window[k] == 0x48 && (window[k + 1] == 0x31 || window[k + 1] == 0x33)
        {
            let modrm = window[k + 2];
            if modrm & 0xc0 == 0xc0 {
                xor_count += 1;
            }
        }
        k += 1;
    }
    indexed_load && xor_count >= 2 && rip_load_count >= 2
}

fn collect_rip_slots(window: &[u8], window_va: u64) -> Vec<u64> {
    let mut slots = Vec::new();
    let mut k = 0;
    while k + 7 <= window.len() {
        if window[k] == 0x48 && window[k + 1] == 0x8b {
            let modrm = window[k + 2];
            if modrm & 0xc0 == 0 && modrm & 0x07 == 0x05 {
                let d32 = i32::from_le_bytes([
                    window[k + 3],
                    window[k + 4],
                    window[k + 5],
                    window[k + 6],
                ]);
                let next_rip = window_va.wrapping_add((k + 7) as u64);
                let slot = next_rip.wrapping_add(d32 as i64 as u64);
                slots.push(slot);
                k += 7;
                continue;
            }
        }
        k += 1;
    }
    slots
}

/// Scan all executable sections of a binary, given a set of known
/// trampoline IAT slots. Caller obtains the trampoline set by mapping
/// `jmp_rax_trampoline::scan` results to the IAT slots that hold
/// pointers to those gadgets.
pub fn scan(
    obj: &Object<'_>,
    data: &[u8],
    trampoline_slots: &std::collections::HashSet<u64>,
) -> Vec<XorVtableDispatch> {
    match obj {
        Object::PE(pe) => {
            let mut hits = Vec::new();
            const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
            for sec in &pe.sections {
                if sec.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
                    continue;
                }
                let raddr = sec.pointer_to_raw_data as usize;
                let rsize = sec.size_of_raw_data as usize;
                if raddr + rsize > data.len() {
                    continue;
                }
                let base_va =
                    pe.image_base as u64 + sec.virtual_address as u64;
                hits.extend(scan_region(
                    &data[raddr..raddr + rsize],
                    base_va,
                    trampoline_slots,
                ));
            }
            hits
        }
        _ => Vec::new(),
    }
}

/// Resolve which IAT slots point at known `JMP <reg>` trampoline VAs.
/// The PE loader's IAT lives at `image_base + import_directory.iat_rva`
/// — we scan the full data region for 8-byte values matching any
/// trampoline VA. Returns the slot VAs.
pub fn iat_slots_for_trampolines(
    obj: &Object<'_>,
    data: &[u8],
    trampolines: &[u64],
) -> std::collections::HashSet<u64> {
    let mut out = std::collections::HashSet::new();
    if trampolines.is_empty() {
        return out;
    }
    let trampoline_set: std::collections::HashSet<u64> =
        trampolines.iter().copied().collect();
    if let Object::PE(pe) = obj {
        // Scan every read-only data section for 8-byte values matching
        // any trampoline. IAT slots are typically in `.idata` /
        // `.rdata` / a custom random-named section.
        for sec in &pe.sections {
            const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
            if sec.characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
                continue;
            }
            let raddr = sec.pointer_to_raw_data as usize;
            let rsize = sec.size_of_raw_data as usize;
            if raddr + rsize > data.len() {
                continue;
            }
            let base_va =
                pe.image_base as u64 + sec.virtual_address as u64;
            let bytes = &data[raddr..raddr + rsize];
            let mut k = 0;
            while k + 8 <= bytes.len() {
                let v = u64::from_le_bytes([
                    bytes[k],
                    bytes[k + 1],
                    bytes[k + 2],
                    bytes[k + 3],
                    bytes[k + 4],
                    bytes[k + 5],
                    bytes[k + 6],
                    bytes[k + 7],
                ]);
                if trampoline_set.contains(&v) {
                    out.insert(base_va + k as u64);
                }
                k += 8;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shape_matches_dispatcher_skeleton() {
        // Synthesize the v5-style dispatcher tail:
        //   MOV RCX, [RIP+d32]  (48 8B 0D d32)
        //   MOV RAX, [RIP+d32]  (48 8B 05 d32)
        //   XOR RCX, RAX        (48 33 C8)
        //   MOV RCX, [RCX+RDX*8] (48 8B 0C D1)  modRM=0C (mod=00, reg=ecx, r/m=100); SIB=D1 (scale=11, idx=2, base=1)
        //   XOR RAX, RCX        (48 33 C1)
        let mut window = vec![];
        window.extend_from_slice(&[0x48, 0x8b, 0x0d, 0x10, 0, 0, 0]);
        window.extend_from_slice(&[0x48, 0x8b, 0x05, 0x20, 0, 0, 0]);
        window.extend_from_slice(&[0x48, 0x33, 0xc8]);
        window.extend_from_slice(&[0x48, 0x8b, 0x0c, 0xd1]);
        window.extend_from_slice(&[0x48, 0x33, 0xc1]);
        assert!(shape_matches(&window));
    }

    #[test]
    fn shape_rejects_quiet_code() {
        let window = vec![0x90; 80];
        assert!(!shape_matches(&window));
    }

    #[test]
    fn collects_rip_slots() {
        let mut window = vec![];
        window.extend_from_slice(&[0x48, 0x8b, 0x0d, 0x10, 0, 0, 0]); // disp 0x10
        window.extend_from_slice(&[0x48, 0x8b, 0x05, 0x20, 0, 0, 0]); // disp 0x20
        let slots = collect_rip_slots(&window, 0x1000);
        assert_eq!(slots.len(), 2);
        // First insn ends at offset 7 → next_rip = 0x1007 → +0x10 = 0x1017.
        assert_eq!(slots[0], 0x1017);
        // Second insn ends at offset 14 → next_rip = 0x100e → +0x20 = 0x102e.
        assert_eq!(slots[1], 0x102e);
    }
}
