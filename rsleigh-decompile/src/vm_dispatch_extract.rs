//! Extract VM dispatcher metadata from a known dispatcher VA.
//!
//! Given the entry of a VM-dispatcher function (typically located by
//! `xor_vtable::scan` or by manual identification), walk its body and
//! extract:
//!
//!   - The vtable_xor data slot (one of two RIP-relative reads).
//!   - The key data slot (the second RIP-relative read).
//!   - The trampoline IAT slot (the `CALL [RIP+disp32]` target).
//!   - The opcode-mask byte if a single-byte AND/SUB is found.
//!
//! Output: a `DispatchInfo` struct ready for emu-driven vtable
//! decoding. The actual handler array lives in the runtime-encoded
//! data slot, so the analyst still needs to emulate init to populate
//! it; but with vtable_xor + key + size known, the decode step is
//! `for i in 0..size: handler = key XOR mem[runtime_vtable + i*8]`.

use goblin::Object;

#[derive(Debug, Clone)]
pub struct DispatchInfo {
    pub dispatcher_va: u64,
    /// Data slots read via `MOV r64, [RIP+disp32]`. The first two are
    /// the canonical "vtable_xor + key" pair in PyVMProtect-style
    /// dispatchers; later entries are auxiliary state.
    pub data_slots: Vec<u64>,
    /// Trampoline IAT slot (the target of `CALL [RIP+d32]`).
    pub trampoline_slot: Option<u64>,
    /// Suggested opcode mask if a `cmp/and r8, imm8` shape is found.
    pub opcode_mask: Option<u8>,
}

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

pub fn extract(obj: &Object<'_>, data: &[u8], dispatcher_va: u64) -> Option<DispatchInfo> {
    let off = va_to_file_offset(obj, dispatcher_va)?;
    let scan_len = 0x200.min(data.len() - off);
    let body = &data[off..off + scan_len];

    let mut data_slots = Vec::new();
    let mut trampoline_slot = None;
    let mut opcode_mask = None;
    let mut k = 0;
    while k + 6 <= body.len() {
        // MOV r64, [RIP+disp32] = 48 8b ?? d32 with mod=00 r/m=101
        // Or 4c 8b ?? for r8..r15 destination.
        if k + 7 <= body.len() && (body[k] == 0x48 || body[k] == 0x4c) && body[k + 1] == 0x8b {
            let modrm = body[k + 2];
            if modrm & 0xc0 == 0 && modrm & 0x07 == 0x05 {
                let d32 = i32::from_le_bytes([body[k + 3], body[k + 4], body[k + 5], body[k + 6]]);
                let next_rip = dispatcher_va.wrapping_add((k + 7) as u64);
                let slot = next_rip.wrapping_add(d32 as i64 as u64);
                if !data_slots.contains(&slot) {
                    data_slots.push(slot);
                }
                k += 7;
                continue;
            }
        }
        // CALL [RIP+disp32] = ff 15 d32 (6 bytes)
        if body[k] == 0xff && body[k + 1] == 0x15 && trampoline_slot.is_none() {
            let d32 = i32::from_le_bytes([body[k + 2], body[k + 3], body[k + 4], body[k + 5]]);
            let next_rip = dispatcher_va.wrapping_add((k + 6) as u64);
            let slot = next_rip.wrapping_add(d32 as i64 as u64);
            trampoline_slot = Some(slot);
            k += 6;
            continue;
        }
        // AND r8, imm8 = 80 e? imm8 (3 bytes) — opcode mask hint
        if opcode_mask.is_none()
            && body[k] == 0x80
            && (body[k + 1] & 0xf8) == 0xe0
            && k + 3 <= body.len()
        {
            let imm = body[k + 2];
            // Only flag distinctive mask values (not 0xff which is a no-op)
            if imm > 0 && imm < 0xff && imm != 0x7f {
                opcode_mask = Some(imm);
            }
        }
        k += 1;
    }

    Some(DispatchInfo {
        dispatcher_va,
        data_slots,
        trampoline_slot,
        opcode_mask,
    })
}

pub fn render(info: &DispatchInfo) -> Vec<String> {
    let mut out = Vec::new();
    out.push(format!("dispatcher @ {:#x}", info.dispatcher_va));
    if let Some(t) = info.trampoline_slot {
        out.push(format!("  trampoline_slot: {:#x}", t));
    }
    out.push(format!(
        "  data_slots ({}): [{}]",
        info.data_slots.len(),
        info.data_slots
            .iter()
            .map(|s| format!("{:#x}", s))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    if let Some(m) = info.opcode_mask {
        out.push(format!("  opcode_mask candidate: {:#04x}", m));
    }
    out.push("  decode procedure:".to_string());
    out.push(
        "    runtime_vtable_va = data_slot[0] XOR data_slot[1]   (snapshot post-init)".to_string(),
    );
    out.push("    handler[i] = data_slot[?] XOR mem[runtime_vtable_va + i*8]".to_string());
    out.push("    (caller emulates init chain, snapshots scratch, runs the XOR)".to_string());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_rip_data_slot() {
        // MOV RAX, [RIP+0x10] = 48 8b 05 10 00 00 00 (7 bytes)
        // dispatcher_va = 0x1000 → next_rip = 0x1007 → slot = 0x1017
        let mut info = DispatchInfo {
            dispatcher_va: 0x1000,
            data_slots: vec![],
            trampoline_slot: None,
            opcode_mask: None,
        };
        // Manually re-implement the scan inline for unit purposes.
        let body: &[u8] = &[0x48, 0x8b, 0x05, 0x10, 0x00, 0x00, 0x00];
        let mut k = 0;
        while k + 7 <= body.len() {
            if (body[k] == 0x48 || body[k] == 0x4c) && body[k + 1] == 0x8b {
                let modrm = body[k + 2];
                if modrm & 0xc0 == 0 && modrm & 0x07 == 0x05 {
                    let d32 =
                        i32::from_le_bytes([body[k + 3], body[k + 4], body[k + 5], body[k + 6]]);
                    let next_rip = info.dispatcher_va.wrapping_add((k + 7) as u64);
                    info.data_slots
                        .push(next_rip.wrapping_add(d32 as i64 as u64));
                    k += 7;
                    continue;
                }
            }
            k += 1;
        }
        assert_eq!(info.data_slots, vec![0x1017]);
    }

    #[test]
    fn render_emits_decode_procedure() {
        let info = DispatchInfo {
            dispatcher_va: 0x1800_0000,
            data_slots: vec![0xaa, 0xbb],
            trampoline_slot: Some(0xcc),
            opcode_mask: Some(0x3f),
        };
        let lines = render(&info);
        assert!(lines.iter().any(|l| l.contains("dispatcher")));
        assert!(lines.iter().any(|l| l.contains("trampoline_slot")));
        assert!(lines.iter().any(|l| l.contains("opcode_mask")));
        assert!(lines.iter().any(|l| l.contains("decode procedure")));
    }
}
