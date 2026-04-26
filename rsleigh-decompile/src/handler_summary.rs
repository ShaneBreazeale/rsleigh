//! Summarise per-handler IAT API usage + stack-pop count.
//!
//! Given a handler address, scan its body for `CALL [RIP+disp32]`
//! instructions and resolve each disp32 to an IAT slot name (caller
//! provides the slot → name map). Also count the number of stack-pop
//! patterns: instances of `DEC dword ptr [RBX + 0x8]` /
//! `MOV [RBX + RCX*8 - 8]` (the common shape used by the v5 47-handler
//! stack VM).
//!
//! Output: a one-line-per-handler signature like
//! `0x180018960  pops=3  apis=[PyObject_Call, _Py_Dealloc]`
//!
//! Use case: rapidly classify a 47-handler dispatch table without
//! decompiling each individually. In v5 RE this was the technique
//! that revealed `0x180018960` = CALL_FN (PyObject_Call), `0x180017750`
//! = STORE_TO_DICT (PyDict_SetItem), etc.

use goblin::Object;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct HandlerSummary {
    pub addr: u64,
    pub pop_count: u32,
    pub apis: Vec<String>,
}

/// Build an IAT-slot → name map by walking the PE import directory
/// directly. We do this rather than rely on `goblin::pe::PE::imports`
/// because goblin's `imp.rva` can be ambiguous between OriginalFirst-
/// Thunk (name-table) and FirstThunk (IAT-slot) addresses depending on
/// the binary; the IAT-slot address is what callers reference at
/// runtime, so we resolve it ourselves.
pub fn build_iat_map(obj: &Object<'_>, data: &[u8]) -> HashMap<u64, String> {
    let mut map = HashMap::new();
    let pe = match obj {
        Object::PE(p) => p,
        _ => return map,
    };
    let optional = match pe.header.optional_header {
        Some(o) => o,
        None => return map,
    };
    let imp_dir = match optional.data_directories.get_import_table() {
        Some(d) => d,
        None => return map,
    };
    let imp_dir_rva = imp_dir.virtual_address as usize;
    if imp_dir_rva == 0 {
        return map;
    }
    let resolve = |rva: usize| -> Option<usize> {
        for sec in &pe.sections {
            let s_rva = sec.virtual_address as usize;
            let s_size = sec.virtual_size as usize;
            if rva >= s_rva && rva < s_rva + s_size {
                let raddr = sec.pointer_to_raw_data as usize;
                let off = raddr + (rva - s_rva);
                if off < data.len() {
                    return Some(off);
                }
            }
        }
        None
    };
    let mut idx = 0;
    loop {
        let desc_rva = imp_dir_rva + idx * 0x14;
        let Some(desc_off) = resolve(desc_rva) else {
            break;
        };
        if desc_off + 0x14 > data.len() {
            break;
        }
        let descbytes = &data[desc_off..desc_off + 0x14];
        if descbytes.iter().all(|&b| b == 0) {
            break;
        }
        let oft_rva =
            u32::from_le_bytes([descbytes[0], descbytes[1], descbytes[2], descbytes[3]]) as usize;
        let ft_rva =
            u32::from_le_bytes([descbytes[16], descbytes[17], descbytes[18], descbytes[19]])
                as usize;
        // Walk the name list (OriginalFirstThunk if present, else FirstThunk).
        let walk_rva = if oft_rva != 0 { oft_rva } else { ft_rva };
        let iat_rva = if ft_rva != 0 { ft_rva } else { oft_rva };
        let mut j = 0;
        loop {
            let entry_off = match resolve(walk_rva + j * 8) {
                Some(o) => o,
                None => break,
            };
            if entry_off + 8 > data.len() {
                break;
            }
            let v = u64::from_le_bytes([
                data[entry_off],
                data[entry_off + 1],
                data[entry_off + 2],
                data[entry_off + 3],
                data[entry_off + 4],
                data[entry_off + 5],
                data[entry_off + 6],
                data[entry_off + 7],
            ]);
            if v == 0 {
                break;
            }
            // High bit set = ordinal import; skip name resolution.
            if v & (1 << 63) == 0 {
                let name_rva = (v & 0x7fff_ffff) as usize;
                // First 2 bytes are hint, then null-terminated name.
                if let Some(name_off) = resolve(name_rva + 2) {
                    let mut end = name_off;
                    while end < data.len() && data[end] != 0 && end - name_off < 256 {
                        end += 1;
                    }
                    if let Ok(name) = std::str::from_utf8(&data[name_off..end]) {
                        let slot_va = pe.image_base as u64 + (iat_rva + j * 8) as u64;
                        map.insert(slot_va, name.to_string());
                    }
                }
            }
            j += 1;
            if j > 4096 {
                break;
            }
        }
        idx += 1;
        if idx > 256 {
            break;
        }
    }
    map
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

/// Summarise a single handler. Scans up to 0x400 bytes of the handler
/// body. Stops at the first RET that's followed by INT3 padding (likely
/// end of function).
pub fn summarise_handler(
    obj: &Object<'_>,
    data: &[u8],
    addr: u64,
    iat: &HashMap<u64, String>,
) -> Option<HandlerSummary> {
    let off = va_to_file_offset(obj, addr)?;
    let scan_len = 0x400.min(data.len() - off);
    let body = &data[off..off + scan_len];

    let mut apis = Vec::new();
    let mut seen_apis: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut pop_count = 0u32;
    let mut k = 0;
    while k + 6 <= body.len() {
        // CALL [RIP+disp32] = FF 15 d32 (6 bytes)
        if body[k] == 0xff && body[k + 1] == 0x15 {
            let d32 = i32::from_le_bytes([body[k + 2], body[k + 3], body[k + 4], body[k + 5]]);
            let next_rip = addr.wrapping_add((k + 6) as u64);
            let target = next_rip.wrapping_add(d32 as i64 as u64);
            if let Some(name) = iat.get(&target) {
                if seen_apis.insert(name.clone()) {
                    apis.push(name.clone());
                }
            }
            k += 6;
            continue;
        }
        // Stack pop pattern: DEC dword ptr [RBX + 0x8] (FF 4B 08)
        // or MOV qword ptr [RBX + reg*8 - 8], 0 patterns.
        // We pattern on the bare `LEA EAX, [RCX + -0x1]` (8D 41 FF) +
        // `MOV [RBX + 0x8], EAX` (89 43 08) — the v5 stack pop shape.
        if k + 6 <= body.len()
            && body[k] == 0x8d
            && body[k + 1] == 0x41
            && body[k + 2] == 0xff
            && body[k + 3] == 0x89
            && body[k + 4] == 0x43
            && body[k + 5] == 0x08
        {
            pop_count += 1;
            k += 6;
            continue;
        }
        // RET — possible end. If next byte is INT3, stop scanning.
        if body[k] == 0xc3 {
            if k + 1 < body.len() && body[k + 1] == 0xcc {
                break;
            }
        }
        k += 1;
    }

    Some(HandlerSummary {
        addr,
        pop_count,
        apis,
    })
}

pub fn summarise_all(obj: &Object<'_>, data: &[u8], addrs: &[u64]) -> Vec<HandlerSummary> {
    let iat = build_iat_map(obj, data);
    addrs
        .iter()
        .filter_map(|a| summarise_handler(obj, data, *a, &iat))
        .collect()
}

pub fn render(summaries: &[HandlerSummary]) -> Vec<String> {
    summaries
        .iter()
        .map(|s| format!("{:#x}  pops={}  apis={:?}", s.addr, s.pop_count, s.apis))
        .collect()
}
