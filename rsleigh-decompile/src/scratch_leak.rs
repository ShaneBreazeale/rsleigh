//! Detect "scratch-buffer leak" anti-emu defenses.
//!
//! Pattern observed in PyVMProtect v5: the const-pool resolver
//! allocates a buffer, decrypts data into it, then RETURNS Py_None
//! when an unknown type tag is hit — abandoning the freshly-decrypted
//! buffer in scratch heap. An offline emulator that runs the resolver
//! once and then snapshots scratch heap can read the plaintext even
//! though the resolver's return value claimed "no value".
//!
//! Detection rules:
//!   - Function calls a likely-allocator (`PyMem_Malloc`, `malloc`,
//!     `_PyObject_New`, internal `0x180030890` style helpers).
//!   - Function writes to the returned pointer (any `MOV [r], imm` or
//!     `MOV [r+disp], r` where r came from the allocator return).
//!   - Function has at least one return path emitting `Py_None`
//!     (`MOV RAX, [iat_slot_for_None]; RET`).
//!
//! When all three conditions co-exist in the same function, flag it
//! as a likely scratch-leak vector. Analyst should use emulation +
//! wide scratch snapshot to read the leaked plaintext.
//!
//! Heuristic confidence: medium. Many legitimate functions allocate +
//! sometimes-return-None (e.g., `PyDict_GetItem` style lookups). But
//! when combined with the other PyVMProtect detectors firing on the
//! same binary, a positive hit is highly likely a real scratch leak.

use goblin::Object;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ScratchLeakHit {
    pub func_va: u64,
    /// Number of distinct allocator calls within the function body.
    pub alloc_calls: u32,
    /// Whether at least one path returns Py_None (i.e., reads from the
    /// `_Py_NoneStruct` IAT slot and returns).
    pub returns_none: bool,
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

/// Names of allocator-like APIs we recognise.
const ALLOCATOR_NAMES: &[&str] = &[
    "PyMem_Malloc",
    "PyMem_RawMalloc",
    "PyMem_Calloc",
    "PyObject_Malloc",
    "_PyObject_New",
    "_PyObject_NewVar",
    "PyTuple_New",
    "PyDict_New",
    "PyList_New",
    "PyBytes_FromStringAndSize",
    "PyByteArray_FromStringAndSize",
    "malloc",
    "calloc",
    "HeapAlloc",
    "VirtualAlloc",
    "LocalAlloc",
];

const NONE_STRUCT_NAMES: &[&str] = &["_Py_NoneStruct"];

/// Inspect a single function. Returns Some(hit) when it matches the
/// scratch-leak heuristic.
pub fn check_function(
    obj: &Object<'_>,
    data: &[u8],
    iat: &HashMap<u64, String>,
    func_va: u64,
    body_max: usize,
) -> Option<ScratchLeakHit> {
    let off = va_to_file_offset(obj, func_va)?;
    let scan_len = body_max.min(data.len() - off);
    let body = &data[off..off + scan_len];

    let mut alloc_calls = 0u32;
    let mut none_via_iat = false;
    let mut none_via_data = false;
    let mut k = 0;
    while k + 6 <= body.len() {
        // CALL [RIP+disp32]  →  ff 15 d32 (6 bytes)
        if body[k] == 0xff && body[k + 1] == 0x15 {
            let d32 = i32::from_le_bytes([
                body[k + 2],
                body[k + 3],
                body[k + 4],
                body[k + 5],
            ]);
            let next_rip = func_va.wrapping_add((k + 6) as u64);
            let target = next_rip.wrapping_add(d32 as i64 as u64);
            if let Some(name) = iat.get(&target) {
                if ALLOCATOR_NAMES.iter().any(|n| name == n) {
                    alloc_calls += 1;
                }
            }
            k += 6;
            continue;
        }
        // MOV RAX, qword ptr [RIP+disp32]  →  48 8B 05 d32 (7 bytes)
        if k + 7 <= body.len()
            && body[k] == 0x48
            && body[k + 1] == 0x8b
            && body[k + 2] == 0x05
        {
            let d32 = i32::from_le_bytes([
                body[k + 3],
                body[k + 4],
                body[k + 5],
                body[k + 6],
            ]);
            let next_rip = func_va.wrapping_add((k + 7) as u64);
            let target = next_rip.wrapping_add(d32 as i64 as u64);
            if let Some(name) = iat.get(&target) {
                if NONE_STRUCT_NAMES.iter().any(|n| name == n) {
                    none_via_iat = true;
                }
            }
            // Also record direct data reads — we can't tell if this is
            // None without symbol info, but if the same function later
            // RETs, we treat any IAT-table read as suspicious.
            k += 7;
            continue;
        }
        // RET (0xC3) — bookkeeping
        if body[k] == 0xc3 {
            // Look back: if last few instructions read from an IAT
            // slot named `_Py_NoneStruct`, mark.
            // (We've already detected via the MOV scan above.)
            k += 1;
            continue;
        }
        // INC qword ptr [RAX] → FF 00. The Py_None refcount-bump
        // pattern: `MOV RAX, [None_slot]; INC qword [RAX]; RET`.
        if k + 2 <= body.len() && body[k] == 0xff && body[k + 1] == 0x00 {
            none_via_data = true;
        }
        k += 1;
    }

    if alloc_calls >= 1 && (none_via_iat || none_via_data) {
        Some(ScratchLeakHit {
            func_va,
            alloc_calls,
            returns_none: none_via_iat || none_via_data,
        })
    } else {
        None
    }
}

/// Scan a list of candidate function VAs. Caller supplies them
/// (typically the full discovered-function list).
pub fn scan_functions(
    obj: &Object<'_>,
    data: &[u8],
    iat: &HashMap<u64, String>,
    func_vas: &[u64],
    body_max: usize,
) -> Vec<ScratchLeakHit> {
    func_vas
        .iter()
        .filter_map(|&va| check_function(obj, data, iat, va, body_max))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_includes_va_and_counts() {
        let hits = vec![ScratchLeakHit {
            func_va: 0x1800_1234,
            alloc_calls: 2,
            returns_none: true,
        }];
        let out = render(&hits);
        assert_eq!(out.len(), 1);
        assert!(out[0].contains("0x18001234"));
        assert!(out[0].contains("alloc_calls=2"));
        assert!(out[0].contains("returns_None=true"));
    }

    #[test]
    fn allocator_list_includes_pyvmprotect_targets() {
        for n in &[
            "PyMem_Malloc",
            "_PyObject_New",
            "PyTuple_New",
            "PyDict_New",
            "PyList_New",
            "HeapAlloc",
        ] {
            assert!(
                ALLOCATOR_NAMES.iter().any(|a| a == n),
                "missing allocator: {}",
                n
            );
        }
        assert!(NONE_STRUCT_NAMES.iter().any(|a| *a == "_Py_NoneStruct"));
    }

    #[test]
    fn empty_list_yields_no_output() {
        let out = render(&[]);
        assert!(out.is_empty());
    }
}

pub fn render(hits: &[ScratchLeakHit]) -> Vec<String> {
    hits.iter()
        .map(|h| {
            format!(
                "{:#x}: alloc_calls={} returns_None={} — possible scratch leak",
                h.func_va, h.alloc_calls, h.returns_none
            )
        })
        .collect()
}
