//! Static PE64 Structured Exception Handling (SEH) enumerator.
//!
//! Walks the PE32+ `.pdata` exception directory, parses each `RUNTIME_FUNCTION`
//! entry's `UNWIND_INFO`, and returns the list of registered exception
//! handlers. This is the groundwork for detecting SEH-driven self-modifying
//! code (SMC) in obfuscators such as PyVMProtect v5 and VMProtect 3.x, where
//! the key-derivation graph is deliberately routed through
//! `__except_handler4` / personality functions so that naive emulators
//! (unicorn, qemu-user) never execute the real decryption path.
//!
//! Layout reference:
//!   * RUNTIME_FUNCTION       — 12 bytes: (BeginAddress, EndAddress, UnwindData)
//!   * UNWIND_INFO            — header (4 bytes) + unwind codes + optional
//!                              trailer: either a chained RUNTIME_FUNCTION
//!                              (flags & UNW_FLAG_CHAININFO) or
//!                              (ExceptionHandler RVA, ExceptionData[]).
//!   * UNW_FLAG_EHANDLER=1, UNW_FLAG_UHANDLER=2, UNW_FLAG_CHAININFO=4.
//!
//! This module is PE64-only.  PE32 SEH lives in the PE load config's
//! SafeSEH table, which we do not walk here.

use std::convert::TryInto;

/// A single exception-handler registration recovered from `.pdata` + UNWIND_INFO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SehRecord {
    /// VA of the covered function's first byte.
    pub func_begin: u64,
    /// VA one past the covered function's last byte.
    pub func_end: u64,
    /// VA of the registered exception handler, if any.
    ///
    /// Present when `UNW_FLAG_EHANDLER` or `UNW_FLAG_UHANDLER` is set in the
    /// flags byte of the handler's `UNWIND_INFO`.  `None` for pure unwind
    /// records.
    pub handler: Option<u64>,
    /// VA of the handler's scope table / language-specific data area, if any.
    ///
    /// For compiler-emitted C/C++ handlers this is a `SCOPE_TABLE` structure
    /// describing individual `__try` ranges.  For custom handlers (e.g.,
    /// obfuscator personality functions) this can be arbitrary binary data.
    pub scope_table: Option<u64>,
    /// UNWIND_INFO version byte (1 or 2).
    pub version: u8,
    /// UNWIND_INFO flags byte.
    pub flags: u8,
}

impl SehRecord {
    pub fn has_ehandler(&self) -> bool { (self.flags & 0x1) != 0 }
    pub fn has_uhandler(&self) -> bool { (self.flags & 0x2) != 0 }
    pub fn has_chaininfo(&self) -> bool { (self.flags & 0x4) != 0 }
}

/// Parse PE64 SEH records.  Returns an empty vec for non-PE, PE32, or
/// PEs without an exception directory.
///
/// `image_data` is the raw file bytes.  Handler / scope-table addresses are
/// returned as virtual addresses (image base added).
pub fn parse_pe64_seh(image_data: &[u8]) -> Vec<SehRecord> {
    let obj = match goblin::Object::parse(image_data) { Ok(o) => o, Err(_) => return vec![] };
    let pe = match obj { goblin::Object::PE(pe) => pe, _ => return vec![] };
    if !pe.is_64 { return vec![]; }
    let base = pe.image_base as u64;

    // Find the .pdata section.  goblin does not expose the exception
    // directory separately, so we locate the section by name.
    let pdata = pe.sections.iter()
        .find(|s| std::str::from_utf8(&s.name).unwrap_or("").trim_end_matches('\0') == ".pdata");
    let Some(pdata) = pdata else { return vec![]; };
    let pd_fo = pdata.pointer_to_raw_data as usize;
    let pd_sz = pdata.virtual_size.min(pdata.size_of_raw_data) as usize;
    if pd_fo + pd_sz > image_data.len() || pd_sz < 12 { return vec![]; }

    // Helper: RVA -> file offset using the section table.
    let rva_to_fo = |rva: u32| -> Option<usize> {
        let rva = rva as u64;
        for sec in &pe.sections {
            let va  = sec.virtual_address as u64;
            let vsz = sec.virtual_size as u64;
            if rva >= va && rva < va + vsz {
                return Some(sec.pointer_to_raw_data as usize + (rva - va) as usize);
            }
        }
        None
    };

    let read_u32 = |fo: usize| -> Option<u32> {
        if fo + 4 > image_data.len() { return None; }
        Some(u32::from_le_bytes(image_data[fo..fo + 4].try_into().ok()?))
    };

    // Recursively resolve an UNWIND_INFO at an RVA.  Follows CHAININFO links
    // to the last entry in the chain (that's where the real handler sits).
    // `depth` bound prevents pathological loops.
    fn resolve_unwind(
        unwind_rva: u32,
        image: &[u8],
        rva_to_fo: &dyn Fn(u32) -> Option<usize>,
        depth: u32,
    ) -> Option<UnwindSummary> {
        if depth > 8 { return None; }
        let fo = rva_to_fo(unwind_rva)?;
        if fo + 4 > image.len() { return None; }
        let hdr0 = image[fo];
        let count_of_codes = image[fo + 2] as usize;
        let version = hdr0 & 0x07;
        let flags   = (hdr0 >> 3) & 0x1f;
        if version == 0 || version > 2 { return None; }

        // UNWIND_CODE entries: 2 bytes each, DWORD-padded as a block.
        let codes_bytes = ((count_of_codes + 1) & !1) * 2;
        let trailer_fo = fo + 4 + codes_bytes;

        if flags & 0x4 != 0 {
            // CHAININFO: trailer is a RUNTIME_FUNCTION.  Recurse on its
            // UnwindData to pick up the handler that actually lives at the
            // chain's tail.
            if trailer_fo + 12 > image.len() { return None; }
            let next_unwind = u32::from_le_bytes(
                image[trailer_fo + 8..trailer_fo + 12].try_into().ok()?);
            return resolve_unwind(next_unwind, image, rva_to_fo, depth + 1);
        }

        if flags & 0x3 != 0 {
            // Handler present: trailer is (ExceptionHandlerRVA, ExceptionData[]).
            if trailer_fo + 4 > image.len() { return None; }
            let handler_rva = u32::from_le_bytes(
                image[trailer_fo..trailer_fo + 4].try_into().ok()?);
            let scope_rva = (trailer_fo + 4) as u32; // file offset; we convert below
            return Some(UnwindSummary {
                version,
                flags,
                handler_rva: Some(handler_rva),
                // Scope table sits right after the handler RVA.  Store its RVA
                // (which we compute by deriving from fo + 4 + codes_bytes + 4).
                scope_table_rva: Some(unwind_rva + 4 + codes_bytes as u32 + 4),
            });
        }

        Some(UnwindSummary { version, flags, handler_rva: None, scope_table_rva: None })
    }

    // Walk each 12-byte RUNTIME_FUNCTION.
    let mut out = Vec::new();
    let mut off = 0;
    while off + 12 <= pd_sz {
        let Some(begin) = read_u32(pd_fo + off)       else { break; };
        let Some(end)   = read_u32(pd_fo + off + 4)   else { break; };
        let Some(uwd)   = read_u32(pd_fo + off + 8)   else { break; };
        off += 12;
        // Sentinel: end of table.
        if begin == 0 && end == 0 && uwd == 0 { break; }

        let Some(summary) = resolve_unwind(uwd, image_data, &rva_to_fo, 0) else {
            out.push(SehRecord {
                func_begin: base + begin as u64,
                func_end:   base + end   as u64,
                handler:    None,
                scope_table:None,
                version:    1,
                flags:      0,
            });
            continue;
        };

        out.push(SehRecord {
            func_begin: base + begin as u64,
            func_end:   base + end   as u64,
            handler:    summary.handler_rva.map(|r| base + r as u64),
            scope_table:summary.scope_table_rva.map(|r| base + r as u64),
            version:    summary.version,
            flags:      summary.flags,
        });
    }
    out
}

/// Collect every distinct handler VA from the records.  Handy as a
/// function-discovery augmentation: these VAs point into .text but are
/// never reached by CALL descent or vtable scans, so naive heuristics
/// miss them.
pub fn handler_addresses(records: &[SehRecord]) -> Vec<u64> {
    let mut set: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    for r in records {
        if let Some(h) = r.handler { set.insert(h); }
    }
    set.into_iter().collect()
}

/// Summary returned by `resolve_unwind`.
#[derive(Debug, Clone, Copy)]
struct UnwindSummary {
    version: u8,
    flags: u8,
    handler_rva: Option<u32>,
    scope_table_rva: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: crackmev3.pyd is a known PyVMProtect fixture bundled in
    /// test-harness/fixtures.  It has a small `.pdata` with a handful of
    /// unwind-only records (no `__except` handlers in the shipped build).
    /// The test skips if the fixture is not present.
    #[test]
    fn crackmev3_pdata_parses() {
        // Locate the fixture relative to the crate manifest.
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let fixture  = manifest.parent().unwrap()
            .join("test-harness/fixtures/crackmev3.pyd");
        if !fixture.exists() {
            eprintln!("skipping: {:?} not staged", fixture);
            return;
        }
        let bytes = std::fs::read(&fixture).unwrap();
        let recs = parse_pe64_seh(&bytes);
        assert!(!recs.is_empty(), "expected at least one .pdata record");
        // All records must reference addresses in the PE64 image range.
        for r in &recs {
            assert!(r.func_begin >= 0x180000000 && r.func_begin < 0x181000000,
                "func_begin {:#x} out of range", r.func_begin);
            assert!(r.func_end > r.func_begin,
                "end {:#x} <= begin {:#x}", r.func_end, r.func_begin);
        }
    }

    #[test]
    fn handler_addresses_deduped() {
        let rs = vec![
            SehRecord { func_begin: 0x1000, func_end: 0x1100,
                        handler: Some(0x2000), scope_table: None,
                        version: 1, flags: 1 },
            SehRecord { func_begin: 0x1200, func_end: 0x1300,
                        handler: Some(0x2000), scope_table: None,
                        version: 1, flags: 1 },
            SehRecord { func_begin: 0x1400, func_end: 0x1500,
                        handler: None, scope_table: None,
                        version: 1, flags: 0 },
            SehRecord { func_begin: 0x1600, func_end: 0x1700,
                        handler: Some(0x3000), scope_table: None,
                        version: 1, flags: 1 },
        ];
        let addrs = handler_addresses(&rs);
        assert_eq!(addrs, vec![0x2000, 0x3000]);
    }
}
