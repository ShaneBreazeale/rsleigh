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

// ===========================================================================
// Handler body analysis — detects self-modifying-code (SMC) patterns
// ===========================================================================
//
// Win64 SEH ABI:
//   RCX = ExceptionRecord*      (ExceptionAddress at +0x08, ExceptionCode at +0x00)
//   RDX = EstablisherFrame
//   R8  = ContextRecord*        (Rax at +0x78 ... Rip at +0xF8, EFlags at +0x44)
//   R9  = DispatcherContext*    (ControlPc at +0x00, TargetIp at +0x20)
//
// Common SMC patterns that route key material through the exception dispatcher:
//
//   1. Rip-rewrite to decrypted target:
//        mov [r8 + 0xF8], <imm64>           ; or
//        mov [r8 + 0xF8], <reg>             ; where reg was computed from
//                                           ; ExceptionRecord->ExceptionInformation
//
//   2. Nanomite-style skip:
//        add [r8 + 0xF8], <imm8>            ; skip past faulting byte(s)
//
//   3. Page-patch via WriteProcessMemory / VirtualProtect:
//        GetCurrentProcess → WriteProcessMemory(proc, target, src, len, &written)
//
//   4. Direct mprotect+write (process itself):
//        VirtualProtect(target, sz, PAGE_EXECUTE_READWRITE, &old)
//        rep movsb                          ; or mov [target], reg
//        VirtualProtect(target, sz, old, &old)
//
// The analyser labels a handler with the patterns it matches so downstream
// passes can decide whether to evaluate the handler's effects precisely.

/// What behaviours the handler exhibits.  Flags are disjoint; a handler can
/// match several simultaneously.
#[derive(Debug, Clone, Default)]
pub struct HandlerAnalysis {
    /// `mov [r8+0xf8], imm/reg` — rewrites ContextRecord.Rip, i.e. the
    /// handler redirects execution somewhere of its choosing.
    pub redirects_rip: bool,
    /// `add [r8+0xf8], imm` — nanomite-style "skip instruction" handler.
    pub skips_rip: bool,
    /// Handler writes through ContextRecord fields other than Rip (common
    /// prelude to state-munging attacks).
    pub mutates_context: bool,
    /// Handler reads from ExceptionRecord->ExceptionInformation (carries
    /// the faulting address on #GP / page faults).
    pub reads_exception_info: bool,
    /// Handler invokes WriteProcessMemory / NtWriteVirtualMemory via IAT.
    pub calls_wpm: bool,
    /// Handler invokes VirtualProtect / NtProtectVirtualMemory via IAT.
    pub calls_vprotect: bool,
    /// Handler issues a REP MOVS* — mass in-process copy, usually part of
    /// page-patch SMC.
    pub uses_rep_movs: bool,
    /// Resumption address written into Rip, if the analyser can recover a
    /// concrete 64-bit immediate (`mov [r8+0xf8], imm64` via
    /// `mov reg64, imm64; mov [r8+0xf8], reg64`).
    pub resumption_va: Option<u64>,
    /// Distinct IAT-visible function names called by this handler, in
    /// first-seen order. Caps at 16 for sanity.
    pub iat_calls: Vec<String>,
    /// Number of x86-64 instructions scanned before a RET or trap stopped
    /// us (mostly for diagnostics).
    pub insn_count: usize,
}

impl HandlerAnalysis {
    /// True if this handler plausibly participates in self-modifying code.
    pub fn is_smc_candidate(&self) -> bool {
        self.redirects_rip
            || self.skips_rip
            || self.calls_wpm
            || self.calls_vprotect
            || self.uses_rep_movs
    }
}

/// Analyse every SEH-registered handler in `image` and return an analysis
/// keyed on handler VA.  Handlers are analysed once even if several records
/// share the same handler address.
pub fn analyse_all_handlers(image: &[u8]) -> std::collections::BTreeMap<u64, HandlerAnalysis> {
    let records = parse_pe64_seh(image);
    let mut out = std::collections::BTreeMap::new();
    let handlers = handler_addresses(&records);
    for h in handlers {
        if let Some(a) = analyse_handler(image, h) {
            out.insert(h, a);
        }
    }
    out
}

/// Analyse a single handler body starting at `handler_va`.  Returns None
/// when the body cannot be located in the image.
pub fn analyse_handler(image: &[u8], handler_va: u64) -> Option<HandlerAnalysis> {
    use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind, Register};

    let obj = match goblin::Object::parse(image) { Ok(o) => o, _ => return None };
    let pe = match obj { goblin::Object::PE(p) => p, _ => return None };
    if !pe.is_64 { return None; }
    let base = pe.image_base as u64;

    // Locate handler body: find the .text section containing handler_va, then
    // read a bounded window. Stop at the first RET (or UD2 / INT3 run).
    let mut handler_fo: Option<usize> = None;
    for sec in &pe.sections {
        let va  = base + sec.virtual_address as u64;
        let vsz = sec.virtual_size as u64;
        if handler_va >= va && handler_va < va + vsz {
            let delta = (handler_va - va) as usize;
            handler_fo = Some(sec.pointer_to_raw_data as usize + delta);
            break;
        }
    }
    let fo = handler_fo?;
    let max_len = 4096usize.min(image.len().saturating_sub(fo));
    if max_len == 0 { return None; }

    // IAT slot -> imported symbol name, for call target resolution.
    let mut iat_name: std::collections::HashMap<u64, String> =
        std::collections::HashMap::new();
    if let Some(imports) = pe.imports.iter().next().map(|_| &pe.imports) {
        for imp in imports.iter() {
            let slot = base + imp.offset as u64;
            iat_name.insert(slot, imp.name.to_string());
        }
    }

    let bytes = &image[fo..fo + max_len];
    let mut dec = Decoder::with_ip(64, bytes, handler_va, DecoderOptions::NONE);
    let mut insn = iced_x86::Instruction::default();
    let mut a = HandlerAnalysis::default();

    // Simple scalar tracking: last-seen 64-bit immediate per register. Lets
    // us resolve `mov rax, imm64; mov [r8+0xf8], rax` → concrete Rip write.
    let mut imm64_of: [Option<u64>; 16] = [None; 16];
    let reg_idx = |r: Register| -> Option<usize> {
        match r {
            Register::RAX => Some(0), Register::RCX => Some(1),
            Register::RDX => Some(2), Register::RBX => Some(3),
            Register::RSP => Some(4), Register::RBP => Some(5),
            Register::RSI => Some(6), Register::RDI => Some(7),
            Register::R8  => Some(8), Register::R9  => Some(9),
            Register::R10 => Some(10), Register::R11 => Some(11),
            Register::R12 => Some(12), Register::R13 => Some(13),
            Register::R14 => Some(14), Register::R15 => Some(15),
            _ => None,
        }
    };

    while dec.can_decode() && a.insn_count < 1024 {
        dec.decode_out(&mut insn);
        a.insn_count += 1;

        let op = insn.mnemonic();
        match op {
            Mnemonic::Ret | Mnemonic::Ud2 | Mnemonic::Int3 => break,
            _ => {}
        }

        // ---- Immediate-into-register tracking ---------------------------
        if op == Mnemonic::Mov
            && insn.op_count() == 2
            && insn.op_kind(0) == OpKind::Register
            && insn.op_kind(1) == OpKind::Immediate64
        {
            if let Some(i) = reg_idx(insn.op_register(0)) {
                imm64_of[i] = Some(insn.immediate64());
            }
        } else if op == Mnemonic::Mov
            && insn.op_count() == 2
            && insn.op_kind(0) == OpKind::Register
        {
            // Any other write to a register clears the tracked immediate.
            if let Some(i) = reg_idx(insn.op_register(0)) {
                imm64_of[i] = None;
            }
        }

        // ---- Memory-write classification --------------------------------
        // ContextRecord via R8:
        //   [r8 + disp] on op0 when op0 kind is memory
        let is_mem_write_to_r8 = insn.op_count() >= 1
            && insn.op_kind(0) == OpKind::Memory
            && insn.memory_base() == Register::R8;
        let is_mem_write_to_rcx = insn.op_count() >= 1
            && insn.op_kind(0) == OpKind::Memory
            && insn.memory_base() == Register::RCX;

        if is_mem_write_to_r8 {
            let disp = insn.memory_displacement64();
            // Rip field is at +0xF8 in Win64 CONTEXT.
            if disp == 0xF8 {
                match op {
                    Mnemonic::Mov => {
                        a.redirects_rip = true;
                        if insn.op_kind(1) == OpKind::Register {
                            if let Some(i) = reg_idx(insn.op_register(1)) {
                                a.resumption_va = imm64_of[i];
                            }
                        } else if insn.op_kind(1) == OpKind::Immediate32to64 {
                            a.resumption_va = Some(insn.immediate64());
                        }
                    }
                    Mnemonic::Add | Mnemonic::Sub | Mnemonic::Inc | Mnemonic::Dec => {
                        a.skips_rip = true;
                    }
                    _ => {}
                }
            } else {
                a.mutates_context = true;
            }
        } else if is_mem_write_to_rcx {
            // ExceptionRecord.ExceptionInformation is at offset 0x20 (after
            // ExceptionCode/Flags/Record/Address/NumberParameters).
            let disp = insn.memory_displacement64();
            if disp >= 0x20 {
                a.reads_exception_info = true; // conservative: write here is
                                               // also a signal the handler
                                               // is rewriting fault metadata.
            }
        }

        // ---- Memory reads -----------------------------------------------
        // Look for `[rcx + N]` reads where N lies in ExceptionRecord.  N=0x8
        // = ExceptionAddress; N=0x20..=0x30 = ExceptionInformation[0..2].
        for i in 0..insn.op_count() {
            if insn.op_kind(i) == OpKind::Memory
                && insn.memory_base() == Register::RCX
                && i > 0 // skip destination operand
            {
                let disp = insn.memory_displacement64();
                if disp == 0x08 || (0x20..=0x30).contains(&disp) {
                    a.reads_exception_info = true;
                }
            }
        }

        // ---- REP MOVSB / REP MOVSD / REP MOVSQ ---------------------------
        if insn.has_rep_prefix() && matches!(op, Mnemonic::Movsb | Mnemonic::Movsd | Mnemonic::Movsq) {
            a.uses_rep_movs = true;
        }

        // ---- IAT calls ---------------------------------------------------
        if op == Mnemonic::Call
            && insn.op_count() == 1
            && insn.op_kind(0) == OpKind::Memory
            && insn.is_ip_rel_memory_operand()
        {
            let target = insn.ip_rel_memory_address();
            if let Some(name) = iat_name.get(&target) {
                if a.iat_calls.len() < 16 && !a.iat_calls.contains(name) {
                    a.iat_calls.push(name.clone());
                }
                match name.as_str() {
                    "WriteProcessMemory" | "NtWriteVirtualMemory"
                        | "ZwWriteVirtualMemory" => a.calls_wpm = true,
                    "VirtualProtect" | "VirtualProtectEx"
                        | "NtProtectVirtualMemory" | "ZwProtectVirtualMemory"
                        => a.calls_vprotect = true,
                    _ => {}
                }
            }
        }
    }

    Some(a)
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
    fn crackmev3_handler_analysis_detects_rtl_unwind() {
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let fixture  = manifest.parent().unwrap()
            .join("test-harness/fixtures/crackmev3.pyd");
        if !fixture.exists() {
            eprintln!("skipping: crackmev3.pyd not staged");
            return;
        }
        let bytes = std::fs::read(&fixture).unwrap();
        let analyses = analyse_all_handlers(&bytes);
        assert!(!analyses.is_empty(), "expected at least one handler analysed");
        // 0x180019ca0 is the MSVC personality-function handler in this
        // fixture; it definitely calls RtlUnwindEx.
        let h = analyses.get(&0x180019ca0)
            .expect("handler 0x180019ca0 missing");
        assert!(h.insn_count > 50,
            "expected > 50 instructions in personality handler, got {}", h.insn_count);
        assert!(h.iat_calls.iter().any(|s| s == "RtlUnwindEx"),
            "expected RtlUnwindEx IAT call, got: {:?}", h.iat_calls);
        // No SMC flags should fire on this v4 sample (v4 uses inline PCG,
        // not SEH-driven self-modification). This guards against false
        // positives when handler scanning evolves.
        for (va, a) in &analyses {
            assert!(!a.is_smc_candidate(),
                "handler {:#x} wrongly flagged as SMC: {:?}", va, a);
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
