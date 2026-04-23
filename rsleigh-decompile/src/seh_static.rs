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

/// A single entry from the `SCOPE_TABLE` that `_C_specific_handler` and
/// `__except_handler4` use as language-specific data.
///
/// Each entry describes one `__try` block within the covered function.
/// For a `__try / __except`, `handler_va` is the filter function VA and
/// `jump_target_va` is where execution resumes after the handler runs.
/// For a `__try / __finally`, `handler_va` is a constant (0 or 1), and
/// `jump_target_va` is the finally-block entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopeRecord {
    pub begin_va: u64,
    pub end_va: u64,
    pub handler_va: u64,
    pub jump_target_va: u64,
}

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
    //
    // The undocumented "UnwindData low-bit" optimisation (Ken Johnson /
    // Matt Miller): when (UnwindData & 1) is set, the value with the low
    // bit cleared is itself an RVA of a RUNTIME_FUNCTION (the first in a
    // chain) rather than a pointer to UNWIND_INFO.  Rare in practice but
    // correct to model.
    fn resolve_unwind(
        mut unwind_rva: u32,
        image: &[u8],
        rva_to_fo: &dyn Fn(u32) -> Option<usize>,
        depth: u32,
    ) -> Option<UnwindSummary> {
        if depth > 8 { return None; }
        if (unwind_rva & 1) != 0 {
            // Follow the RUNTIME_FUNCTION reference.
            let rf_fo = rva_to_fo(unwind_rva & !1)?;
            if rf_fo + 12 > image.len() { return None; }
            let next_unwind = u32::from_le_bytes(
                image[rf_fo + 8..rf_fo + 12].try_into().ok()?);
            unwind_rva = next_unwind;
        }
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

/// Read a `SCOPE_TABLE` for a `_C_specific_handler`-class handler, if the
/// handler's exception-data pointer references one.
///
/// Layout:
///   `DWORD Count;`
///   followed by `Count` records of `{ BeginRVA, EndRVA, HandlerRVA, JumpTargetRVA }`.
///
/// The call is best-effort: if the pointed-to structure does not look like a
/// plausible scope table (implausible `Count`, out-of-section addresses,
/// begin >= end, etc.), it returns an empty vector so callers can safely
/// ignore non-C-handler scope data.
pub fn read_scope_table(image: &[u8], scope_table_va: u64) -> Vec<ScopeRecord> {
    let obj = match goblin::Object::parse(image) { Ok(o) => o, _ => return vec![] };
    let pe = match obj { goblin::Object::PE(p) => p, _ => return vec![] };
    if !pe.is_64 { return vec![]; }
    let base = pe.image_base as u64;

    let va_to_fo = |va: u64| -> Option<usize> {
        for sec in &pe.sections {
            let sva = base + sec.virtual_address as u64;
            let vsz = sec.virtual_size as u64;
            if va >= sva && va < sva + vsz {
                return Some(sec.pointer_to_raw_data as usize + (va - sva) as usize);
            }
        }
        None
    };
    let Some(fo) = va_to_fo(scope_table_va) else { return vec![]; };
    if fo + 4 > image.len() { return vec![]; }
    let count = u32::from_le_bytes(image[fo..fo + 4].try_into().unwrap_or([0; 4]));
    if count == 0 || count > 1024 { return vec![]; }
    let need = 4usize + count as usize * 16;
    if fo + need > image.len() { return vec![]; }

    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let r = fo + 4 + i * 16;
        let begin    = u32::from_le_bytes(image[r     ..r + 4 ].try_into().unwrap()) as u64;
        let end      = u32::from_le_bytes(image[r + 4 ..r + 8 ].try_into().unwrap()) as u64;
        let handler  = u32::from_le_bytes(image[r + 8 ..r + 12].try_into().unwrap()) as u64;
        let jump     = u32::from_le_bytes(image[r + 12..r + 16].try_into().unwrap()) as u64;
        // Sanity: begin/end should form a valid covered range; handler 0 or 1
        // is a __finally sentinel, otherwise it must land in the image.
        if end <= begin { return vec![]; }
        out.push(ScopeRecord {
            begin_va:       base + begin,
            end_va:         base + end,
            handler_va:     if handler <= 1 { handler } else { base + handler },
            jump_target_va: if jump == 0    { 0        } else { base + jump    },
        });
    }
    out
}

/// Harvest every additional function-start VA that can be recovered from
/// scope tables of handlers in the image.  Typically surfaces filter
/// functions and `__except` / `__finally` resumption blocks that are not
/// reachable from any CALL site.
///
/// Handles **nested SEH**: a filter function discovered via one scope table
/// may have its own `RUNTIME_FUNCTION` entry with another scope table (e.g.,
/// `__except { __try { ... } __except { ... } }`).  The traversal walks
/// that graph up to a hard depth of 8.
pub fn scope_table_addresses(image: &[u8]) -> Vec<u64> {
    let records = parse_pe64_seh(image);

    // Build a side map from function-start VA to scope_table VA so that a
    // discovered filter function can be looked up for its nested handler.
    let mut scope_by_fn: std::collections::HashMap<u64, u64> = std::collections::HashMap::new();
    for r in &records {
        if let Some(st) = r.scope_table {
            scope_by_fn.insert(r.func_begin, st);
        }
    }

    let mut visited_st: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut out: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();

    // BFS over scope tables.  Each newly found filter/resume VA is checked
    // for a further scope table (via scope_by_fn); if it has one and has
    // not been visited yet, enqueue it.
    let mut queue: std::collections::VecDeque<(u64, u32)> = std::collections::VecDeque::new();
    for r in &records {
        if let Some(st) = r.scope_table {
            queue.push_back((st, 0));
        }
    }

    while let Some((st_va, depth)) = queue.pop_front() {
        if depth > 8 { continue; }
        if !visited_st.insert(st_va) { continue; }
        for sr in read_scope_table(image, st_va) {
            if sr.handler_va > 1 {
                out.insert(sr.handler_va);
                if let Some(&next_st) = scope_by_fn.get(&sr.handler_va) {
                    queue.push_back((next_st, depth + 1));
                }
            }
            if sr.jump_target_va != 0 {
                out.insert(sr.jump_target_va);
                if let Some(&next_st) = scope_by_fn.get(&sr.jump_target_va) {
                    queue.push_back((next_st, depth + 1));
                }
            }
        }
    }

    out.into_iter().collect()
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

// ===========================================================================
// Patch extraction
// ===========================================================================
//
// v1 of static patch-apply for SEH-driven SMC. Each handler is walked with a
// tiny abstract interpreter whose sole concern is: "which concrete bytes
// does this handler write to the image?"
//
// State tracked per register (Rax..R15):
//   - `Imm(u64)`  — register holds a known 64-bit immediate.
//   - `Addr(u64)` — register holds a known pointer (e.g. `lea rax, [rip+N]`).
//   - `Top`       — unknown / dataflow-diverged.
//
// Patch emission:
//   - `mov [imm_or_addr_reg + disp], imm/tracked_reg` → direct byte patch at
//     (base + disp).
//   - `rep movsb` with all three of rdi/rsi/rcx tracked → byte-copy patch.
//
// v1 deliberately refuses to model:
//   - Control flow (branches, loops other than a single `rep movs`).
//   - Memory reads from unknown locations.
//   - Non-constant writes (e.g. writing a value derived from ExceptionRecord).
//
// Those are v2 concerns; for the crackme v4 set there is nothing to apply
// anyway, so v1 is the right complexity budget.

/// A single byte-level patch the handler produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImagePatch {
    /// Target virtual address of the first patched byte.
    pub target_va: u64,
    /// Replacement bytes.
    pub bytes: Vec<u8>,
    /// Handler that produced this patch.
    pub handler_va: u64,
}

/// Abstract register value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegVal {
    Top,
    Imm(u64),
    Addr(u64),
}

impl RegVal {
    fn as_concrete(self) -> Option<u64> {
        match self { RegVal::Imm(v) | RegVal::Addr(v) => Some(v), RegVal::Top => None }
    }
}

/// Extract every concretely resolvable patch a handler emits.
///
/// v2: control-flow aware.  Walks the handler body as a worklist over
/// (basic-block-entry pc, register lattice state), follows both sides of
/// every conditional branch, follows unconditional jumps, and merges
/// register state at reconvergence points.  A reconvergence point whose
/// merged state differs from what was recorded for it on a previous visit
/// re-queues the block; otherwise it is skipped (fixpoint).
///
/// Stops each path at RET / UD2 / INT3.  Instructions-visited hard cap
/// defends against pathological loops.
///
/// Returns `Vec<ImagePatch>`. Empty for handlers that do not emit SMC or
/// whose writes depend on dynamic state the v2 interpreter cannot resolve.
pub fn extract_handler_patches(image: &[u8], handler_va: u64) -> Vec<ImagePatch> {
    use iced_x86::{Decoder, DecoderOptions, FlowControl, Mnemonic, OpKind, Register};

    let obj = match goblin::Object::parse(image) { Ok(o) => o, _ => return vec![] };
    let pe = match obj { goblin::Object::PE(p) => p, _ => return vec![] };
    if !pe.is_64 { return vec![]; }
    let base = pe.image_base as u64;

    // Locate handler body in the file.
    let mut handler_fo: Option<usize> = None;
    for sec in &pe.sections {
        let va  = base + sec.virtual_address as u64;
        let vsz = sec.virtual_size as u64;
        if handler_va >= va && handler_va < va + vsz {
            handler_fo = Some(sec.pointer_to_raw_data as usize + (handler_va - va) as usize);
            break;
        }
    }
    let Some(fo) = handler_fo else { return vec![]; };
    let max_len = 8192usize.min(image.len().saturating_sub(fo));
    if max_len == 0 { return vec![]; }
    let bytes_slice = &image[fo..fo + max_len];

    // Helper to read at a VA from the file image (not the in-memory image).
    let va_to_fo = |va: u64| -> Option<usize> {
        for sec in &pe.sections {
            let sva = base + sec.virtual_address as u64;
            let vsz = sec.virtual_size as u64;
            if va >= sva && va < sva + vsz {
                return Some(sec.pointer_to_raw_data as usize + (va - sva) as usize);
            }
        }
        None
    };
    let read_u64 = |va: u64| -> Option<u64> {
        let o = va_to_fo(va)?;
        if o + 8 > image.len() { return None; }
        Some(u64::from_le_bytes(image[o..o + 8].try_into().ok()?))
    };
    let read_bytes = |va: u64, len: usize| -> Option<Vec<u8>> {
        let o = va_to_fo(va)?;
        if o + len > image.len() { return None; }
        Some(image[o..o + len].to_vec())
    };

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

    // -------- Control-flow worklist --------
    // Entries: (pc_absolute_va, regs_at_entry).
    // Merged state per visited pc allows fixpoint termination.
    let merge = |a: [RegVal; 16], b: [RegVal; 16]| -> [RegVal; 16] {
        let mut out = [RegVal::Top; 16];
        for i in 0..16 {
            out[i] = match (a[i], b[i]) {
                (x, y) if x == y => x,
                _ => RegVal::Top,
            };
        }
        out
    };
    let mut visited: std::collections::HashMap<u64, [RegVal; 16]> = std::collections::HashMap::new();
    let mut worklist: Vec<(u64, [RegVal; 16])> = Vec::new();
    worklist.push((handler_va, [RegVal::Top; 16]));
    let mut patches: Vec<ImagePatch> = Vec::new();
    // Dedup so paths through the same patch site don't inflate output.
    let mut patch_set: std::collections::HashSet<(u64, Vec<u8>)> = std::collections::HashSet::new();
    let mut total_icount = 0usize;
    let icount_cap = 8192usize;

    'outer: while let Some((pc_start, mut regs)) = worklist.pop() {
        // Merge with any prior state at this entry; if unchanged, skip.
        if let Some(prev) = visited.get(&pc_start) {
            let merged = merge(*prev, regs);
            if merged == *prev { continue; }
            visited.insert(pc_start, merged);
            regs = merged;
        } else {
            visited.insert(pc_start, regs);
        }

        // Locate file offset for pc_start (could equal handler_va or a
        // jump-target a few basic blocks away).
        let Some(start_off) = (|| -> Option<usize> {
            if pc_start < handler_va { return None; }
            let delta = (pc_start - handler_va) as usize;
            if delta >= bytes_slice.len() { return None; }
            Some(delta)
        })() else { continue; };

        let mut dec = Decoder::with_ip(
            64,
            &bytes_slice[start_off..],
            pc_start,
            DecoderOptions::NONE,
        );
        let mut insn = iced_x86::Instruction::default();

        while dec.can_decode() {
            if total_icount >= icount_cap { break 'outer; }
            dec.decode_out(&mut insn);
            total_icount += 1;

            let op = insn.mnemonic();
            if matches!(op, Mnemonic::Ret | Mnemonic::Ud2 | Mnemonic::Int3) { break; }

            // Branches: handle before generic fallthrough logic.
            match insn.flow_control() {
                FlowControl::UnconditionalBranch => {
                    // Straight jmp — if target resolvable statically, requeue it.
                    if insn.op_count() == 1 && insn.op_kind(0) == OpKind::NearBranch64 {
                        worklist.push((insn.near_branch64(), regs));
                    }
                    break;
                }
                FlowControl::ConditionalBranch => {
                    // Queue branch target.  Then fall through with the
                    // same register state (conservative).
                    if insn.op_count() == 1 && insn.op_kind(0) == OpKind::NearBranch64 {
                        worklist.push((insn.near_branch64(), regs));
                    }
                    // No `break`: continue linear decode for the fall-through.
                }
                FlowControl::IndirectBranch => {
                    // Can't follow statically; terminate this path.
                    break;
                }
                _ => {}
            }

        // ---- Pure register updates --------------------------------------
        if op == Mnemonic::Mov && insn.op_count() == 2 && insn.op_kind(0) == OpKind::Register {
            let dst = insn.op_register(0);
            let Some(di) = reg_idx(dst) else {
                // Destination is a subregister we do not model — fall through.
                continue;
            };
            match insn.op_kind(1) {
                OpKind::Immediate64 => regs[di] = RegVal::Imm(insn.immediate64()),
                OpKind::Immediate32to64 => regs[di] = RegVal::Imm(insn.immediate64()),
                OpKind::Immediate32 => regs[di] = RegVal::Imm(insn.immediate32() as u64),
                OpKind::Register => {
                    if let Some(si) = reg_idx(insn.op_register(1)) {
                        regs[di] = regs[si];
                    } else {
                        regs[di] = RegVal::Top;
                    }
                }
                OpKind::Memory => {
                    // Constant address load: `mov reg, [rip + disp]` or
                    // `mov reg, [abs imm]`.  Used for constant tables.
                    if insn.is_ip_rel_memory_operand() {
                        let a = insn.ip_rel_memory_address();
                        if let Some(v) = read_u64(a) {
                            regs[di] = RegVal::Imm(v);
                        } else {
                            regs[di] = RegVal::Top;
                        }
                    } else {
                        regs[di] = RegVal::Top;
                    }
                }
                _ => regs[di] = RegVal::Top,
            }
            continue;
        }

        // LEA reg, [rip + disp] — common for loading addresses of
        // patch source / destination constants.
        if op == Mnemonic::Lea
            && insn.op_count() == 2
            && insn.op_kind(0) == OpKind::Register
            && insn.op_kind(1) == OpKind::Memory
        {
            let dst = insn.op_register(0);
            if let Some(di) = reg_idx(dst) {
                if insn.is_ip_rel_memory_operand() {
                    regs[di] = RegVal::Addr(insn.ip_rel_memory_address());
                } else if insn.memory_base() != Register::None
                    && insn.memory_index() == Register::None
                {
                    if let Some(si) = reg_idx(insn.memory_base()) {
                        if let Some(v) = regs[si].as_concrete() {
                            regs[di] = RegVal::Addr(v.wrapping_add(insn.memory_displacement64()));
                            continue;
                        }
                    }
                    regs[di] = RegVal::Top;
                } else {
                    regs[di] = RegVal::Top;
                }
            }
            continue;
        }

        // ---- Direct memory write ----------------------------------------
        //   `mov [base_reg + disp], imm`  or  `mov [base_reg + disp], src_reg`
        //
        // Emit a patch iff base_reg is tracked as Addr/Imm *and* the disp
        // resolves to a known VA *and* the source is known.  Skip writes to
        // the ContextRecord (base == r8) — those are handled by the upstream
        // analyser, not patches to the image.
        if op == Mnemonic::Mov
            && insn.op_count() == 2
            && insn.op_kind(0) == OpKind::Memory
        {
            // Determine target VA.
            let target_va = if insn.is_ip_rel_memory_operand() {
                Some(insn.ip_rel_memory_address())
            } else if insn.memory_base() != Register::None
                && insn.memory_index() == Register::None
            {
                let base_reg = insn.memory_base();
                // Skip writes through r8 / rcx — those are ContextRecord /
                // ExceptionRecord fields, not image bytes.
                if matches!(base_reg, Register::R8 | Register::RCX) { None }
                else if let Some(bi) = reg_idx(base_reg) {
                    regs[bi].as_concrete().map(|v| v.wrapping_add(insn.memory_displacement64()))
                } else { None }
            } else {
                None
            };
            let Some(tva) = target_va else { continue; };

            // Determine value to store and its width.
            let width = insn.memory_size().size();
            if width == 0 || width > 8 { continue; }
            let value: Option<u64> = match insn.op_kind(1) {
                OpKind::Immediate8 | OpKind::Immediate8to16
                | OpKind::Immediate8to32 | OpKind::Immediate8to64 => Some(insn.immediate8() as i8 as i64 as u64),
                OpKind::Immediate16 => Some(insn.immediate16() as u64),
                OpKind::Immediate32 | OpKind::Immediate32to64 => Some(insn.immediate32() as u64),
                OpKind::Immediate64 => Some(insn.immediate64()),
                OpKind::Register => {
                    if let Some(si) = reg_idx(insn.op_register(1)) {
                        regs[si].as_concrete()
                    } else { None }
                }
                _ => None,
            };
            let Some(v) = value else { continue; };
            let mut buf = v.to_le_bytes().to_vec();
            buf.truncate(width);
            if patch_set.insert((tva, buf.clone())) {
                patches.push(ImagePatch { target_va: tva, bytes: buf, handler_va });
            }
            continue;
        }

        // ---- REP MOVSB / MOVSQ ------------------------------------------
        //   rep movsb  ; dst=rdi, src=rsi, count=rcx
        //   rep movsq  ; count in qwords
        // If all three are tracked as concrete addresses/immediates, read
        // `count` bytes from `src` and emit a patch at `dst`.
        if insn.has_rep_prefix() && matches!(op, Mnemonic::Movsb | Mnemonic::Movsq | Mnemonic::Movsd) {
            let rdi = regs[reg_idx(Register::RDI).unwrap()].as_concrete();
            let rsi = regs[reg_idx(Register::RSI).unwrap()].as_concrete();
            let rcx = regs[reg_idx(Register::RCX).unwrap()].as_concrete();
            if let (Some(dst), Some(src), Some(cnt)) = (rdi, rsi, rcx) {
                let unit = match op { Mnemonic::Movsb => 1, Mnemonic::Movsd => 4, Mnemonic::Movsq => 8, _ => 1 };
                let total = (cnt as usize).saturating_mul(unit);
                // Guard against absurd sizes from stale register tracking.
                if total > 0 && total <= 0x10000 {
                    if let Some(body) = read_bytes(src, total) {
                        if patch_set.insert((dst, body.clone())) {
                            patches.push(ImagePatch { target_va: dst, bytes: body, handler_va });
                        }
                    }
                }
            }
            // After rep, count is consumed; be conservative and invalidate.
            regs[reg_idx(Register::RCX).unwrap()] = RegVal::Top;
            regs[reg_idx(Register::RDI).unwrap()] = RegVal::Top;
            regs[reg_idx(Register::RSI).unwrap()] = RegVal::Top;
            continue;
        }

        // Any other instruction that writes to a general-purpose register
        // clears our tracking for that register.
        if insn.op_count() >= 1 && insn.op_kind(0) == OpKind::Register {
            if let Some(di) = reg_idx(insn.op_register(0)) {
                regs[di] = RegVal::Top;
            }
        }
        } // inner `while dec.can_decode()`
    } // outer 'outer worklist loop

    patches
}

/// Convenience: extract patches from every handler in `image` and flatten
/// into a single list.  Caller may group / apply / diff.
pub fn extract_all_patches(image: &[u8]) -> Vec<ImagePatch> {
    let records = parse_pe64_seh(image);
    let mut seen: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    let mut out: Vec<ImagePatch> = Vec::new();
    for r in &records {
        if let Some(h) = r.handler {
            if seen.insert(h) {
                out.extend(extract_handler_patches(image, h));
            }
        }
    }
    out
}

/// Result of running the SMC-fixpoint loop.
#[derive(Debug, Clone)]
pub struct FixpointResult {
    /// The patched image (a clone of the input, mutated).
    pub image: Vec<u8>,
    /// Every patch applied, in the order it first appeared. Deduplicated by
    /// (target_va, bytes).
    pub patches: Vec<ImagePatch>,
    /// Function start VAs that became visible only after patches were
    /// applied.  Union over all iterations; deduplicated.  Callers can feed
    /// this straight into their function symbol table.
    pub newly_discovered_fns: Vec<u64>,
    /// Iterations executed before a fixpoint (or `max_iters`) was reached.
    pub iterations: usize,
    /// True when the loop terminated because no new patches and no new
    /// discovered functions were produced by the last iteration.
    pub converged: bool,
}

/// Iterate "extract patches → apply → re-enumerate" until nothing new
/// appears or `max_iters` is hit.  This is the backbone of SMC-aware static
/// lifting: each round may uncover handlers that only exist after a
/// previous round's patch reveals their prologue, register them as
/// discoverable functions, and generate further patches of their own.
///
/// The loop is bounded in two ways:
///   * a hard iteration cap (default 16 via `smc_fixpoint`);
///   * a convergence test on (patches, discovered_fns) — if neither set
///     grew, the current image is a fixpoint with respect to the static
///     SEH pipeline.
///
/// `discover_fn` is a callback that re-runs function discovery on a
/// (possibly mutated) image and returns the set of function VAs it found.
/// The seh_static crate does not want to depend on rsleigh-cli's discovery
/// code, so the caller supplies it.  A minimal implementation is:
///
/// ```ignore
/// |bytes| {
///     // whatever rsleigh-cli does under the hood
///     ::rsleigh_cli::discover_all(bytes)
/// }
/// ```
///
/// For tests or simple callers that only care about SEH-derived functions,
/// use [`smc_fixpoint_seh_only`] which re-enumerates SEH handlers +
/// scope-table addresses at every step.
pub fn smc_fixpoint<F>(
    image: &[u8],
    max_iters: usize,
    mut discover_fn: F,
) -> FixpointResult
where
    F: FnMut(&[u8]) -> Vec<u64>,
{
    let mut working = image.to_vec();
    let mut applied: Vec<ImagePatch> = Vec::new();
    let mut applied_set: std::collections::HashSet<(u64, Vec<u8>)> = std::collections::HashSet::new();
    let mut discovered: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    // Seed discovery with pre-patch function set so we report deltas only.
    let baseline: std::collections::BTreeSet<u64> = discover_fn(&working).into_iter().collect();

    let mut iter = 0usize;
    let converged = loop {
        if iter >= max_iters { break false; }
        iter += 1;

        // 1. Extract patches from the current image.
        let fresh = extract_all_patches(&working);
        let mut new_this_round: Vec<ImagePatch> = Vec::new();
        for p in fresh {
            let key = (p.target_va, p.bytes.clone());
            if applied_set.insert(key) {
                new_this_round.push(p);
            }
        }

        // 2. Apply them (if any).
        let applied_count = if new_this_round.is_empty() {
            0
        } else {
            let n = apply_patches(&mut working, &new_this_round);
            applied.extend(new_this_round.into_iter());
            n
        };

        // 3. Re-run discovery on the (possibly patched) image.
        let now: std::collections::BTreeSet<u64> = discover_fn(&working).into_iter().collect();
        let prev_size = discovered.len();
        for va in now.difference(&baseline) {
            discovered.insert(*va);
        }
        let discovered_grew = discovered.len() > prev_size;

        // 4. Convergence check.
        if applied_count == 0 && !discovered_grew {
            break true;
        }
    };

    FixpointResult {
        image: working,
        patches: applied,
        newly_discovered_fns: discovered.into_iter().collect(),
        iterations: iter,
        converged,
    }
}

/// Convenience wrapper that re-enumerates only the SEH-surface functions
/// at each step (handlers + scope table entries).  Suitable for tests and
/// callers that do not have access to the full rsleigh-cli discovery
/// pipeline.
pub fn smc_fixpoint_seh_only(image: &[u8], max_iters: usize) -> FixpointResult {
    smc_fixpoint(image, max_iters, |img| {
        let mut v = handler_addresses(&parse_pe64_seh(img));
        v.extend(scope_table_addresses(img));
        v.sort_unstable();
        v.dedup();
        v
    })
}

/// Apply `patches` to a mutable in-memory image representation.  The `image`
/// slice here is the *raw* PE bytes (file image).  Returns the number of
/// patches successfully written.
///
/// Out-of-bounds patches are silently skipped (they would indicate a bug in
/// the extractor or a handler whose target lies outside the shipped file).
pub fn apply_patches(image: &mut [u8], patches: &[ImagePatch]) -> usize {
    let obj = match goblin::Object::parse(image) { Ok(o) => o, _ => return 0 };
    let pe = match obj { goblin::Object::PE(p) => p, _ => return 0 };
    if !pe.is_64 { return 0; }
    let base = pe.image_base as u64;
    // Snapshot the section table to a local vec so we can release the borrow
    // before mutating.
    let secs: Vec<(u64, u64, usize, usize)> = pe.sections.iter().map(|s| (
        base + s.virtual_address as u64,
        s.virtual_size as u64,
        s.pointer_to_raw_data as usize,
        s.size_of_raw_data as usize,
    )).collect();
    drop(pe);

    let mut n = 0usize;
    for p in patches {
        let Some((va, vsz, fo, fsz)) = secs.iter()
            .find(|(va, vsz, _, _)| p.target_va >= *va && p.target_va < va + vsz)
            .copied()
        else { continue };
        let in_section = (p.target_va - va) as usize;
        if in_section >= fsz { continue; }
        let end = in_section + p.bytes.len();
        if end > fsz || fo + end > image.len() { continue; }
        image[fo + in_section .. fo + end].copy_from_slice(&p.bytes);
        n += 1;
        let _ = vsz; // silence unused warning
    }
    n
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
    fn crackmev3_fixpoint_converges_with_zero_patches() {
        // crackmev3 v4 has zero SMC. The fixpoint loop must converge on
        // the first iteration: no patches, no new functions from re-enum.
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let fixture  = manifest.parent().unwrap()
            .join("test-harness/fixtures/crackmev3.pyd");
        if !fixture.exists() {
            eprintln!("skipping: crackmev3.pyd not staged");
            return;
        }
        let bytes = std::fs::read(&fixture).unwrap();
        let r = smc_fixpoint_seh_only(&bytes, 16);
        assert!(r.converged, "expected convergence on a no-SMC fixture");
        assert_eq!(r.patches.len(), 0);
        assert_eq!(r.newly_discovered_fns.len(), 0);
        assert_eq!(r.iterations, 1);
        assert_eq!(r.image, bytes, "image must be unchanged");
    }

    #[test]
    fn fixpoint_stops_at_max_iters() {
        // Pathological discover_fn that always claims to find a new fn.
        // Fixpoint should bail at max_iters and report converged=false.
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let fixture  = manifest.parent().unwrap()
            .join("test-harness/fixtures/crackmev3.pyd");
        if !fixture.exists() {
            eprintln!("skipping: crackmev3.pyd not staged");
            return;
        }
        let bytes = std::fs::read(&fixture).unwrap();
        let mut counter = 0u64;
        let r = smc_fixpoint(&bytes, 4, |_| {
            counter = counter.wrapping_add(1);
            // Always return a brand-new VA to force non-convergence.
            vec![0x180_0000_0000 + counter]
        });
        assert!(!r.converged, "expected non-convergence under adversarial oracle");
        assert_eq!(r.iterations, 4);
        assert!(r.newly_discovered_fns.len() >= 4);
    }

    #[test]
    fn crackmev3_scope_tables_parse() {
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let fixture  = manifest.parent().unwrap()
            .join("test-harness/fixtures/crackmev3.pyd");
        if !fixture.exists() {
            eprintln!("skipping: crackmev3.pyd not staged");
            return;
        }
        let bytes = std::fs::read(&fixture).unwrap();
        // crackmev3 has 112 EH records — plenty of C_specific_handler scope
        // tables to parse.  Total scope-table-derived addresses should be
        // non-zero and all addresses should fall inside the image.
        let extra = scope_table_addresses(&bytes);
        assert!(!extra.is_empty(),
            "expected at least one scope-table-derived address");
        for a in &extra {
            assert!(*a >= 0x180000000 && *a < 0x181000000,
                "scope address {:#x} out of image range", a);
        }
    }

    #[test]
    fn crackmev3_no_patches_from_handlers() {
        // v4 of the crackme uses inline PCG decryption, not SEH-driven SMC.
        // The patch extractor must therefore produce zero patches from any
        // registered handler.  Catching a spurious patch here would be a
        // false positive from the abstract interpreter.
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let fixture  = manifest.parent().unwrap()
            .join("test-harness/fixtures/crackmev3.pyd");
        if !fixture.exists() {
            eprintln!("skipping: crackmev3.pyd not staged");
            return;
        }
        let bytes = std::fs::read(&fixture).unwrap();
        let patches = extract_all_patches(&bytes);
        assert!(patches.is_empty(),
            "expected zero patches on crackmev3 v4, got {} (first: {:?})",
            patches.len(), patches.first());
    }

    // Assemble a tiny x86-64 sequence that writes two concrete bytes at a
    // tracked absolute address and then returns.  The abstract interpreter
    // should recover both writes as a single contiguous patch (or two
    // adjacent patches) without needing a full PE around it.
    //
    // We exercise the decoder-level guts by driving iced directly, the same
    // way `extract_handler_patches` does, so the test is independent of
    // `goblin` / `.pdata` plumbing.
    fn abstract_patches_from(bytes: &[u8]) -> Vec<ImagePatch> {
        use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind, Register};
        let mut regs: [RegVal; 16] = [RegVal::Top; 16];
        let mut patches: Vec<ImagePatch> = Vec::new();
        let reg_idx = |r: Register| -> Option<usize> {
            match r {
                Register::RAX=>Some(0), Register::RCX=>Some(1),
                Register::RDX=>Some(2), Register::RBX=>Some(3),
                Register::RSP=>Some(4), Register::RBP=>Some(5),
                Register::RSI=>Some(6), Register::RDI=>Some(7),
                Register::R8=>Some(8),  Register::R9=>Some(9),
                Register::R10=>Some(10),Register::R11=>Some(11),
                Register::R12=>Some(12),Register::R13=>Some(13),
                Register::R14=>Some(14),Register::R15=>Some(15),
                _ => None,
            }
        };
        let mut dec = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
        let mut insn = iced_x86::Instruction::default();
        while dec.can_decode() {
            dec.decode_out(&mut insn);
            let op = insn.mnemonic();
            if matches!(op, Mnemonic::Ret | Mnemonic::Ud2 | Mnemonic::Int3) { break; }
            if op == Mnemonic::Mov && insn.op_count()==2 && insn.op_kind(0)==OpKind::Register {
                let Some(di) = reg_idx(insn.op_register(0)) else { continue; };
                regs[di] = match insn.op_kind(1) {
                    OpKind::Immediate64 => RegVal::Imm(insn.immediate64()),
                    OpKind::Immediate32to64 => RegVal::Imm(insn.immediate64()),
                    OpKind::Register => reg_idx(insn.op_register(1))
                        .map(|i| regs[i]).unwrap_or(RegVal::Top),
                    _ => RegVal::Top,
                };
            }
            if op == Mnemonic::Mov && insn.op_count()==2 && insn.op_kind(0)==OpKind::Memory {
                let base = insn.memory_base();
                if !matches!(base, Register::R8 | Register::RCX) {
                    let tva = reg_idx(base).and_then(|i| regs[i].as_concrete())
                        .map(|v| v.wrapping_add(insn.memory_displacement64()));
                    if let Some(tva) = tva {
                        let width = insn.memory_size().size();
                        let v: Option<u64> = match insn.op_kind(1) {
                            OpKind::Immediate8 | OpKind::Immediate8to64 =>
                                Some(insn.immediate8() as u64),
                            OpKind::Immediate32 | OpKind::Immediate32to64 =>
                                Some(insn.immediate32() as u64),
                            OpKind::Immediate64 => Some(insn.immediate64()),
                            OpKind::Register => reg_idx(insn.op_register(1))
                                .and_then(|i| regs[i].as_concrete()),
                            _ => None,
                        };
                        if let Some(v) = v {
                            let mut buf = v.to_le_bytes().to_vec();
                            buf.truncate(width);
                            patches.push(ImagePatch { target_va: tva, bytes: buf, handler_va: 0 });
                        }
                    }
                }
            }
        }
        patches
    }

    #[test]
    fn abstract_interpreter_recovers_two_byte_patches() {
        // mov rax, 0x400000
        // mov byte [rax + 0x10], 0x90
        // mov byte [rax + 0x11], 0x90
        // ret
        let bytes = [
            0x48, 0xB8, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64
            0xC6, 0x40, 0x10, 0x90,                                     // mov byte [rax+0x10], 0x90
            0xC6, 0x40, 0x11, 0x90,                                     // mov byte [rax+0x11], 0x90
            0xC3,                                                        // ret
        ];
        let patches = abstract_patches_from(&bytes);
        assert_eq!(patches.len(), 2);
        assert_eq!(patches[0].target_va, 0x00400010);
        assert_eq!(patches[0].bytes, vec![0x90]);
        assert_eq!(patches[1].target_va, 0x00400011);
        assert_eq!(patches[1].bytes, vec![0x90]);
    }

    #[test]
    fn control_flow_interp_explores_both_branches() {
        // Hand-assembled sequence that writes two different single-byte
        // patches on either side of a conditional branch:
        //
        //   handler:
        //     mov rax, 0x400000                 ; tracked
        //     cmp dword ptr [rcx], 0x80000003   ; ExceptionCode == BREAKPOINT?
        //     je  .then
        //     mov byte ptr [rax + 0x10], 0x90   ; patch on !je path
        //     ret
        //   .then:
        //     mov byte ptr [rax + 0x20], 0xcc   ; patch on je path
        //     ret
        //
        // Control-flow aware interp must recover BOTH writes as patches.
        let bytes: [u8; 0x20] = [
            // 0x00: 48 B8 00 00 40 00 00 00 00 00      mov rax, 0x400000
            0x48, 0xB8, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
            // 0x0A: 81 39 03 00 00 80                  cmp dword [rcx], 0x80000003
            0x81, 0x39, 0x03, 0x00, 0x00, 0x80,
            // 0x10: 74 06                              je +6
            0x74, 0x06,
            // 0x12: C6 40 10 90                        mov byte [rax+0x10], 0x90
            0xC6, 0x40, 0x10, 0x90,
            // 0x16: C3                                 ret
            0xC3,
            // 0x17: 90                                 nop (padding before target)
            0x90,
            // 0x18: C6 40 20 CC                        mov byte [rax+0x20], 0xCC
            0xC6, 0x40, 0x20, 0xCC,
            // 0x1C: C3                                 ret
            0xC3,
            // 0x1D..0x1F: padding
            0x90, 0x90, 0x90,
        ];
        let patches = cf_abstract_patches_from(&bytes);
        assert_eq!(patches.len(), 2, "both branches should yield a patch: {:?}", patches);
        let tvas: std::collections::BTreeSet<u64> = patches.iter().map(|p| p.target_va).collect();
        assert_eq!(tvas, vec![0x00400010, 0x00400020].into_iter().collect());
    }

    /// Control-flow-aware mini-interpreter used by the test above.  Keeps
    /// the test decoupled from `goblin` / `.pdata` plumbing while exercising
    /// the same worklist shape as `extract_handler_patches`.
    fn cf_abstract_patches_from(bytes: &[u8]) -> Vec<ImagePatch> {
        use iced_x86::{Decoder, DecoderOptions, FlowControl, Mnemonic, OpKind, Register};
        fn merge(a: [RegVal; 16], b: [RegVal; 16]) -> [RegVal; 16] {
            let mut out = [RegVal::Top; 16];
            for i in 0..16 {
                out[i] = if a[i] == b[i] { a[i] } else { RegVal::Top };
            }
            out
        }
        let reg_idx = |r: Register| -> Option<usize> {
            match r {
                Register::RAX=>Some(0), Register::RCX=>Some(1),
                Register::RDX=>Some(2), Register::RBX=>Some(3),
                Register::RSP=>Some(4), Register::RBP=>Some(5),
                Register::RSI=>Some(6), Register::RDI=>Some(7),
                Register::R8=>Some(8),  Register::R9=>Some(9),
                Register::R10=>Some(10),Register::R11=>Some(11),
                Register::R12=>Some(12),Register::R13=>Some(13),
                Register::R14=>Some(14),Register::R15=>Some(15),
                _ => None,
            }
        };
        let start_va = 0x1000u64;
        let mut worklist: Vec<(u64, [RegVal; 16])> = vec![(start_va, [RegVal::Top; 16])];
        let mut visited: std::collections::HashMap<u64, [RegVal; 16]> = std::collections::HashMap::new();
        let mut patches: Vec<ImagePatch> = Vec::new();
        let mut patch_set: std::collections::HashSet<(u64, Vec<u8>)> = std::collections::HashSet::new();

        while let Some((pc, mut regs)) = worklist.pop() {
            if let Some(prev) = visited.get(&pc) {
                let m = merge(*prev, regs);
                if m == *prev { continue; }
                visited.insert(pc, m);
                regs = m;
            } else { visited.insert(pc, regs); }
            let off = (pc - start_va) as usize;
            if off >= bytes.len() { continue; }
            let mut dec = Decoder::with_ip(64, &bytes[off..], pc, DecoderOptions::NONE);
            let mut insn = iced_x86::Instruction::default();
            while dec.can_decode() {
                dec.decode_out(&mut insn);
                let op = insn.mnemonic();
                if matches!(op, Mnemonic::Ret | Mnemonic::Ud2 | Mnemonic::Int3) { break; }
                match insn.flow_control() {
                    FlowControl::UnconditionalBranch => {
                        if insn.op_count()==1 && insn.op_kind(0)==OpKind::NearBranch64 {
                            worklist.push((insn.near_branch64(), regs));
                        }
                        break;
                    }
                    FlowControl::ConditionalBranch => {
                        if insn.op_count()==1 && insn.op_kind(0)==OpKind::NearBranch64 {
                            worklist.push((insn.near_branch64(), regs));
                        }
                    }
                    FlowControl::IndirectBranch => break,
                    _ => {}
                }
                if op == Mnemonic::Mov && insn.op_count()==2 && insn.op_kind(0)==OpKind::Register {
                    let Some(di) = reg_idx(insn.op_register(0)) else { continue; };
                    regs[di] = match insn.op_kind(1) {
                        OpKind::Immediate64 => RegVal::Imm(insn.immediate64()),
                        OpKind::Immediate32to64 => RegVal::Imm(insn.immediate64()),
                        OpKind::Register => reg_idx(insn.op_register(1))
                            .map(|i| regs[i]).unwrap_or(RegVal::Top),
                        _ => RegVal::Top,
                    };
                }
                if op == Mnemonic::Mov && insn.op_count()==2 && insn.op_kind(0)==OpKind::Memory {
                    let base = insn.memory_base();
                    if !matches!(base, Register::R8 | Register::RCX) {
                        let tva = reg_idx(base).and_then(|i| regs[i].as_concrete())
                            .map(|v| v.wrapping_add(insn.memory_displacement64()));
                        if let Some(tva) = tva {
                            let width = insn.memory_size().size();
                            let v: Option<u64> = match insn.op_kind(1) {
                                OpKind::Immediate8 | OpKind::Immediate8to64 =>
                                    Some(insn.immediate8() as u64),
                                OpKind::Immediate32 | OpKind::Immediate32to64 =>
                                    Some(insn.immediate32() as u64),
                                OpKind::Immediate64 => Some(insn.immediate64()),
                                OpKind::Register => reg_idx(insn.op_register(1))
                                    .and_then(|i| regs[i].as_concrete()),
                                _ => None,
                            };
                            if let Some(v) = v {
                                let mut buf = v.to_le_bytes().to_vec();
                                buf.truncate(width);
                                if patch_set.insert((tva, buf.clone())) {
                                    patches.push(ImagePatch { target_va: tva, bytes: buf, handler_va: 0 });
                                }
                            }
                        }
                    }
                }
            }
        }
        patches
    }

    #[test]
    fn apply_patches_oob_is_noop() {
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let fixture  = manifest.parent().unwrap()
            .join("test-harness/fixtures/crackmev3.pyd");
        if !fixture.exists() {
            eprintln!("skipping: crackmev3.pyd not staged");
            return;
        }
        let mut bytes = std::fs::read(&fixture).unwrap();
        let bogus = vec![
            ImagePatch { target_va: 0xDEADBEEF_00000000, bytes: vec![0u8; 4], handler_va: 0 },
            ImagePatch { target_va: 0,                   bytes: vec![0u8; 4], handler_va: 0 },
        ];
        let n = apply_patches(&mut bytes, &bogus);
        assert_eq!(n, 0, "out-of-bounds patches should be ignored");
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
