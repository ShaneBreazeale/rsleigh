use std::collections::HashMap;

/// Build a map of address → import function name from a binary.
pub fn resolve_imports(binary: &[u8]) -> HashMap<u64, String> {
    let mut map = HashMap::new();
    let Ok(obj) = goblin::Object::parse(binary) else { return map };

    match &obj {
        goblin::Object::Elf(elf) => resolve_elf(elf, &mut map),
        goblin::Object::Mach(goblin::mach::Mach::Binary(macho)) => {
            resolve_macho(macho, binary, &mut map);
        }
        goblin::Object::PE(pe) => resolve_pe(pe, &mut map),
        _ => {
        }
    }

    map
}

fn resolve_elf(elf: &goblin::elf::Elf, map: &mut HashMap<u64, String>) {
    // Dynamic imports
    for sym in elf.dynsyms.iter() {
        if sym.is_import() && sym.st_value != 0 {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                if !name.is_empty() { map.insert(sym.st_value, name.to_string()); }
            }
        }
    }
    // PLT relocations → stub addresses
    for reloc in elf.pltrelocs.iter() {
        if let Some(sym) = elf.dynsyms.get(reloc.r_sym) {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                if !name.is_empty() { map.insert(reloc.r_offset, name.to_string()); }
            }
        }
    }
    // Named functions from .symtab
    for sym in elf.syms.iter() {
        if sym.st_type() == goblin::elf::sym::STT_FUNC && sym.st_value != 0 {
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                if !name.is_empty() && !name.starts_with("FUN_") {
                    map.insert(sym.st_value, name.to_string());
                }
            }
        }
    }
}

fn resolve_macho(macho: &goblin::mach::MachO, binary: &[u8], map: &mut HashMap<u64, String>) {
    // Collect named symbols
    for sym in macho.symbols() {
        if let Ok((name, nlist)) = sym {
            if nlist.n_type & 0x0e == 0x0e && nlist.n_value != 0 {
                let clean = name.strip_prefix('_').unwrap_or(name);
                if !clean.is_empty() {
                    map.insert(nlist.n_value, clean.to_string());
                }
            }
        }
    }

    // Resolve __stubs → import names via indirect symbol table.
    // Each stub is a JMP [rip+offset] (x86) or BR (arm64) to a GOT entry.
    // The GOT entries are mapped to symbols via the indirect symbol table.
    // Build GOT address → symbol name map first, then resolve stubs through it.
    let _got_to_name: HashMap<u64, String> = HashMap::new();

    // Parse indirect symbol table entries for __got section
    // The indirect symbols array (from LC_DYSYMTAB) + section's reserved1 field
    // gives us the mapping. Since goblin doesn't expose reserved1, we parse
    // the __got section's indirect entries by position.
    // Alternative: read the Mach-O load commands directly for the indirect table.

    // Simpler approach: use undefined symbols. Each undefined external symbol
    // corresponds to an import. We can match stub JMP targets to GOT entries,
    // and GOT entries to symbols by their order in the indirect symbol table.
    // Since otool -Iv shows this mapping, we reconstruct it:

    // 1. Find all undefined external symbols (imports)
    // These have n_value == 0 and n_type indicates undefined
    let mut undef_syms: Vec<(usize, String)> = Vec::new();
    for (idx, sym_result) in macho.symbols().enumerate() {
        if let Ok((name, nlist)) = sym_result {
            // Undefined symbols: value is 0 and not in any section
            let is_undefined = nlist.n_value == 0 && (nlist.n_type & 0x0e) == 0;
            if is_undefined && !name.is_empty() {
                let clean = name.strip_prefix('_').unwrap_or(name);
                undef_syms.push((idx, clean.to_string()));
            }
        }
    }

    // 2. Find __stubs and __got sections and their stub/GOT entry sizes
    let mut stubs_addr = 0u64;
    let mut stubs_size = 0u64;
    let mut stubs_fo = 0u64;
    let mut got_addr = 0u64;
    let mut got_size = 0u64;

    for seg in &macho.segments {
        for (sect, _data) in seg.sections().unwrap_or_default() {
            let name = std::str::from_utf8(&sect.sectname).unwrap_or("").trim_end_matches('\0');
            match name {
                "__stubs" => {
                    stubs_addr = sect.addr;
                    stubs_size = sect.size;
                    stubs_fo = sect.offset as u64;
                }
                "__got" => {
                    got_addr = sect.addr;
                    got_size = sect.size;
                }
                _ => {}
            }
        }
    }

    if stubs_addr == 0 || got_addr == 0 { return; }

    // 3. Determine stub entry size from architecture:
    //    x86-64: 6 bytes (FF 25 disp32)
    //    AArch64: 12 bytes (ADRP+LDR+BR)
    let stub_size = if stubs_size > 0 && stubs_fo as usize + 2 <= binary.len() {
        let off = stubs_fo as usize;
        if binary[off] == 0xff && binary[off + 1] == 0x25 {
            6u64 // x86-64 JMP [rip+disp32]
        } else {
            12u64 // AArch64 ADRP+LDR+BR
        }
    } else { 6 };

    let n_stubs = if stub_size > 0 { stubs_size / stub_size } else { 0 };

    // 4. For each stub, decode the JMP target to find which GOT entry it uses
    let mut stub_to_got: Vec<(u64, u64)> = Vec::new();
    for i in 0..n_stubs {
        let stub_va = stubs_addr + i * stub_size;
        let file_off = (stubs_fo + i * stub_size) as usize;

        if stub_size == 6 && file_off + 6 <= binary.len() {
            // x86-64: FF 25 disp32
            if binary[file_off] == 0xff && binary[file_off + 1] == 0x25 {
                let disp = i32::from_le_bytes([
                    binary[file_off + 2], binary[file_off + 3],
                    binary[file_off + 4], binary[file_off + 5],
                ]);
                let got_entry = (stub_va + 6).wrapping_add(disp as u64);
                stub_to_got.push((stub_va, got_entry));
            }
        } else if stub_size == 12 && file_off + 12 <= binary.len() {
            // AArch64: ADRP+LDR+BR — GOT entry is computed from ADRP page + LDR offset
            // For simplicity, map by position: stub i → GOT entry i
            let got_entry = got_addr + i * 8;
            stub_to_got.push((stub_va, got_entry));
        }
    }

    // 5. Map stubs to import names via GOT index.
    // Each stub jumps to a GOT entry. The GOT entries are in the same order as
    // the undefined symbols. GOT entry i → undef_syms[i].
    for (stub_va, got_entry) in &stub_to_got {
        if *got_entry >= got_addr && *got_entry < got_addr + got_size {
            let got_idx = ((*got_entry - got_addr) / 8) as usize;
            // The GOT entry at index `got_idx` corresponds to undef_syms[got_idx]
            if got_idx < undef_syms.len() {
                let name = &undef_syms[got_idx].1;
                if !name.is_empty() {
                    map.insert(*stub_va, name.clone());
                }
            }
        }
    }
}

fn resolve_pe(pe: &goblin::pe::PE, map: &mut HashMap<u64, String>) {
    for import in pe.imports.iter() {
        if import.rva != 0 {
            let addr = import.rva as u64 + pe.image_base as u64;
            map.insert(addr, import.name.to_string());
        }
    }
    for export in pe.exports.iter() {
        if let Some(name) = export.name {
            if export.rva != 0 {
                let addr = export.rva as u64 + pe.image_base as u64;
                map.insert(addr, name.to_string());
            }
        }
    }
}
