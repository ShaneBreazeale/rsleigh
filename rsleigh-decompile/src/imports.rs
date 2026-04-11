use std::collections::HashMap;

/// Demangle a C++ symbol name if applicable, returning a simplified form.
fn demangle_name(name: &str) -> String {
    // Strip @@ version suffix first
    let clean = name.split("@@").next().unwrap_or(name);
    // Strip __chk suffix (e.g., __strcpy_chk → strcpy)
    let clean = if clean.starts_with("__") && clean.ends_with("_chk") {
        &clean[2..clean.len()-4]
    } else { clean };
    let clean = clean.to_string();
    // Try C++ demangling
    if let Ok(sym) = cpp_demangle::Symbol::new(name.as_bytes()) {
        let Ok(demangled) = sym.demangle() else { return clean; };
        // Strip parameter list: "func(int, char*)" → "func"
        // But keep the full name for overloaded operators
        let simplified = simplify_cpp_name(&demangled);
        // Strip trailing parameter list for cleaner call display.
        // "phttp::Initialize()" → "phttp::Initialize"
        // "operator new(unsigned long)" → "operator new" (keep operator name)
        // "signal_handler(int)" → "signal_handler"
        if let Some(paren) = simplified.find('(') {
            let before = &simplified[..paren];
            // Keep the part before the first '(' as the function name
            if !before.is_empty() && !before.ends_with('>') {
                return before.to_string();
            }
        }
        simplified
    } else {
        clean
    }
}

/// Simplify demangled C++ names for readability.
fn simplify_cpp_name(name: &str) -> String {
    // std::operator<<(std::basic_ostream<char, ...>&, char const*)
    // → cout << (just show the operator)
    if name.contains("operator<<") && name.contains("basic_ostream") && name.contains("char const*") {
        return "cout_write".to_string();
    }
    if name.contains("operator<<") && name.contains("basic_ostream") {
        return "cout_write".to_string();
    }
    if name.contains("operator>>") && name.contains("basic_istream") {
        return "cin_read".to_string();
    }
    // std::basic_string<char, ...>::basic_string(...) → string()
    if name.contains("basic_string") && name.contains("::basic_string") {
        return "string_ctor".to_string();
    }
    if name.contains("basic_string") && name.contains("::~basic_string") {
        return "string_dtor".to_string();
    }
    // std::basic_ifstream<char, ...>::basic_ifstream(...) → ifstream()
    if name.contains("basic_ifstream") && name.contains("::basic_ifstream") {
        return "ifstream_ctor".to_string();
    }
    // std::allocator<char>::allocator() → alloc_ctor
    if name.contains("allocator") && name.contains("::allocator") {
        return "alloc_ctor".to_string();
    }
    if name.contains("allocator") && name.contains("::~allocator") {
        return "alloc_dtor".to_string();
    }
    // For other C++ names, strip std:: prefix and template args
    let mut s = name.replace("std::", "");
    // Remove template parameters for readability
    while let Some(start) = s.find('<') {
        if let Some(end) = find_matching_angle(&s, start) {
            s = format!("{}{}", &s[..start], &s[end + 1..]);
        } else {
            break;
        }
    }
    // Clean up whitespace
    s = s.replace("  ", " ").trim().to_string();
    if s.len() > 60 { s.truncate(60); }
    s
}

fn find_matching_angle(s: &str, start: usize) -> Option<usize> {
    let mut depth = 0;
    for (i, c) in s[start..].char_indices() {
        if c == '<' { depth += 1; }
        if c == '>' { depth -= 1; if depth == 0 { return Some(start + i); } }
    }
    None
}

/// Build a map of address → import function name from a binary.
pub fn resolve_imports(binary: &[u8]) -> HashMap<u64, String> {
    let mut map = HashMap::new();
    let Ok(obj) = goblin::Object::parse(binary) else {
        // Fallback: try manual PE import parsing for malformed binaries
        if binary.len() > 0x40 && &binary[0..2] == b"MZ" {
            resolve_pe_manual(binary, &mut map);
        }
        return map;
    };

    match &obj {
        goblin::Object::Elf(elf) => resolve_elf(elf, binary, &mut map),
        goblin::Object::Mach(goblin::mach::Mach::Binary(macho)) => {
            resolve_macho(macho, binary, &mut map);
        }
        goblin::Object::PE(pe) => resolve_pe(pe, binary, &mut map),
        _ => {
        }
    }

    map
}

fn resolve_elf(elf: &goblin::elf::Elf, binary: &[u8], map: &mut HashMap<u64, String>) {
    // Build GOT address → symbol name map from PLT relocations
    let mut got_to_name: HashMap<u64, String> = HashMap::new();
    for reloc in elf.pltrelocs.iter() {
        if let Some(sym) = elf.dynsyms.get(reloc.r_sym) {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                if !name.is_empty() {
                    let clean = demangle_name(name);
                    got_to_name.insert(reloc.r_offset, clean.clone());
                    map.insert(reloc.r_offset, clean);
                }
            }
        }
    }

    // Find .plt section and map PLT stub addresses to names
    // Each PLT entry is typically 16 bytes (x86-64): jmp [GOT]; push idx; jmp resolver
    for sh in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
        if name == ".plt" || name == ".plt.got" || name == ".plt.sec" {
            let entry_size = if sh.sh_entsize > 0 { sh.sh_entsize } else { 16 };
            let plt_start = sh.sh_addr;
            let n_entries = sh.sh_size / entry_size;
            let file_off = sh.sh_offset as usize;

            // Skip the first entry (PLT[0] is the resolver stub)
            for i in 1..n_entries.min(10000) { // cap at 10K entries for safety
                let Some(stub_addr) = plt_start.checked_add(i.checked_mul(entry_size).unwrap_or(u64::MAX)) else { break; };
                let Some(off) = file_off.checked_add((i * entry_size) as usize) else { break; };

                // Decode the JMP [addr] at the start of the PLT entry
                if off + 6 <= binary.len() && binary[off] == 0xff && binary[off + 1] == 0x25 {
                    let raw_addr = u32::from_le_bytes([
                        binary[off + 2], binary[off + 3],
                        binary[off + 4], binary[off + 5],
                    ]);
                    // 64-bit: RIP-relative (signed displacement from next instruction)
                    // 32-bit: absolute GOT address
                    let is_64bit = elf.header.e_machine == 0x3E; // EM_X86_64
                    let got_entry = if is_64bit {
                        (stub_addr + 6).wrapping_add(raw_addr as i32 as i64 as u64)
                    } else {
                        raw_addr as u64 // absolute address for 32-bit
                    };
                    if let Some(name) = got_to_name.get(&got_entry) {
                        map.insert(stub_addr, name.clone());
                    }
                }
                // Also try: indirect JMP via endbr64 prefix (CET-enabled PLT)
                // endbr64 = F3 0F 1E FA, then BND JMP *[rip+disp32] = F2 FF 25 disp32
                // or without BND: FF 25 disp32
                else if off + 4 <= binary.len()
                    && binary[off] == 0xf3 && binary[off + 1] == 0x0f
                    && binary[off + 2] == 0x1e && binary[off + 3] == 0xfa
                {
                    // After endbr64 (4 bytes), check for:
                    // FF 25 disp32 (plain jmp *[rip+disp])
                    // F2 FF 25 disp32 (bnd jmp *[rip+disp])
                    let jmp_off = off + 4;
                    let (disp_off, rip_len) = if jmp_off + 6 <= binary.len()
                        && binary[jmp_off] == 0xff && binary[jmp_off + 1] == 0x25
                    {
                        (jmp_off + 2, 6u64) // plain jmp: 6 bytes from endbr64+jmp to next
                    } else if jmp_off + 7 <= binary.len()
                        && binary[jmp_off] == 0xf2 && binary[jmp_off + 1] == 0xff
                        && binary[jmp_off + 2] == 0x25
                    {
                        (jmp_off + 3, 7u64) // bnd jmp: 7 bytes from jmp start
                    } else {
                        continue;
                    };
                    let disp = i32::from_le_bytes([
                        binary[disp_off], binary[disp_off + 1],
                        binary[disp_off + 2], binary[disp_off + 3],
                    ]);
                    let got_entry = (stub_addr + 4 + rip_len).wrapping_add(disp as u64);
                    if let Some(name) = got_to_name.get(&got_entry) {
                        map.insert(stub_addr, name.clone());
                    }
                }
            }
        }
    }

    // Dynamic imports (non-PLT) + data object symbols (stdin, stdout, stderr)
    for sym in elf.dynsyms.iter() {
        if sym.st_value != 0 {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                if !name.is_empty() {
                    map.insert(sym.st_value, demangle_name(name));
                }
            }
        }
    }
    // Also map GOT entries for data objects (stdin, stdout, stderr)
    // These are accessed via *(GOT_addr) in the code
    for reloc in &elf.dynrels {
        if let Some(sym) = elf.dynsyms.get(reloc.r_sym) {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                if !name.is_empty() && reloc.r_offset != 0 {
                    map.entry(reloc.r_offset).or_insert_with(|| demangle_name(name));
                }
            }
        }
    }

    // Named functions and global objects from .symtab
    for sym in elf.syms.iter() {
        if (sym.st_type() == goblin::elf::sym::STT_FUNC
            || sym.st_type() == goblin::elf::sym::STT_OBJECT)
            && sym.st_value != 0
        {
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                if !name.is_empty() && !name.starts_with("FUN_") {
                    let clean = name.split("@@").next().unwrap_or(name);
                    // Skip linker-internal symbols that collide with real names
                    if clean == "__TMC_END__" || clean.starts_with("_ITM_")
                        || clean == "_IO_stdin_used" || clean == "completed.0"
                    { continue; }
                    // Don't overwrite existing names from dynsyms (stdin, stdout, etc.)
                    map.entry(sym.st_value).or_insert_with(|| demangle_name(name));
                }
            }
        }
    }
}

fn resolve_macho(macho: &goblin::mach::MachO, binary: &[u8], map: &mut HashMap<u64, String>) {
    // Collect named symbols (defined functions)
    let mut all_symbols: Vec<(String, u64, u8)> = Vec::new();
    for sym in macho.symbols() {
        if let Ok((name, nlist)) = sym {
            let clean = name.strip_prefix('_').unwrap_or(name);
            let demangled = demangle_name(clean);
            all_symbols.push((demangled.clone(), nlist.n_value, nlist.n_type));
            // Defined symbols (type 0x0e = N_SECT)
            if nlist.n_type & 0x0e == 0x0e && nlist.n_value != 0 && !demangled.is_empty() {
                map.insert(nlist.n_value, demangled);
            }
        }
    }

    // Parse indirect symbol table to map stubs → import names.
    // The Mach-O indirect symbol table (from LC_DYSYMTAB) maps each GOT/stub
    // entry to a symbol index in the main symbol table.

    // Find LC_DYSYMTAB: indirect symbol table offset and count
    let mut indirect_symoff = 0u32;
    let mut n_indirect_syms = 0u32;
    for lc in &macho.load_commands {
        if let goblin::mach::load_command::CommandVariant::Dysymtab(dysym) = &lc.command {
            indirect_symoff = dysym.indirectsymoff;
            n_indirect_syms = dysym.nindirectsyms;
            break;
        }
    }

    if indirect_symoff == 0 || n_indirect_syms == 0 { return; }

    // Read the indirect symbol table: array of u32 symbol indices
    let indirect_table: Vec<u32> = {
        let off = indirect_symoff as usize;
        let count = n_indirect_syms as usize;
        if off + count * 4 > binary.len() { return; }
        (0..count).map(|i| {
            u32::from_le_bytes([
                binary[off + i*4], binary[off + i*4 + 1],
                binary[off + i*4 + 2], binary[off + i*4 + 3],
            ])
        }).collect()
    };

    // Find __stubs, __got, __la_symbol_ptr sections with their reserved1 field.
    // reserved1 gives the index into the indirect symbol table for this section.
    // goblin doesn't expose reserved1, so we parse it from the raw section headers.
    #[derive(Default)]
    struct SectionInfo { addr: u64, size: u64, offset: u64, reserved1: u32 }
    let mut stubs = SectionInfo::default();
    let mut got = SectionInfo::default();
    let mut la_sym = SectionInfo::default();

    // Parse section headers from raw binary to get reserved1
    // Mach-O 64-bit section_64 struct: 80 bytes each, reserved1 at offset 60
    for lc in &macho.load_commands {
        if let goblin::mach::load_command::CommandVariant::Segment64(seg) = &lc.command {
            let sections_start = lc.offset + 72; // LC_SEGMENT_64 header is 72 bytes
            for i in 0..seg.nsects {
                let sect_off = sections_start + (i as usize) * 80;
                if sect_off + 80 > binary.len() { break; }
                let sectname = std::str::from_utf8(&binary[sect_off..sect_off+16])
                    .unwrap_or("").trim_end_matches('\0');
                let addr = u64::from_le_bytes(binary[sect_off+32..sect_off+40].try_into().unwrap_or([0;8]));
                let size = u64::from_le_bytes(binary[sect_off+40..sect_off+48].try_into().unwrap_or([0;8]));
                let offset = u32::from_le_bytes(binary[sect_off+48..sect_off+52].try_into().unwrap_or([0;4]));
                let reserved1 = u32::from_le_bytes(binary[sect_off+60..sect_off+64].try_into().unwrap_or([0;4]));

                match sectname {
                    "__stubs" => { stubs = SectionInfo { addr, size, offset: offset as u64, reserved1 }; }
                    "__got" => { got = SectionInfo { addr, size, offset: offset as u64, reserved1 }; }
                    "__la_symbol_ptr" => { la_sym = SectionInfo { addr, size, offset: offset as u64, reserved1 }; }
                    _ => {}
                }
            }
        }
    }

    // Map GOT entries → symbol names via indirect symbol table
    let mut got_to_name: HashMap<u64, String> = HashMap::new();
    if got.addr != 0 {
        let n_got = got.size / 8;
        for i in 0..n_got {
            let ind_idx = got.reserved1 as usize + i as usize;
            if ind_idx < indirect_table.len() {
                let sym_idx = indirect_table[ind_idx] as usize;
                // 0x80000000 = INDIRECT_SYMBOL_LOCAL, 0x40000000 = INDIRECT_SYMBOL_ABS
                if sym_idx < all_symbols.len() {
                    let entry_addr = got.addr + i * 8;
                    got_to_name.insert(entry_addr, all_symbols[sym_idx].0.clone());
                }
            }
        }
    }

    // Map lazy symbol pointer entries → symbol names
    if la_sym.addr != 0 {
        let n_la = la_sym.size / 8;
        for i in 0..n_la {
            let ind_idx = la_sym.reserved1 as usize + i as usize;
            if ind_idx < indirect_table.len() {
                let sym_idx = indirect_table[ind_idx] as usize;
                if sym_idx < all_symbols.len() {
                    let entry_addr = la_sym.addr + i * 8;
                    got_to_name.insert(entry_addr, all_symbols[sym_idx].0.clone());
                }
            }
        }
    }

    if stubs.addr == 0 { return; }

    // Determine stub entry size: x86-64 = 6 bytes, AArch64 = 12 bytes
    let stub_size = if stubs.offset as usize + 2 <= binary.len() {
        let off = stubs.offset as usize;
        if binary[off] == 0xff && binary[off + 1] == 0x25 { 6u64 }
        else { 12u64 }
    } else { 6 };

    let n_stubs = if stub_size > 0 { stubs.size / stub_size } else { 0 };

    // Map each stub directly via the __stubs section's indirect symbol table entries.
    // stub i → indirect_table[stubs.reserved1 + i] → symbol_table[sym_idx] → name
    for i in 0..n_stubs {
        let stub_va = stubs.addr + i * stub_size;
        let ind_idx = stubs.reserved1 as usize + i as usize;
        if ind_idx < indirect_table.len() {
            let sym_idx = indirect_table[ind_idx] as usize;
            if sym_idx < all_symbols.len() {
                let name = &all_symbols[sym_idx].0;
                if !name.is_empty() {
                    map.insert(stub_va, name.clone());
                }
            }
        }
    }

    // Also map GOT entries directly for non-lazy bindings (called via GOT, no stub)
    for (got_entry, name) in &got_to_name {
        if !name.is_empty() && !map.values().any(|v| v == name) {
            // No stub for this import — it's called via GOT directly
            map.insert(*got_entry, name.clone());
        }
    }
}

/// Walk PE import descriptors and map IAT addresses → function names.
///
/// goblin's `pe.imports[].rva` points to the ILT (Import Lookup Table), but code
/// references the IAT (Import Address Table). We walk the import descriptors to get
/// IAT base addresses, then resolve names from either the ILT or (when ILT is zeroed,
/// e.g. UPX-unpacked binaries) directly from the IAT entries which contain hint/name RVAs.
/// Try to resolve a PE address as an MSVC RTTI vtable.
/// Returns the demangled class name if the address points to a vtable
/// with a valid RTTI Complete Object Locator at [addr-8].
pub fn resolve_pe_vtable(addr: u64, binary: &[u8]) -> Option<String> {
    let Ok(obj) = goblin::Object::parse(binary) else { return None };
    let goblin::Object::PE(pe) = &obj else { return None };
    let base = pe.image_base as u64;
    let is_64 = pe.is_64;

    let rva_to_off = |rva: u64| -> Option<usize> {
        for s in &pe.sections {
            let sva = s.virtual_address as u64;
            let vsz = s.virtual_size as u64;
            let fo = s.pointer_to_raw_data as u64;
            if rva >= sva && rva < sva + vsz {
                return Some((fo + (rva - sva)) as usize);
            }
        }
        None
    };

    // Read the COL pointer at [vtable - ptr_size]
    let vtable_rva = addr.checked_sub(base)?;
    let col_ptr_off = rva_to_off(vtable_rva.checked_sub(if is_64 { 8 } else { 4 })?)?;
    if col_ptr_off + 8 > binary.len() { return None; }

    let col_rva = if is_64 {
        // PE64: COL pointer is an RVA (not full VA) in newer MSVC
        // But it could also be a full VA — try both
        let raw = u64::from_le_bytes(binary[col_ptr_off..col_ptr_off+8].try_into().ok()?);
        if raw > base { raw - base } else { raw }
    } else {
        u32::from_le_bytes(binary[col_ptr_off..col_ptr_off+4].try_into().ok()?) as u64
    };

    let col_off = rva_to_off(col_rva)?;
    if col_off + 24 > binary.len() { return None; }

    // COL signature must be 0 (PE32) or 1 (PE64)
    let sig = u32::from_le_bytes(binary[col_off..col_off+4].try_into().ok()?);
    if sig > 1 { return None; }

    // TypeDescriptor RVA at offset 12
    let td_rva = u32::from_le_bytes(binary[col_off+12..col_off+16].try_into().ok()?) as u64;
    let td_off = rva_to_off(td_rva)?;

    // TD: pVFTable(ptr_size) + spare(ptr_size) + name(null-terminated)
    let name_off = td_off + if is_64 { 16 } else { 8 };
    if name_off >= binary.len() { return None; }
    let name_end = binary[name_off..].iter().position(|&b| b == 0)?;
    if name_end == 0 || name_end > 256 { return None; }
    let mangled = std::str::from_utf8(&binary[name_off..name_off + name_end]).ok()?;

    // Demangle MSVC type name: ".?AVbad_array_new_length@std@@" → "std::bad_array_new_length"
    let clean = mangled
        .strip_prefix(".?AV").or_else(|| mangled.strip_prefix(".?AU"))
        .unwrap_or(mangled)
        .trim_end_matches('@');
    // Reverse the namespace: "bad_array_new_length@std" → "std::bad_array_new_length"
    let parts: Vec<&str> = clean.split('@').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() { return None; }
    let demangled = if parts.len() > 1 {
        let mut rev = parts.clone();
        rev.reverse();
        format!("{}::vftable", rev.join("::"))
    } else {
        format!("{}::vftable", parts[0])
    };

    Some(demangled)
}

fn resolve_pe(pe: &goblin::pe::PE, binary: &[u8], map: &mut HashMap<u64, String>) {
    let base = pe.image_base as u64;
    let ptr_size = if pe.is_64 { 8usize } else { 4usize };
    let ordinal_flag: u64 = if pe.is_64 { 0x8000000000000000 } else { 0x80000000 };

    // RVA → file offset using section table
    let rva_to_off = |rva: u64| -> Option<usize> {
        for s in &pe.sections {
            let va = s.virtual_address as u64;
            let vsz = s.virtual_size as u64;
            let fo = s.pointer_to_raw_data as u64;
            if rva >= va && rva < va + vsz {
                return Some((fo + (rva - va)) as usize);
            }
        }
        None
    };

    // Read a null-terminated ASCII name from a hint/name table entry
    let read_hint_name = |rva: u64| -> Option<String> {
        let off = rva_to_off(rva)?;
        if off + 3 > binary.len() { return None; }
        // Skip 2-byte hint, read null-terminated name
        let name_start = off + 2;
        let name_end = binary[name_start..].iter().position(|&b| b == 0)?;
        let name = std::str::from_utf8(&binary[name_start..name_start + name_end]).ok()?;
        if name.is_empty() { return None; }
        Some(name.to_string())
    };

    if let Some(ref import_data) = pe.import_data {
        for entry in &import_data.import_data {
            let iat_rva = entry.import_directory_entry.import_address_table_rva as u64;
            if iat_rva == 0 { continue; }

            if let Some(ref ilt) = entry.import_lookup_table {
                // goblin parsed the ILT — use it for names, but map to IAT addresses
                for (i, lookup) in ilt.iter().enumerate() {
                    let iat_addr = base + iat_rva + (i as u64) * ptr_size as u64;
                    match lookup {
                        goblin::pe::import::SyntheticImportLookupTableEntry::HintNameTableRVA((_, ref hint_entry)) => {
                            map.insert(iat_addr, hint_entry.name.to_string());
                        }
                        goblin::pe::import::SyntheticImportLookupTableEntry::OrdinalNumber(ord) => {
                            map.insert(iat_addr, format!("{}!ordinal_{}", entry.name, ord));
                        }
                    }
                }
            } else {
                // ILT is missing (e.g., UPX-unpacked). Walk the IAT directly:
                // on disk, IAT entries still contain hint/name RVAs (not resolved yet).
                let Some(iat_off) = rva_to_off(iat_rva) else { continue };
                let mut i = 0usize;
                loop {
                    let entry_off = iat_off + i * ptr_size;
                    if entry_off + ptr_size > binary.len() { break; }
                    let raw_entry = if ptr_size == 4 {
                        u32::from_le_bytes(binary[entry_off..entry_off+4].try_into().unwrap_or([0;4])) as u64
                    } else {
                        u64::from_le_bytes(binary[entry_off..entry_off+8].try_into().unwrap_or([0;8]))
                    };
                    if raw_entry == 0 { break; }

                    let iat_addr = base + iat_rva + (i as u64) * ptr_size as u64;
                    if raw_entry & ordinal_flag != 0 {
                        map.insert(iat_addr, format!("{}!ordinal_{}", entry.name, raw_entry & 0xffff));
                    } else if let Some(name) = read_hint_name(raw_entry) {
                        map.insert(iat_addr, name);
                    }
                    i += 1;
                    if i > 10000 { break; }
                }
            }
        }
    }

    for export in pe.exports.iter() {
        if let Some(name) = export.name {
            if export.rva != 0 {
                map.insert(export.rva as u64 + base, name.to_string());
            }
        }
    }
}

/// Manual PE import parsing for malformed binaries that goblin can't handle.
/// Parses the PE header, section table, and import directory with error tolerance.
/// Skips corrupted entries gracefully instead of failing entirely.
fn resolve_pe_manual(binary: &[u8], map: &mut HashMap<u64, String>) {
    if binary.len() < 0x80 { return; }
    let pe_off = u32::from_le_bytes(binary[0x3c..0x40].try_into().unwrap_or([0;4])) as usize;
    if pe_off + 24 > binary.len() || &binary[pe_off..pe_off+4] != b"PE\0\0" { return; }

    let opt_off = pe_off + 24;
    let magic = u16::from_le_bytes(binary[opt_off..opt_off+2].try_into().unwrap_or([0;2]));
    let is_64 = magic == 0x20b;
    let ptr_size: usize = if is_64 { 8 } else { 4 };
    let image_base = if is_64 {
        u64::from_le_bytes(binary.get(opt_off+24..opt_off+32)
            .and_then(|s| s.try_into().ok()).unwrap_or([0;8]))
    } else {
        u32::from_le_bytes(binary.get(opt_off+28..opt_off+32)
            .and_then(|s| s.try_into().ok()).unwrap_or([0;4])) as u64
    };

    // Parse section table
    let num_sec = u16::from_le_bytes(binary[pe_off+6..pe_off+8].try_into().unwrap_or([0;2])) as usize;
    let opt_hdr_size = u16::from_le_bytes(binary[pe_off+20..pe_off+22].try_into().unwrap_or([0;2])) as usize;
    let sec_off = opt_off + opt_hdr_size;
    struct Sec { va: u64, vsz: u64, raw: u64 }
    let mut sections: Vec<Sec> = Vec::new();
    for i in 0..num_sec.min(32) {
        let off = sec_off + i * 40;
        if off + 40 > binary.len() { break; }
        sections.push(Sec {
            va: u32::from_le_bytes(binary[off+12..off+16].try_into().unwrap_or([0;4])) as u64,
            vsz: u32::from_le_bytes(binary[off+8..off+12].try_into().unwrap_or([0;4])) as u64,
            raw: u32::from_le_bytes(binary[off+20..off+24].try_into().unwrap_or([0;4])) as u64,
        });
    }
    let rva_to_off = |rva: u64| -> Option<usize> {
        for s in &sections {
            if rva >= s.va && rva < s.va + s.vsz {
                return Some((s.raw + (rva - s.va)) as usize);
            }
        }
        None
    };

    // Import directory RVA
    if opt_off + 108 > binary.len() { return; }
    let import_rva = u32::from_le_bytes(binary[opt_off+104..opt_off+108].try_into().unwrap_or([0;4])) as u64;
    if import_rva == 0 { return; }
    let Some(imp_off) = rva_to_off(import_rva) else { return; };

    // Walk import descriptors with error tolerance
    for i in 0..100 {
        let off = imp_off + i * 20;
        if off + 20 > binary.len() { break; }
        let ilt_rva = u32::from_le_bytes(binary[off..off+4].try_into().unwrap_or([0;4])) as u64;
        let name_rva = u32::from_le_bytes(binary[off+12..off+16].try_into().unwrap_or([0;4])) as u64;
        let iat_rva = u32::from_le_bytes(binary[off+16..off+20].try_into().unwrap_or([0;4])) as u64;
        if ilt_rva == 0 && name_rva == 0 { break; }

        // Skip descriptors with invalid name RVA (anti-analysis technique)
        let Some(name_off) = rva_to_off(name_rva) else { continue; };
        if name_off >= binary.len() { continue; }

        // Read import entries from ILT or IAT
        let source_rva = if ilt_rva != 0 { ilt_rva } else { iat_rva };
        let Some(source_off) = rva_to_off(source_rva) else { continue; };
        let ordinal_flag: u64 = if is_64 { 0x8000000000000000 } else { 0x80000000 };

        for j in 0..1000 {
            let entry_off = source_off + j * ptr_size;
            if entry_off + ptr_size > binary.len() { break; }
            let raw_entry = if ptr_size == 4 {
                u32::from_le_bytes(binary[entry_off..entry_off+4].try_into().unwrap_or([0;4])) as u64
            } else {
                u64::from_le_bytes(binary[entry_off..entry_off+8].try_into().unwrap_or([0;8]))
            };
            if raw_entry == 0 { break; }

            let iat_addr = image_base + iat_rva + (j as u64) * ptr_size as u64;
            if raw_entry & ordinal_flag != 0 {
                // Ordinal import — skip (no name)
            } else if let Some(hint_off) = rva_to_off(raw_entry) {
                if hint_off + 3 < binary.len() {
                    let name_start = hint_off + 2;
                    if let Some(end) = binary[name_start..].iter().position(|&b| b == 0) {
                        if let Ok(name) = std::str::from_utf8(&binary[name_start..name_start + end]) {
                            if !name.is_empty() && name.len() < 256 {
                                map.insert(iat_addr, name.to_string());
                            }
                        }
                    }
                }
            }
            // Skip entries with invalid hint RVA (corrupted/anti-analysis)
        }
    }
}
