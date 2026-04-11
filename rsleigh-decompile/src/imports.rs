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
        let demangled = demangled;
        // Simplify common patterns
        simplify_cpp_name(&demangled)
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
    let Ok(obj) = goblin::Object::parse(binary) else { return map };

    match &obj {
        goblin::Object::Elf(elf) => resolve_elf(elf, binary, &mut map),
        goblin::Object::Mach(goblin::mach::Mach::Binary(macho)) => {
            resolve_macho(macho, binary, &mut map);
        }
        goblin::Object::PE(pe) => resolve_pe(pe, &mut map),
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
            for i in 1..n_entries {
                let stub_addr = plt_start + i * entry_size;
                let off = file_off + (i * entry_size) as usize;

                // Decode the JMP [rip+disp32] at the start of the PLT entry
                if off + 6 <= binary.len() && binary[off] == 0xff && binary[off + 1] == 0x25 {
                    let disp = i32::from_le_bytes([
                        binary[off + 2], binary[off + 3],
                        binary[off + 4], binary[off + 5],
                    ]);
                    let got_entry = (stub_addr + 6).wrapping_add(disp as u64);
                    if let Some(name) = got_to_name.get(&got_entry) {
                        map.insert(stub_addr, name.clone());
                    }
                }
                // Also try: indirect JMP via endbr64 prefix (CET-enabled PLT)
                // endbr64 = F3 0F 1E FA, then FF 25 disp32
                else if off + 10 <= binary.len()
                    && binary[off] == 0xf3 && binary[off + 1] == 0x0f
                    && binary[off + 2] == 0x1e && binary[off + 3] == 0xfa
                    && binary[off + 4] == 0xff && binary[off + 5] == 0x25
                {
                    let disp = i32::from_le_bytes([
                        binary[off + 6], binary[off + 7],
                        binary[off + 8], binary[off + 9],
                    ]);
                    let got_entry = (stub_addr + 10).wrapping_add(disp as u64);
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
                    map.insert(sym.st_value, demangle_name(name));
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
            all_symbols.push((clean.to_string(), nlist.n_value, nlist.n_type));
            // Defined symbols (type 0x0e = N_SECT)
            if nlist.n_type & 0x0e == 0x0e && nlist.n_value != 0 && !clean.is_empty() {
                map.insert(nlist.n_value, clean.to_string());
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
