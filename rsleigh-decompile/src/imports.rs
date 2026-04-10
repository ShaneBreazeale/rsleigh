use std::collections::HashMap;

/// Build a map of address → import function name from a binary.
pub fn resolve_imports(binary: &[u8]) -> HashMap<u64, String> {
    let mut map = HashMap::new();
    let Ok(obj) = goblin::Object::parse(binary) else { return map };

    match obj {
        goblin::Object::Elf(elf) => {
            // ELF: collect from .dynsym (imported functions) and .symtab
            for sym in elf.dynsyms.iter() {
                if sym.is_import() && sym.st_value != 0 {
                    if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                        if !name.is_empty() {
                            map.insert(sym.st_value, name.to_string());
                        }
                    }
                }
            }
            // Also map PLT entries — PLT stub addresses to import names
            // PLT relocations map slot addresses to symbol names
            for reloc in elf.pltrelocs.iter() {
                let sym_idx = reloc.r_sym;
                if let Some(sym) = elf.dynsyms.get(sym_idx) {
                    if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                        if !name.is_empty() {
                            // The reloc offset points to the GOT entry; we want the PLT stub
                            // PLT stubs are typically at a fixed offset before the GOT
                            map.insert(reloc.r_offset, name.to_string());
                        }
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
        goblin::Object::Mach(goblin::mach::Mach::Binary(macho)) => {
            // Mach-O: imports come from lazy/non-lazy binding info + symbol stubs
            for import in macho.imports().unwrap_or_default() {
                if import.address != 0 {
                    let name = import.name.strip_prefix('_').unwrap_or(import.name);
                    map.insert(import.address, name.to_string());
                }
            }
            // Also collect named symbols
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
        }
        goblin::Object::PE(pe) => {
            // PE: imports
            for import in pe.imports.iter() {
                if import.rva != 0 {
                    let addr = import.rva as u64 + pe.image_base as u64;
                    map.insert(addr, import.name.to_string().to_string());
                }
            }
            // PE: exports
            for export in pe.exports.iter() {
                if let Some(name) = export.name {
                    if export.rva != 0 {
                        let addr = export.rva as u64 + pe.image_base as u64;
                        map.insert(addr, name.to_string());
                    }
                }
            }
        }
        _ => {}
    }

    map
}
