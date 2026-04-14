//! C++ class/vtable/hierarchy recovery from RTTI and field access patterns.
//!
//! Recovers C++ class definitions by combining:
//! 1. MSVC RTTI: CompleteObjectLocator → ClassHierarchyDescriptor → BaseClassDescriptors
//! 2. GCC RTTI: typeinfo symbols (_ZTI*) with base class pointers
//! 3. Vtable analysis: function pointers from vtables → virtual method lists
//! 4. Field access patterns: this->field_XX accesses → member layout

use std::collections::BTreeMap;

/// A recovered C++ class definition.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CppClass {
    pub name: String,
    pub vtable_addr: u64,
    pub base_classes: Vec<String>,
    pub virtual_methods: Vec<VirtualMethod>,
    pub fields: Vec<ClassField>,
    pub size_estimate: u64,
}

/// A virtual method in a vtable.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VirtualMethod {
    pub index: usize,
    pub address: u64,
    pub name: String,
}

/// A class field inferred from access patterns.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ClassField {
    pub offset: u64,
    pub size: u32,
    pub name: String,
    pub inferred_type: String,
}

/// Recover C++ classes from a PE binary using MSVC RTTI.
pub fn recover_msvc_classes(binary: &[u8]) -> Vec<CppClass> {
    let Ok(obj) = goblin::Object::parse(binary) else { return vec![] };
    let goblin::Object::PE(pe) = &obj else { return vec![] };
    let base = pe.image_base as u64;
    let is_64 = pe.is_64;
    let ptr_size = if is_64 { 8usize } else { 4 };

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

    // Find .rdata section for vtable/RTTI scanning
    let rdata = pe.sections.iter().find(|s| {
        let name = std::str::from_utf8(&s.name).unwrap_or("").trim_end_matches('\0');
        name == ".rdata" || name == ".data"
    });
    let Some(rdata) = rdata else { return vec![] };
    let rdata_rva = rdata.virtual_address as u64;
    let rdata_fo = rdata.pointer_to_raw_data as usize;
    let rdata_size = rdata.virtual_size as usize;

    // Find text section for method validation
    let text_rva_start = pe.sections.iter()
        .filter(|s| s.characteristics & 0x20000000 != 0)
        .map(|s| s.virtual_address as u64)
        .min().unwrap_or(0);
    let text_rva_end = pe.sections.iter()
        .filter(|s| s.characteristics & 0x20000000 != 0)
        .map(|s| s.virtual_address as u64 + s.virtual_size as u64)
        .max().unwrap_or(0);

    let mut classes = Vec::new();

    // Scan .rdata for MSVC RTTI Complete Object Locators
    // COL layout (PE64): signature(4) offset(4) cdOffset(4) typeDescriptor_rva(4) classHierarchy_rva(4) self_rva(4)
    // COL layout (PE32): signature(4) offset(4) cdOffset(4) typeDescriptor_va(4) classHierarchy_va(4)
    let col_size = if is_64 { 24 } else { 20 };

    for i in (0..rdata_size.saturating_sub(col_size)).step_by(4) {
        let fo = rdata_fo + i;
        if fo + col_size > binary.len() { break; }

        let sig = u32::from_le_bytes(binary[fo..fo+4].try_into().unwrap_or([0;4]));
        if sig != 0 && sig != 1 { continue; } // Must be 0 (PE32) or 1 (PE64)
        if is_64 && sig != 1 { continue; }
        if !is_64 && sig != 0 { continue; }

        // Read TypeDescriptor RVA/VA
        let td_ref = u32::from_le_bytes(binary[fo+12..fo+16].try_into().unwrap_or([0;4])) as u64;
        let td_rva = if is_64 { td_ref } else { td_ref.checked_sub(base).unwrap_or(td_ref) };
        let Some(td_off) = rva_to_off(td_rva) else { continue };

        // Validate TypeDescriptor: first field is pVFTable (should point to .rdata)
        if td_off + ptr_size * 2 + 4 > binary.len() { continue; }

        // Read class name from TypeDescriptor
        let name_off = td_off + ptr_size * 2;
        if name_off >= binary.len() { continue; }
        let name_end = binary[name_off..].iter().position(|&b| b == 0).unwrap_or(0);
        if name_end == 0 || name_end > 256 { continue; }
        let mangled = match std::str::from_utf8(&binary[name_off..name_off + name_end]) {
            Ok(s) => s,
            Err(_) => continue,
        };

        // Must start with ".?AV" (class) or ".?AU" (struct)
        if !mangled.starts_with(".?AV") && !mangled.starts_with(".?AU") { continue; }

        // Demangle: ".?AVMyClass@MyNamespace@@" → "MyNamespace::MyClass"
        let clean = mangled
            .strip_prefix(".?AV").or_else(|| mangled.strip_prefix(".?AU"))
            .unwrap_or(mangled)
            .trim_end_matches('@');
        let parts: Vec<&str> = clean.split('@').filter(|s| !s.is_empty()).collect();
        let class_name = if parts.len() > 1 {
            let mut reversed = parts.clone();
            reversed.reverse();
            reversed.join("::")
        } else {
            parts.join("")
        };

        if class_name.is_empty() { continue; }

        // Read ClassHierarchyDescriptor to find base classes
        let chd_ref = u32::from_le_bytes(binary[fo+16..fo+20].try_into().unwrap_or([0;4])) as u64;
        let chd_rva = if is_64 { chd_ref } else { chd_ref.checked_sub(base).unwrap_or(chd_ref) };
        let mut base_classes = Vec::new();

        if let Some(chd_off) = rva_to_off(chd_rva) {
            if chd_off + 16 <= binary.len() {
                let num_bases = u32::from_le_bytes(binary[chd_off+8..chd_off+12].try_into().unwrap_or([0;4])) as usize;
                let bca_ref = u32::from_le_bytes(binary[chd_off+12..chd_off+16].try_into().unwrap_or([0;4])) as u64;
                let bca_rva = if is_64 { bca_ref } else { bca_ref.checked_sub(base).unwrap_or(bca_ref) };

                if let Some(bca_off) = rva_to_off(bca_rva) {
                    // BaseClassArray: array of RVAs/VAs to BaseClassDescriptors
                    for j in 1..num_bases.min(20) { // skip index 0 (self)
                        let entry_off = bca_off + j * 4;
                        if entry_off + 4 > binary.len() { break; }
                        let bcd_ref = u32::from_le_bytes(binary[entry_off..entry_off+4].try_into().unwrap_or([0;4])) as u64;
                        let bcd_rva = if is_64 { bcd_ref } else { bcd_ref.checked_sub(base).unwrap_or(bcd_ref) };
                        if let Some(bcd_off) = rva_to_off(bcd_rva) {
                            // BCD: TypeDescriptor_ref at offset 0
                            if bcd_off + 4 <= binary.len() {
                                let base_td_ref = u32::from_le_bytes(binary[bcd_off..bcd_off+4].try_into().unwrap_or([0;4])) as u64;
                                let base_td_rva = if is_64 { base_td_ref } else { base_td_ref.checked_sub(base).unwrap_or(base_td_ref) };
                                if let Some(base_td_off) = rva_to_off(base_td_rva) {
                                    let base_name_off = base_td_off + ptr_size * 2;
                                    if base_name_off < binary.len() {
                                        let end = binary[base_name_off..].iter().position(|&b| b == 0).unwrap_or(0);
                                        if end > 0 && end < 256 {
                                            if let Ok(base_mangled) = std::str::from_utf8(&binary[base_name_off..base_name_off+end]) {
                                                let base_clean = base_mangled
                                                    .strip_prefix(".?AV").or_else(|| base_mangled.strip_prefix(".?AU"))
                                                    .unwrap_or(base_mangled)
                                                    .trim_end_matches('@');
                                                let bp: Vec<&str> = base_clean.split('@').filter(|s| !s.is_empty()).collect();
                                                let base_name = if bp.len() > 1 { let mut r = bp; r.reverse(); r.join("::") } else { bp.join("") };
                                                if !base_name.is_empty() && base_name != class_name {
                                                    base_classes.push(base_name);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Find vtable: COL is at [vtable - ptr_size], so vtable = COL_addr + ptr_size
        let col_rva = rdata_rva + i as u64;
        // Scan for pointers to this COL in .rdata (that's the vtable[-1] slot)
        let mut vtable_addr = 0u64;
        let mut virtual_methods = Vec::new();

        for k in (0..rdata_size.saturating_sub(ptr_size)).step_by(ptr_size) {
            let ptr_off = rdata_fo + k;
            if ptr_off + ptr_size > binary.len() { break; }
            let ptr_val = if is_64 {
                let raw = u64::from_le_bytes(binary[ptr_off..ptr_off+8].try_into().unwrap_or([0;8]));
                if raw > base { raw - base } else { raw }
            } else {
                u32::from_le_bytes(binary[ptr_off..ptr_off+4].try_into().unwrap_or([0;4])) as u64
            };

            if ptr_val == col_rva {
                // Found! Vtable starts at next entry
                vtable_addr = base + rdata_rva + k as u64 + ptr_size as u64;

                // Read virtual method entries
                let mut vt_off = rdata_fo + k + ptr_size;
                let mut idx = 0;
                while vt_off + ptr_size <= binary.len() {
                    let method_rva = if is_64 {
                        let raw = u64::from_le_bytes(binary[vt_off..vt_off+8].try_into().unwrap_or([0;8]));
                        if raw > base { raw - base } else { raw }
                    } else {
                        u32::from_le_bytes(binary[vt_off..vt_off+4].try_into().unwrap_or([0;4])) as u64
                    };

                    // Must point into .text
                    if method_rva < text_rva_start || method_rva >= text_rva_end { break; }

                    virtual_methods.push(VirtualMethod {
                        index: idx,
                        address: base + method_rva,
                        name: format!("vmethod_{}", idx),
                    });
                    idx += 1;
                    vt_off += ptr_size;
                    if idx > 50 { break; } // sanity limit
                }
                break;
            }
        }

        // Estimate class size from field accesses (would need decompiled output)
        let size_estimate = if !virtual_methods.is_empty() { ptr_size as u64 } else { 0 }
            + virtual_methods.len() as u64 * 0; // vtable is a pointer, not inline

        classes.push(CppClass {
            name: class_name,
            vtable_addr,
            base_classes,
            virtual_methods,
            fields: Vec::new(), // filled in later from decompiled output
            size_estimate,
        });
    }

    // Deduplicate by class name
    classes.sort_by(|a, b| a.name.cmp(&b.name));
    classes.dedup_by(|a, b| a.name == b.name);

    classes
}

/// Recover C++ classes from an ELF binary using GCC/Itanium ABI RTTI.
/// GCC RTTI uses _ZTI* (typeinfo), _ZTV* (vtable), _ZTS* (typeinfo name) symbols.
pub fn recover_gcc_classes(binary: &[u8]) -> Vec<CppClass> {
    let Ok(obj) = goblin::Object::parse(binary) else { return vec![] };
    let goblin::Object::Elf(elf) = &obj else { return vec![] };

    let mut classes = Vec::new();

    // Find _ZTV* (vtable) and _ZTI* (typeinfo) symbols
    let all_syms: Vec<_> = elf.syms.iter().chain(elf.dynsyms.iter()).collect();
    let strtab = |sym: &goblin::elf::Sym| -> Option<&str> {
        elf.strtab.get_at(sym.st_name)
            .or_else(|| elf.dynstrtab.get_at(sym.st_name))
    };

    for sym in &all_syms {
        let Some(name) = strtab(sym) else { continue };
        if !name.starts_with("_ZTV") { continue; } // vtable symbol
        if sym.st_value == 0 { continue; }

        // Demangle the vtable name: _ZTV + mangled_class_name
        let mangled_class = &name[4..]; // skip "_ZTV"
        let class_name = demangle_itanium(mangled_class);
        if class_name.is_empty() { continue; }

        let vtable_addr = sym.st_value;
        let vtable_size = sym.st_size as usize;

        // Read vtable entries: [offset_to_top, typeinfo_ptr, vfunc0, vfunc1, ...]
        let mut virtual_methods = Vec::new();
        let ptr_size = 8usize; // ELF64

        // Find file offset for vtable
        let vtable_fo = elf.section_headers.iter().find_map(|sh| {
            if vtable_addr >= sh.sh_addr && vtable_addr < sh.sh_addr + sh.sh_size {
                Some((sh.sh_offset + (vtable_addr - sh.sh_addr)) as usize)
            } else { None }
        });

        if let Some(fo) = vtable_fo {
            // Skip offset_to_top (8 bytes) and typeinfo_ptr (8 bytes)
            let start = fo + ptr_size * 2;
            let max_entries = if vtable_size > ptr_size * 2 { (vtable_size - ptr_size * 2) / ptr_size } else { 20 };

            // Find .text bounds for validation
            let text_bounds: Vec<(u64, u64)> = elf.section_headers.iter()
                .filter(|sh| sh.sh_flags & 0x4 != 0)
                .map(|sh| (sh.sh_addr, sh.sh_addr + sh.sh_size))
                .collect();
            let in_text = |addr: u64| text_bounds.iter().any(|(s, e)| addr >= *s && addr < *e);

            for idx in 0..max_entries.min(50) {
                let entry_off = start + idx * ptr_size;
                if entry_off + ptr_size > binary.len() { break; }
                let method_addr = u64::from_le_bytes(
                    binary[entry_off..entry_off+8].try_into().unwrap_or([0;8]));
                if method_addr == 0 || !in_text(method_addr) { break; }

                // Try to find a symbol name for this method
                let method_name = all_syms.iter()
                    .find(|s| s.st_value == method_addr && s.st_type() == goblin::elf::sym::STT_FUNC)
                    .and_then(|s| strtab(s))
                    .map(|n| {
                        // Try to demangle
                        if n.starts_with("_Z") {
                            cpp_demangle::Symbol::new(n.as_bytes())
                                .ok()
                                .and_then(|s| s.demangle().ok())
                                .unwrap_or_else(|| n.to_string())
                        } else { n.to_string() }
                    })
                    .unwrap_or_else(|| format!("vmethod_{}", idx));

                virtual_methods.push(VirtualMethod {
                    index: idx,
                    address: method_addr,
                    name: method_name,
                });
            }
        }

        // Find base classes from _ZTI* typeinfo
        let mut base_classes = Vec::new();
        let ti_name = format!("_ZTI{}", mangled_class);
        if let Some(ti_sym) = all_syms.iter().find(|s| strtab(s) == Some(&ti_name)) {
            if ti_sym.st_value != 0 {
                let ti_fo = elf.section_headers.iter().find_map(|sh| {
                    if ti_sym.st_value >= sh.sh_addr && ti_sym.st_value < sh.sh_addr + sh.sh_size {
                        Some((sh.sh_offset + (ti_sym.st_value - sh.sh_addr)) as usize)
                    } else { None }
                });
                if let Some(fo) = ti_fo {
                    // Itanium typeinfo layout:
                    // __si_class_type_info: [vtable_ptr(8), name_ptr(8), base_type_ptr(8)]
                    // __vmi_class_type_info: [vtable_ptr(8), name_ptr(8), flags(4), base_count(4), bases...]
                    if fo + 24 <= binary.len() {
                        let base_ti_ptr = u64::from_le_bytes(
                            binary[fo+16..fo+24].try_into().unwrap_or([0;8]));
                        // Find the symbol for this typeinfo to get the base class name
                        if let Some(base_sym) = all_syms.iter().find(|s| s.st_value == base_ti_ptr) {
                            if let Some(base_name) = strtab(base_sym) {
                                if base_name.starts_with("_ZTI") {
                                    let base_class = demangle_itanium(&base_name[4..]);
                                    if !base_class.is_empty() {
                                        base_classes.push(base_class);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        classes.push(CppClass {
            name: class_name,
            vtable_addr,
            base_classes,
            virtual_methods,
            fields: Vec::new(),
            size_estimate: 0,
        });
    }

    classes.sort_by(|a, b| a.name.cmp(&b.name));
    classes.dedup_by(|a, b| a.name == b.name);
    classes
}

/// Demangle Itanium ABI mangled name (simplified).
fn demangle_itanium(mangled: &str) -> String {
    // Try cpp_demangle first
    let full = format!("_Z{}", mangled);
    if let Ok(sym) = cpp_demangle::Symbol::new(full.as_bytes()) {
        if let Ok(demangled) = sym.demangle() {
            return demangled;
        }
    }
    // Simple fallback: N<len><name>... pattern
    // E.g., "N3std6vectorIiEE" → "std::vector<int>"
    if mangled.starts_with('N') {
        let mut result = Vec::new();
        let chars: Vec<char> = mangled[1..].chars().collect();
        let mut i = 0;
        while i < chars.len() {
            if chars[i] == 'E' { break; }
            if chars[i].is_ascii_digit() {
                let mut len_str = String::new();
                while i < chars.len() && chars[i].is_ascii_digit() {
                    len_str.push(chars[i]);
                    i += 1;
                }
                let len: usize = len_str.parse().unwrap_or(0);
                let name: String = chars[i..i+len.min(chars.len()-i)].iter().collect();
                result.push(name);
                i += len;
            } else {
                i += 1;
            }
        }
        return result.join("::");
    }
    // Simple name: <len><name>
    if let Some(first) = mangled.chars().next() {
        if first.is_ascii_digit() {
            let len_end = mangled.find(|c: char| !c.is_ascii_digit()).unwrap_or(mangled.len());
            let len: usize = mangled[..len_end].parse().unwrap_or(0);
            return mangled[len_end..len_end+len.min(mangled.len()-len_end)].to_string();
        }
    }
    mangled.to_string()
}

/// Enrich class definitions with field layout from decompiled pseudocode.
/// Scans pseudocode for `this->field_XX` patterns and infers field types.
pub fn enrich_with_fields(classes: &mut [CppClass], pseudocode_map: &BTreeMap<u64, String>) {
    for class in classes.iter_mut() {
        let mut fields: BTreeMap<u64, (u32, String)> = BTreeMap::new(); // offset → (size, type)

        // Scan pseudocode of all virtual methods for field accesses
        for vm in &class.virtual_methods {
            if let Some(code) = pseudocode_map.get(&vm.address) {
                for line in code.lines() {
                    let t = line.trim();
                    // Match: param_0->field_XX or this->field_XX
                    if let Some(pos) = t.find("->field_") {
                        let hex_start = pos + 8;
                        let hex_end = t[hex_start..].find(|c: char| !c.is_ascii_hexdigit())
                            .map(|e| hex_start + e).unwrap_or(t.len());
                        if hex_end > hex_start {
                            if let Ok(offset) = u64::from_str_radix(&t[hex_start..hex_end], 16) {
                                // Infer type from context
                                let inferred = if t.contains("strcmp") || t.contains("strlen") || t.contains("printf") {
                                    "char *"
                                } else if t.contains("*(uint32_t*)") || t.contains("(int)") {
                                    "int"
                                } else if t.contains("*(uint64_t*)") || t.contains("(long)") {
                                    "long"
                                } else if t.contains("*(uint8_t*)") {
                                    "uint8_t"
                                } else {
                                    "void *"
                                };
                                fields.entry(offset).or_insert((8, inferred.to_string()));
                            }
                        }
                    }
                }
            }
        }

        // Convert to ClassField list
        let field_list: Vec<u64> = fields.keys().copied().collect();
        for (i, &offset) in field_list.iter().enumerate() {
            let (_, ref inferred_type) = fields[&offset];
            let size = if i + 1 < field_list.len() {
                (field_list[i+1] - offset).min(8) as u32
            } else { 8 };
            class.fields.push(ClassField {
                offset,
                size,
                name: format!("field_{:x}", offset),
                inferred_type: inferred_type.clone(),
            });
        }

        // Update size estimate
        if let Some(last) = class.fields.last() {
            class.size_estimate = last.offset + last.size as u64;
        }
    }
}

/// Format recovered classes as C++ header output.
pub fn format_classes(classes: &[CppClass]) -> String {
    let mut out = String::new();
    for class in classes {
        // Class declaration
        if class.base_classes.is_empty() {
            out.push_str(&format!("class {} {{\n", class.name));
        } else {
            out.push_str(&format!("class {} : public {} {{\n",
                class.name, class.base_classes.join(", public ")));
        }
        out.push_str("public:\n");

        // Virtual methods
        if !class.virtual_methods.is_empty() {
            for vm in &class.virtual_methods {
                out.push_str(&format!("    virtual void {}(); // 0x{:x}\n", vm.name, vm.address));
            }
        }

        // Fields
        for field in &class.fields {
            out.push_str(&format!("    {} {}; // +0x{:x}\n", field.inferred_type, field.name, field.offset));
        }

        out.push_str("};\n\n");
    }
    out
}
