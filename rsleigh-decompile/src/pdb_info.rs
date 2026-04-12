use std::collections::HashMap;
use std::path::Path;

use fallible_iterator::FallibleIterator;

use crate::dwarf::{FunctionDebugInfo, StructFieldMap};

/// Parse PDB debug info from a companion .pdb file for a PE binary.
/// Searches for <binary_stem>.pdb in the same directory.
pub fn parse_pdb_from_path(binary_path: &Path) -> (HashMap<u64, FunctionDebugInfo>, StructFieldMap) {
    // Look for <name>.pdb next to the binary
    let pdb_path = binary_path.with_extension("pdb");
    if pdb_path.exists() {
        return parse_pdb_file(&pdb_path);
    }

    // Also try the same directory with lowercase .pdb
    if let Some(stem) = binary_path.file_stem() {
        let dir = binary_path.parent().unwrap_or(Path::new("."));
        let lower_pdb = dir.join(format!("{}.pdb", stem.to_string_lossy()));
        if lower_pdb.exists() {
            return parse_pdb_file(&lower_pdb);
        }
    }

    (HashMap::new(), HashMap::new())
}

/// Parse a PDB file, extracting function debug info and struct field maps.
fn parse_pdb_file(pdb_path: &Path) -> (HashMap<u64, FunctionDebugInfo>, StructFieldMap) {
    let file = match std::fs::File::open(pdb_path) {
        Ok(f) => f,
        Err(_) => return (HashMap::new(), HashMap::new()),
    };

    let mut pdb = match pdb::PDB::open(file) {
        Ok(p) => p,
        Err(_) => return (HashMap::new(), HashMap::new()),
    };

    let functions = extract_functions(&mut pdb);
    let fields = extract_struct_fields(&mut pdb);

    (functions, fields)
}

/// Extract function debug info: address → (param names, local names, return type).
fn extract_functions(pdb: &mut pdb::PDB<'_, std::fs::File>) -> HashMap<u64, FunctionDebugInfo> {
    let mut result = HashMap::new();

    let address_map = match pdb.address_map() {
        Ok(m) => m,
        Err(_) => return result,
    };

    let dbi = match pdb.debug_information() {
        Ok(d) => d,
        Err(_) => return result,
    };

    // Build a type finder for resolving type indices to names
    let type_info = pdb.type_information().ok();
    let mut type_finder = None;
    if let Some(ref ti) = type_info {
        let mut finder = ti.finder();
        let mut iter = ti.iter();
        while iter.next().ok().flatten().is_some() {
            finder.update(&iter);
        }
        type_finder = Some(finder);
    }

    // Iterate modules and their symbols
    let mut modules = match dbi.modules() {
        Ok(m) => m,
        Err(_) => return result,
    };

    while let Ok(Some(module)) = modules.next() {
        let module_info = match pdb.module_info(&module) {
            Ok(Some(mi)) => mi,
            _ => continue,
        };

        let mut symbols = match module_info.symbols() {
            Ok(s) => s,
            Err(_) => continue,
        };

        let mut current_func: Option<(u64, FunctionDebugInfo)> = None;

        while let Ok(Some(symbol)) = symbols.next() {
            match symbol.parse() {
                Ok(pdb::SymbolData::Procedure(proc)) => {
                    // Save previous function
                    if let Some((addr, info)) = current_func.take() {
                        if addr != 0 {
                            result.insert(addr, info);
                        }
                    }

                    // Convert section offset to RVA
                    let rva = match proc.offset.to_rva(&address_map) {
                        Some(r) => r,
                        None => continue,
                    };

                    let mut info = FunctionDebugInfo::default();

                    // Try to resolve return type from the procedure's type index
                    if let Some(ref finder) = type_finder {
                        info.return_type = resolve_procedure_return_type(finder, proc.type_index);
                    }

                    current_func = Some((rva.0 as u64, info));
                }

                // Local/parameter variables defined by register-relative location
                Ok(pdb::SymbolData::RegisterRelative(regrel)) => {
                    if let Some((_, ref mut info)) = current_func {
                        let name = regrel.name.to_string().to_string();
                        // Positive offsets from frame pointer are typically parameters,
                        // negative offsets are locals. But MSVC uses RSP-relative,
                        // so we store by offset and let the decompiler sort it out.
                        if is_likely_parameter(&name, regrel.offset) {
                            info.param_names.push(name);
                        } else {
                            info.local_names.insert(regrel.offset as i64, name);
                        }
                    }
                }

                // Local variables via register
                Ok(pdb::SymbolData::Local(local)) => {
                    if let Some((_, ref mut info)) = current_func {
                        let name = local.name.to_string().to_string();
                        // Locals without a specific offset — store with a synthetic offset
                        // based on position to avoid collisions
                        let synthetic_offset = -(info.local_names.len() as i64 + 1) * 8;
                        info.local_names.insert(synthetic_offset, name);
                    }
                }

                _ => {}
            }
        }

        // Save last function
        if let Some((addr, info)) = current_func.take() {
            if addr != 0 {
                result.insert(addr, info);
            }
        }
    }

    result
}

/// Heuristic: is this variable likely a parameter?
/// MSVC x64: parameters are at positive offsets from RSP in the home space.
/// First 4 params: RCX, RDX, R8, R9 with home space at RSP+8..RSP+32.
fn is_likely_parameter(name: &str, offset: i32) -> bool {
    // Common parameter naming patterns
    if name.starts_with("__formal") { return true; }
    // In MSVC debug builds, parameters typically live at small positive offsets
    // (the "home space" above the return address)
    offset >= 0 && offset <= 64
}

/// Resolve a procedure's return type from its type index.
fn resolve_procedure_return_type(
    finder: &pdb::TypeFinder<'_>,
    type_index: pdb::TypeIndex,
) -> Option<String> {
    let item = finder.find(type_index).ok()?;
    match item.parse().ok()? {
        pdb::TypeData::Procedure(proc) => {
            proc.return_type.and_then(|rt| resolve_type_name(finder, rt))
        }
        pdb::TypeData::MemberFunction(mf) => {
            resolve_type_name(finder, mf.return_type)
        }
        _ => None,
    }
}

/// Resolve a type index to a human-readable C type name.
fn resolve_type_name(finder: &pdb::TypeFinder<'_>, type_index: pdb::TypeIndex) -> Option<String> {
    // Check for primitive types (type index < 0x1000)
    if type_index.0 < 0x1000 {
        return Some(primitive_type_name(type_index.0).to_string());
    }

    let item = finder.find(type_index).ok()?;
    match item.parse().ok()? {
        pdb::TypeData::Primitive(prim) => {
            Some(format!("{:?}", prim.kind))
        }
        pdb::TypeData::Class(class) => {
            Some(class.name.to_string().to_string())
        }
        pdb::TypeData::Union(u) => {
            Some(u.name.to_string().to_string())
        }
        pdb::TypeData::Enumeration(e) => {
            Some(e.name.to_string().to_string())
        }
        pdb::TypeData::Pointer(ptr) => {
            let inner = resolve_type_name(finder, ptr.underlying_type)
                .unwrap_or_else(|| "void".to_string());
            Some(format!("{}*", inner))
        }
        pdb::TypeData::Array(arr) => {
            let elem = resolve_type_name(finder, arr.element_type)
                .unwrap_or_else(|| "?".to_string());
            Some(format!("{}[]", elem))
        }
        pdb::TypeData::Modifier(m) => {
            let inner = resolve_type_name(finder, m.underlying_type)?;
            if m.constant {
                Some(format!("const {}", inner))
            } else if m.volatile {
                Some(format!("volatile {}", inner))
            } else {
                Some(inner)
            }
        }
        pdb::TypeData::Procedure(proc) => {
            let ret = proc.return_type
                .and_then(|rt| resolve_type_name(finder, rt))
                .unwrap_or_else(|| "void".to_string());
            Some(format!("{}(*)()", ret))
        }
        _ => None,
    }
}

/// Map PDB primitive type indices to C type names.
/// See https://llvm.org/docs/PDB/TpiStream.html#type-indices
fn primitive_type_name(idx: u32) -> &'static str {
    match idx {
        0x0000 => "void",        // T_NOTYPE
        0x0003 => "void",        // T_VOID
        0x0010 => "int8_t",      // T_CHAR
        0x0011 => "int16_t",     // T_SHORT
        0x0012 => "int32_t",     // T_LONG
        0x0013 => "int64_t",     // T_QUAD
        0x0020 => "uint8_t",     // T_UCHAR
        0x0021 => "uint16_t",    // T_USHORT
        0x0022 => "uint32_t",    // T_ULONG
        0x0023 => "uint64_t",    // T_UQUAD
        0x0030 => "bool",        // T_BOOL08
        0x0040 => "float",       // T_REAL32
        0x0041 => "double",      // T_REAL64
        0x0068 => "int8_t",      // T_INT1
        0x0069 => "uint8_t",     // T_UINT1
        0x0070 => "char",        // T_RCHAR
        0x0071 => "wchar_t",     // T_WCHAR
        0x0072 => "int16_t",     // T_INT2
        0x0073 => "uint16_t",    // T_UINT2
        0x0074 => "int32_t",     // T_INT4
        0x0075 => "uint32_t",    // T_UINT4
        0x0076 => "int64_t",     // T_INT8
        0x0077 => "uint64_t",    // T_UINT8
        0x0103 => "void*",       // T_PVOID (32-bit pointer)
        0x0403 => "void*",       // T_32PVOID
        0x0603 => "void*",       // T_64PVOID
        0x0410 => "char*",       // T_32PCHAR
        0x0610 => "char*",       // T_64PCHAR
        0x0470 => "char*",       // T_32PRCHAR
        0x0670 => "char*",       // T_64PRCHAR
        0x0471 => "wchar_t*",    // T_32PWCHAR
        0x0671 => "wchar_t*",    // T_64PWCHAR
        _ => "int",              // fallback
    }
}

/// Extract struct/class field information: byte_offset → field_name.
fn extract_struct_fields(pdb: &mut pdb::PDB<'_, std::fs::File>) -> StructFieldMap {
    let mut fields = HashMap::new();

    let type_info = match pdb.type_information() {
        Ok(ti) => ti,
        Err(_) => return fields,
    };

    let mut finder = type_info.finder();
    let mut iter = type_info.iter();

    // First pass: build the type finder index
    while iter.next().ok().flatten().is_some() {
        finder.update(&iter);
    }

    // Second pass: iterate all types looking for structs/classes
    let mut iter2 = type_info.iter();
    while let Ok(Some(item)) = iter2.next() {
        match item.parse() {
            Ok(pdb::TypeData::Class(class)) => {
                if let Some(fl) = class.fields {
                    extract_field_list(&finder, fl, &mut fields);
                }
            }
            Ok(pdb::TypeData::Union(u)) => {
                extract_field_list(&finder, u.fields, &mut fields);
            }
            _ => {}
        }
    }

    fields
}

/// Extract fields from a FieldList type index.
fn extract_field_list(
    finder: &pdb::TypeFinder<'_>,
    field_list_index: pdb::TypeIndex,
    fields: &mut StructFieldMap,
) {
    let item = match finder.find(field_list_index) {
        Ok(i) => i,
        Err(_) => return,
    };

    if let Ok(pdb::TypeData::FieldList(fl)) = item.parse() {
        for field in &fl.fields {
            if let pdb::TypeData::Member(member) = field {
                let name = member.name.to_string().to_string();
                if !name.is_empty() {
                    fields.insert(member.offset, name);
                }
            }
        }

        // Handle continuation records for large structs
        if let Some(cont) = fl.continuation {
            extract_field_list(finder, cont, fields);
        }
    }
}
