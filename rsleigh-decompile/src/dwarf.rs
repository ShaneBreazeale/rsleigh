use object::{Object, ObjectSection};
use std::collections::HashMap;
use std::path::Path;

/// Information extracted from DWARF debug info for a function.
#[derive(Debug, Clone, Default)]
pub struct FunctionDebugInfo {
    pub param_names: Vec<String>,
    pub local_names: HashMap<i64, String>,
    pub return_type: Option<String>,
}

/// Map of struct field byte offset → field name, indexed by struct identity.
/// The key is the byte offset within the struct, the value is the field name.
pub type StructFieldMap = HashMap<u64, String>;

/// Extract DWARF debug info from a binary file path.
/// On macOS, automatically searches for companion .dSYM bundle.
pub fn parse_dwarf_from_path(binary_path: &Path) -> HashMap<u64, FunctionDebugInfo> {
    // Try the binary itself first (works for Linux ELF with embedded DWARF)
    if let Ok(data) = std::fs::read(binary_path) {
        let result = parse_dwarf(&data);
        if !result.is_empty() {
            return result;
        }
    }

    // On macOS, look for .dSYM bundle
    // Format: <path>.dSYM/Contents/Resources/DWARF/<filename>
    if let Some(file_name) = binary_path.file_name() {
        let mut dsym_path = binary_path.as_os_str().to_os_string();
        dsym_path.push(".dSYM");
        let dsym_dir = Path::new(&dsym_path);
        let dsym_dwarf = dsym_dir
            .join("Contents")
            .join("Resources")
            .join("DWARF")
            .join(file_name);
        if let Ok(data) = std::fs::read(&dsym_dwarf) {
            let result = parse_dwarf(&data);
            if !result.is_empty() {
                return result;
            }
        }
    }

    HashMap::new()
}

/// Extract DWARF debug info for functions from raw binary bytes.
pub fn parse_dwarf(binary: &[u8]) -> HashMap<u64, FunctionDebugInfo> {
    let mut result = HashMap::new();
    let Ok(obj) = object::File::parse(binary) else {
        return result;
    };

    let endian = if obj.endianness() == object::Endianness::Little {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };

    let load_section = |id: gimli::SectionId| -> Result<gimli::EndianSlice<'_, gimli::RunTimeEndian>, gimli::Error> {
        let data = obj.section_by_name(id.name())
            .and_then(|s| s.data().ok())
            .unwrap_or(&[]);
        Ok(gimli::EndianSlice::new(data, endian))
    };

    let dwarf = match gimli::Dwarf::load(&load_section) {
        Ok(d) => d,
        Err(_) => return result,
    };

    let mut units = dwarf.units();
    while let Ok(Some(header)) = units.next() {
        let Ok(unit) = dwarf.unit(header) else {
            continue;
        };
        let mut entries = unit.entries();

        let mut current_func: Option<(u64, FunctionDebugInfo)> = None;

        while let Ok(Some((_, entry))) = entries.next_dfs() {
            match entry.tag() {
                gimli::DW_TAG_subprogram => {
                    if let Some((addr, info)) = current_func.take() {
                        if !info.param_names.is_empty() {
                            result.insert(addr, info);
                        }
                    }
                    let addr = get_low_pc(&dwarf, &unit, entry).unwrap_or(0);
                    let info = FunctionDebugInfo::default();
                    current_func = Some((addr, info));
                }
                gimli::DW_TAG_formal_parameter => {
                    if let Some((_, ref mut info)) = current_func {
                        if let Some(name) = get_die_name(&dwarf, &unit, entry) {
                            info.param_names.push(name);
                        }
                    }
                }
                gimli::DW_TAG_variable => {
                    if let Some((_, ref mut info)) = current_func {
                        if let Some(name) = get_die_name(&dwarf, &unit, entry) {
                            if let Some(offset) = get_stack_offset(&unit, entry) {
                                info.local_names.insert(offset, name);
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        if let Some((addr, info)) = current_func {
            if !info.param_names.is_empty() {
                result.insert(addr, info);
            }
        }
    }

    result
}

type DwarfSlice<'a> = gimli::Dwarf<gimli::EndianSlice<'a, gimli::RunTimeEndian>>;
type UnitSlice<'a> = gimli::Unit<gimli::EndianSlice<'a, gimli::RunTimeEndian>, usize>;
type EntrySlice<'a> =
    gimli::DebuggingInformationEntry<'a, 'a, gimli::EndianSlice<'a, gimli::RunTimeEndian>, usize>;

/// Get the low_pc address, handling both DWARF4 (Addr) and DWARF5 (DebugAddrIndex).
fn get_low_pc(dwarf: &DwarfSlice<'_>, unit: &UnitSlice<'_>, entry: &EntrySlice<'_>) -> Option<u64> {
    let attr = entry.attr_value(gimli::DW_AT_low_pc).ok()??;
    match attr {
        gimli::AttributeValue::Addr(a) => Some(a),
        gimli::AttributeValue::DebugAddrIndex(idx) => dwarf.address(unit, idx).ok(),
        _ => None,
    }
}

/// Get the DW_AT_name, handling String, DebugStrRef (DWARF4), and DebugStrOffsetsIndex (DWARF5).
fn get_die_name(
    dwarf: &DwarfSlice<'_>,
    unit: &UnitSlice<'_>,
    entry: &EntrySlice<'_>,
) -> Option<String> {
    let attr = entry.attr(gimli::DW_AT_name).ok()??;
    let s = dwarf.attr_string(unit, attr.value()).ok()?;
    std::str::from_utf8(s.slice()).ok().map(|s| s.to_string())
}

/// Extract stack frame offset from DW_AT_location (DW_OP_fbreg).
fn get_stack_offset(unit: &UnitSlice<'_>, entry: &EntrySlice<'_>) -> Option<i64> {
    let attr = entry.attr(gimli::DW_AT_location).ok()??;
    if let gimli::AttributeValue::Exprloc(ref expr) = attr.value() {
        let mut ops = expr.clone().operations(unit.encoding());
        if let Ok(Some(gimli::Operation::FrameOffset { offset })) = ops.next() {
            return Some(offset);
        }
    }
    None
}

/// Get the DW_AT_data_member_location (byte offset within struct).
fn get_member_offset(unit: &UnitSlice<'_>, entry: &EntrySlice<'_>) -> Option<u64> {
    let attr = entry.attr_value(gimli::DW_AT_data_member_location).ok()??;
    match attr {
        gimli::AttributeValue::Udata(n) => Some(n),
        gimli::AttributeValue::Sdata(n) => Some(n as u64),
        gimli::AttributeValue::Exprloc(ref expr) => {
            // DW_OP_plus_uconst N — common for member offsets
            let mut ops = expr.clone().operations(unit.encoding());
            if let Ok(Some(gimli::Operation::PlusConstant { value })) = ops.next() {
                return Some(value);
            }
            None
        }
        gimli::AttributeValue::Data1(n) => Some(n as u64),
        gimli::AttributeValue::Data2(n) => Some(n as u64),
        gimli::AttributeValue::Data4(n) => Some(n as u64),
        gimli::AttributeValue::Data8(n) => Some(n),
        _ => None,
    }
}

/// Parse all struct definitions from DWARF, returning a merged map of
/// field_byte_offset → field_name across all structs in the binary.
pub fn parse_struct_fields(binary: &[u8]) -> StructFieldMap {
    let mut fields = HashMap::new();
    let Ok(obj) = object::File::parse(binary) else {
        return fields;
    };

    let endian = if obj.endianness() == object::Endianness::Little {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };

    let load_section = |id: gimli::SectionId| -> Result<gimli::EndianSlice<'_, gimli::RunTimeEndian>, gimli::Error> {
        let data = obj.section_by_name(id.name())
            .and_then(|s| s.data().ok())
            .unwrap_or(&[]);
        Ok(gimli::EndianSlice::new(data, endian))
    };

    let dwarf = match gimli::Dwarf::load(&load_section) {
        Ok(d) => d,
        Err(_) => return fields,
    };

    let mut units = dwarf.units();
    while let Ok(Some(header)) = units.next() {
        let Ok(unit) = dwarf.unit(header) else {
            continue;
        };
        let mut entries = unit.entries();

        let mut in_struct = false;
        // Track parent member offsets for nested structs
        let mut parent_offsets: Vec<u64> = Vec::new();
        let mut prev_depth = 0isize;

        while let Ok(Some((depth, entry))) = entries.next_dfs() {
            if depth < prev_depth {
                for _ in 0..(prev_depth - depth) {
                    parent_offsets.pop();
                }
                if parent_offsets.is_empty() {
                    in_struct = false;
                }
            }
            prev_depth = depth;

            match entry.tag() {
                gimli::DW_TAG_structure_type | gimli::DW_TAG_union_type => {
                    in_struct = true;
                    parent_offsets.push(0); // will be updated by the enclosing member
                }
                gimli::DW_TAG_member if in_struct => {
                    if let Some(offset) = get_member_offset(&unit, entry) {
                        // Update parent offset if this member introduces a nested type
                        if let Some(last) = parent_offsets.last_mut() {
                            // The member's offset relative to parent struct
                            *last = offset;
                        }
                        if let Some(name) = get_die_name(&dwarf, &unit, entry) {
                            // Insert at both the raw offset AND the accumulated offset
                            // This handles both flat structs and nested ones
                            fields.insert(offset, name.clone());
                            let accumulated: u64 = parent_offsets.iter().sum();
                            if accumulated != offset {
                                fields.insert(accumulated, name);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fields
}

/// Parse struct fields from a binary file path (with dSYM support).
pub fn parse_struct_fields_from_path(binary_path: &Path) -> StructFieldMap {
    if let Ok(data) = std::fs::read(binary_path) {
        let result = parse_struct_fields(&data);
        if !result.is_empty() {
            return result;
        }
    }
    // Try dSYM
    if let Some(file_name) = binary_path.file_name() {
        let mut dsym_path = binary_path.as_os_str().to_os_string();
        dsym_path.push(".dSYM");
        let dsym_dwarf = Path::new(&dsym_path)
            .join("Contents")
            .join("Resources")
            .join("DWARF")
            .join(file_name);
        if let Ok(data) = std::fs::read(&dsym_dwarf) {
            return parse_struct_fields(&data);
        }
    }
    HashMap::new()
}
