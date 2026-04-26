//! Go `.gopclntab` parser for function-name recovery on stripped Go binaries.
//!
//! Supports Go 1.20+ (pcHeader magic 0xfffffff1). Earlier layouts fall
//! through — Go 1.18 used 0xfffffff0 with split tables; Go 1.16 and below
//! packed everything differently.
//!
//! Produces (pc → function_name) pairs suitable for merging into the
//! CLI's symbol list.

use std::collections::HashMap;

const MAGIC_GO120: u32 = 0xfffffff1;

/// Walks ELF/Mach-O/PE sections looking for `.gopclntab`, decodes the
/// Go 1.20+ header, and yields (function_pc, name) pairs. Returns an
/// empty map when the section is absent or unsupported.
pub fn parse(binary: &[u8]) -> HashMap<u64, String> {
    let Ok(obj) = goblin::Object::parse(binary) else {
        return HashMap::new();
    };
    let (section_data, section_va) = match find_gopclntab(&obj, binary) {
        Some(v) => v,
        None => return HashMap::new(),
    };
    parse_table(section_data, section_va).unwrap_or_default()
}

fn find_gopclntab<'a>(obj: &goblin::Object<'a>, binary: &'a [u8]) -> Option<(&'a [u8], u64)> {
    match obj {
        goblin::Object::Elf(elf) => {
            for sh in &elf.section_headers {
                let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
                if name == ".gopclntab" {
                    let start = sh.sh_offset as usize;
                    let end = start + sh.sh_size as usize;
                    if end <= binary.len() {
                        return Some((&binary[start..end], sh.sh_addr));
                    }
                }
            }
            None
        }
        goblin::Object::Mach(goblin::mach::Mach::Binary(m)) => {
            for seg in m.segments.iter() {
                if let Ok(sects) = seg.sections() {
                    for (sect, sdata) in sects {
                        if sect.name().unwrap_or("") == "__gopclntab" {
                            // sdata is a &[u8] reference; compute its VA.
                            return Some((sdata, sect.addr));
                        }
                    }
                }
            }
            None
        }
        goblin::Object::PE(pe) => {
            // Go Windows binaries place the table in the .text section's
            // .gopclntab sub-range; goblin exposes sections by name.
            for s in &pe.sections {
                if s.name().unwrap_or("") == ".gopclntab" {
                    let start = s.pointer_to_raw_data as usize;
                    let end = start + s.size_of_raw_data as usize;
                    if end <= binary.len() {
                        let va = pe.image_base as u64 + s.virtual_address as u64;
                        return Some((&binary[start..end], va));
                    }
                }
            }
            None
        }
        _ => None,
    }
}

fn parse_table(data: &[u8], _section_va: u64) -> Option<HashMap<u64, String>> {
    if data.len() < 64 {
        return None;
    }
    let magic = u32::from_le_bytes(data[0..4].try_into().ok()?);
    if magic != MAGIC_GO120 {
        // TODO: 0xfffffff0 (Go 1.18/1.19) + 0xfffffffa (Go 1.16) layouts.
        return None;
    }
    // Fixed-layout header for Go 1.20+ (matches src/runtime/symtab.go pcHeader).
    //   u32 magic
    //   u16 pad
    //   u8  minLC
    //   u8  ptrSize
    //   uN  nfunc
    //   uN  nfiles
    //   uN  textStart
    //   uN  funcnameOffset
    //   uN  cuOffset
    //   uN  filetabOffset
    //   uN  pctabOffset
    //   uN  pclnOffset
    let minlc = data[6];
    let ptrsize = data[7] as usize;
    if ptrsize != 8 && ptrsize != 4 {
        return None;
    }
    let _ = minlc;
    let mut p = 8usize;
    let read_word = |p: usize| -> Option<u64> {
        if p + ptrsize > data.len() {
            return None;
        }
        Some(match ptrsize {
            8 => u64::from_le_bytes(data[p..p + 8].try_into().ok()?),
            4 => u32::from_le_bytes(data[p..p + 4].try_into().ok()?) as u64,
            _ => unreachable!(),
        })
    };
    let nfunc = read_word(p)?;
    p += ptrsize;
    let _nfiles = read_word(p)?;
    p += ptrsize;
    let text_start = read_word(p)?;
    p += ptrsize;
    let funcname_off = read_word(p)? as usize;
    p += ptrsize;
    let _cu_off = read_word(p)?;
    p += ptrsize;
    let _filetab_off = read_word(p)?;
    p += ptrsize;
    let _pctab_off = read_word(p)?;
    p += ptrsize;
    let pcln_off = read_word(p)? as usize;

    if funcname_off >= data.len() || pcln_off >= data.len() {
        return None;
    }
    let pcln = &data[pcln_off..];
    // Go 1.20+ functab: array of {u32 entryoff, u32 funcoff} — both
    // u32 regardless of ptrSize. Entry size = 8 bytes.
    let entry_size = 8usize;
    let mut out = HashMap::new();
    let max = (nfunc as usize).min(65536);
    for i in 0..max {
        let base = i * entry_size;
        if base + entry_size > pcln.len() {
            break;
        }
        let entry_off = u32::from_le_bytes(pcln[base..base + 4].try_into().ok()?) as u64;
        let func_off = u32::from_le_bytes(pcln[base + 4..base + 8].try_into().ok()?) as u64;
        let pc = text_start.wrapping_add(entry_off);
        // _func struct at pcln_off + func_off.
        let fpos = pcln_off + func_off as usize;
        if fpos + 8 > data.len() {
            continue;
        }
        // Go 1.20+ _func layout starts with:
        //   u32 entryoff (pc offset from textStart — duplicate)
        //   u32 nameoff  (offset into funcnametab)
        let name_off = u32::from_le_bytes(data[fpos + 4..fpos + 8].try_into().ok()?) as usize;
        let name_abs = funcname_off + name_off;
        if name_abs >= data.len() {
            continue;
        }
        // Name is null-terminated ASCII.
        let end = data[name_abs..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| name_abs + p)
            .unwrap_or(data.len());
        if end - name_abs == 0 || end - name_abs > 512 {
            continue;
        }
        let name = match std::str::from_utf8(&data[name_abs..end]) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if name.is_empty() {
            continue;
        }
        out.insert(pc, sanitize(name));
    }
    Some(out)
}

/// Convert a Go mangled symbol name into something safe to emit inside C
/// pseudocode. Go names embed `.`, `/`, `(`, `)`, `*`, `[`, `]`, `,`, `:`,
/// spaces — all invalid in C identifiers.
fn sanitize(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_underscore = false;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
            last_underscore = false;
        } else if !last_underscore {
            out.push('_');
            last_underscore = true;
        }
    }
    out.trim_end_matches('_').to_string()
}
