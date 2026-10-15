//! `.eh_frame` / LSDA parsing for C++ exception region annotation.
//!
//! Builds a map from function entry address → list of try/catch call-site regions.
//! Used by the printer to annotate where try blocks begin/end, matching Ghidra's
//! `/* try { // try from 0xA to 0xB has its CatchHandler @ 0xC */` comments.
//!
//! Itanium C++ ABI LSDA format (after each FDE's augmentation data points to it):
//! ```text
//!   u8         LPStart encoding (often DW_EH_PE_omit = 0xFF)
//!   [encoded]  LPStart value        (if !omit)
//!   u8         TType encoding
//!   [uleb128]  TType offset         (if TType encoding != omit)
//!   u8         Call-site table encoding
//!   uleb128    Call-site table length
//!   call-site entries (encoded as per above):
//!     start       (offset from LPStart / fde.initial_address())
//!     length
//!     landing_pad (0 = no handler, cleanup only)
//!     action_entry uleb128 (0 = cleanup-only, nonzero = catch)
//! ```
//!
//! We only decode the call-site table — enough to know where try regions are and
//! which landing pad (catch handler) they point to. Type info is not extracted.

use std::collections::HashMap;

use gimli::{BaseAddresses, CieOrFde, EhFrame, LittleEndian, UnwindSection};

#[derive(Debug, Clone)]
pub struct TryRegion {
    pub start: u64,
    pub end: u64,
    pub landing_pad: u64,
}

/// Parse `.eh_frame` + LSDAs and return a map from FDE initial_address → try regions.
pub fn parse_eh_frame(binary: &[u8]) -> HashMap<u64, Vec<TryRegion>> {
    static CACHE: crate::binary_cache::Cache<HashMap<u64, Vec<TryRegion>>> =
        crate::binary_cache::Cache::new();
    let key = crate::binary_cache::Key::bytes(binary);
    crate::binary_cache::cached(&CACHE, Some(key), || parse_eh_frame_uncached(binary))
}

fn parse_eh_frame_uncached(binary: &[u8]) -> HashMap<u64, Vec<TryRegion>> {
    let mut out: HashMap<u64, Vec<TryRegion>> = HashMap::new();
    let Ok(obj) = goblin::Object::parse(binary) else {
        return out;
    };
    let elf = match obj {
        goblin::Object::Elf(e) => e,
        _ => return out,
    };

    // Find .eh_frame section + its base address
    let mut eh_frame_data: Option<&[u8]> = None;
    let mut eh_frame_addr: u64 = 0;
    let mut text_addr: u64 = 0;
    for sh in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
        match name {
            ".eh_frame" => {
                let off = sh.sh_offset as usize;
                let sz = sh.sh_size as usize;
                if off + sz <= binary.len() {
                    eh_frame_data = Some(&binary[off..off + sz]);
                    eh_frame_addr = sh.sh_addr;
                }
            }
            ".text" => {
                text_addr = sh.sh_addr;
            }
            _ => {}
        }
    }
    let Some(data) = eh_frame_data else {
        return out;
    };

    let bases = BaseAddresses::default()
        .set_eh_frame(eh_frame_addr)
        .set_text(text_addr);
    let eh_frame = EhFrame::new(data, LittleEndian);
    let mut entries = eh_frame.entries(&bases);

    while let Ok(Some(entry)) = entries.next() {
        let fde = match entry {
            CieOrFde::Cie(_) => continue,
            CieOrFde::Fde(partial) => match partial.parse(EhFrame::cie_from_offset) {
                Ok(fde) => fde,
                Err(_) => continue,
            },
        };
        let func_start = fde.initial_address();
        let Some(lsda_ptr) = fde.lsda() else {
            continue;
        };
        let lsda_addr = match lsda_ptr {
            gimli::Pointer::Direct(a) => a,
            gimli::Pointer::Indirect(a) => a,
        };
        // Find LSDA file offset from its virtual address (search via section headers)
        let Some(lsda_off) = va_to_file_offset(&elf, lsda_addr) else {
            continue;
        };
        if lsda_off >= binary.len() {
            continue;
        }
        let regions = parse_lsda(&binary[lsda_off..], func_start);
        if !regions.is_empty() {
            out.insert(func_start, regions);
        }
    }

    out
}

/// Code extents recorded by `.eh_frame`.
#[derive(Debug, Default)]
pub struct FdeLayout {
    /// FDE start → end (exclusive) for every non-PLT FDE.
    pub extents: HashMap<u64, u64>,
    /// Starts of FDEs whose code begins inside an established frame.
    ///
    /// At a function entry the call has pushed only the return address, so
    /// the first unwind row is the architecture's entry state. GCC hot/cold
    /// splitting gives each `foo.cold` part its own FDE whose first row
    /// already records `foo`'s frame (larger CFA offset, saved callee
    /// registers). Function discovery lists those starts as functions, but
    /// they are pieces of the function that jumps to them. The entry state
    /// is the commonest first-row CFA in the binary.
    pub mid_frame: std::collections::HashSet<u64>,
}

/// Read FDE extents and mid-frame starts. PLT FDEs are skipped: PLT0 also
/// starts mid-frame but is shared lazy-binding code, not a fragment.
pub fn fde_layout(binary: &[u8]) -> FdeLayout {
    let mut out = FdeLayout::default();
    let Ok(goblin::Object::Elf(elf)) = goblin::Object::parse(binary) else {
        return out;
    };
    let mut eh_frame_data: Option<&[u8]> = None;
    let (mut eh_frame_addr, mut text_addr) = (0u64, 0u64);
    let mut plt = Vec::new();
    for sh in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
        if name == ".eh_frame" {
            let (off, sz) = (sh.sh_offset as usize, sh.sh_size as usize);
            if off + sz <= binary.len() {
                eh_frame_data = Some(&binary[off..off + sz]);
                eh_frame_addr = sh.sh_addr;
            }
        } else if name == ".text" {
            text_addr = sh.sh_addr;
        } else if name.starts_with(".plt") {
            plt.push(sh.sh_addr..sh.sh_addr + sh.sh_size);
        }
    }
    let Some(data) = eh_frame_data else {
        return out;
    };
    let bases = BaseAddresses::default()
        .set_eh_frame(eh_frame_addr)
        .set_text(text_addr);
    let eh_frame = EhFrame::new(data, LittleEndian);
    let mut entries = eh_frame.entries(&bases);
    let mut ctx = gimli::UnwindContext::new();
    let mut first_rows = Vec::new();
    while let Ok(Some(entry)) = entries.next() {
        let CieOrFde::Fde(partial) = entry else {
            continue;
        };
        let Ok(fde) = partial.parse(EhFrame::cie_from_offset) else {
            continue;
        };
        let start = fde.initial_address();
        if plt.iter().any(|r| r.contains(&start)) {
            continue;
        }
        out.extents.insert(start, start + fde.len());
        let ra = fde.cie().return_address_register();
        let Ok(row) = fde.unwind_info_for_address(&eh_frame, &bases, &mut ctx, start) else {
            continue;
        };
        let saves = row.registers().any(|(register, rule)| {
            *register != ra
                && !matches!(
                    rule,
                    gimli::RegisterRule::Undefined | gimli::RegisterRule::SameValue
                )
        });
        first_rows.push((start, row.cfa().clone(), saves));
    }
    let mut counts: Vec<(&gimli::CfaRule<usize>, usize)> = Vec::new();
    for (_, cfa, _) in &first_rows {
        match counts.iter_mut().find(|(rule, _)| *rule == cfa) {
            Some((_, n)) => *n += 1,
            None => counts.push((cfa, 1)),
        }
    }
    let Some(entry_cfa) = counts
        .iter()
        .max_by_key(|(_, n)| *n)
        .map(|(rule, _)| (*rule).clone())
    else {
        return out;
    };
    for (start, cfa, saves) in first_rows {
        if saves || cfa != entry_cfa {
            out.mid_frame.insert(start);
        }
    }
    out
}

fn va_to_file_offset(elf: &goblin::elf::Elf, va: u64) -> Option<usize> {
    for sh in &elf.section_headers {
        if va >= sh.sh_addr && va < sh.sh_addr + sh.sh_size {
            return Some((sh.sh_offset + (va - sh.sh_addr)) as usize);
        }
    }
    None
}

/// Decode Itanium LSDA call-site table. Returns try regions whose landing_pad > 0
/// (those with a catch handler or cleanup action).
fn parse_lsda(data: &[u8], func_start: u64) -> Vec<TryRegion> {
    let mut out = Vec::new();
    let mut p = 0usize;
    if p >= data.len() {
        return out;
    }

    // LPStart encoding byte
    let lp_enc = data[p];
    p += 1;
    let lp_start = if lp_enc == DW_EH_PE_OMIT {
        func_start
    } else {
        match read_encoded(data, &mut p, lp_enc, func_start) {
            Some(v) => v,
            None => return out,
        }
    };

    // TType encoding + offset
    if p >= data.len() {
        return out;
    }
    let ttype_enc = data[p];
    p += 1;
    if ttype_enc != DW_EH_PE_OMIT {
        let _ttype_off = match read_uleb(data, &mut p) {
            Some(v) => v,
            None => return out,
        };
    }

    // Call-site table encoding + length
    if p >= data.len() {
        return out;
    }
    let cs_enc = data[p];
    p += 1;
    let cs_len = match read_uleb(data, &mut p) {
        Some(v) => v,
        None => return out,
    };
    let cs_end = p + cs_len as usize;
    if cs_end > data.len() {
        return out;
    }

    while p < cs_end {
        // For Itanium C++ ABI the four fields are encoded per cs_enc. Typically
        // DW_EH_PE_uleb128 for all four. Handle the common cases.
        let start_off = match read_encoded(data, &mut p, cs_enc, 0) {
            Some(v) => v,
            None => break,
        };
        let length = match read_encoded(data, &mut p, cs_enc, 0) {
            Some(v) => v,
            None => break,
        };
        let lp_off = match read_encoded(data, &mut p, cs_enc, 0) {
            Some(v) => v,
            None => break,
        };
        let _action = match read_uleb(data, &mut p) {
            Some(v) => v,
            None => break,
        };

        if length == 0 {
            continue;
        }
        if lp_off == 0 {
            continue;
        } // cleanup-only or no handler — skip

        out.push(TryRegion {
            start: func_start.wrapping_add(start_off),
            end: func_start.wrapping_add(start_off).wrapping_add(length),
            landing_pad: lp_start.wrapping_add(lp_off),
        });
    }

    out
}

// DW_EH_PE encoding constants (subset needed for typical LSDAs)
const DW_EH_PE_OMIT: u8 = 0xFF;
const DW_EH_PE_ABSPTR: u8 = 0x00;
const DW_EH_PE_ULEB128: u8 = 0x01;
const DW_EH_PE_UDATA2: u8 = 0x02;
const DW_EH_PE_UDATA4: u8 = 0x03;
const DW_EH_PE_UDATA8: u8 = 0x04;
const DW_EH_PE_SLEB128: u8 = 0x09;
const DW_EH_PE_SDATA2: u8 = 0x0A;
const DW_EH_PE_SDATA4: u8 = 0x0B;
const DW_EH_PE_SDATA8: u8 = 0x0C;

fn read_encoded(data: &[u8], p: &mut usize, enc: u8, pc_rel_base: u64) -> Option<u64> {
    let format = enc & 0x0F;
    let application = enc & 0x70;
    let v: u64 = match format {
        DW_EH_PE_ABSPTR => {
            // Default: pointer-sized, i.e. u64 on 64-bit, u32 on 32-bit.
            // Assume 64-bit for AArch64/x86-64 (caller ensures this).
            if *p + 8 > data.len() {
                return None;
            }
            let v = u64::from_le_bytes(data[*p..*p + 8].try_into().ok()?);
            *p += 8;
            v
        }
        DW_EH_PE_ULEB128 => read_uleb(data, p)?,
        DW_EH_PE_UDATA2 => {
            if *p + 2 > data.len() {
                return None;
            }
            let v = u16::from_le_bytes(data[*p..*p + 2].try_into().ok()?) as u64;
            *p += 2;
            v
        }
        DW_EH_PE_UDATA4 => {
            if *p + 4 > data.len() {
                return None;
            }
            let v = u32::from_le_bytes(data[*p..*p + 4].try_into().ok()?) as u64;
            *p += 4;
            v
        }
        DW_EH_PE_UDATA8 => {
            if *p + 8 > data.len() {
                return None;
            }
            let v = u64::from_le_bytes(data[*p..*p + 8].try_into().ok()?);
            *p += 8;
            v
        }
        DW_EH_PE_SLEB128 => {
            let sv = read_sleb(data, p)?;
            sv as u64
        }
        DW_EH_PE_SDATA2 => {
            if *p + 2 > data.len() {
                return None;
            }
            let v = i16::from_le_bytes(data[*p..*p + 2].try_into().ok()?) as i64 as u64;
            *p += 2;
            v
        }
        DW_EH_PE_SDATA4 => {
            if *p + 4 > data.len() {
                return None;
            }
            let v = i32::from_le_bytes(data[*p..*p + 4].try_into().ok()?) as i64 as u64;
            *p += 4;
            v
        }
        DW_EH_PE_SDATA8 => {
            if *p + 8 > data.len() {
                return None;
            }
            let v = i64::from_le_bytes(data[*p..*p + 8].try_into().ok()?) as u64;
            *p += 8;
            v
        }
        _ => return None,
    };
    // Apply application modifier (pcrel, etc.) — for call-site table,
    // the spec says "no application" for call-site offsets; only LPStart
    // may use pcrel. Keep simple: pcrel adds pc_rel_base.
    const DW_EH_PE_PCREL: u8 = 0x10;
    if application == DW_EH_PE_PCREL {
        Some(v.wrapping_add(pc_rel_base))
    } else {
        Some(v)
    }
}

fn read_uleb(data: &[u8], p: &mut usize) -> Option<u64> {
    let mut result: u64 = 0;
    let mut shift = 0;
    loop {
        if *p >= data.len() {
            return None;
        }
        let b = data[*p];
        *p += 1;
        result |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
}

fn read_sleb(data: &[u8], p: &mut usize) -> Option<i64> {
    let mut result: i64 = 0;
    let mut shift = 0;
    let mut byte = 0;
    loop {
        if *p >= data.len() {
            return None;
        }
        byte = data[*p];
        *p += 1;
        result |= ((byte & 0x7F) as i64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
        if shift >= 64 {
            return None;
        }
    }
    // Sign-extend if shift < 64 and sign bit of last byte is set
    if shift < 64 && (byte & 0x40) != 0 {
        result |= !0i64 << shift;
    }
    Some(result)
}
