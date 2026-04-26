//! rsleigh-fid-gen — build a FID database (.fidb) from an ELF/Mach-O/PE.
//!
//! Usage:
//!   rsleigh-fid-gen --lib <lib_name> --arch <arch> --out <file.fidb> <binary> [<binary2> ...]
//!
//! Walks each binary's function symbols, fingerprints each body, writes
//! the collected rows as a gzipped FID database.

use rsleigh_api::Architecture;
use rsleigh_fid::db::FidEntry;
use rsleigh_fid::ingest::fingerprint;
use rsleigh_fid::FidDb;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

fn arch_from_str(s: &str) -> Option<Architecture> {
    Some(match s {
        "x86_64" | "x64" | "amd64" => Architecture::X86_64,
        "x86" | "x86_32" | "i386" => Architecture::X86_32,
        "aarch64" | "arm64" => Architecture::AArch64,
        "arm32" | "arm" => Architecture::ARM32,
        "mips32" | "mips" => Architecture::MIPS32,
        "riscv64" | "rv64" => Architecture::RiscV64,
        _ => return None,
    })
}

struct Args {
    lib: String,
    arch: Architecture,
    out: String,
    inputs: Vec<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut it = std::env::args().skip(1);
    let mut lib = None;
    let mut arch = None;
    let mut out = None;
    let mut inputs = Vec::new();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--lib" => lib = it.next(),
            "--arch" => {
                let s = it.next().ok_or("--arch needs value")?;
                arch = Some(arch_from_str(&s).ok_or_else(|| format!("unknown arch: {s}"))?);
            }
            "--out" => out = it.next(),
            "-h" | "--help" => {
                eprintln!("rsleigh-fid-gen --lib NAME --arch ARCH --out FILE bin [bin...]");
                std::process::exit(0);
            }
            _ => inputs.push(a),
        }
    }
    Ok(Args {
        lib: lib.ok_or("missing --lib")?,
        arch: arch.ok_or("missing --arch")?,
        out: out.ok_or("missing --out")?,
        inputs: if inputs.is_empty() {
            return Err("no input binaries".into());
        } else {
            inputs
        },
    })
}

fn ingest_any(data: &[u8], arch: Architecture) -> Vec<(String, u64, Vec<u8>)> {
    match goblin::Object::parse(data) {
        Ok(goblin::Object::Elf(_)) => ingest_elf(data, arch),
        Ok(goblin::Object::Mach(m)) => ingest_macho(data, arch, m),
        Ok(goblin::Object::PE(pe)) => ingest_pe(data, arch, pe),
        Ok(goblin::Object::Archive(a)) => ingest_archive(data, arch, a),
        _ => Vec::new(),
    }
}

fn ingest_macho(
    data: &[u8],
    _arch: Architecture,
    mach: goblin::mach::Mach,
) -> Vec<(String, u64, Vec<u8>)> {
    use goblin::mach::Mach;
    let mo = match mach {
        Mach::Binary(m) => m,
        Mach::Fat(fat) => match fat.into_iter().next() {
            Some(Ok(goblin::mach::SingleArch::MachO(m))) => m,
            _ => return Vec::new(),
        },
    };
    // Build vm→file mapping from segments.
    let mut segs: Vec<(u64, u64, u64, u64)> = Vec::new();
    for seg in mo.segments.iter() {
        segs.push((
            seg.vmaddr,
            seg.vmaddr + seg.vmsize,
            seg.fileoff,
            seg.filesize,
        ));
    }
    let va_to_off = |va: u64, sz: u64| -> Option<(usize, usize)> {
        for (s, e, o, f) in &segs {
            if va >= *s && va + sz <= *e {
                let d = va - s;
                if d + sz > *f {
                    return None;
                }
                return Some(((o + d) as usize, sz as usize));
            }
        }
        None
    };
    // Sort N_SECT symbols by address to derive sizes from gaps.
    let mut syms: Vec<(u64, String)> = Vec::new();
    if let Ok(it) = mo.symbols.as_ref().ok_or(()).map(|s| s.iter()) {
        for r in it {
            if let Ok((name, nlist)) = r {
                if nlist.is_stab() {
                    continue;
                }
                if (nlist.n_type & goblin::mach::symbols::N_TYPE) != goblin::mach::symbols::N_SECT {
                    continue;
                }
                if nlist.n_value == 0 || name.is_empty() {
                    continue;
                }
                let n = if let Some(s) = name.strip_prefix('_') {
                    s
                } else {
                    name
                };
                syms.push((nlist.n_value, n.to_string()));
            }
        }
    }
    syms.sort_by_key(|s| s.0);
    let mut out = Vec::new();
    for i in 0..syms.len() {
        let (va, ref name) = syms[i];
        let size_guess = if i + 1 < syms.len() {
            (syms[i + 1].0 - va).min(4096)
        } else {
            512
        };
        if size_guess < 16 {
            continue;
        }
        if let Some((o, l)) = va_to_off(va, size_guess) {
            if o + l <= data.len() {
                out.push((name.clone(), va, data[o..o + l].to_vec()));
            }
        }
    }
    out
}

fn ingest_pe(data: &[u8], _arch: Architecture, pe: goblin::pe::PE) -> Vec<(String, u64, Vec<u8>)> {
    // PE/COFF lacks a per-symbol size field; fall back to sorting exports
    // by RVA and deriving body length from the next export.
    let image_base = pe.image_base as u64;
    let sections = pe.sections;
    let rva_to_off = |rva: u64, sz: u64| -> Option<(usize, usize)> {
        for s in &sections {
            let vs = s.virtual_address as u64;
            let ve = vs + s.virtual_size.max(s.size_of_raw_data) as u64;
            if rva >= vs && rva + sz <= ve {
                let d = rva - vs;
                let fstart = s.pointer_to_raw_data as u64 + d;
                if fstart as usize + sz as usize > data.len() {
                    return None;
                }
                return Some((fstart as usize, sz as usize));
            }
        }
        None
    };
    let mut exps: Vec<(u64, String)> = pe
        .exports
        .iter()
        .filter_map(|e| e.name.map(|n| (e.rva as u64, n.to_string())))
        .collect();
    exps.sort_by_key(|e| e.0);
    let mut out = Vec::new();
    for i in 0..exps.len() {
        let (rva, ref name) = exps[i];
        let size_guess = if i + 1 < exps.len() {
            (exps[i + 1].0 - rva).min(4096)
        } else {
            512
        };
        if size_guess < 16 {
            continue;
        }
        if let Some((o, l)) = rva_to_off(rva, size_guess) {
            out.push((name.clone(), image_base + rva, data[o..o + l].to_vec()));
        }
    }
    out
}

fn ingest_archive(
    data: &[u8],
    arch: Architecture,
    archive: goblin::archive::Archive,
) -> Vec<(String, u64, Vec<u8>)> {
    let mut out = Vec::new();
    for (name, member, _) in archive.summarize() {
        let start = member.offset as usize;
        let end = start + member.size();
        if end > data.len() {
            continue;
        }
        let member_data = &data[start..end];
        // Each archive member is typically an ELF relocatable object.
        let before = out.len();
        if let Ok(goblin::Object::Elf(_)) = goblin::Object::parse(member_data) {
            out.extend(ingest_elf(member_data, arch));
        } else if let Ok(goblin::Object::Mach(m)) = goblin::Object::parse(member_data) {
            out.extend(ingest_macho(member_data, arch, m));
        }
        let added = out.len() - before;
        if added > 0 {
            eprintln!("  [{}]: +{}", name, added);
        }
    }
    out
}

fn ingest_elf(data: &[u8], arch: Architecture) -> Vec<(String, u64, Vec<u8>)> {
    use goblin::elf::{sym::STT_FUNC, Elf};
    let elf = match Elf::parse(data) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    // Build addr → file offset via program headers.
    let mut segs: Vec<(u64, u64, u64, u64)> = elf
        .program_headers
        .iter()
        .filter(|ph| ph.p_type == goblin::elf::program_header::PT_LOAD)
        .map(|ph| {
            (
                ph.p_vaddr,
                ph.p_vaddr + ph.p_memsz,
                ph.p_offset,
                ph.p_filesz,
            )
        })
        .collect();
    segs.sort_by_key(|s| s.0);
    let va_to_off = |va: u64, sz: u64| -> Option<(usize, usize)> {
        for (start, end, off, filesz) in &segs {
            if va >= *start && va + sz <= *end {
                let d = va - start;
                if d + sz > *filesz {
                    return None;
                }
                return Some(((off + d) as usize, sz as usize));
            }
        }
        None
    };
    let _ = arch;
    let mut out = Vec::new();
    for sym in elf.syms.iter().chain(elf.dynsyms.iter()) {
        if sym.st_type() != STT_FUNC {
            continue;
        }
        if sym.st_value == 0 || sym.st_size == 0 {
            continue;
        }
        // AArch32/Thumb: low bit of st_value is Thumb marker; align.
        let va = sym.st_value & !1;
        let (off, len) = match va_to_off(va, sym.st_size) {
            Some(x) => x,
            None => continue,
        };
        if off + len > data.len() {
            continue;
        }
        let name = match elf
            .strtab
            .get_at(sym.st_name)
            .or(elf.dynstrtab.get_at(sym.st_name))
        {
            Some(n) => n.to_string(),
            None => continue,
        };
        if name.is_empty() {
            continue;
        }
        out.push((name, va, data[off..off + len].to_vec()));
    }
    out
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(1);
        }
    };

    let mut db = FidDb::new();
    let lib_id = db.add_lib(&args.lib);

    // Two-pass: first compute full hashes, then recompute specific hash
    // with a name→full map for direct-call disambiguation.
    let mut funcs: Vec<(String, u64, Vec<u8>)> = Vec::new();
    for path in &args.inputs {
        let data = match fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("skip {path}: {e}");
                continue;
            }
        };
        let before = funcs.len();
        funcs.extend(ingest_any(&data, args.arch));
        eprintln!(
            "{}: {} funcs",
            Path::new(path).file_name().unwrap().to_string_lossy(),
            funcs.len() - before
        );
    }

    // Pass 1: full hash only.
    let mut addr_to_full: HashMap<u64, u64> = HashMap::new();
    let mut pending: Vec<(String, u64, Vec<u8>)> = Vec::new();
    for (name, va, body) in funcs {
        if let Some(h) = fingerprint(args.arch, &body, va, |_| None) {
            addr_to_full.insert(va, h.full);
            pending.push((name, va, body));
        }
    }

    // Pass 2: specific hash with callee lookup.
    let mut kept = 0usize;
    for (name, va, body) in &pending {
        if let Some(h) = fingerprint(args.arch, body, *va, |t| addr_to_full.get(&t).copied()) {
            db.insert(FidEntry {
                hash: h,
                lib_id,
                name: name.clone(),
            });
            kept += 1;
        }
    }
    eprintln!("wrote {} entries -> {}", kept, args.out);
    let f = match fs::File::create(&args.out) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("create {}: {e}", args.out);
            return ExitCode::from(2);
        }
    };
    if let Err(e) = db.write(f) {
        eprintln!("write: {e}");
        return ExitCode::from(3);
    }
    ExitCode::SUCCESS
}
