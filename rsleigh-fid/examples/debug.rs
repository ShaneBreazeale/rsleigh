use goblin::elf::{sym::STT_FUNC, Elf};
use rsleigh_api::Architecture;
use rsleigh_fid::{ingest::fingerprint, FidDb};
use std::fs;

fn main() {
    let data = fs::read("/tmp/nekoray_bin/nekoray/usr/lib/libQt5Core.so.5").unwrap();
    let db = FidDb::read(fs::File::open("/tmp/qt5core.fidb").unwrap()).unwrap();
    let elf = Elf::parse(&data).unwrap();
    let segs: Vec<_> = elf
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
    let va_to_off = |va, sz| -> Option<(usize, usize)> {
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
    let mut multi_examples = 0;
    for sym in elf.dynsyms.iter() {
        if sym.st_type() != STT_FUNC || sym.st_size < 32 {
            continue;
        }
        let name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("");
        let name = name.split('@').next().unwrap_or(name);
        let va = sym.st_value & !1;
        let (o, l) = match va_to_off(va, sym.st_size) {
            Some(x) => x,
            None => continue,
        };
        let body = &data[o..o + l];
        if let Some(hq) = fingerprint(Architecture::X86_64, body, va, |_| None) {
            let m = db.match_specific(hq.specific);
            if m.len() > 1 {
                let names: Vec<&str> = m.iter().map(|i| db.entries[*i].name.as_str()).collect();
                let distinct: std::collections::HashSet<&str> = names.iter().copied().collect();
                if distinct.len() > 1 {
                    multi_examples += 1;
                    if multi_examples <= 3 {
                        println!(
                            "QUERY: {} ({} bytes, {} units)",
                            name, hq.body_len, hq.code_units
                        );
                        println!("  matches ({}):", m.len());
                        for n in distinct.iter().take(5) {
                            println!("    {}", n);
                        }
                    }
                }
            }
            if multi_examples >= 3 {
                break;
            }
        }
    }
    println!("total multi-diff examples: {}", multi_examples);
}
