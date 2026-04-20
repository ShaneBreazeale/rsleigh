// Round-trip smoke test against Qt5Core.
use std::fs;
use goblin::elf::{Elf, sym::STT_FUNC};
use rsleigh_api::Architecture;
use rsleigh_fid::{FidDb, identify, ingest::fingerprint};

fn same_abi_variant(a: &str, b: &str) -> bool {
    if a == b { return true; }
    for tag in ["C1E","C2E","C3E","D0E","D1E","D2E"] {
        if let Some(pa) = a.find(tag) {
            for tag2 in ["C1E","C2E","C3E","D0E","D1E","D2E"] {
                if let Some(pb) = b.find(tag2) {
                    if pa == pb && tag.as_bytes()[0] == tag2.as_bytes()[0]
                        && &a[..pa] == &b[..pb] && &a[pa+2..] == &b[pb+2..] {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn main() {
    let data = fs::read("/tmp/nekoray_bin/nekoray/usr/lib/libQt5Core.so.5").unwrap();
    let db = FidDb::read(fs::File::open("/tmp/qt5core.fidb").unwrap()).unwrap();
    let elf = Elf::parse(&data).unwrap();
    let segs: Vec<_> = elf.program_headers.iter()
        .filter(|ph| ph.p_type == goblin::elf::program_header::PT_LOAD)
        .map(|ph| (ph.p_vaddr, ph.p_vaddr + ph.p_memsz, ph.p_offset, ph.p_filesz))
        .collect();
    let va_to_off = |va: u64, sz: u64| -> Option<(usize, usize)> {
        for (s, e, o, f) in &segs {
            if va >= *s && va + sz <= *e {
                let d = va - s;
                if d + sz > *f { return None; }
                return Some(((o + d) as usize, sz as usize));
            }
        }
        None
    };
    let mut tested = 0;
    let mut matched = 0;
    let mut mismatched = 0;
    let mut multi_diff = 0;
    let mut nohit = 0;
    for sym in elf.dynsyms.iter() {
        if sym.st_type() != STT_FUNC || sym.st_size < 32 { continue; }
        let name = match elf.dynstrtab.get_at(sym.st_name) { Some(n) => n, None => continue };
        let name = name.split('@').next().unwrap_or(name);
        let va = sym.st_value & !1;
        let (o, l) = match va_to_off(va, sym.st_size) { Some(x) => x, None => continue };
        let body = &data[o..o+l];
        let got = identify(Architecture::X86_64, body, va, &db);
        match got {
            Some(n) if n == name => matched += 1,
            Some(n) if same_abi_variant(n, name) => matched += 1,
            Some(n) => { mismatched += 1; if mismatched < 5 { eprintln!("MISMATCH: want {}, got {}", name, n); } }
            None => {
                // Distinguish multi-match (different names) vs no-hit.
                if let Some(hq) = fingerprint(Architecture::X86_64, body, va, |_| None) {
                    let m = db.match_specific(hq.specific);
                    if m.is_empty() {
                        let f = db.match_full(hq.full);
                        if f.is_empty() { nohit += 1; } else { multi_diff += 1; }
                    } else {
                        multi_diff += 1;
                    }
                }
            }
        }
        tested += 1;
        if tested >= 500 { break; }
    }
    println!(
        "tested={} matched={} mismatched={} multi_diff_names={} nohit={}",
        tested, matched, mismatched, multi_diff, nohit
    );
}
