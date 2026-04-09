use std::io::Write;
use std::path::Path;

fn main() {
    let slaspec = Path::new("../slaspec/x86/x86-64.slaspec");
    println!("cargo::rerun-if-changed={}", slaspec.display());

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let sub_dir = Path::new(&out_dir).join("x86_64");
    std::fs::create_dir_all(&sub_dir).unwrap();

    eprintln!("Generating x86-64 disassembler (split mode)...");
    let modules = rsleigh::codegen::generate_split_disassembler(
        slaspec,
        200, // constructors per file
        sub_dir.to_str().unwrap(),
    )
    .expect("failed to generate disassembler");

    for m in &modules {
        let path = sub_dir.join(&m.filename);
        if let Some(raw) = &m.raw_code {
            std::fs::write(&path, raw).unwrap();
        } else {
            let code = m.code.to_string();
            std::fs::write(&path, &code).unwrap();
        }
        eprintln!("  wrote {}: {:.1} KB", m.filename, std::fs::metadata(&path).unwrap().len() as f64 / 1e3);
    }
    eprintln!("Generated {} files", modules.len());
}
