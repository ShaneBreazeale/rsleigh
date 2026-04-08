use std::io::Write;
use std::path::Path;

fn main() {
    let slaspec = Path::new("../slaspec/x86/x86-64.slaspec");
    println!("cargo::rerun-if-changed={}", slaspec.display());

    eprintln!("Generating x86-64 disassembler...");
    let tokens = rsleigh::codegen::generate_disassembler(slaspec)
        .expect("failed to generate disassembler");

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let out_path = Path::new(&out_dir).join("x86_64.rs");
    let code = tokens.to_string();
    eprintln!("Generated {:.1} MB", code.len() as f64 / 1e6);
    let mut f = std::fs::File::create(&out_path).unwrap();
    write!(f, "{}", code).unwrap();
}
