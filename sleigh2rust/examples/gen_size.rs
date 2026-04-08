use std::path::Path;
use std::io::Write;

fn main() {
    let path = Path::new("slaspec/x86/x86-64.slaspec");
    eprintln!("Generating from {}...", path.display());

    let tokens = sleigh2rust::generate_disassembler(path)
        .expect("failed to generate");

    let code = tokens.to_string();
    let total = code.len();
    eprintln!("Total generated: {} bytes ({:.1} MB)", total, total as f64 / 1e6);

    // Approximate: measure each section by markers
    // Count PcodeOp-related code (lift methods)
    let pcode_bytes: usize = code.match_indices("PcodeOp").map(|_| 8).sum();
    eprintln!("PcodeOp references: ~{} bytes", pcode_bytes);

    // Count .clone() calls
    let clone_count = code.matches(". clone ()").count();
    eprintln!(".clone() calls: {}", clone_count);

    // Count Varnode:: constructor calls
    let varnode_count = code.matches("Varnode ::").count();
    eprintln!("Varnode:: calls: {}", varnode_count);

    // Write to a file we can analyze
    let out = std::env::var("OUT_DIR").unwrap_or("/tmp".into());
    let out_path = format!("{}/x86_64_full.rs", out);
    let mut f = std::fs::File::create(&out_path).unwrap();
    write!(f, "{}", code).unwrap();
    eprintln!("Written to {}", out_path);
}
