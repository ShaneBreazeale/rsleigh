use std::path::Path;

use rsleigh::codegen::GeneratedModuleKind;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let archs: Vec<&str> = if args.len() > 1 {
        args[1..].iter().map(|s| s.as_str()).collect()
    } else {
        vec!["x86-64", "aarch64", "riscv", "mips", "arm32"]
    };

    for arch in &archs {
        match *arch {
            "x86-64" | "x86" => generate_arch(
                "x86-64",
                Path::new("slaspec/x86/x86-64.slaspec"),
                "x86",
                200,
                8,
            ),
            "aarch64" | "arm64" => generate_arch(
                "aarch64",
                Path::new("slaspec/AARCH64/AARCH64.slaspec"),
                "aarch64",
                200,
                4,
            ),
            "mips" | "mips32" => generate_arch(
                "mips32",
                Path::new("slaspec/MIPS/mips32be.slaspec"),
                "mips",
                200,
                2,
            ),
            "arm32" | "arm" => generate_arch(
                "arm32",
                Path::new("slaspec/ARM/ARM7_le_base.slaspec"),
                "arm32",
                200,
                2,
            ),
            "riscv" | "riscv64" => generate_arch(
                "riscv64",
                Path::new("slaspec/RISCV/riscv.lp64d.slaspec"),
                "riscv",
                200,
                2,
            ),
            other => {
                eprintln!("Unknown arch: {other}. Supported: x86-64, aarch64");
                std::process::exit(1);
            }
        }
    }
}

fn generate_arch(
    display_name: &str,
    slaspec: &Path,
    prefix: &str,
    constructors_per_file: usize,
    num_batches: usize,
) {
    let out_dir = Path::new("generated");

    eprintln!("Parsing {display_name} slaspec...");
    let modules = rsleigh::codegen::generate_split_disassembler(
        slaspec,
        constructors_per_file,
        "PLACEHOLDER",
    )
    .expect(&format!("failed to generate {display_name} disassembler"));

    let mut instr_files = Vec::new();
    let mut subtable_files = Vec::new();

    for m in &modules {
        match m.kind {
            GeneratedModuleKind::Shared | GeneratedModuleKind::Root => {}
            GeneratedModuleKind::TableBatch => instr_files.push(m),
            GeneratedModuleKind::TableEnum => subtable_files.push(m),
        }
    }

    eprintln!(
        "  {} modules: {} instruction files, {} subtable files",
        modules.len(),
        instr_files.len(),
        subtable_files.len()
    );

    // Write shared.rs
    let shared_dir = out_dir.join(format!("{prefix}-shared/out"));
    std::fs::create_dir_all(&shared_dir).unwrap();
    let shared = modules.iter().find(|m| m.filename == "shared.rs").unwrap();
    write_module(&shared_dir.join("shared.rs"), shared);

    // Write subtables
    let subtable_dir = out_dir.join(format!("{prefix}-subtables/out"));
    std::fs::create_dir_all(&subtable_dir).unwrap();
    {
        let mut combined = String::new();
        for m in &subtable_files {
            let code = get_code(m);
            let code = strip_super_import(&code);
            combined.push_str(&code);
            combined.push('\n');
        }
        std::fs::write(subtable_dir.join("subtables.rs"), &combined).unwrap();
        eprintln!("  subtables: {:.1} KB", combined.len() as f64 / 1e3);
    }

    // Separate recursive constructors from non-recursive
    let mut recursive_code = String::new();
    let mut nonrecursive_files: Vec<String> = Vec::new();

    for m in &instr_files {
        let code = strip_super_import(&get_code(m));
        if code.contains("Tableinstruction") {
            recursive_code.push_str(&code);
            recursive_code.push('\n');
        } else {
            nonrecursive_files.push(code);
        }
    }

    // Split non-recursive into batches
    let actual_batches = num_batches.min(nonrecursive_files.len().max(1));
    let files_per_batch = if nonrecursive_files.is_empty() {
        1
    } else {
        (nonrecursive_files.len() + actual_batches - 1) / actual_batches
    };

    for batch_idx in 0..actual_batches {
        let batch_name = format!("{prefix}-instr-{:02}", batch_idx);
        let batch_dir = out_dir.join(&batch_name).join("out");
        std::fs::create_dir_all(&batch_dir).unwrap();

        let start = batch_idx * files_per_batch;
        let end = (start + files_per_batch).min(nonrecursive_files.len());
        let mut combined = String::new();
        for code in &nonrecursive_files[start..end] {
            combined.push_str(code);
            combined.push('\n');
        }
        std::fs::write(batch_dir.join("batch.rs"), &combined).unwrap();
        eprintln!(
            "  {batch_name}: {:.1} KB ({} files)",
            combined.len() as f64 / 1e3,
            end - start
        );
    }

    // Write empty batches for unused slots (so crate shells don't fail)
    for batch_idx in actual_batches..num_batches {
        let batch_name = format!("{prefix}-instr-{:02}", batch_idx);
        let batch_dir = out_dir.join(&batch_name).join("out");
        std::fs::create_dir_all(&batch_dir).unwrap();
        std::fs::write(batch_dir.join("batch.rs"), "").unwrap();
    }

    // Write root.rs
    let root_dir = out_dir.join(format!("{prefix}-root/out"));
    std::fs::create_dir_all(&root_dir).unwrap();
    let root = modules.iter().find(|m| m.filename == "root.rs").unwrap();
    let mut parse_fn = if let Some(raw) = &root.raw_code {
        let mut result = String::new();
        if let Some(idx) = raw.find("pub fn parse_instruction") {
            result.push_str(&raw[idx..]);
        }
        for i in 0..300 {
            result = result.replace(&format!("table_{} :: ", i), "");
        }
        result
    } else {
        root.code.to_string()
    };

    let mut root_code = String::new();
    root_code.push_str(&recursive_code);
    root_code.push('\n');
    root_code.push_str(&parse_fn);
    std::fs::write(root_dir.join("root.rs"), &root_code).unwrap();
    eprintln!("  root: {:.1} KB", root_code.len() as f64 / 1e3);

    eprintln!("  Done!");
}

fn get_code(m: &rsleigh::codegen::GeneratedModule) -> String {
    if let Some(raw) = &m.raw_code {
        raw.clone()
    } else {
        m.code.to_string()
    }
}

fn strip_super_import(code: &str) -> String {
    code.replace("# [allow (unused_imports)] use super :: * ;", "")
}

fn write_module(path: &Path, m: &rsleigh::codegen::GeneratedModule) {
    if let Some(raw) = &m.raw_code {
        std::fs::write(path, raw).unwrap();
    } else {
        std::fs::write(path, m.code.to_string()).unwrap();
    }
}
