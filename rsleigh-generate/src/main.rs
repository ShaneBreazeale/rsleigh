use std::path::Path;

fn main() {
    let slaspec = Path::new("slaspec/x86/x86-64.slaspec");
    let out_dir = Path::new("generated");

    eprintln!("Parsing x86-64 slaspec...");
    let modules = rsleigh::codegen::generate_split_disassembler(
        slaspec,
        200, // constructors per file for instruction table batching
        "PLACEHOLDER", // not used for multi-crate mode
    )
    .expect("failed to generate disassembler");

    // Categorize modules:
    // - shared.rs -> x86-shared/out/shared.rs
    // - table_0..23 -> instruction table (split into 8 batches of 3 files)
    // - table_24..259 -> subtables (all into one crate)
    // - root.rs -> x86-root/out/root.rs

    // Find the boundary between instruction table files and subtable files
    // Instruction table files contain "instructionVar" constructors
    let mut instr_files = Vec::new();
    let mut subtable_files = Vec::new();

    for m in &modules {
        if m.filename == "shared.rs" || m.filename == "root.rs" {
            continue;
        }
        let code_str = if let Some(raw) = &m.raw_code {
            raw.clone()
        } else {
            m.code.to_string()
        };
        if code_str.contains("instructionVar") || code_str.contains("Tableinstruction") {
            instr_files.push(m);
        } else {
            subtable_files.push(m);
        }
    }

    eprintln!(
        "Generated {} modules: {} instruction files, {} subtable files",
        modules.len(),
        instr_files.len(),
        subtable_files.len()
    );

    // Write shared.rs
    let shared_dir = out_dir.join("x86-shared/out");
    std::fs::create_dir_all(&shared_dir).unwrap();
    let shared = modules.iter().find(|m| m.filename == "shared.rs").unwrap();
    write_module(&shared_dir.join("shared.rs"), shared);
    eprintln!("  wrote x86-shared/out/shared.rs");

    // Write subtables (all into one file with individual module includes)
    let subtable_dir = out_dir.join("x86-subtables/out");
    std::fs::create_dir_all(&subtable_dir).unwrap();
    {
        let mut combined = String::new();
        for m in &subtable_files {
            let code = if let Some(raw) = &m.raw_code {
                raw.clone()
            } else {
                m.code.to_string()
            };
            // Replace "use super::*;" with nothing (imports come from lib.rs)
            let code = code.replace("# [allow (unused_imports)] use super :: * ;", "");
            combined.push_str(&code);
            combined.push('\n');
        }
        std::fs::write(subtable_dir.join("subtables.rs"), &combined).unwrap();
        eprintln!(
            "  wrote x86-subtables/out/subtables.rs ({:.1} KB)",
            combined.len() as f64 / 1e3
        );
    }

    // Separate recursive instruction constructors (those referencing Tableinstruction)
    // from non-recursive ones. Recursive ones go into x86-root with the enum.
    let mut recursive_code = String::new();
    let mut nonrecursive_files: Vec<String> = Vec::new();

    for m in &instr_files {
        let code = if let Some(raw) = &m.raw_code {
            raw.clone()
        } else {
            m.code.to_string()
        };
        let code = code.replace("# [allow (unused_imports)] use super :: * ;", "");
        if code.contains("Tableinstruction") {
            // Both recursive constructors and the enum go to root
            recursive_code.push_str(&code);
            recursive_code.push('\n');
        } else {
            nonrecursive_files.push(code);
        }
    }

    eprintln!(
        "  {} non-recursive instruction files, {:.1} KB recursive",
        nonrecursive_files.len(),
        recursive_code.len() as f64 / 1e3,
    );

    // Split non-recursive files into 8 batches
    let num_batches = 8;
    let files_per_batch = (nonrecursive_files.len() + num_batches - 1) / num_batches;

    for batch_idx in 0..num_batches {
        let batch_name = format!("x86-instr-{:02}", batch_idx);
        let batch_dir = out_dir.join(&batch_name).join("out");
        std::fs::create_dir_all(&batch_dir).unwrap();

        let start = batch_idx * files_per_batch;
        let end = (start + files_per_batch).min(nonrecursive_files.len());

        let mut combined = String::new();
        if start < end {
            for code in &nonrecursive_files[start..end] {
                combined.push_str(code);
                combined.push('\n');
            }
        }
        std::fs::write(batch_dir.join("batch.rs"), &combined).unwrap();
        eprintln!(
            "  wrote {}/out/batch.rs ({:.1} KB, {} files)",
            batch_name,
            combined.len() as f64 / 1e3,
            end.saturating_sub(start),
        );
    }

    // Write root.rs: recursive constructors + instruction enum + parse_instruction
    let root_dir = out_dir.join("x86-root/out");
    std::fs::create_dir_all(&root_dir).unwrap();
    let root = modules.iter().find(|m| m.filename == "root.rs").unwrap();
    let parse_fn = if let Some(raw) = &root.raw_code {
        let mut result = String::new();
        if let Some(idx) = raw.find("pub fn parse_instruction") {
            result.push_str(&raw[idx..]);
        }
        // Remove module-prefixed paths (e.g. "table_23 :: Tableinstruction" -> "Tableinstruction")
        // These come from the old include!()-based split approach
        for i in 0..300 {
            result = result.replace(&format!("table_{} :: ", i), "");
        }
        result
    } else {
        root.code.to_string()
    };

    // recursive_code already includes both recursive constructors AND the enum file
    // (anything containing "Tableinstruction"), so no need to add enum separately
    let mut root_code = String::new();
    root_code.push_str(&recursive_code);
    root_code.push('\n');
    root_code.push_str(&parse_fn);

    std::fs::write(root_dir.join("root.rs"), &root_code).unwrap();
    eprintln!(
        "  wrote x86-root/out/root.rs ({:.1} KB)",
        root_code.len() as f64 / 1e3
    );

    eprintln!("Done! Now run: cargo build -p x86-root");
}

fn write_module(path: &Path, m: &rsleigh::codegen::GeneratedModule) {
    if let Some(raw) = &m.raw_code {
        std::fs::write(path, raw).unwrap();
    } else {
        std::fs::write(path, m.code.to_string()).unwrap();
    }
}
