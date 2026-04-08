//! Generate a multi-crate decoder workspace from a .slaspec file.
//!
//! Usage: cargo run --example gen_workspace -- <slaspec> <output_dir> [max_constructors_per_crate]
//!
//! This produces:
//!   output_dir/
//!     Cargo.toml          (workspace)
//!     shared/             (shared types: AddrType, Register, Display, Context)
//!     chunk_N/            (constructor structs + table enums)
//!     decoder/            (root crate: re-exports + parse_instruction)

use std::io::Write;
use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let slaspec = args.get(1).expect("usage: gen_workspace <slaspec> <output_dir> [max_per_crate]");
    let output_dir = args.get(2).expect("usage: gen_workspace <slaspec> <output_dir> [max_per_crate]");
    let max_per_crate: usize = args.get(3).map(|s| s.parse().unwrap()).unwrap_or(200);

    let out = Path::new(output_dir);

    eprintln!("Generating from {} into {} (max {} constructors/crate)...",
        slaspec, output_dir, max_per_crate);

    let modules = sleigh2rust::generate_split_disassembler(
        slaspec,
        max_per_crate,
        &out.join("dummy").to_string_lossy(), // not used for actual include paths
    ).expect("failed to generate");

    // Count table files
    let table_files: Vec<_> = modules.iter()
        .filter(|m| m.filename.starts_with("table_"))
        .collect();
    let shared = modules.iter().find(|m| m.filename == "shared.rs").unwrap();
    let root = modules.iter().find(|m| m.filename == "root.rs").unwrap();

    let num_chunks = table_files.len();
    eprintln!("  {} table files, splitting into crates...", num_chunks);

    // 1. Workspace Cargo.toml
    std::fs::create_dir_all(out).unwrap();
    let mut members = vec!["shared".to_string(), "decoder".to_string()];
    for i in 0..num_chunks {
        members.push(format!("chunk_{}", i));
    }
    let members_toml: Vec<String> = members.iter().map(|m| format!("    \"{}\"", m)).collect();
    write_file(out.join("Cargo.toml"), &format!(
        "[workspace]\nmembers = [\n{}\n]\nresolver = \"2\"\n",
        members_toml.join(",\n")
    ));

    // 2. shared/ crate
    let shared_dir = out.join("shared");
    std::fs::create_dir_all(shared_dir.join("src")).unwrap();
    write_file(shared_dir.join("Cargo.toml"), &format!(
        "[package]\nname = \"x86-64-shared\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\npcode-ir = {{ path = \"{}\" }}\n",
        std::fs::canonicalize("pcode-ir").unwrap().display()
    ));
    let shared_code = shared.code.to_string();
    write_file(shared_dir.join("src/lib.rs"), &format!(
        "#![allow(non_camel_case_types, non_snake_case, unused_variables, unused_mut, unused_parens, clippy::all)]\n{}",
        shared_code
    ));

    // 3. chunk_N/ crates (each contains some table files)
    for (i, table_mod) in table_files.iter().enumerate() {
        let chunk_dir = out.join(format!("chunk_{}", i));
        std::fs::create_dir_all(chunk_dir.join("src")).unwrap();

        // Each chunk depends on shared + all other chunks (for cross-table references)
        let mut deps = format!(
            "[dependencies]\npcode-ir = {{ path = \"{}\" }}\nx86-64-shared = {{ path = \"../shared\" }}\n",
            std::fs::canonicalize("pcode-ir").unwrap().display()
        );
        for j in 0..num_chunks {
            if j != i {
                deps.push_str(&format!(
                    "x86-64-chunk-{} = {{ path = \"../chunk_{}\" }}\n", j, j
                ));
            }
        }

        write_file(chunk_dir.join("Cargo.toml"), &format!(
            "[package]\nname = \"x86-64-chunk-{}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n{}\n",
            i, deps
        ));

        let code = table_mod.code.to_string();
        // Replace `use super::*` with actual crate imports
        let code = code.replace(
            "# [allow (unused_imports)] use super :: * ;",
            &format!("pub use x86_64_shared::*;\n{}",
                (0..num_chunks).filter(|&j| j != i)
                    .map(|j| format!("pub use x86_64_chunk_{}::*;", j))
                    .collect::<Vec<_>>().join("\n")
            )
        );
        write_file(chunk_dir.join("src/lib.rs"), &format!(
            "#![allow(non_camel_case_types, non_snake_case, unused_variables, unused_mut, unused_parens, unused_imports, clippy::all)]\n{}",
            code
        ));
    }

    // 4. decoder/ crate (root: re-exports + parse_instruction)
    let decoder_dir = out.join("decoder");
    std::fs::create_dir_all(decoder_dir.join("src")).unwrap();
    let mut decoder_deps = format!(
        "[dependencies]\npcode-ir = {{ path = \"{}\" }}\nx86-64-shared = {{ path = \"../shared\" }}\n",
        std::fs::canonicalize("pcode-ir").unwrap().display()
    );
    for i in 0..num_chunks {
        decoder_deps.push_str(&format!(
            "x86-64-chunk-{} = {{ path = \"../chunk_{}\" }}\n", i, i
        ));
    }
    write_file(decoder_dir.join("Cargo.toml"), &format!(
        "[package]\nname = \"x86-64-decoder\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n{}\n",
        decoder_deps
    ));

    let root_code = if let Some(raw) = &root.raw_code {
        raw.clone()
    } else {
        root.code.to_string()
    };
    write_file(decoder_dir.join("src/lib.rs"), &format!(
        "#![allow(non_camel_case_types, non_snake_case, unused_variables, unused_mut, unused_parens, unused_imports, clippy::all)]\npub use x86_64_shared::*;\n{}\n{}",
        (0..num_chunks).map(|i| format!("pub use x86_64_chunk_{}::*;", i)).collect::<Vec<_>>().join("\n"),
        "// parse_instruction will be added here"
    ));

    eprintln!("Generated {} crates in {}", num_chunks + 2, output_dir);
}

fn write_file(path: impl AsRef<Path>, content: &str) {
    let mut f = std::fs::File::create(path.as_ref()).unwrap();
    f.write_all(content.as_bytes()).unwrap();
}
