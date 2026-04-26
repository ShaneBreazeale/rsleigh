//! Regression tests for string literal false positives in Load addresses.
//!
//! Spec: docs/superpowers/specs/2026-04-17-string-false-positive-design.md

fn decompile_func(func_va: u64, max_len: usize) -> Option<String> {
    use pcode_ir::PcodeOp;
    use rsleigh_api::{Architecture, Decoder};

    let path = "/Users/shane/Downloads/test_bin/cb_baristas_secret_x64.exe";
    let data = std::fs::read(path).ok()?;
    let pe = goblin::pe::PE::parse(&data).ok()?;
    let image_base = pe.image_base as u64;
    let rva = func_va - image_base;
    let mut file_off = None;
    for s in &pe.sections {
        let s_va = s.virtual_address as u64;
        let s_sz = s.virtual_size as u64;
        if rva >= s_va && rva < s_va + s_sz {
            file_off = Some((s.pointer_to_raw_data as u64 + (rva - s_va)) as usize);
            break;
        }
    }
    let off = file_off?;
    let func_len = max_len.min(data.len() - off);
    let bytes = data[off..off + func_len].to_vec();

    let mut dec = Decoder::new(Architecture::X86_64);
    let mut insts = Vec::new();
    let mut io = 0usize;
    while io < bytes.len() {
        match dec.decode(&bytes[io..], func_va + io as u64) {
            Ok(inst) => {
                let is_ret = inst
                    .ops
                    .iter()
                    .any(|op| matches!(op, PcodeOp::Return { .. }));
                let l = inst.len as usize;
                insts.push((func_va + io as u64, inst));
                io += l;
                if is_ret {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    let out = rsleigh_decompile::decompile_with_binary(
        Architecture::X86_64,
        &insts,
        Some(&data),
        Some(std::path::Path::new(path)),
    );
    Some(out)
}

/// Primary test: no string literal may appear as a Load address in 0x140001154.
/// Catches all deref-of-string patterns: *("...") or *(type*)("...").
/// Before the fix this emits *(*("ȡ")), *("`@"), etc.
#[test]
fn no_string_literal_as_load_address() {
    let handle = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let out = match decompile_func(0x140001154, 0x400) {
                Some(s) => s,
                None => {
                    eprintln!("skipping: fixture not found");
                    return;
                }
            };

            // Check for any deref-of-string-literal pattern: *("...") anywhere in output
            let bad_lines: Vec<&str> = out
                .lines()
                .filter(|l| {
                    // *(  "  — direct deref of string
                    // *( something *)( "  — typed deref of string
                    (l.contains("*(\"")) || (l.contains("*(") && l.contains("*)(\""))
                })
                .collect();
            assert!(
                bad_lines.is_empty(),
                "string literal used as load address:\n{}",
                bad_lines.join("\n")
            );
        })
        .expect("thread spawn");
    handle.join().expect("test panicked");
}

/// Positive guard: after the fix, the load positions must show DAT_ names or hex.
/// Prevents a vacuous pass where the output is just empty.
#[test]
fn load_address_uses_dat_or_hex() {
    let handle = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let out = match decompile_func(0x140001154, 0x400) {
                Some(s) => s,
                None => {
                    eprintln!("skipping: fixture not found");
                    return;
                }
            };
            assert!(
                out.contains("DAT_") || out.contains("0x1400"),
                "expected DAT_ or hex address in output after fix:\n{}",
                out
            );
        })
        .expect("thread spawn");
    handle.join().expect("test panicked");
}

/// Regression guard: real long strings (≥4 chars) in .rdata must still be resolved.
/// Function 0x140001a68 passes "v`cav``|rarqzprQAVD>" (19 chars) — must still appear.
#[test]
fn real_strings_still_resolved() {
    let handle = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let out = match decompile_func(0x140001a68, 0x400) {
                Some(s) => s,
                None => {
                    eprintln!("skipping: fixture not found");
                    return;
                }
            };
            assert!(
                out.contains("\"v`cav"),
                "real string literal was suppressed by the fix:\n{}",
                out
            );
        })
        .expect("thread spawn");
    handle.join().expect("test panicked");
}
