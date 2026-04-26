//! VM packer / obfuscator family fingerprinting from PE section layout.
//!
//! Many commercial-style protection schemes leave a recognisable "shape" in
//! the section table: randomised lowercase-alphanumeric section names,
//! tiny seed-blob sections, a single large executable section, sometimes a
//! runtime-populated function-pointer table. When the shape matches, we
//! can emit a one-line hint that tells the analyst what they're dealing
//! with before they spend hours figuring it out manually.
//!
//! Current catalogue:
//!   - **PyVMProtect** — author's signature scheme (`r/ReverseEngineering`
//!     posts, `crackmev3.pyd`, `crackmev5.pyd`, ...). Recognisable by:
//!       * Single executable section with a 5-character lowercase-
//!         alphanumeric random-looking name (e.g. `.7qx3j`, `.2z7n8`).
//!       * Three or four 8-byte read-only sections (the seed blobs the
//!         init chain consumes).
//!       * A 256-byte RW `.fptable` section that holds runtime-resolved
//!         Win32 API pointers.
//!       * One large `.irfts`-style RO section that carries the encrypted
//!         IAT names + 209-string pool.
//!       * One `.2ke3f`-style RW section holding sbox / vtable / seeds.

use goblin::Object;

/// Result of a fingerprint pass. `family` is human-readable. `notes` is
/// a short list of lines describing the strongest signals.
#[derive(Debug, Clone)]
pub struct Fingerprint {
    pub family: &'static str,
    pub notes: Vec<String>,
}

/// Looks at a parsed `goblin::Object` and returns a `Fingerprint` if it
/// matches a known VM-packer shape. Currently recognises only the
/// PyVMProtect family.
pub fn detect(obj: &Object<'_>) -> Option<Fingerprint> {
    match obj {
        Object::PE(pe) => detect_pe(pe),
        _ => None,
    }
}

fn is_random_lowercase_alphanumeric(name: &str) -> bool {
    // Strip leading dot.
    let stem = name.strip_prefix('.').unwrap_or(name);
    if stem.len() < 4 || stem.len() > 6 {
        return false;
    }
    if !stem.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()) {
        return false;
    }
    // Reject well-known names that happen to be all-lowercase: text, data,
    // bss, rdata, idata, edata, pdata, rsrc, reloc, tls, crt, debug, init,
    // bound, srdata, sxdata, ndata, rodata, sdata, sbss.
    matches!(
        stem,
        "text" | "data" | "bss" | "rdata" | "idata" | "edata" | "pdata"
            | "rsrc" | "reloc" | "tls" | "debug" | "init"
            | "bound" | "srdata" | "sxdata" | "ndata" | "rodata"
            | "sdata" | "sbss" | "got" | "plt" | "fini" | "ctors" | "dtors"
            | "rsrcz"
    )
    .not()
}

trait BoolNot {
    fn not(self) -> bool;
}
impl BoolNot for bool {
    fn not(self) -> bool {
        !self
    }
}

fn detect_pe(pe: &goblin::pe::PE) -> Option<Fingerprint> {
    let sections = &pe.sections;
    if sections.is_empty() {
        return None;
    }

    let mut signals = Vec::new();
    let mut random_named: Vec<String> = Vec::new();
    let mut seed_blob_count = 0usize;
    let mut has_fptable = false;
    let mut large_exec_random = false;
    let mut total_random = 0usize;

    for section in sections {
        let name = section.name().unwrap_or("");
        let vsize = section.virtual_size as usize;

        if name == ".fptable" {
            has_fptable = true;
        }
        if is_random_lowercase_alphanumeric(name) {
            total_random += 1;
            if vsize == 8 {
                seed_blob_count += 1;
            }
            // Single large executable random-named section is the
            // signature.
            const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
            if (section.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0
                && vsize >= 0x10_000
            {
                large_exec_random = true;
            }
            random_named.push(name.to_string());
        }
    }

    // Score the signals. PyVMProtect needs at minimum:
    //   - One large random-named executable section
    //   - At least 2 8-byte seed blobs
    //   - .fptable section
    let strong = large_exec_random && seed_blob_count >= 2 && has_fptable;
    if !strong {
        return None;
    }

    if large_exec_random {
        signals.push(format!(
            "single large executable section with random name ({})",
            random_named
                .iter()
                .find(|n| !n.is_empty())
                .cloned()
                .unwrap_or_default()
        ));
    }
    if seed_blob_count >= 2 {
        signals.push(format!(
            "{} ×8-byte seed-blob sections (random-named)",
            seed_blob_count
        ));
    }
    if has_fptable {
        signals.push("`.fptable` runtime-populated API pointer table".to_string());
    }
    if total_random >= 5 {
        signals.push(format!(
            "{} total randomised section names — typical PyVMProtect template",
            total_random
        ));
    }

    Some(Fingerprint {
        family: "PyVMProtect",
        notes: signals,
    })
}

/// Produce the multi-line banner the CLI prints when a fingerprint is hit.
pub fn banner(fp: &Fingerprint) -> String {
    let mut out = String::new();
    out.push_str(&format!("// [vm-fingerprint] family: {}\n", fp.family));
    for n in &fp.notes {
        out.push_str(&format!("//   - {}\n", n));
    }
    if fp.family == "PyVMProtect" {
        out.push_str("// hint: VM dispatcher likely reads opcode → sbox lookup → ");
        out.push_str("vtable XOR → CALL [trampoline].\n");
        out.push_str(
            "// hint: const-pool resolver decrypts type-tagged entries via PCG \
             keystream — buffer alloc happens BEFORE tag check, so unknown \
             tags can leak plaintext into scratch heap.\n",
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_alphanumeric_names_match() {
        assert!(is_random_lowercase_alphanumeric(".7qx3j"));
        assert!(is_random_lowercase_alphanumeric(".2z7n8"));
        assert!(is_random_lowercase_alphanumeric(".jwvaz"));
        assert!(is_random_lowercase_alphanumeric(".hylll"));
    }

    #[test]
    fn standard_names_rejected() {
        assert!(!is_random_lowercase_alphanumeric(".text"));
        assert!(!is_random_lowercase_alphanumeric(".data"));
        assert!(!is_random_lowercase_alphanumeric(".rdata"));
        assert!(!is_random_lowercase_alphanumeric(".pdata"));
        assert!(!is_random_lowercase_alphanumeric(".reloc"));
        assert!(!is_random_lowercase_alphanumeric(".rsrc"));
        assert!(!is_random_lowercase_alphanumeric(".bss"));
    }

    #[test]
    fn uppercase_or_long_rejected() {
        assert!(!is_random_lowercase_alphanumeric(".TEXT"));
        assert!(!is_random_lowercase_alphanumeric(".verylongname"));
        assert!(!is_random_lowercase_alphanumeric(".x"));
    }
}
