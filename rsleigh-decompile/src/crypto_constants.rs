//! Crypto / hash constant annotation.
//!
//! Many cryptographic and hash routines pin specific magic 32-bit constants
//! into their inner loops. When we see one of those values flow into an
//! IMUL / XOR site, the surrounding code is almost certainly that
//! algorithm's compress / round / mixing function. Annotating the constant
//! up-front gives the reader the algorithm name without forcing a search.
//!
//! This catalogue is high-precision — each entry is rare enough that a
//! random 4-byte constant has effectively zero chance of colliding with one
//! of these values. The annotation is therefore safe to emit unconditionally
//! whenever a 4-byte constant matches.
//!
//! Catalogue draws on the public RE corpus (Wikipedia, Crypto++ source,
//! reference implementations) and direct observation from PyVMProtect-style
//! crackme RE — see `repos/CrackMe_PyVMP_v5/WHITEPAPER.md` for the
//! motivating session, which used PCG / FNV / Knuth all in one resolver
//! and benefits a lot from inline naming.

use std::collections::HashMap;
use std::sync::LazyLock;

/// Single catalogue entry. Algorithm name + role of this constant in it.
#[derive(Clone, Copy, Debug)]
pub struct Annotation {
    pub algorithm: &'static str,
    pub role: &'static str,
}

const ENTRIES: &[(u32, &str, &str)] = &[
    // ── Knuth / Fibonacci hashing ───────────────────────────────────────
    // The "golden ratio" 32-bit Knuth multiplicative-hash multiplier.
    // Appears in CityHash, MurmurHash3 mixing, PyVMProtect VM dispatch,
    // many custom hash routines.
    (0x9e3779b9, "Knuth", "golden ratio multiplier"),
    (0x61c88647, "Knuth", "golden ratio (signed-negation form)"),
    // ── FNV (Fowler-Noll-Vo) ────────────────────────────────────────────
    (0x01000193, "FNV-1", "32-bit prime"),
    (0x811c9dc5, "FNV-1", "32-bit init / offset basis"),
    // Note: FNV 64-bit prime is 0x100000001b3 (33 bits) — out of range for
    // this 32-bit catalogue. Caller-side detection only.
    // ── PCG (Permuted Congruential Generator) ───────────────────────────
    // From O'Neill's "PCG: A Family of Simple Fast Space-Efficient
    // Statistically Good Algorithms for Random Number Generation" (2014).
    // Common in modern obfuscation as a keystream PRNG.
    (0x045d9f3b, "PCG", "32-bit hash multiplier 1"),
    (0x27d4eb2d, "PCG", "32-bit hash multiplier 2"),
    (0x165667b1, "PCG", "32-bit hash additive"),
    (
        0x3d4d51cb,
        "PCG",
        "Murmur-style finalizer multiplier (signed-neg)",
    ),
    (
        0xc2b2ae35,
        "PCG",
        "Murmur-style finalizer multiplier (unsigned)",
    ),
    // ── MurmurHash3 ─────────────────────────────────────────────────────
    (0xcc9e2d51, "MurmurHash3", "x86_32 c1"),
    (0x1b873593, "MurmurHash3", "x86_32 c2"),
    (0x85ebca6b, "MurmurHash3", "x86_32 finalizer m1"),
    (
        0xc2b2ae35_u32.wrapping_mul(0),
        "MurmurHash3",
        "x86_32 finalizer m2",
    ), // dup
    (0x239b961b, "MurmurHash3", "x86_128 c1"),
    (0xab0e9789, "MurmurHash3", "x86_128 c2"),
    (0x38b34ae5, "MurmurHash3", "x86_128 c3"),
    (0xa1e38b93, "MurmurHash3", "x86_128 c4"),
    // ── DJB2 family ─────────────────────────────────────────────────────
    (5381, "DJB2", "init / offset basis"),
    (33, "DJB2", "step multiplier (33)"),
    // ── CRC-32 (IEEE 802.3) ─────────────────────────────────────────────
    (0xedb88320, "CRC-32", "reversed polynomial (Ethernet)"),
    (0x04c11db7, "CRC-32", "forward polynomial"),
    // ── CRC-32C (Castagnoli) ────────────────────────────────────────────
    (0x82f63b78, "CRC-32C", "reversed polynomial (iSCSI/SSE4.2)"),
    (0x1edc6f41, "CRC-32C", "forward polynomial"),
    // ── SHA-256 H0 init constants ───────────────────────────────────────
    // First 32 bits of fractional parts of square roots of first 8 primes.
    (0x6a09e667, "SHA-256", "H0[0]"),
    (0xbb67ae85, "SHA-256", "H0[1]"),
    (0x3c6ef372, "SHA-256", "H0[2]"),
    (0xa54ff53a, "SHA-256", "H0[3]"),
    (0x510e527f, "SHA-256", "H0[4]"),
    (0x9b05688c, "SHA-256", "H0[5]"),
    (0x1f83d9ab, "SHA-256", "H0[6]"),
    (0x5be0cd19, "SHA-256", "H0[7]"),
    // SHA-256 K[0..15] — first 16 round constants. Catching any one or
    // two of these in an inner loop is enough to ID the algorithm.
    (0x428a2f98, "SHA-256", "K[0]"),
    (0x71374491, "SHA-256", "K[1]"),
    (0xb5c0fbcf, "SHA-256", "K[2]"),
    (0xe9b5dba5, "SHA-256", "K[3]"),
    (0x3956c25b, "SHA-256", "K[4]"),
    (0x59f111f1, "SHA-256", "K[5]"),
    (0x923f82a4, "SHA-256", "K[6]"),
    (0xab1c5ed5, "SHA-256", "K[7]"),
    // ── SHA-1 init ──────────────────────────────────────────────────────
    (0x67452301, "SHA-1/MD5", "h0/A init"),
    (0xefcdab89, "SHA-1/MD5", "h1/B init"),
    (0x98badcfe, "SHA-1/MD5", "h2/C init"),
    (0x10325476, "SHA-1/MD5", "h3/D init"),
    (0xc3d2e1f0, "SHA-1", "h4 init"),
    (0x5a827999, "SHA-1", "K1 (rounds 0-19)"),
    (0x6ed9eba1, "SHA-1", "K2 (rounds 20-39)"),
    (0x8f1bbcdc, "SHA-1", "K3 (rounds 40-59)"),
    (0xca62c1d6, "SHA-1", "K4 (rounds 60-79)"),
    // ── MD5 round shifts (S table — less common, skipped) ───────────────
    // T constants from sin function (first 16). Match any → MD5 likely.
    (0xd76aa478, "MD5", "T[1]"),
    (0xe8c7b756, "MD5", "T[2]"),
    (0x242070db, "MD5", "T[3]"),
    (0xc1bdceee, "MD5", "T[4]"),
    (0xf57c0faf, "MD5", "T[5]"),
    // ── ChaCha / Salsa20 ────────────────────────────────────────────────
    (0x61707865, "ChaCha20/Salsa20", "constant 'expa'"),
    (0x3320646e, "ChaCha20/Salsa20", "constant 'nd 3'"),
    (0x79622d32, "ChaCha20/Salsa20", "constant '2-by'"),
    (0x6b206574, "ChaCha20/Salsa20", "constant 'te k'"),
    // ── AES Rcon ────────────────────────────────────────────────────────
    // Single-byte Rcon values are too low-entropy. AES-specific 32-bit
    // values are typically embedded in the SBox / InvSBox tables which we
    // don't catalogue at constant level.
    // ── XXH (xxHash) ────────────────────────────────────────────────────
    (0x9e3779b1, "xxHash", "PRIME32_2"),
    (0x85ebca77, "xxHash", "PRIME32_3"),
    (0xc2b2ae3d, "xxHash", "PRIME32_4"),
    (0x27d4eb2f, "xxHash", "PRIME32_5"),
    // ── Adler-32 ────────────────────────────────────────────────────────
    (65521, "Adler-32", "modulus"),
    // ── Mersenne Twister (MT19937) ──────────────────────────────────────
    (0x9908b0df, "MT19937", "twist matrix MAGIC"),
    (0x6c078965, "MT19937", "init multiplier"),
    // ── PyVMProtect-specific (observed in v5) ──────────────────────────
    (0x6b43a9b1, "PyVMProtect", "string-rotation XOR multiplier"),
    (0x12cf2b23, "PyVMProtect", "seed integrity-check XOR"),
    (0x56951cea, "PyVMProtect", "bytecode pass-1 mix"),
    (0xa96ae315, "PyVMProtect", "bytecode pass-2 mix A"),
    (0xac6d77ca, "PyVMProtect", "bytecode pass-2 mix B"),
    (0xaeb27f1a, "PyVMProtect", "aux pass-1 seed-13c tweak"),
    (0xad27fd3c, "PyVMProtect", "aux pass-1 mix"),
    (0x52d802c3, "PyVMProtect", "aux pass-2 mix A"),
    (0x7986b27c, "PyVMProtect", "aux pass-2 mix B"),
    // ── LCG multipliers (Numerical Recipes / glibc rand) ────────────────
    (0x019660D, "Numerical-Recipes-LCG", "multiplier"),
    (0x3c6ef35f, "Numerical-Recipes-LCG", "increment"),
    (1103515245, "glibc-rand", "LCG multiplier"),
    (12345, "glibc-rand", "LCG increment"),
];

static CATALOGUE: LazyLock<HashMap<u32, Annotation>> = LazyLock::new(|| {
    let mut m: HashMap<u32, Annotation> = HashMap::new();
    for &(val, alg, role) in ENTRIES {
        // Skip fully-zero entries from broken duplicates above.
        if val == 0 {
            continue;
        }
        // First-write-wins: earlier entries take precedence on collision
        // so we keep the most canonical/common interpretation.
        m.entry(val).or_insert(Annotation {
            algorithm: alg,
            role,
        });
    }
    m
});

/// Look up a 32-bit constant in the crypto catalogue. Returns
/// `Some(annotation)` when the value is a known cryptographic / hash magic.
pub fn resolve(val: u32) -> Option<&'static Annotation> {
    CATALOGUE.get(&val).map(|a| a as &'static Annotation)
}

/// Cheap pre-filter: most crypto constants are large random-looking
/// 32-bit values. Skip cataloguing very small numbers, page-aligned
/// addresses, and printable ASCII so the inline annotation doesn't fire
/// on common loop counters / flags.
pub fn worth_checking(val: u32) -> bool {
    // Below 1024: too low-entropy (loop counters, masks, flag fields).
    // EXCEPT: a few catalogue entries are intentionally low (5381 DJB2 init,
    // 12345 glibc, 33 DJB2 step, 65521 Adler-32). Those are checked
    // explicitly in resolve() — worth_checking just gates the broad scan.
    if val < 1000 {
        return false;
    }
    // ASCII-printable packed: 0x20..0x7e per byte. Probably a string fragment.
    let bytes = val.to_le_bytes();
    let printable = bytes
        .iter()
        .filter(|&&b| (0x20..=0x7e).contains(&b))
        .count();
    if printable == 4 {
        return false;
    }
    true
}

/// Generate a stable C-style identifier for a crypto constant. Used by
/// `--annotate-crypto` to replace raw hex literals with named symbols.
/// Format: `<ALG_UPPER>_<HEX>` where ALG is upper-snake, HEX is 8 chars.
pub fn symbol(val: u32) -> Option<String> {
    let ann = resolve(val)?;
    let mut alg = String::new();
    for c in ann.algorithm.chars() {
        if c.is_ascii_alphanumeric() {
            alg.push(c.to_ascii_uppercase());
        } else if !alg.is_empty() && !alg.ends_with('_') {
            alg.push('_');
        }
    }
    let alg = alg.trim_matches('_').to_string();
    Some(format!("{}_{:08X}", alg, val))
}

/// Rewrite a decompile output blob, replacing any hex literal whose
/// value matches a crypto-catalogue entry with a stable symbolic name.
/// Constants embedded in `/* ... */` annotation comments are left
/// untouched so the comment still reads naturally.
pub fn rewrite_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    let mut in_comment = false;
    while i < bytes.len() {
        // Track /* ... */ block-comment depth so we don't rewrite
        // constants inside the inline-annotation comment we already
        // emit.
        if !in_comment && i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            in_comment = true;
            out.push('/');
            out.push('*');
            i += 2;
            continue;
        }
        if in_comment && i + 1 < bytes.len() && bytes[i] == b'*' && bytes[i + 1] == b'/' {
            in_comment = false;
            out.push('*');
            out.push('/');
            i += 2;
            continue;
        }
        if !in_comment
            && bytes[i] == b'0'
            && i + 1 < bytes.len()
            && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X')
        {
            let mut j = i + 2;
            while j < bytes.len() && bytes[j].is_ascii_hexdigit() {
                j += 1;
            }
            if j > i + 2 && j - (i + 2) <= 8 {
                let hex = &input[i + 2..j];
                if let Ok(v) = u32::from_str_radix(hex, 16) {
                    if let Some(sym) = symbol(v) {
                        out.push_str(&sym);
                        i = j;
                        continue;
                    }
                }
            }
            // Not a crypto match — emit verbatim.
            out.push_str(&input[i..j]);
            i = j;
            continue;
        }
        // Printer renders large immediate constants as `DAT_<hex>` data
        // labels when the value isn't decodable as a known data type.
        // For crypto magic, that re-render is misleading — the bytes are
        // the constant itself, not a pointer. Replace the matching
        // `DAT_<hex>` with the canonical symbol.
        if !in_comment
            && i + 4 < bytes.len()
            && &bytes[i..i + 4] == b"DAT_"
            && bytes[i + 4].is_ascii_hexdigit()
        {
            let mut j = i + 4;
            while j < bytes.len() && bytes[j].is_ascii_hexdigit() {
                j += 1;
            }
            if j - (i + 4) <= 8 {
                let hex = &input[i + 4..j];
                if let Ok(v) = u32::from_str_radix(hex, 16) {
                    if let Some(sym) = symbol(v) {
                        out.push_str(&sym);
                        i = j;
                        continue;
                    }
                }
            }
            out.push_str(&input[i..j]);
            i = j;
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn knuth_golden_resolves() {
        let a = resolve(0x9e3779b9).expect("knuth");
        assert_eq!(a.algorithm, "Knuth");
    }

    #[test]
    fn sha256_h0_resolves() {
        assert!(resolve(0x6a09e667).is_some());
        assert!(resolve(0x428a2f98).is_some());
    }

    #[test]
    fn pyvmp_constant_resolves() {
        assert!(resolve(0x12cf2b23).is_some());
        assert!(resolve(0x6b43a9b1).is_some());
    }

    #[test]
    fn random_value_does_not_resolve() {
        assert!(resolve(0xdeadbeef).is_none());
        assert!(resolve(0x12345678).is_none());
    }

    #[test]
    fn symbol_for_known_constant() {
        assert_eq!(symbol(0x9e3779b9).as_deref(), Some("KNUTH_9E3779B9"));
        assert_eq!(symbol(0x01000193).as_deref(), Some("FNV_1_01000193"));
        assert_eq!(symbol(0x6a09e667).as_deref(), Some("SHA_256_6A09E667"));
        assert!(symbol(0xdeadbeef).is_none());
    }

    #[test]
    fn rewrite_replaces_known_const() {
        let out = rewrite_text("EAX *= 0x9e3779b9;\n");
        assert!(out.contains("KNUTH_9E3779B9"));
        assert!(!out.contains("0x9e3779b9"));
    }

    #[test]
    fn rewrite_leaves_unknowns_alone() {
        let s = "var = 0x12345678 + 0xdeadbeef;\n";
        assert_eq!(rewrite_text(s), s);
    }

    #[test]
    fn rewrite_replaces_dat_label() {
        let out = rewrite_text("x = y * DAT_45d9f3b;\n");
        assert!(out.contains("PCG_045D9F3B"));
        assert!(!out.contains("DAT_45d9f3b"));
    }

    #[test]
    fn rewrite_leaves_dat_address_alone() {
        let s = "ptr = DAT_1800639d8;\n";
        assert_eq!(rewrite_text(s), s);
    }

    #[test]
    fn rewrite_skips_inline_annotation_comment() {
        let s = "x = 0x9e3779b9 /* Knuth golden ratio multiplier */;\n";
        let out = rewrite_text(s);
        // Hex outside the comment got replaced; identical text inside
        // the existing inline annotation block stays untouched.
        assert!(out.contains("KNUTH_9E3779B9"));
        assert!(out.contains("Knuth golden ratio multiplier"));
    }

    #[test]
    fn worth_checking_filter() {
        assert!(!worth_checking(42));
        assert!(!worth_checking(0x20202020)); // four spaces
        assert!(worth_checking(0x9e3779b9));
    }
}
