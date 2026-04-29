//! Brute single-byte-XOR string recovery.
//!
//! IoT botnets in the Mirai/Gafgyt/Bashlite lineage hide their
//! C2 hostnames, hardcoded credentials, and command tables as
//! XOR-encoded byte tables. The keys are short — usually a single
//! repeating byte (`0x22`, `0x37`, `0x54`, etc.) or a 4-byte key
//! like `0xDEDEFFBA`. Single-byte coverage catches the majority
//! of public Mirai-derivative variants.
//!
//! Strategy:
//!   * For each candidate key K in 1..=255:
//!       walk the input, accumulate runs of bytes B where
//!       `B ^ K` is printable ASCII (or tab/newline). When the
//!       run breaks, emit if length >= `min_run`.
//!   * Skip key 0 — that's plaintext, already covered by `strings`.
//!   * Drop runs whose source bytes are *already mostly printable*:
//!     decoding plaintext with a small key produces another
//!     mostly-printable run, but it would already have been visible
//!     to the analyst and creates noise.
//!
//! False-positive surface is non-trivial — random data XOR'd with
//! the right key occasionally yields short pronounceable runs. The
//! `min_run` floor (default 8) and the plaintext-source filter
//! collapse the visible noise to a manageable level.

use std::collections::BTreeSet;

/// One decoded string + the key that produced it. Keys are stored
/// as a `Vec<u8>` to support both single-byte and multi-byte
/// (e.g. Mirai's 4-byte 0xDEDEFFBA) schemes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Decoded {
    /// XOR key bytes; length 1 for single-byte, 4 for Mirai-class.
    pub key: Vec<u8>,
    pub offset: usize,
    pub text: String,
}

impl Decoded {
    pub fn key_hex(&self) -> String {
        self.key.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

/// Known multi-byte keys observed in IoT-botnet families. Tried by
/// `brute_decode` after single-byte exhaustion so classic
/// Mirai/Gafgyt config tables decode without operator hints. Add
/// new keys as new variants surface.
const KNOWN_MULTI_BYTE_KEYS: &[&[u8]] = &[
    // Mirai original (Anna-Senpai release, table.c).
    &[0xDE, 0xAD, 0xBE, 0xEF],
    &[0xDE, 0xDE, 0xFF, 0xBA],
    // Gafgyt / Bashlite variants.
    &[0xBA, 0xAD, 0xF0, 0x0D],
    &[0x54, 0x76, 0x12, 0x9D],
    // Mozi / Hajime occasional 4-byte schemes.
    &[0x37, 0x37, 0x37, 0x37],
    &[0x22, 0x22, 0x22, 0x22],
];

#[inline]
fn is_printable(b: u8) -> bool {
    (0x20..0x7f).contains(&b) || b == b'\t'
}

/// Tiny seed dictionary of tokens that appear with very high
/// frequency in IoT-botnet config tables, syscall name lists, and
/// command/credential blobs. The brute decoder retains a candidate
/// run only when at least one of these substrings appears in the
/// case-insensitive decoded text. Bias is conservative: we'd rather
/// miss exotic obfuscated strings than flood the operator with
/// thousands of noise hits.
const SEED_WORDS: &[&str] = &[
    // Filesystem path tokens
    "/bin", "/etc", "/proc", "/tmp", "/usr", "/var", "/dev", "/sys",
    "/lib", "/run", "/home", "/mnt", "/opt", "/sbin",
    // Syscall + libc surface
    "open", "read", "write", "fork", "exec", "kill", "connect",
    "socket", "send", "recv", "fcntl", "ioctl", "ptrace", "getpid",
    // Mirai/Gafgyt vocabulary
    "shell", "telnet", "scan", "attack", "flood", "kworker",
    "ksoftirqd", "ngrok", "router", "bot", "cnc", "loader", "crypt",
    // Protocol / network tokens
    "http", "https", "ftp", "tcp", "udp", "irc", "smtp", "ssh",
    "tor", "onion", "dns",
    // Credential / account tokens
    "admin", "root", "pass", "user", "login", "guest", "default",
    // System artefacts often referenced
    "init", "systemd", "rc.d", "cron", "reboot", "shutdown",
    "iptables", "busybox", "wget", "curl", "tftp",
    // Words that show up in shell command strings
    "echo", "cat", "rm ", "ls ", "cp ", "mv ", "chmod", "chattr",
];

fn contains_seed_word(decoded: &[u8]) -> bool {
    let lower: Vec<u8> = decoded.iter().map(|b| b.to_ascii_lowercase()).collect();
    SEED_WORDS
        .iter()
        .any(|word| word_boundary_search(&lower, word.as_bytes()))
}

/// Substring search with word-boundary discipline: short seeds like
/// `ssh` would otherwise match `SSSH` triple-S patterns in any
/// binary's constant pool. Require the byte before/after the match
/// to NOT be ASCII alphabetic.
fn word_boundary_search(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    let first_alpha = needle[0].is_ascii_alphabetic();
    let last_alpha = needle[needle.len() - 1].is_ascii_alphabetic();
    haystack
        .windows(needle.len())
        .enumerate()
        .any(|(i, w)| {
            if w != needle {
                return false;
            }
            let before_ok = !first_alpha
                || i == 0
                || !haystack[i - 1].is_ascii_alphabetic();
            let after_idx = i + needle.len();
            let after_ok = !last_alpha
                || after_idx >= haystack.len()
                || !haystack[after_idx].is_ascii_alphabetic();
            before_ok && after_ok
        })
}

/// Brute single-byte-XOR scan plus known multi-byte keys.
/// Returns deduped decoded runs of at least `min_run` bytes that
/// are not already plaintext.
pub fn brute_decode(data: &[u8], min_run: usize) -> Vec<Decoded> {
    let mut hits: BTreeSet<(String, Vec<u8>)> = BTreeSet::new();
    let mut out = Vec::new();

    for key in 1u8..=255 {
        scan_with_key(data, &[key], min_run, &mut hits, &mut out);
    }
    for k in KNOWN_MULTI_BYTE_KEYS {
        scan_with_key(data, k, min_run, &mut hits, &mut out);
    }

    out.sort();
    out
}

/// Decode `data` with an arbitrary repeating key. Used by
/// `brute_decode` and exposed for callers that already know the
/// key (e.g. extracted at runtime from a config-resolver routine).
pub fn decode_with_key(data: &[u8], key: &[u8], min_run: usize) -> Vec<Decoded> {
    let mut hits: BTreeSet<(String, Vec<u8>)> = BTreeSet::new();
    let mut out = Vec::new();
    scan_with_key(data, key, min_run, &mut hits, &mut out);
    out.sort();
    out
}

fn scan_with_key(
    data: &[u8],
    key: &[u8],
    min_run: usize,
    hits: &mut BTreeSet<(String, Vec<u8>)>,
    out: &mut Vec<Decoded>,
) {
    if key.is_empty() {
        return;
    }
    let mut run_start: Option<usize> = None;
    let mut i = 0;
    while i < data.len() {
        let dec = data[i] ^ key[i % key.len()];
        if is_printable(dec) {
            if run_start.is_none() {
                run_start = Some(i);
            }
        } else if let Some(start) = run_start.take() {
            if i - start >= min_run {
                emit_run(data, start, i, key, hits, out);
            }
        }
        i += 1;
    }
    if let Some(start) = run_start {
        if data.len() - start >= min_run {
            emit_run(data, start, data.len(), key, hits, out);
        }
    }
}

fn emit_run(
    data: &[u8],
    start: usize,
    end: usize,
    key: &[u8],
    hits: &mut BTreeSet<(String, Vec<u8>)>,
    out: &mut Vec<Decoded>,
) {
    // Plaintext-source filter: if the source bytes are already
    // mostly printable, skip — the user will see it in `strings`.
    let printable_src = data[start..end].iter().filter(|&&b| is_printable(b)).count();
    if printable_src * 2 >= end - start {
        return;
    }
    let decoded: Vec<u8> = data[start..end]
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key[(start + i) % key.len()])
        .collect();
    // Quality filter:
    //   - >= 70% letters (no digits, no space) — pure-digit runs
    //     and tab/space-only runs are dominant noise sources.
    //   - >= 5 distinct letters — kills repetitive ASCII-art runs
    //     that dominate the brute-output otherwise.
    let letters = decoded
        .iter()
        .filter(|&&b| b.is_ascii_alphabetic())
        .count();
    if letters * 10 < decoded.len() * 7 {
        return;
    }
    let mut seen = [false; 26];
    for &b in &decoded {
        if b.is_ascii_alphabetic() {
            seen[(b.to_ascii_lowercase() - b'a') as usize] = true;
        }
    }
    if seen.iter().filter(|x| **x).count() < 5 {
        return;
    }
    // Dictionary check: require at least one IoT-malware seed word
    // (path component, syscall name, or protocol token) to appear in
    // the decoded run. Brute output without this filter is dominated
    // by noise that happens to pass length + letter-density checks
    // but contains no recognisable English/PATH structure.
    if !contains_seed_word(&decoded) {
        return;
    }
    let s = match std::str::from_utf8(&decoded) {
        Ok(s) => s.to_string(),
        Err(_) => return,
    };
    let dedupe_key = (s.clone(), key.to_vec());
    if hits.insert(dedupe_key) {
        out.push(Decoded {
            key: key.to_vec(),
            offset: start,
            text: s,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_yields_nothing() {
        assert!(brute_decode(&[], 8).is_empty());
    }

    #[test]
    fn recovers_xor_string_substring() {
        // Encoded with single-byte key. Decoder should produce a
        // run containing the plaintext under the right key. Exact
        // run boundaries depend on the surrounding bytes' XOR
        // image — assert substring containment, not equality.
        let plain = b"/usr/bin/wget http_payload";
        let key = 0x77u8;
        let encoded: Vec<u8> = plain.iter().map(|b| b ^ key).collect();
        let hits = brute_decode(&encoded, 8);
        let found = hits
            .iter()
            .any(|d| d.key == vec![key] && d.text.contains("/usr/bin/wget"));
        assert!(found, "missed XOR=0x77 plaintext: {:?}", hits);
    }

    #[test]
    fn skips_plaintext_input() {
        // Source bytes are already printable — must not be emitted
        // (would just be plaintext-XOR-with-K noise).
        let plain = b"this is just plaintext that any strings tool finds";
        let hits = brute_decode(plain, 8);
        assert!(
            hits.is_empty(),
            "emitted decode for plaintext source: {:?}",
            hits
        );
    }

    #[test]
    fn min_run_floor_enforced() {
        // 3-char encoded payload — must not appear with min_run=8.
        let plain = b"foo";
        let key = 0x55u8;
        let encoded: Vec<u8> = plain.iter().map(|b| b ^ key).collect();
        let mut buf = vec![0x00];
        buf.extend_from_slice(&encoded);
        buf.push(0x00);
        let hits = brute_decode(&buf, 8);
        assert!(hits.iter().all(|d| d.text != "foo"));
    }

    #[test]
    fn dedupe_avoids_duplicate_emit_per_key() {
        // Same encoded run twice in the buffer separated by a
        // byte guaranteed non-printable for the chosen key.
        let plain = b"shell_attack_handler_v1";
        // 0xAA flips bit 7 on every printable byte, so encoded
        // bytes pass the source-non-printable filter.
        let key = 0xAAu8;
        // 0xAA ^ 0xAA = 0x00 — clean separator.
        let sep = 0xAAu8;
        let encoded: Vec<u8> = plain.iter().map(|b| b ^ key).collect();
        let mut buf = Vec::new();
        buf.extend_from_slice(&encoded);
        buf.push(sep);
        buf.extend_from_slice(&encoded);
        let hits = brute_decode(&buf, 8);
        let n = hits
            .iter()
            .filter(|d| d.key == vec![key] && d.text.contains("shell_attack_handler_v1"))
            .count();
        assert_eq!(n, 1, "expected single dedupe entry, got {}: {:?}", n, hits);
    }

    #[test]
    fn recovers_mirai_4byte_xor() {
        // Plaintext padded to a multiple of 4 so the XOR roundtrip
        // is byte-aligned to the key. Pick a realistic Mirai-class
        // string under the canonical 0xDEDEFFBA key.
        let plain = b"command_handler_attack_table_v1xxx";
        let key = [0xDEu8, 0xDE, 0xFF, 0xBA];
        let encoded: Vec<u8> = plain
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % 4])
            .collect();
        let hits = decode_with_key(&encoded, &key, 8);
        let found = hits.iter().any(|d| d.text.contains("command_handler"));
        assert!(found, "missed Mirai 4-byte decode: {:?}", hits);
        assert_eq!(hits[0].key_hex(), "dedeffba");
    }

    #[test]
    fn dictionary_filter_rejects_random_letters() {
        // High-entropy bytes that pass length + letter-density +
        // distinct-letter checks but contain no IoT-malware seed
        // word should be rejected.
        let plain = b"abcdefghijklmnopqrstuvwxyz"; // 26 distinct letters, ~100% letters
        let key = 0xAAu8;
        let encoded: Vec<u8> = plain.iter().map(|b| b ^ key).collect();
        let hits = brute_decode(&encoded, 8);
        let leaked = hits.iter().any(|d| {
            d.text.contains("abcdefghij")
        });
        assert!(!leaked, "dictionary filter passed noise: {:?}", hits);
    }

    #[test]
    fn known_keys_in_brute_decode() {
        // brute_decode should also try multi-byte known keys.
        let plain = b"shell_command_killer_v2_payload";
        let key = [0xBA, 0xAD, 0xF0, 0x0D];
        let encoded: Vec<u8> = plain
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % 4])
            .collect();
        let hits = brute_decode(&encoded, 8);
        let found = hits
            .iter()
            .any(|d| d.key == key.to_vec() && d.text.contains("shell_command"));
        assert!(found, "brute_decode missed multi-byte key: {:?}", hits);
    }
}
