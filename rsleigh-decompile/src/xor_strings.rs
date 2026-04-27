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

/// One decoded string + the key that produced it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Decoded {
    pub key: u8,
    pub offset: usize,
    pub text: String,
}

#[inline]
fn is_printable(b: u8) -> bool {
    (0x20..0x7f).contains(&b) || b == b'\t'
}

/// Brute single-byte-XOR scan. Returns deduped decoded runs of at
/// least `min_run` bytes that are not already plaintext.
pub fn brute_decode(data: &[u8], min_run: usize) -> Vec<Decoded> {
    let mut hits: BTreeSet<(String, u8)> = BTreeSet::new();
    let mut out = Vec::new();

    for key in 1u8..=255 {
        let mut run_start: Option<usize> = None;
        let mut i = 0;
        while i < data.len() {
            let dec = data[i] ^ key;
            if is_printable(dec) {
                if run_start.is_none() {
                    run_start = Some(i);
                }
            } else if let Some(start) = run_start.take() {
                if i - start >= min_run {
                    emit_run(data, start, i, key, &mut hits, &mut out);
                }
            }
            i += 1;
        }
        if let Some(start) = run_start {
            if data.len() - start >= min_run {
                emit_run(data, start, data.len(), key, &mut hits, &mut out);
            }
        }
    }

    out.sort();
    out
}

fn emit_run(
    data: &[u8],
    start: usize,
    end: usize,
    key: u8,
    hits: &mut BTreeSet<(String, u8)>,
    out: &mut Vec<Decoded>,
) {
    // Plaintext-source filter: if the source bytes are already
    // mostly printable, skip — the user will see it in `strings`.
    let printable_src = data[start..end].iter().filter(|&&b| is_printable(b)).count();
    if printable_src * 2 >= end - start {
        return;
    }
    let decoded: Vec<u8> = data[start..end].iter().map(|b| b ^ key).collect();
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
    let s = match std::str::from_utf8(&decoded) {
        Ok(s) => s.to_string(),
        Err(_) => return,
    };
    let dedupe_key = (s.clone(), key);
    if hits.insert(dedupe_key) {
        out.push(Decoded {
            key,
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
        let plain = b"google.com.suffix";
        let key = 0x77u8;
        let encoded: Vec<u8> = plain.iter().map(|b| b ^ key).collect();
        let hits = brute_decode(&encoded, 8);
        let found = hits
            .iter()
            .any(|d| d.key == key && d.text.contains("google.com.suffix"));
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
        let plain = b"command_handler_v1";
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
            .filter(|d| d.key == key && d.text.contains("command_handler_v1"))
            .count();
        assert_eq!(n, 1, "expected single dedupe entry, got {}: {:?}", n, hits);
    }
}
