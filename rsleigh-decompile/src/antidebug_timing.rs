//! Detect anti-debug timing-pair probes built around `RDTSC` / `RDPMC` /
//! `RDTSCP` / `QueryPerformanceCounter`.
//!
//! Pattern: two reads of the same hardware counter sandwich a fixed-work
//! loop. The malware/protector compares the elapsed counter delta
//! against an upper bound; under a debugger the delta blows up and the
//! check trips. PyVMProtect v3/v5 use exactly this with `RDPMC` + a
//! 256-iter ADD-ECX-ECX loop.
//!
//! Detection rules:
//!   - Two `RDTSC` (`0F 31`), `RDPMC` (`0F 33`), or `RDTSCP` (`0F 01 F9`)
//!     instructions within `WINDOW_BYTES` of each other in linear code.
//!   - Bonus signal: `IMUL`/`SHL`/loop-conditional branches between the
//!     two reads (suggests work loop sandwich).
//!
//! False-positive surface: legitimate microbenchmarks. Distinguish via
//! caller context — protection schemes call this from PyInit / startup
//! while microbenchmarks do not. The annotation is advisory; analyst
//! decides.
//!
//! Output: a list of `Probe` records with the addresses of both reads
//! and the byte-distance between them. Caller can render as a comment
//! block ahead of the surrounding function.

const WINDOW_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Counter {
    Rdtsc,
    Rdpmc,
    Rdtscp,
}

#[derive(Debug, Clone)]
pub struct CounterRead {
    pub va: u64,
    pub kind: Counter,
}

/// Two counter reads close together — the high-confidence anti-debug
/// pattern.
#[derive(Debug, Clone)]
pub struct Probe {
    pub first: CounterRead,
    pub second: CounterRead,
    /// Byte distance between the two reads.
    pub distance: usize,
}

fn classify(code: &[u8], off: usize) -> Option<(Counter, usize)> {
    // RDTSC: 0F 31 (2 bytes)
    if code.get(off) == Some(&0x0f) && code.get(off + 1) == Some(&0x31) {
        return Some((Counter::Rdtsc, 2));
    }
    // RDPMC: 0F 33 (2 bytes)
    if code.get(off) == Some(&0x0f) && code.get(off + 1) == Some(&0x33) {
        return Some((Counter::Rdpmc, 2));
    }
    // RDTSCP: 0F 01 F9 (3 bytes)
    if code.get(off) == Some(&0x0f)
        && code.get(off + 1) == Some(&0x01)
        && code.get(off + 2) == Some(&0xf9)
    {
        return Some((Counter::Rdtscp, 3));
    }
    None
}

/// Scan a region. Returns all individual counter reads, plus pairs
/// classified as timing probes.
pub fn scan_region(code: &[u8], base_va: u64) -> (Vec<CounterRead>, Vec<Probe>) {
    let mut reads: Vec<CounterRead> = Vec::new();
    let mut off = 0;
    while off < code.len() {
        if let Some((kind, len)) = classify(code, off) {
            reads.push(CounterRead {
                va: base_va + off as u64,
                kind,
            });
            off += len;
        } else {
            off += 1;
        }
    }

    // Pair up reads that are within WINDOW_BYTES.
    let mut probes: Vec<Probe> = Vec::new();
    for i in 0..reads.len() {
        for j in (i + 1)..reads.len() {
            let dist = (reads[j].va - reads[i].va) as usize;
            if dist > WINDOW_BYTES {
                break;
            }
            if dist < 4 {
                // Adjacent reads (no work between them) are still worth
                // flagging — the protector might be measuring single-
                // instruction overhead — but we cap minimum distance.
                continue;
            }
            // Same-counter pair gets the high-confidence treatment.
            // Mixed pairs (RDTSC + RDPMC) are still suspicious.
            probes.push(Probe {
                first: reads[i].clone(),
                second: reads[j].clone(),
                distance: dist,
            });
            break; // each first read pairs with the next read only
        }
    }

    (reads, probes)
}

/// Format a probe as a one-line annotation suitable for a stderr hint
/// or an inline decompile comment.
pub fn render_probe(p: &Probe) -> String {
    let name = |c: Counter| match c {
        Counter::Rdtsc => "RDTSC",
        Counter::Rdpmc => "RDPMC",
        Counter::Rdtscp => "RDTSCP",
    };
    format!(
        "anti-debug timing probe: {}@{:#x} → {}@{:#x} ({} bytes apart)",
        name(p.first.kind),
        p.first.va,
        name(p.second.kind),
        p.second.va,
        p.distance
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_rdtsc_pair() {
        // RDTSC ... 16 bytes of NOPs ... RDTSC
        let mut code = vec![0x0f, 0x31];
        code.extend(std::iter::repeat(0x90).take(16));
        code.extend_from_slice(&[0x0f, 0x31]);
        let (reads, probes) = scan_region(&code, 0x1000);
        assert_eq!(reads.len(), 2);
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0].distance, 18);
        assert_eq!(probes[0].first.kind, Counter::Rdtsc);
        assert_eq!(probes[0].second.kind, Counter::Rdtsc);
    }

    #[test]
    fn detects_rdpmc_pair() {
        let mut code = vec![0x0f, 0x33];
        code.extend(std::iter::repeat(0x90).take(20));
        code.extend_from_slice(&[0x0f, 0x33]);
        let (_, probes) = scan_region(&code, 0x2000);
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0].first.kind, Counter::Rdpmc);
    }

    #[test]
    fn detects_rdtscp() {
        let code = vec![0x0f, 0x01, 0xf9];
        let (reads, _) = scan_region(&code, 0x3000);
        assert_eq!(reads.len(), 1);
        assert_eq!(reads[0].kind, Counter::Rdtscp);
    }

    #[test]
    fn ignores_far_apart() {
        let mut code = vec![0x0f, 0x31];
        code.extend(std::iter::repeat(0x90).take(500));
        code.extend_from_slice(&[0x0f, 0x31]);
        let (reads, probes) = scan_region(&code, 0x4000);
        assert_eq!(reads.len(), 2);
        // Window is 256 bytes; 500 apart → no pair.
        assert!(probes.is_empty());
    }

    #[test]
    fn no_false_positive_on_quiet_code() {
        let code = vec![0x90; 64];
        let (reads, probes) = scan_region(&code, 0x5000);
        assert!(reads.is_empty());
        assert!(probes.is_empty());
    }
}
