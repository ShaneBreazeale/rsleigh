//! IoT-botnet capability classifier.
//!
//! Linux IoT malware (Mirai/Gafgyt/Bashlite/Tsunami/Mozi) ships
//! highly recognizable string sets — anti-honeypot probes, systemd
//! persistence templates, kernel-thread name camouflage, multi-arch
//! payload loaders. Surfacing these as a one-line capability summary
//! lets a triage analyst skim a binary without grepping the strings
//! dump. Detection is strings-only — no decompile or disasm needed,
//! so it works on any architecture rsleigh's IOC scanner already
//! handles.
//!
//! Each `Capability` carries a stable kebab-case `id` (machine
//! consumable) and a vector of evidence substrings observed in the
//! input. Classifier returns capabilities sorted by id for stable
//! output.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub id: &'static str,
    pub label: &'static str,
    pub evidence: Vec<String>,
}

/// Convenience: extract printable ASCII runs at the given minimum
/// length from raw bytes, then classify. Use when the caller has
/// the binary data but no pre-extracted string corpus, or when the
/// caller's extraction threshold is too high to catch short arch
/// suffixes like `.mips`, `.sh4`, `.ppc`.
pub fn classify_bytes(data: &[u8]) -> Vec<Capability> {
    let mut texts: Vec<String> = Vec::new();
    let mut run: Vec<u8> = Vec::with_capacity(64);
    for &b in data {
        if (0x20..0x7f).contains(&b) || b == b'\t' {
            run.push(b);
        } else {
            if run.len() >= 4 {
                if let Ok(s) = std::str::from_utf8(&run) {
                    texts.push(s.to_string());
                }
            }
            run.clear();
        }
    }
    if run.len() >= 4 {
        if let Ok(s) = std::str::from_utf8(&run) {
            texts.push(s.to_string());
        }
    }
    classify(&texts)
}

/// Classify the given string corpus into IoT-malware capabilities.
/// Each capability fires when at least one of its rule's substrings
/// matches, with a per-rule minimum-hit threshold for noisy buckets
/// (e.g. multi-arch loader requires 3 distinct arch suffixes).
pub fn classify(strings: &[String]) -> Vec<Capability> {
    let mut out = Vec::new();

    let collect = |needles: &[&str]| -> Vec<String> {
        let mut hits = Vec::new();
        for n in needles {
            if strings.iter().any(|s| s.contains(n)) {
                hits.push((*n).to_string());
            }
        }
        hits
    };

    // Anti-honeypot: probes for medium-interaction SSH/HTTP honeypots.
    let h = collect(&[
        "/etc/cowrie.cfg", "/opt/cowrie", "/home/cowrie",
        "/opt/kippo", "/home/kippo",
        "/opt/dionaea", "/var/run/dionaea.pid",
    ]);
    if !h.is_empty() {
        out.push(Capability {
            id: "anti-honeypot",
            label: "Anti-honeypot probes (cowrie/kippo/dionaea)",
            evidence: h,
        });
    }

    // Process-name camouflage: spoofs kernel worker thread names so
    // `ps`/`top` output looks unremarkable.
    let cam = collect(&[
        "[kworker/", "kworker/0:", "kworker/u", "ksoftirqd",
    ]);
    if !cam.is_empty() {
        out.push(Capability {
            id: "process-camouflage",
            label: "Process-name camouflage (kworker/ksoftirqd spoof)",
            evidence: cam,
        });
    }

    // systemd / cron / inittab persistence template fragments.
    let p = collect(&[
        "WantedBy=multi-user.target",
        "After=network.target",
        "ExecStart=",
        "Restart=always",
        "@reboot",
        "null::respawn:",
        "/etc/init.d/",
        "/etc/rc.local",
        "/etc/systemd/system/",
    ]);
    if !p.is_empty() {
        out.push(Capability {
            id: "persistence",
            label: "Persistence (systemd unit / cron @reboot / inittab respawn)",
            evidence: p,
        });
    }

    // Multi-arch payload loader: lists of arch-suffix strings the
    // dropper feeds into a wget/curl URL template. Real samples carry
    // 5+; require at least 3 to fire.
    // Dedupe arch families. Word-boundary match: `.x86` must not
    // count when only `.x86_64` is present (substring would otherwise
    // double-count). Threshold is 3+ distinct architectures.
    let token_present = |needle: &str| -> bool {
        strings.iter().any(|s| {
            let mut start = 0usize;
            while let Some(pos) = s[start..].find(needle) {
                let abs = start + pos;
                let after = s[abs + needle.len()..].chars().next();
                let bounded = after.map_or(true, |c| !c.is_ascii_alphanumeric() && c != '_');
                if bounded {
                    return true;
                }
                start = abs + 1;
            }
            false
        })
    };
    let arch_families: &[&[&str]] = &[
        &[".x86_64"], &[".x86"], &[".i686", ".i586", ".i486"],
        &[".armv7l", ".armv7"], &[".armv6l", ".armv6"],
        &[".armv5l", ".armv5"], &[".armv4l", ".armv4"],
        &[".aarch64"], &[".mipsel"], &[".mips"],
        &[".sh4"], &[".sparc"], &[".ppc"], &[".m68k"],
    ];
    let arch_suffixes: Vec<String> = arch_families
        .iter()
        .filter_map(|family| {
            family
                .iter()
                .find(|n| token_present(n))
                .map(|s| (*s).to_string())
        })
        .collect();
    if arch_suffixes.len() >= 3 {
        out.push(Capability {
            id: "multi-arch-loader",
            label: "Multi-arch payload loader (arch-suffix URL fetch)",
            evidence: arch_suffixes,
        });
    }

    // Container / sandbox awareness probes.
    let sb = collect(&[
        "/var/lib/docker", "/.dockerenv", "/run/systemd/",
        "/sys/fs/cgroup/", "/cgroup.procs", "/cgroup.kill",
        "TracerPid", "/proc/self/status",
    ]);
    if !sb.is_empty() {
        out.push(Capability {
            id: "anti-sandbox",
            label: "Anti-sandbox / container detection",
            evidence: sb,
        });
    }

    // External downloader fallback chain.
    let dl = collect(&[
        "/usr/bin/wget", "/usr/sbin/wget",
        "/usr/bin/curl", "/usr/sbin/curl",
        "/usr/bin/tftp", "/usr/sbin/tftp",
        "/usr/bin/ftpget", "/usr/sbin/ftpget",
    ]);
    if dl.len() >= 2 {
        out.push(Capability {
            id: "downloader-fallback",
            label: "Multi-tool downloader fallback (wget/curl/tftp/ftpget)",
            evidence: dl,
        });
    }

    // /etc/ld.so.preload tamper — both rootkit-install and
    // anti-rootkit (some loaders refuse to run if a preload hook is
    // already present).
    if strings.iter().any(|s| s.contains("/etc/ld.so.preload")) {
        out.push(Capability {
            id: "ld-preload-aware",
            label: "/etc/ld.so.preload aware (rootkit install or detect)",
            evidence: vec!["/etc/ld.so.preload".to_string()],
        });
    }

    // DDoS module marker — Source-engine UDP query is a Mirai-class
    // attack payload that has no legitimate use in non-game code.
    if strings.iter().any(|s| s.contains("TSource Engine Query")) {
        out.push(Capability {
            id: "ddos-source-engine",
            label: "DDoS module (Source Engine Query payload)",
            evidence: vec!["TSource Engine Query".to_string()],
        });
    }

    out.sort_by_key(|c| c.id);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn empty_corpus_yields_nothing() {
        assert!(classify(&[]).is_empty());
    }

    #[test]
    fn legitimate_userland_strings_quiet() {
        let strings = s(&[
            "GLIBC_2.17", "Hello, world", "/usr/share/locale",
            "version 1.2.3",
        ]);
        let caps = classify(&strings);
        assert!(caps.is_empty(), "false-positive: {:?}", caps);
    }

    #[test]
    fn detects_cowrie_kippo() {
        let strings = s(&["/etc/cowrie.cfg", "/home/kippo"]);
        let caps = classify(&strings);
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].id, "anti-honeypot");
        assert_eq!(caps[0].evidence.len(), 2);
    }

    #[test]
    fn multi_arch_requires_three_suffixes() {
        let two = s(&[".armv7l", ".aarch64"]);
        let caps = classify(&two);
        assert!(caps.is_empty(), "fired with only 2 arch suffixes");

        let three = s(&[".armv7l", ".aarch64", ".mipsel"]);
        let caps = classify(&three);
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].id, "multi-arch-loader");
    }

    #[test]
    fn iot_botnet_corpus_fires_full_set() {
        let strings = s(&[
            "/etc/cowrie.cfg", "/home/kippo", "/var/run/dionaea.pid",
            "[kworker/u1:0]", "ksoftirqd",
            "WantedBy=multi-user.target", "@reboot ", "null::respawn:",
            ".x86_64", ".armv7l", ".aarch64", ".mipsel",
            "/var/lib/docker", "TracerPid",
            "/usr/bin/wget", "/usr/bin/curl", "/usr/sbin/tftp",
            "/etc/ld.so.preload",
            "TSource Engine Query",
        ]);
        let caps = classify(&strings);
        let ids: Vec<_> = caps.iter().map(|c| c.id).collect();
        assert!(ids.contains(&"anti-honeypot"));
        assert!(ids.contains(&"process-camouflage"));
        assert!(ids.contains(&"persistence"));
        assert!(ids.contains(&"multi-arch-loader"));
        assert!(ids.contains(&"anti-sandbox"));
        assert!(ids.contains(&"downloader-fallback"));
        assert!(ids.contains(&"ld-preload-aware"));
        assert!(ids.contains(&"ddos-source-engine"));
    }

    #[test]
    fn x86_64_does_not_double_count_as_x86() {
        // Only `.x86_64` and `.aarch64` and `.mipsel` present —
        // three distinct families. `.x86` MUST NOT also fire from
        // the `.x86_64` substring.
        let strings = s(&[".x86_64", ".aarch64", ".mipsel"]);
        let caps = classify(&strings);
        let arch = caps.iter().find(|c| c.id == "multi-arch-loader").unwrap();
        assert_eq!(arch.evidence.len(), 3);
        assert!(arch.evidence.contains(&".x86_64".to_string()));
        assert!(!arch.evidence.contains(&".x86".to_string()));
    }

    #[test]
    fn mips_word_boundary_blocks_mipsel_match() {
        // `.mips` must require terminator after; `.mipsel` should
        // match `.mipsel` family but not `.mips` family.
        let strings = s(&[".mipsel", ".aarch64", ".armv7l"]);
        let caps = classify(&strings);
        let arch = caps.iter().find(|c| c.id == "multi-arch-loader").unwrap();
        assert!(arch.evidence.contains(&".mipsel".to_string()));
        assert!(!arch.evidence.contains(&".mips".to_string()));
    }

    #[test]
    fn output_is_sorted_by_id() {
        let strings = s(&[
            "TSource Engine Query",
            "/etc/cowrie.cfg",
            "/etc/ld.so.preload",
        ]);
        let caps = classify(&strings);
        let ids: Vec<_> = caps.iter().map(|c| c.id).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted);
    }
}
