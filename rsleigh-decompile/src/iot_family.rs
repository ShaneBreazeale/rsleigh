//! IoT-botnet family fingerprint.
//!
//! Linux IoT malware lineages share string sets and structural
//! markers that uniquely fingerprint them. Surfacing a family
//! hint up front lets the analyst align with the public knowledge
//! base for that family before diving into the specific sample.
//!
//! This module classifies the binary's string corpus into a
//! single best-guess family with optional variant tag. Detection
//! is conservative — when no strong evidence is found, returns
//! `None` rather than guessing. The classifier is intentionally
//! independent from `iot_capabilities`: capabilities describe
//! what the binary does; family describes which lineage it came
//! from.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyHint {
    /// Stable kebab-case family id.
    pub id: &'static str,
    /// Human-readable family name.
    pub label: &'static str,
    /// Specific variant marker, if recognised (e.g. release codename).
    pub variant: Option<String>,
    /// Strings that triggered the match.
    pub evidence: Vec<String>,
}

struct Rule {
    id: &'static str,
    label: &'static str,
    /// Markers required to be ALL present (ANDed). At least one
    /// distinct rule must hit for the family to fire.
    markers: &'static [&'static str],
    /// Optional regex-free variant capture: substring with a
    /// `{}` placeholder. The placeholder spans `[A-Za-z0-9._-]+`.
    variant_template: Option<&'static str>,
}

const RULES: &[Rule] = &[
    Rule {
        id: "mirai",
        label: "Mirai",
        markers: &[
            "TSource Engine Query",
            "/proc/net/tcp",
        ],
        variant_template: None,
    },
    Rule {
        id: "mirai",
        label: "Mirai",
        markers: &[
            "table_unlock_val",
            "table_lock_val",
        ],
        variant_template: None,
    },
    Rule {
        id: "gafgyt",
        label: "Gafgyt / Bashlite",
        markers: &[
            "PRIVMSG",
            "PING :",
        ],
        variant_template: None,
    },
    Rule {
        id: "mozi",
        label: "Mozi",
        markers: &[
            "[Mozi]",
        ],
        variant_template: None,
    },
    Rule {
        id: "hajime",
        label: "Hajime",
        markers: &[
            ".i.hajime",
        ],
        variant_template: None,
    },
    Rule {
        id: "tsunami",
        label: "Tsunami / Kaiten",
        markers: &[
            "PRIVMSG ",
            "JOIN #",
            "NICK ",
        ],
        variant_template: None,
    },
    Rule {
        id: "guoanbu",
        label: "Guoanbu (MSS-themed)",
        markers: &[
            "Guoanbu-session-",
        ],
        variant_template: Some("Guoanbu-session-{}"),
    },
    Rule {
        id: "xorddos",
        label: "XorDDoS",
        markers: &[
            "BB2FA36AAA9541F0",
        ],
        variant_template: None,
    },
];

/// Classify the input string corpus into a single best-fit family.
/// Returns `None` if no rule matches.
pub fn classify(strings: &[String]) -> Option<FamilyHint> {
    let mut best: Option<(&Rule, Vec<String>)> = None;

    for rule in RULES {
        let mut hits = Vec::new();
        for marker in rule.markers {
            if let Some(s) = strings.iter().find(|s| s.contains(marker)) {
                hits.push(s.clone());
            }
        }
        if hits.len() == rule.markers.len() {
            // All markers present. Prefer the rule with the most
            // specific markers (longest combined marker length).
            let score: usize = rule.markers.iter().map(|m| m.len()).sum();
            let best_score = best
                .as_ref()
                .map(|(r, _)| r.markers.iter().map(|m| m.len()).sum::<usize>())
                .unwrap_or(0);
            if score >= best_score {
                best = Some((rule, hits));
            }
        }
    }

    best.map(|(rule, evidence)| {
        let variant = rule.variant_template.and_then(|tpl| {
            extract_variant(strings, tpl)
        });
        FamilyHint {
            id: rule.id,
            label: rule.label,
            variant,
            evidence,
        }
    })
}

fn extract_variant(strings: &[String], template: &str) -> Option<String> {
    let placeholder = template.find("{}")?;
    let prefix = &template[..placeholder];
    let suffix = &template[placeholder + 2..];
    for s in strings {
        if let Some(start) = s.find(prefix) {
            let after = start + prefix.len();
            let tail = &s[after..];
            // Match `[A-Za-z0-9._-]+`
            let end = tail
                .char_indices()
                .find(|(_, c)| {
                    !(c.is_ascii_alphanumeric() || *c == '.' || *c == '_' || *c == '-')
                })
                .map(|(i, _)| i)
                .unwrap_or(tail.len());
            if end == 0 {
                continue;
            }
            let variant = &tail[..end];
            if !suffix.is_empty() && !s[after + end..].starts_with(suffix) {
                continue;
            }
            return Some(variant.to_string());
        }
    }
    None
}

/// Convenience wrapper: extract printable runs from raw bytes
/// at the given minimum length, then classify.
pub fn classify_bytes(data: &[u8]) -> Option<FamilyHint> {
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

/// Aggregate hits per id so callers can see all matched families
/// rather than just the highest-score winner. Useful when a single
/// binary embeds multiple lineages (loader + payload).
pub fn classify_all(strings: &[String]) -> BTreeMap<&'static str, FamilyHint> {
    let mut out = BTreeMap::new();
    for rule in RULES {
        let mut hits = Vec::new();
        for marker in rule.markers {
            if let Some(s) = strings.iter().find(|s| s.contains(marker)) {
                hits.push(s.clone());
            }
        }
        if hits.len() == rule.markers.len() && !out.contains_key(rule.id) {
            let variant = rule
                .variant_template
                .and_then(|tpl| extract_variant(strings, tpl));
            out.insert(
                rule.id,
                FamilyHint {
                    id: rule.id,
                    label: rule.label,
                    variant,
                    evidence: hits,
                },
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn empty_corpus_yields_none() {
        assert!(classify(&[]).is_none());
    }

    #[test]
    fn benign_corpus_yields_none() {
        let strings = s(&["GLIBC_2.17", "Hello, world", "/usr/share/locale"]);
        assert!(classify(&strings).is_none());
    }

    #[test]
    fn detects_mirai_strict() {
        let strings = s(&["TSource Engine Query", "/proc/net/tcp", "other"]);
        let hint = classify(&strings).unwrap();
        assert_eq!(hint.id, "mirai");
        assert!(hint.variant.is_none());
    }

    #[test]
    fn extracts_guoanbu_variant() {
        let strings = s(&[
            "Guoanbu-session-v2",
            "kworker/0:0",
            "/etc/cowrie.cfg",
        ]);
        let hint = classify(&strings).unwrap();
        assert_eq!(hint.id, "guoanbu");
        assert_eq!(hint.variant.as_deref(), Some("v2"));
    }

    #[test]
    fn requires_all_markers_present() {
        // Mirai rule needs BOTH markers. Only one present → no fire.
        let strings = s(&["TSource Engine Query"]);
        assert!(classify(&strings).is_none());
    }

    #[test]
    fn classify_all_returns_multiple_families() {
        let strings = s(&[
            "Guoanbu-session-v2",
            "TSource Engine Query",
            "/proc/net/tcp",
        ]);
        let all = classify_all(&strings);
        assert!(all.contains_key("guoanbu"));
        assert!(all.contains_key("mirai"));
    }
}
