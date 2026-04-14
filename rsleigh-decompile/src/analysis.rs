//! Binary analysis API for Spectra and other frontends.
//!
//! Provides structured analysis results without requiring CLI invocation.
//! All functions return serializable data structures.

use rsleigh_api::Architecture;
use pcode_ir::Instruction;
use std::collections::{BTreeMap, HashMap};

/// Metadata for a single decompiled function.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FunctionMeta {
    pub name: String,
    pub address: u64,
    pub params: usize,
    pub return_type: String,
    pub calls: Vec<String>,
    pub strings: Vec<String>,
    pub complexity: usize,
    pub tags: Vec<String>,
    pub pseudocode: String,
}

/// A vulnerability finding.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VulnFinding {
    pub severity: String,  // CRIT, HIGH, MED, LOW, INFO
    pub address: u64,
    pub function: String,
    pub description: String,
    pub context: String,
}

/// Call graph entry for a single function.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CallGraphEntry {
    pub address: u64,
    pub calls: Vec<String>,
    pub called_by: Vec<String>,
    pub return_type: String,
    pub tags: Vec<String>,
}

/// Extract metadata from decompiled pseudocode.
pub fn extract_function_meta(
    name: &str,
    addr: u64,
    pseudocode: &str,
) -> FunctionMeta {
    let mut calls = Vec::new();
    let mut strings = Vec::new();
    let mut line_count = 0;

    for line in pseudocode.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with("//") { continue; }
        line_count += 1;

        // Extract function calls
        if t.contains('(') {
            let check = if let Some(eq) = t.find(" = ") { &t[eq+3..] } else { t };
            if let Some(p) = check.find('(') {
                let callee = check[..p].trim().trim_start_matches("return ");
                if !callee.is_empty() && !callee.contains(' ') && !callee.starts_with('*')
                    && !callee.starts_with('(') && !callee.starts_with("if")
                    && !callee.starts_with("while") && !callee.starts_with("switch")
                    && !callee.starts_with("for") && callee.len() < 50
                    && !calls.contains(&callee.to_string()) {
                    calls.push(callee.to_string());
                }
            }
        }

        // Extract strings
        if let Some(q1) = t.find('"') {
            if let Some(q2) = t[q1+1..].find('"') {
                let s = &t[q1+1..q1+1+q2];
                if s.len() >= 2 && s.len() <= 80 && !strings.contains(&s.to_string()) {
                    strings.push(s.to_string());
                }
            }
        }
    }

    // Extract return type and params from first line
    let return_type = pseudocode.lines().next()
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or("void").to_string();
    let params = pseudocode.lines().next()
        .map(|l| l.matches("param_").count())
        .unwrap_or(0);

    // Behavioral tags
    let mut tags = Vec::new();
    if calls.iter().any(|c| ["recv","send","socket","connect","accept","bind","listen"]
        .contains(&c.as_str())) { tags.push("network".to_string()); }
    if calls.iter().any(|c| ["CreateFile","fopen","ReadFile","WriteFile","fread","fwrite","open"]
        .contains(&c.as_str())) { tags.push("file_io".to_string()); }
    if calls.iter().any(|c| c.contains("Reg") && (c.contains("Key") || c.contains("Value")))
        { tags.push("registry".to_string()); }
    if calls.iter().any(|c| ["system","exec","execve","popen","ShellExecute","WinExec","CreateProcess"]
        .contains(&c.as_str())) { tags.push("exec".to_string()); }
    if calls.iter().any(|c| ["malloc","free","realloc","VirtualAlloc","mmap","HeapAlloc"]
        .contains(&c.as_str())) { tags.push("memory".to_string()); }
    if pseudocode.contains("AES") || pseudocode.contains("SHA") || pseudocode.contains("CRC")
        || pseudocode.contains("^ 0x") { tags.push("crypto".to_string()); }
    if calls.iter().any(|c| ["scanf","gets","fgets","getenv","getchar","recv","ReadFile"]
        .contains(&c.as_str())) { tags.push("input".to_string()); }
    if calls.iter().any(|c| ["printf","puts","fprintf","send","WriteFile","fwrite"]
        .contains(&c.as_str())) { tags.push("output".to_string()); }

    FunctionMeta {
        name: name.to_string(),
        address: addr,
        params,
        return_type,
        calls,
        strings,
        complexity: line_count,
        tags,
        pseudocode: pseudocode.to_string(),
    }
}

/// Scan pseudocode for vulnerability patterns.
pub fn scan_vulns(
    func_name: &str,
    addr: u64,
    pseudocode: &str,
) -> Vec<VulnFinding> {
    let patterns: &[(&str, &str, &str)] = &[
        ("gets(", "HIGH", "buffer overflow: gets() has no bounds check"),
        ("strcpy(", "MED", "buffer overflow: strcpy()"),
        ("strcat(", "MED", "buffer overflow: strcat()"),
        ("sprintf(", "MED", "buffer overflow/format string: sprintf()"),
        ("printf(param_", "HIGH", "format string: printf() with user-controlled format"),
        ("printf(local_", "HIGH", "format string: printf() with stack variable format"),
        ("system(param_", "CRIT", "command injection: system() with user input"),
        ("system(local_", "HIGH", "command injection: system() with stack variable"),
        ("popen(param_", "CRIT", "command injection: popen() with user input"),
        ("exec(param_", "CRIT", "command execution with user input"),
        ("VirtualProtect(", "MED", "memory protection change (DEP bypass)"),
        ("malloc(param_", "MED", "unchecked alloc with user-controlled size"),
        ("rand()", "LOW", "weak randomness: rand() not cryptographically secure"),
        ("GetProcAddress(", "LOW", "dynamic API resolution (anti-analysis)"),
        ("sqlite3_exec(", "MED", "potential SQL injection"),
    ];

    let mut findings = Vec::new();
    for &(pattern, severity, description) in patterns {
        if pseudocode.contains(pattern) {
            let context = pseudocode.lines()
                .find(|l| l.contains(pattern))
                .unwrap_or("").trim().to_string();
            let context = if context.len() > 80 { format!("{}...", &context[..80]) } else { context };
            findings.push(VulnFinding {
                severity: severity.to_string(),
                address: addr,
                function: func_name.to_string(),
                description: description.to_string(),
                context,
            });
        }
    }

    // Check for missing stack cookie
    let has_cookie = pseudocode.contains("stack cookie") || pseudocode.contains("__security_check_cookie");
    let lines = pseudocode.lines().filter(|l| !l.trim().is_empty()).count();
    if lines > 20 && !has_cookie {
        findings.push(VulnFinding {
            severity: "INFO".to_string(),
            address: addr,
            function: func_name.to_string(),
            description: "missing stack cookie in large function".to_string(),
            context: String::new(),
        });
    }

    findings
}
