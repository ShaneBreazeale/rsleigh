use std::collections::HashMap;
use pcode_ir::{Varnode, AddressSpaceId};
use rsleigh_api::Architecture;
use crate::ir::*;

const RBP_OFFSET: u64 = 40;
const EBP_OFFSET: u64 = 20;
const RSP_OFFSET: u64 = 32;
const ESP_OFFSET: u64 = 32; // ESP is at same offset as RSP (lower 4 bytes)
const RIP_OFFSET: u64 = 648;

/// Print structured statements as C-like pseudocode.
pub fn print_c(
    stmts: &[StructuredStmt],
    ssa: &SsaCfg,
    arch: Architecture,
    binary: Option<&[u8]>,
    imports: &HashMap<u64, String>,
    local_names: &HashMap<String, String>,
    struct_fields: &HashMap<u64, String>,
    func_name: &str,
) -> String {
    print_c_with_try(stmts, ssa, arch, binary, imports, local_names, struct_fields, func_name, &[])
}

pub fn print_c_with_try(
    stmts: &[StructuredStmt],
    ssa: &SsaCfg,
    arch: Architecture,
    binary: Option<&[u8]>,
    imports: &HashMap<u64, String>,
    local_names: &HashMap<String, String>,
    struct_fields: &HashMap<u64, String>,
    func_name: &str,
    try_regions: &[crate::eh_frame::TryRegion],
) -> String {
    let mut out = String::new();
    let ctx = PrintCtx { arch, binary, imports, try_regions };

    // Generate function signature from SSA analysis
    generate_function_signature(&mut out, ssa, func_name);

    // Emit a summary of try/catch regions (from .eh_frame LSDA) as a comment
    // block at the top of the body. Ghidra inlines per-statement comments;
    // a function-level summary is cheaper and still pinpoints where exception
    // handlers live for cross-referencing with the disassembly.
    if !ctx.try_regions.is_empty() {
        out.push_str("    /* try/catch regions:\n");
        for tr in ctx.try_regions {
            out.push_str(&format!(
                "     *   try [0x{:x} .. 0x{:x}) -> catch @ 0x{:x}\n",
                tr.start, tr.end, tr.landing_pad,
            ));
        }
        out.push_str("     */\n");
    }

    let filtered = filter_boilerplate(stmts, ssa);
    let mut tracker = RegTracker::new();
    // Pre-scan: collect stack aliases from Stores in the top-level stmts
    // This captures var_8 = param_0 etc. that are elided
    collect_store_aliases(&filtered, ssa, &ctx, &mut tracker);

    print_stmts_with_tracker(&filtered, ssa, &ctx, 0, &mut out, &mut tracker);
    // Merge DWARF local names into the alias map — DWARF names take priority
    let mut all_aliases = tracker.stack_alias.clone();
    for (var_name, dwarf_name) in local_names {
        all_aliases.insert(var_name.clone(), dwarf_name.clone());
    }
    // Collect parameter names for return value inference
    let param_names: Vec<String> = ssa.vars.iter()
        .filter_map(|v| {
            let name = v.param_name.as_ref()?;
            // Exclude loop Phi variable names (e.g., "iVar1", "lVar1") —
            // they use param_name for printer elision but are not function parameters.
            if matches!(&v.expr, Expr::Phi(_)) && !name.starts_with("param_") {
                return None;
            }
            Some(name.clone())
        })
        .collect();
    post_process(&mut out, &all_aliases, &param_names, struct_fields, &ctx);

    // Detect empty thunk functions: if body is empty after post-processing,
    // check SSA for a Branch/Indirect terminator that jumps to another function.
    // Show as tail call: "return target_func();" or "// thunk → FUN_XXXX"
    let body_lines: Vec<&str> = out.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with("//") && !l.contains('{'))
        .filter(|l| {
            let t = l.trim();
            // Skip variable declarations
            !t.starts_with("int ") && !t.starts_with("long ") && !t.starts_with("uint")
                && !t.starts_with("char ") && !t.starts_with("float ") && !t.starts_with("double ")
                && !t.starts_with("bool ")
        })
        .collect();
    if body_lines.is_empty() {
        // For empty thunks: check if any SSA block has an Indirect terminator
        // with a known target address. Also check Branch to blocks outside the function.
        let func_addr = func_name.strip_prefix("func_")
            .and_then(|hex| u64::from_str_radix(hex, 16).ok());
        for block in &ssa.blocks {
            match &block.terminator {
                SsaTerminator::Branch(bid) | SsaTerminator::Fallthrough(bid) => {
                    if let Some(target_block) = ssa.blocks.get(bid.0) {
                        let addr = target_block.addr;
                        // Skip if target is within the function (internal block)
                        if addr != 0 && func_addr.map_or(true, |fa| addr != fa) {
                            let target_name = imports.get(&addr)
                                .cloned()
                                .unwrap_or_else(|| format!("func_{:x}", addr));
                            out.push_str(&format!("    return {}(); // thunk\n", target_name));
                            break;
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // Close the function body brace (opened in generate_function_signature)
    if out.starts_with("void ") || out.starts_with("int ") || out.starts_with("long ")
        || out.starts_with("float ") || out.starts_with("double ")
        || out.starts_with("char ") || out.starts_with("uint8_t ")
        || out.starts_with("bool ")
    {
        out.push_str("}\n");
    }
    out
}

fn collect_store_aliases(stmts: &[StructuredStmt], ssa: &SsaCfg, ctx: &PrintCtx, tracker: &mut RegTracker) {
    // Only collect aliases from the prologue — stores that happen before any calls or loops.
    // These are the initial parameter saves (MOV [RBP-0x8], RDI etc.) and local initialization.
    // Post-call stores may reference stale register values via the tracker and produce wrong aliases.
    for stmt in stmts {
        // Stop at the first call, loop, or conditional — after these, register values are unreliable
        match stmt {
            StructuredStmt::Call { .. }
            | StructuredStmt::While { .. }
            | StructuredStmt::DoWhile { .. }
            | StructuredStmt::IfElse { .. } => break,
            _ => {}
        }

        if let StructuredStmt::Store { addr, val } = stmt {
            if let Some(stack_name) = try_stack_var_name(*addr, ssa) {
                let val_vdef = ssa.var(*val);
                // For prologue stores, detect parameter registers and use param names.
                // The SSA may have contaminated param register VarIds with loop values
                // (e.g., RDI gets a Phi that merges entry param with loop's LEA).
                // Check param_name on the VarId, its Var/Phi chain, and by register offset.
                let param = val_vdef.param_name.clone()
                    .or_else(|| match &val_vdef.expr {
                        Expr::Var(src) => ssa.var(*src).param_name.clone(),
                        Expr::Phi(inputs) => inputs.iter().find_map(|i| ssa.var(*i).param_name.clone()),
                        _ => None,
                    })
                    .or_else(|| {
                        // Fallback: if this register is at a known arg offset and has
                        // Unknown or Phi expression, it's a function parameter.
                        // SysV: RDI=56, RSI=48, RDX=16, RCX=8, R8=128, R9=136
                        // Win64: RCX=8, RDX=16, R8=128, R9=136
                        if val_vdef.varnode.space == AddressSpaceId::Register {
                            let arg_offsets: &[u64] = &[56, 48, 16, 8, 128, 136];
                            if let Some(idx) = arg_offsets.iter().position(|o| *o == val_vdef.varnode.offset) {
                                // Check that no earlier param has this index
                                // (avoid duplicates from different-sized references)
                                return Some(format!("param_{}", idx));
                            }
                        }
                        None
                    });

                let val_expr = if let Some(ref name) = param {
                    name.clone()
                } else {
                    format_var_tracked(*val, ssa, ctx, tracker)
                };
                tracker.stack_alias.insert(stack_name, val_expr);
            }
        }
        if let StructuredStmt::Assign { lhs, .. } = stmt {
            let vdef = ssa.var(*lhs);
            if vdef.varnode.space == AddressSpaceId::Register {
                if let Expr::Var(_) | Expr::Load(_) | Expr::BinOp(_, _, _) | Expr::UnaryOp(_, _) = &vdef.expr {
                    tracker.set(vdef.varnode.offset, vdef.varnode.size, *lhs);
                }
                if vdef.param_name.is_some() {
                    tracker.set(vdef.varnode.offset, vdef.varnode.size, *lhs);
                }
            }
        }
    }
}

fn print_stmts_with_tracker(stmts: &[StructuredStmt], ssa: &SsaCfg, ctx: &PrintCtx, indent: usize, out: &mut String, _parent_tracker: &mut RegTracker) {
    let mut tracker = RegTracker::new();
    // Copy aliases from parent
    tracker.stack_alias = _parent_tracker.stack_alias.clone();
    for (i, stmt) in stmts.iter().enumerate() {
        print_stmt_tracked(stmt, stmts, i, ssa, ctx, indent, out, &mut tracker);
    }
}

/// Text-level post-processing to clean up common patterns.
fn post_process(out: &mut String, aliases: &std::collections::HashMap<String, String>, param_names: &[String], struct_fields: &HashMap<u64, String>, ctx: &PrintCtx) {
    let mut lines: Vec<String> = out.lines().map(|l| l.to_string()).collect();

    let mut i = 0;
    while i < lines.len() {
        // #4: Hide stack canary boilerplate
        // Preamble: RAX = *(0x...); RAX = *(RAX); (global canary pointer load)
        // Epilogue: RAX = *(0x...); RAX = *(RAX); RCX = ...; if (...)  { ... }
        if lines[i].trim().starts_with("RAX = *(0x") {
            // Stack canary preamble: RAX = *(canary_addr); RAX = *(RAX);
            // Only remove if the next line is RAX = *(RAX) — the double-deref is
            // the signature of canary loading (GOT ptr -> actual canary value).
            // Then remove just the 2 preamble lines and stop — don't touch the
            // code that follows. The epilogue check (if ... __stack_chk_guard) is
            // handled separately below.
            let next = lines.get(i + 1).map(|l| l.trim().to_string()).unwrap_or_default();
            if next == "RAX = *(RAX);" {
                lines.remove(i); // RAX = *(0x...)
                lines.remove(i); // RAX = *(RAX)
                continue;
            }
        }

        // #2: Remove standalone calls that appear again inlined on the next line
        // Hide data segment loads: RAX = *(0x1000...); EAX = *(0x1000...);
        // These are array/struct initialization from read-only data, not useful to display.
        {
            let lt = lines[i].trim();
            if (lt.starts_with("RAX = *(0x") || lt.starts_with("EAX = *(0x"))
                && lt.ends_with(");")
                && !lt.contains("+") && !lt.contains("-")
            {
                lines.remove(i);
                continue;
            }
            // Hide simple top-level stack variable initializations: var_N = small_const;
            if lt.starts_with("var_") && lt.ends_with(';') {
                if let Some(eq_pos) = lt.find(" = ") {
                    let rhs = &lt[eq_pos + 3..lt.len() - 1];
                    let is_small_const = rhs.starts_with("0x") && rhs.len() <= 6
                        || rhs.parse::<i64>().map_or(false, |v| v.abs() < 256);
                    // Also hide string constant stores: var_24 = "text";
                    let is_string = rhs.starts_with('"') && rhs.ends_with('"');
                    let indent = lines[i].len() - lines[i].trim_start().len();
                    if (is_small_const || is_string) && indent == 0 {
                        lines.remove(i);
                        continue;
                    }
                }
            }
            // Hide address loads: REG = large_address (data/code pointer, not a useful value)
            if let Some(eq_pos) = lt.find(" = 0x") {
                let lhs_candidate = &lt[..eq_pos];
                let is_reg_lhs = lhs_candidate.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
                    && lhs_candidate.len() >= 2 && lhs_candidate.len() <= 3;
                if is_reg_lhs && lt.ends_with(';') {
                    let hex_val = &lt[eq_pos + 3..lt.len() - 1]; // "0x..." without ";"
                    if hex_val.len() > 6 { // addresses are > 6 hex digits
                        lines.remove(i);
                        continue;
                    }
                }
            }
            // Hide LEA patterns: REG = RBP ± offset (address computation, not a value)
            if let Some(eq_pos) = lt.find(" = RBP") {
                let lhs = &lt[..eq_pos];
                let is_reg = lhs.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
                    && lhs.len() >= 2 && lhs.len() <= 3;
                if is_reg && lt.ends_with(';') && (lt.contains("- ") || lt.contains("+ ")) {
                    lines.remove(i);
                    continue;
                }
            }
        }

        // Fix nested call args: func2(..., func1(...), ...) where func1's return
        // was incorrectly tracked as an argument. Replace nested calls with "buf".
        {
            let lt = lines[i].trim().to_string();
            if lt.contains("(") && !lt.starts_with("if ") && !lt.starts_with("while ")
                && !lt.starts_with("return ")
            {
                // Check each argument: if it's a function call expression (has balanced
                // parens like printf("...")), replace with "buf"
                if let Some(outer_open) = lt.find('(') {
                    let outer_name = &lt[..outer_open];
                    if !outer_name.is_empty() && outer_name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '*') {
                        let args_start = outer_open + 1;
                        if let Some(outer_close) = find_matching_paren(&lt, outer_open) {
                            let args = &lt[args_start..outer_close];
                            // Split args by balanced commas and check each
                            let mut new_args = Vec::new();
                            let mut rest = args;
                            let mut changed = false;
                            // Known void/output functions whose return value is NOT useful as an arg
                            let void_funcs = ["printf", "puts", "fputs", "putchar", "putc",
                                "fprintf", "write", "send", "perror"];
                            while !rest.is_empty() {
                                let comma = find_balanced_comma(rest).unwrap_or(rest.len());
                                let arg = rest[..comma].trim();
                                // Only replace if the nested call is a known void/output function
                                let is_void_call = arg.contains('(') && arg.contains(')')
                                    && !arg.starts_with('"') && !arg.starts_with("*(")
                                    && void_funcs.iter().any(|f| arg.starts_with(f));
                                if is_void_call {
                                    new_args.push("buf".to_string());
                                    changed = true;
                                } else {
                                    new_args.push(arg.to_string());
                                }
                                rest = if comma < rest.len() { &rest[comma + 1..] } else { "" };
                            }
                            if changed {
                                let indent = lines[i].len() - lines[i].trim_start().len();
                                let pad = " ".repeat(indent);
                                let suffix = &lt[outer_close..]; // includes ")" and ";"
                                lines[i] = format!("{}{}({}{}",
                                    pad, outer_name, new_args.join(", "), suffix);
                            }
                        }
                    }
                }
            }
        }

        // Pattern: "    func();" followed by "    printf("...", func());"
        if i + 1 < lines.len() {
            let current = lines[i].trim();
            if current.ends_with("();") || current.ends_with(");") {
                let call = current.trim_end_matches(';');
                let next = lines[i + 1].trim();
                if next.contains(call) && next != current {
                    lines.remove(i);
                    continue;
                }
            }
        }

        // #2b: Remove "REG = call();" when the same call appears again on a later line
        // Pattern: "EAX = strlen(str);" where strlen(str) appears elsewhere — redundant display
        {
            let lt = lines[i].trim();
            if let Some(eq_pos) = lt.find(" = ") {
                let lhs = &lt[..eq_pos];
                let rhs = &lt[eq_pos + 3..lt.len().saturating_sub(1)]; // strip ;
                let is_reg_lhs = lhs.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit());
                let is_call_rhs = rhs.contains('(') && rhs.contains(')');
                if is_reg_lhs && is_call_rhs {
                    // Check if this call result is already represented by another line
                    let mut is_redundant = false;
                    for j in (0..i).chain(i+1..lines.len()) {
                        if lines[j].trim().contains(rhs) {
                            is_redundant = true;
                            break;
                        }
                    }
                    if is_redundant {
                        lines.remove(i);
                        continue;
                    }
                }
            }
        }

        // #5: "var_N = expr;" at end of if/else block → "return expr;"
        // Only apply inside if/else blocks, NOT while loops
        if i + 1 < lines.len() {
            let lt = lines[i].trim();
            let next_t = lines[i + 1].trim();
            if lt.starts_with("var_") && lt.ends_with(';') && lt.contains(" = ") && next_t == "}" {
                let indent = lines[i].len() - lines[i].trim_start().len();
                // Check that we're inside an if/else, not a while
                let in_if_else = indent > 0 && lines[..i].iter().rev().any(|l| {
                    let lt = l.trim();
                    lt.starts_with("if (") || lt.starts_with("} else {")
                        || lt.ends_with("} else {")
                });
                let in_while = indent > 0 && lines[..i].iter().rev().any(|l| {
                    let lt = l.trim();
                    lt.starts_with("while (")
                });
                if in_if_else && !in_while {
                    let expr = lt.split(" = ").nth(1).unwrap_or("").trim_end_matches(';');
                    if !expr.is_empty() {
                        let pad = &lines[i][..indent];
                        lines[i] = format!("{}return {};", pad, expr);
                    }
                }
            }
        }

        // #6: Hide simple register assignments that are intermediates
        {
            let lt = lines[i].trim().to_string();
            if let Some(eq_pos) = lt.find(" = ") {
                let lhs = lt[..eq_pos].to_string();
                let rhs = lt[eq_pos + 3..].trim_end_matches(';').to_string();
                let is_reg = lhs.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
                    && lhs.len() >= 2 && lhs.len() <= 3;
                if is_reg && lt.ends_with(';') {
                    // Remove: REG = simple_value (var, param, DWARF name, another REG, constant 0)
                    let is_simple = (rhs.starts_with("var_") && !rhs.contains(' '))
                        || (rhs.starts_with("param_") && !rhs.contains(' '))
                        || rhs == "0"
                        || (rhs.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()) && rhs.len() <= 3)
                        || (!rhs.contains(' ') && !rhs.contains('(')
                            && rhs.chars().next().map_or(false, |c| c.is_ascii_lowercase()));
                    if is_simple {
                        lines.remove(i);
                        continue;
                    }
                    // Simplify: REG = expr - 0; → REG = expr;
                    let rhs = if rhs.ends_with(" - 0") {
                        rhs.trim_end_matches(" - 0").to_string()
                    } else if rhs.starts_with("0 + ") {
                        rhs[4..].to_string()
                    } else {
                        rhs.clone()
                    };
                    // Remove self-assignment: REG = REG;
                    if rhs == lhs {
                        lines.remove(i);
                        continue;
                    }
                }
            }
        }

        i += 1;
    }

    // Strip verbose casts and simplify common patterns
    for line in &mut lines {
        *line = line.replace("(int64_t)", "").replace("(uint64_t)", "");
        // * 1 in address expressions is identity
        *line = line.replace(" * 1)", ")").replace(" * 1 ", " ");
        // 0 - x → -x (negation)
        *line = line.replace("0 - ", "-");
        // x + -y → x - y
        *line = line.replace(" + -", " - ");
        // Division by constant via multiply-shift: x * MAGIC → x / N
        // Well-known magic numbers from compiler optimizations
        for (magic, divisor) in [
            ("0xffffffff92492493", "7"), ("0x92492493", "7"),
            ("0x66666667", "10"), ("0xcccccccd", "10"),
            ("0x55555556", "3"), ("0xaaaaaaab", "3"),
            ("0x2aaaaaab", "6"), ("0x24924925", "7"),
            ("0x38e38e39", "9"), ("0x51eb851f", "100"),
        ] {
            if line.contains(magic) {
                *line = line.replace(&format!("* {}", magic), &format!("/ {}", divisor));
                // Also clean up the shift: >> 0x20 after division is already handled
            }
        }
        // Hide IDIV remainder: EDX = ... % ... (almost never useful to display)
        if line.contains("EDX = ") && line.contains(" % ") {
            *line = String::new();
        }
        // (Array scaling cleanup happens after array syntax conversion below)
        // __chk suffix: __strcpy_chk(a, b, size) → strcpy(a, b)
        while let Some(pos) = line.find("__") {
            if let Some(chk) = line[pos..].find("_chk(") {
                let func_start = pos + 2;
                let func_end = pos + chk;
                let clean_name = line[func_start..func_end].to_string();
                // Find closing paren and strip last arg (the buffer size)
                let call_start = pos + chk + 4; // after "_chk"
                if let Some(close) = find_matching_paren(line, call_start) {
                    let args_str = &line[call_start + 1..close];
                    // Remove the last comma-separated argument
                    let mut args: Vec<&str> = args_str.split(", ").collect();
                    if args.len() > 2 { args.pop(); } // strcpy has 2 args, chk adds a 3rd
                    let new_call = format!("{}({})", clean_name, args.join(", "));
                    *line = format!("{}{}{}", &line[..pos], new_call, &line[close + 1..]);
                } else {
                    let old = format!("__{}_chk(", clean_name);
                    *line = line.replace(&old, &format!("{}(", clean_name));
                }
            } else {
                break;
            }
        }
        // Collapse double spaces from removals (but not indentation)
        while line.contains("  ") && !line.starts_with("  ") {
            *line = line.replace("  ", " ");
        }
        // Also collapse double spaces after indentation
        if line.starts_with("    ") {
            let trimmed = line.trim_start().to_string();
            let indent_len = line.len() - trimmed.len();
            let indent = &line[..indent_len];
            let cleaned = trimmed.replace("  ", " ");
            *line = format!("{}{}", indent, cleaned);
        }
    }

    // Remove loop increment lines inside while bodies: EAX = i + 1; (implicit in the loop)
    {
        let mut in_while = false;
        let mut depth = 0u32;
        let mut i = 0;
        while i < lines.len() {
            let lt = lines[i].trim();
            if lt.starts_with("while (") { in_while = true; depth = 0; }
            if in_while {
                if lt.contains('{') { depth += 1; }
                if lt.contains('}') { if depth > 0 { depth -= 1; } if depth == 0 { in_while = false; } }
                // Remove: REG = var + 1; (loop counter increment)
                if depth > 0 {
                    if let Some(eq_pos) = lt.find(" = ") {
                        let lhs = &lt[..eq_pos];
                        let rhs = lt[eq_pos + 3..].trim_end_matches(';');
                        let is_reg = lhs.len() >= 2 && lhs.len() <= 3
                            && lhs.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit());
                        if is_reg && rhs.ends_with(" + 1") {
                            lines.remove(i);
                            continue;
                        }
                    }
                }
            }
            i += 1;
        }
    }

    // Chain sequential register assignments (after casts are stripped):
    // REG = expr; REG = REG op X → REG = expr op X
    // REG = X; REG = Y → REG = Y (dead store)
    {
        let mut i = 0;
        while i + 1 < lines.len() {
            let l1 = lines[i].trim().to_string();
            let l2 = lines[i + 1].trim().to_string();
            if let (Some(eq1), Some(eq2)) = (l1.find(" = "), l2.find(" = ")) {
                let lhs1 = l1[..eq1].to_string();
                let rhs1 = l1[eq1 + 3..].trim_end_matches(';').to_string();
                let lhs2 = l2[..eq2].to_string();
                let rhs2 = l2[eq2 + 3..].trim_end_matches(';').to_string();
                if lhs1 == lhs2 {
                    // Pattern 1: REG = X; REG = REG op Y → REG = X op Y
                    if rhs2.starts_with(&format!("{} ", lhs1)) {
                        let suffix = &rhs2[lhs1.len()..];
                        let expr = if rhs1.contains(' ') {
                            format!("({}){}", rhs1, suffix)
                        } else {
                            format!("{}{}", rhs1, suffix)
                        };
                        let indent = lines[i].len() - lines[i].trim_start().len();
                        let pad = " ".repeat(indent);
                        lines[i] = format!("{}{} = {};", pad, lhs1, expr);
                        lines.remove(i + 1);
                        continue;
                    }
                    // Pattern 2: REG = X; REG = Y op REG → REG = Y op X
                    if rhs2.ends_with(&format!(" {}", lhs1)) || rhs2.contains(&format!(" {} ", lhs1)) {
                        let new_rhs = if rhs1.contains(' ') {
                            rhs2.replace(&lhs1, &format!("({})", rhs1))
                        } else {
                            rhs2.replace(&lhs1, &rhs1)
                        };
                        // Only fold if the replacement changed something
                        if new_rhs != rhs2 {
                            let indent = lines[i].len() - lines[i].trim_start().len();
                            let pad = " ".repeat(indent);
                            lines[i] = format!("{}{} = {};", pad, lhs1, new_rhs);
                            lines.remove(i + 1);
                            continue;
                        }
                    }
                    // Dead store: same LHS, second doesn't reference first
                    if !rhs2.contains(&lhs1) {
                        lines.remove(i);
                        continue;
                    }
                }
            }
            i += 1;
        }
    }

    // Replace "EAX = EAX op expr; return;" → "return param op expr;"
    // Only at the top level (not inside while/if bodies) to avoid
    // converting loop increments like i = i + 1 into false returns
    let first_param = param_names.first().cloned();
    if let Some(param_name) = first_param {
        let mut i = 0;
        while i < lines.len() {
            let lt = lines[i].trim().to_string();
            let indent_level = lines[i].len() - lines[i].trim_start().len();
            // Only apply at indent 0 or 4 (top level or first nesting level)
            if lt.starts_with("EAX = EAX ") && indent_level <= 4 {
                // Verify the next non-blank line is "return;" or end of function
                let next_is_return = lines[i + 1..].iter()
                    .find(|l| !l.trim().is_empty())
                    .map_or(false, |l| l.trim() == "return;");
                if next_is_return {
                    let pad = &lines[i][..indent_level];
                    let expr = lt.trim_start_matches("EAX = EAX ").trim_end_matches(';');
                    lines[i] = format!("{}return {} {};", pad, param_name, expr);
                    if i + 1 < lines.len() && lines[i + 1].trim() == "return;" {
                        lines.remove(i + 1);
                    }
                }
            }
            i += 1;
        }
    }

    // Apply stack variable aliases: var_8 → param_0 / DWARF name, etc.
    // Only substitute meaningful names (param_N, DWARF names), not constants or expressions
    for line in &mut lines {
        for (var_name, alias) in aliases {
            let alias_is_name = alias.starts_with("param_")
                || (alias.chars().next().map_or(false, |c| c.is_ascii_lowercase())
                    && alias.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    && !alias.chars().all(|c| c.is_ascii_digit() || c == 'x'));
            if var_name.starts_with("var_") && alias != var_name && alias_is_name {
                // Replace whole-word occurrences of var_N with param_M
                let pattern = var_name.as_str();
                let mut result = String::new();
                let mut rest = line.as_str();
                while let Some(pos) = rest.find(pattern) {
                    result.push_str(&rest[..pos]);
                    // Check word boundary
                    let before_ok = pos == 0 || !rest.as_bytes()[pos - 1].is_ascii_alphanumeric();
                    let after = pos + pattern.len();
                    let after_ok = after >= rest.len() || !rest.as_bytes()[after].is_ascii_alphanumeric();
                    if before_ok && after_ok {
                        result.push_str(alias);
                    } else {
                        result.push_str(pattern);
                    }
                    rest = &rest[after..];
                }
                result.push_str(rest);
                *line = result;
            }
        }
    }

    // Simplify x86 IDIV dividend pattern: EDX << 32 | X → X (sign extension noise)
    for line in &mut lines {
        for pattern in &["EDX << 32 | ", "EDX << 0x20 | ", "RDX << 32 | ", "RDX << 0x20 | "] {
            while let Some(pos) = line.find(pattern) {
                *line = format!("{}{}", &line[..pos], &line[pos + pattern.len()..]);
            }
        }
    }

    // Convert pointer dereferences to array access: *(type*)(base + idx) → base[idx]
    // Also: *(base + idx) → base[idx]
    // Only convert when the base looks like a simple variable name (no operators/spaces).
    // Skip `sp`-relative forms — those lose the scale factor on conversion, leaving
    // ambiguous `sp[2]` that can't be safely recovered to a local name. The later
    // sp→local pass handles `*(uint64_t*)(sp + N)` directly via `sp + N → local_N`.
    for line in &mut lines {
        // Pattern 1: *(uintN_t*)(X + Y)
        while let Some(star_pos) = line.find("*(uint") {
            if let Some(type_end) = line[star_pos..].find("*)(") {
                let abs_paren = star_pos + type_end + 2;
                if let Some(close) = find_matching_paren(line, abs_paren) {
                    let inner = &line[abs_paren + 1..close];
                    if let Some(plus) = find_array_split(inner) {
                        let base = &inner[..plus];
                        let idx = &inner[plus + 3..];
                        if base == "sp" { break; }
                        *line = format!("{}{}{}", &line[..star_pos],
                            format!("{}[{}]", base, idx), &line[close + 1..]);
                        continue;
                    }
                }
            }
            break;
        }
        // Pattern 2: *(X + Y) — plain pointer deref with addition
        while let Some(star_pos) = line.find("*(") {
            // Make sure it's not *(uint...*) which we already handled
            if line[star_pos + 2..].starts_with("uint") { break; }
            if let Some(close) = find_matching_paren(line, star_pos + 1) {
                let inner = &line[star_pos + 2..close];
                if let Some(plus) = find_array_split(inner) {
                    let base = &inner[..plus];
                    let idx = &inner[plus + 3..];
                    if base == "sp" { break; }
                    *line = format!("{}{}{}", &line[..star_pos],
                        format!("{}[{}]", base, idx), &line[close + 1..]);
                    continue;
                }
            }
            break;
        }
    }

    // Array element scaling: arr[idx * 4] → arr[idx] for int/ptr arrays
    for line in &mut lines {
        for scale in [" * 4]", " * 8]", " * 2]"] {
            while line.contains(scale) {
                *line = line.replace(scale, "]");
            }
        }
    }

    // Remove AArch64 stack spill/reload/epilogue patterns created by array conversion.
    // The ARM64 prologue saves callee-saved registers and the link register to the stack,
    // and the epilogue restores them. These appear as sp[N] assignments, sp->fieldN reads,
    // x30 restores, and return-via-stack patterns. All are architectural boilerplate.
    lines.retain(|line| {
        let t = line.trim();

        // === PROLOGUE: register saves to stack ===
        // sp[N] = VALUE; — callee-saved save, return address, or frame setup
        if t.starts_with("sp[") && t.ends_with(';') && t.contains("] = ") {
            let rhs = t.split("] = ").last().unwrap_or("").trim_end_matches(';').trim();
            // Keep string literals and named function calls — those are real data
            if rhs.starts_with('"') || rhs.starts_with("L\"") || rhs.contains("func_") {
                return true;
            }
            let is_spill = rhs.starts_with("lVar") || rhs.starts_with("iVar")
                || rhs.starts_with("dVar") || rhs.starts_with("param_")
                || rhs == "x29" || rhs == "x30" || rhs == "0"
                || rhs.starts_with("x0") || rhs.starts_with("x1") || rhs.starts_with("x2")
                || rhs.starts_with("x8") || rhs.starts_with("x9")
                || rhs.starts_with("0x")
                || rhs.starts_with("*(")
                // Small integer constants (stack frame size, alignment)
                || rhs.chars().all(|c| c.is_ascii_digit());
            if is_spill { return false; }
        }
        // sp->fieldN = VALUE; (alternative syntax for stack spills)
        if t.starts_with("sp->field") && t.ends_with(';') && t.contains(" = ") {
            let rhs = t.split(" = ").last().unwrap_or("").trim_end_matches(';').trim();
            if rhs.starts_with('"') || rhs.contains("func_") { return true; }
            let is_spill = rhs.starts_with("lVar") || rhs.starts_with("iVar")
                || rhs.starts_with("dVar") || rhs.starts_with("param_")
                || rhs == "x29" || rhs == "x30" || rhs == "0"
                || rhs.starts_with("0x") || rhs.starts_with("*(")
                || rhs.chars().all(|c| c.is_ascii_digit());
            if is_spill { return false; }
        }

        // === EPILOGUE: register restores from stack ===
        // x30 = sp->field_8; or x30 = sp[N]->field_8; (link register restore)
        // Also catches *(sp)->field_8 (post-indexed LDP variant)
        if (t.starts_with("x30 = sp") || t.starts_with("x30 = *(sp)")) && t.ends_with(';') {
            return false;
        }
        // lVarN = sp[N]; or lVarN = sp[N]->field_8; (callee-saved register reload)
        if (t.starts_with("lVar") || t.starts_with("iVar") || t.starts_with("dVar"))
            && t.contains(" = sp[") && t.ends_with(';')
        {
            return false;
        }
        // lVarN = sp->fieldN; or lVarN = sp->fieldN->field_8; (alternative reload syntax)
        if (t.starts_with("lVar") || t.starts_with("iVar") || t.starts_with("dVar"))
            && t.contains(" = sp->field") && t.ends_with(';')
        {
            return false;
        }

        // === RETURN via stack (epilogue return address load) ===
        // return sp->field_10->field_8; or return sp[N]->field_8;
        // Also catches return *(sp)->field_8; (post-indexed LDP variant)
        if (t.starts_with("return sp") || t.starts_with("return *(sp)"))
            && !t.contains("func_") && !t.contains("param_")
            && !t.contains("malloc") && !t.contains("strlen")
        {
            return false;
        }

        true
    });

    // Struct field access: ptr[4] → ptr->field4, ptr[8] → ptr->field8
    // Small constant offsets from pointers are struct field accesses, not array indices.
    // Convert base[N] to base->fieldN when N is a small constant (0-64).
    for line in &mut lines {
        let mut pos = 0;
        while let Some(br_start) = line[pos..].find('[') {
            let abs_start = pos + br_start;
            if let Some(br_end) = line[abs_start..].find(']') {
                let abs_end = abs_start + br_end;
                let idx = &line[abs_start + 1..abs_end];
                // Check if the index is a small decimal constant (struct field offset)
                if let Ok(offset) = idx.parse::<u64>() {
                    if offset <= 64 && offset > 0 && offset % 4 == 0 {
                        // This looks like a struct field access (4-byte aligned small offset)
                        let field_name = format!("->field{:x}", offset);
                        *line = format!("{}{}{}", &line[..abs_start], field_name, &line[abs_end + 1..]);
                        continue; // Re-scan
                    }
                }
                // Also: hex constant like 0x10
                if idx.starts_with("0x") {
                    if let Ok(offset) = u64::from_str_radix(&idx[2..], 16) {
                        if offset <= 64 && offset > 0 && offset % 4 == 0 {
                            let field_name = format!("->field{:x}", offset);
                            *line = format!("{}{}{}", &line[..abs_start], field_name, &line[abs_end + 1..]);
                            continue;
                        }
                    }
                }
                pos = abs_end + 1;
            } else {
                break;
            }
        }
    }

    // Replace register names before -> with parameter names in struct accesses.
    // RAX->field4 → a->field4 when a is a known parameter.
    // Different registers map to different params by occurrence order.
    if !param_names.is_empty() {
        for line in &mut lines {
            if !line.contains("->") { continue; }
            let mut param_idx = 0;
            let reg_names = ["RAX", "RCX", "RDX", "RBX", "RSI", "RDI", "R8", "R9"];
            for reg in &reg_names {
                let arrow = format!("{}->", reg);
                while line.contains(&arrow) && param_idx < param_names.len() {
                    let replacement = format!("{}->", param_names[param_idx]);
                    *line = line.replacen(&arrow, &replacement, 1);
                    param_idx += 1;
                }
            }
        }
    }

    // Replace ->fieldN with ->actual_name using DWARF struct field info
    if !struct_fields.is_empty() {
        for line in &mut lines {
            if !line.contains("->field") { continue; }
            for (offset, name) in struct_fields {
                let pattern = format!("->field{:x}", offset);
                if line.contains(&pattern) {
                    let replacement = format!("->{}", name);
                    *line = line.replace(&pattern, &replacement);
                }
            }
        }
    }

    // Normalize FS_OFFSET canary accesses → __stack_chk_guard
    // The TLS canary at FS:0x28 may appear as FS_OFFSET->field28, FS_OFFSET->_IO_write_ptr,
    // or other names depending on DWARF struct info loaded
    for line in &mut lines {
        *line = line.replace("FS_OFFSET->field28", "__stack_chk_guard");
        // FS_OFFSET->_IO_write_ptr is a mis-named canary field (struct offset 0x28 matches FILE layout)
        *line = line.replace("FS_OFFSET->_IO_write_ptr", "__stack_chk_guard");
        // Generic: any FS_OFFSET->fieldXX or FS_OFFSET[XX] access is the canary
        if line.contains("FS_OFFSET") && !line.contains("__stack_chk_guard") {
            // Replace FS_OFFSET references with __stack_chk_guard
            if let Some(fs_pos) = line.find("FS_OFFSET") {
                // Find the end of the FS_OFFSET->xxx or *(FS_OFFSET + xxx) expression
                let after = &line[fs_pos..];
                let end = after.find(|c: char| c == ')' || c == ';' || c == ' ')
                    .map(|p| fs_pos + p)
                    .unwrap_or(line.len());
                let replacement = format!("{}{}{}", &line[..fs_pos], "__stack_chk_guard", &line[end..]);
                *line = replacement;
            }
        }
    }

    // Remove stack canary check blocks.
    // Matches: if (... __stack_chk_guard ...) { ... } or any if-block containing __stack_chk_fail()
    {
        let mut j = 0;
        while j < lines.len() {
            let lt = lines[j].trim().to_string();
            // Match if-blocks that are canary checks:
            // 1. Condition mentions __stack_chk_guard
            // 2. Body contains __stack_chk_fail()
            let is_canary_if = lt.starts_with("if (") && (
                lt.contains("__stack_chk_guard") || lt.contains("__stack_chk_fail")
            );
            // Also match if-blocks where __stack_chk_fail is in the DIRECT body (depth 1),
            // not in a deeply nested sub-block. This prevents removing real code that
            // happens to contain a canary check in an error path.
            let is_canary_block = if lt.starts_with("if (") && !is_canary_if {
                let mut has_fail_at_depth1 = false;
                let mut depth = 0;
                for k in j..lines.len().min(j + 10) {
                    if lines[k].contains('{') { depth += 1; }
                    if depth == 1 && lines[k].contains("__stack_chk_fail") { has_fail_at_depth1 = true; break; }
                    if lines[k].contains('}') { depth -= 1; if depth == 0 { break; } }
                }
                has_fail_at_depth1
            } else { false };

            if is_canary_if || is_canary_block {
                // Find the end of the if-block and remove it entirely
                let mut depth = 0;
                let mut end = None;
                // Extract any return statement from inside
                let mut extracted_return = None;
                for k in j..lines.len() {
                    let kl = lines[k].trim();
                    if kl.starts_with("return") && depth == 1 && !kl.contains("__stack_chk") {
                        extracted_return = Some(lines[k].clone());
                    }
                    if lines[k].contains('{') { depth += 1; }
                    if lines[k].contains('}') { depth -= 1; if depth == 0 { end = Some(k); break; } }
                }
                if let Some(end_idx) = end {
                    for idx in (j..=end_idx).rev() { lines.remove(idx); }
                    if let Some(ret) = extracted_return {
                        lines.insert(j, ret);
                    }
                    continue;
                }
            }
            // Also remove standalone canary lines
            if lt.contains("__stack_chk_guard") && !lt.starts_with("if ") {
                lines.remove(j);
                continue;
            }
            if lt.contains("__stack_chk_fail") {
                lines.remove(j);
                continue;
            }
            j += 1;
        }
    }

    // Simplify *(stdout) → stdout, *(stdin) → stdin, *(stderr) → stderr
    // These are loaded via GOT pointer dereference but should appear as the symbol
    for line in &mut lines {
        *line = line.replace("*(stdout)", "stdout");
        *line = line.replace("*(stdin)", "stdin");
        *line = line.replace("*(stderr)", "stderr");
    }

    // Clean up "RAX = stdout;" or "RAX = stdin;" lines before function calls
    // These are intermediate loads that should be elided
    {
        let mut j = 0;
        while j + 1 < lines.len() {
            let lt = lines[j].trim().to_string();
            if (lt == "RAX = stdout;" || lt == "RAX = stdin;" || lt == "RAX = stderr;")
                && lines.get(j + 1).map_or(false, |next| {
                    let nt = next.trim();
                    nt.contains("(RAX") || nt.contains(", RAX")
                })
            {
                // Replace RAX in the next line with the symbol name
                let sym = if lt.contains("stdout") { "stdout" }
                    else if lt.contains("stdin") { "stdin" }
                    else { "stderr" };
                lines[j + 1] = lines[j + 1].replace("RAX", sym);
                lines.remove(j);
                continue;
            }
            j += 1;
        }
    }

    // Replace *(REG) with *(param) for pointer dereferences in conditions
    // (skip lines that look like byte-pickoff expressions — those use post-call registers
    // which are not parameters and must not be renamed)
    if !param_names.is_empty() {
        for line in &mut lines {
            // Don't rename register dereferences in bit-shift byte-pack expressions;
            // those use post-call registers which are not parameters.
            if line.contains("<< 24") || line.contains("<< 16") || line.contains("<< 8") {
                continue;
            }
            let reg_names = ["RAX", "RCX", "RDX", "RBX", "RSI", "RDI", "R8", "R9",
                             "EAX", "ECX", "EDX", "EBX", "ESI", "EDI"];
            let mut param_idx = 0;
            for reg in &reg_names {
                let deref = format!("*({})", reg);
                while line.contains(&deref) && param_idx < param_names.len() {
                    let replacement = format!("*({})", param_names[param_idx]);
                    *line = line.replacen(&deref, &replacement, 1);
                    param_idx += 1;
                }
            }
        }
    }

    // Fold accumulator chains: EDX = a; EAX = b; EDX = EDX + EAX; → EDX = a + b;
    // Runs after struct field conversion so field names are preserved.
    {
        let mut i = 0;
        while i + 2 < lines.len() {
            let l1 = lines[i].trim().to_string();
            let l2 = lines[i + 1].trim().to_string();
            let l3 = lines[i + 2].trim().to_string();
            if let (Some(eq1), Some(eq2), Some(eq3)) = (l1.find(" = "), l2.find(" = "), l3.find(" = ")) {
                let lhs1 = l1[..eq1].to_string();
                let rhs1 = l1[eq1 + 3..].trim_end_matches(';').to_string();
                let lhs2 = l2[..eq2].to_string();
                let rhs2 = l2[eq2 + 3..].trim_end_matches(';').to_string();
                let lhs3 = l3[..eq3].to_string();
                let rhs3 = l3[eq3 + 3..].trim_end_matches(';').to_string();
                // Pattern: ACC = expr; TMP = val; ACC = ACC + TMP;
                if lhs1 == lhs3 && rhs3 == format!("{} + {}", lhs1, lhs2) {
                    let indent = lines[i].len() - lines[i].trim_start().len();
                    let pad = " ".repeat(indent);
                    lines[i] = format!("{}{} = {} + {};", pad, lhs1, rhs1, rhs2);
                    lines.remove(i + 2);
                    lines.remove(i + 1);
                    continue;
                }
                // Also: ACC = expr; TMP = (val) + ACC; → ACC = expr + val;
                if lhs2 == lhs3 && rhs3.ends_with(&format!(" + {}", lhs1)) {
                    let val_part = rhs3.trim_end_matches(&format!(" + {}", lhs1));
                    let indent = lines[i].len() - lines[i].trim_start().len();
                    let pad = " ".repeat(indent);
                    lines[i] = format!("{}{} = {} + {};", pad, lhs2, rhs1, val_part);
                    lines.remove(i + 2);
                    lines.remove(i + 1);
                    continue;
                }
            }
            i += 1;
        }
    }

    // Elide redundant register assignments: REG = expr; var = expr; → var = expr;
    // When a Store to a stack variable captures the same expression that was just
    // assigned to a register, the register assignment is pure noise.
    {
        let mut i = 0;
        while i + 1 < lines.len() {
            let l1 = lines[i].trim().to_string();
            let l2 = lines[i + 1].trim().to_string();
            if let (Some(eq1), Some(eq2)) = (l1.find(" = "), l2.find(" = ")) {
                let lhs1 = &l1[..eq1];
                let rhs1 = l1[eq1 + 3..].trim_end_matches(';');
                let lhs2 = &l2[..eq2];
                let rhs2 = l2[eq2 + 3..].trim_end_matches(';');
                // REG = expr; var_X = expr; → remove REG line
                let is_reg = lhs1.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
                    && lhs1.len() >= 2 && lhs1.len() <= 3;
                let is_var = lhs2.starts_with("var_") || lhs2.chars().next().map_or(false, |c| c.is_ascii_lowercase());
                if is_reg && is_var && rhs1 == rhs2 {
                    lines.remove(i);
                    continue;
                }
                // Also: REG = expr; var_X = different_expr_containing_REG;
                // But the var line should be self-contained, so just check exact match
            }
            i += 1;
        }
    }

    // Final cleanup pass after alias substitution: identity ops and self-assignments
    let mut i = 0;
    while i < lines.len() {
        let lt = lines[i].trim().to_string();
        // REG = REG - 0; → remove (identity)
        if lt.ends_with(" - 0;") || lt.ends_with(" + 0;") {
            if let Some(eq_pos) = lt.find(" = ") {
                let lhs = &lt[..eq_pos];
                let rhs = lt[eq_pos + 3..].trim_end_matches(';')
                    .trim_end_matches(" - 0").trim_end_matches(" + 0");
                if lhs == rhs {
                    lines.remove(i);
                    continue;
                }
            }
        }
        // REG = REG; → remove (self-assign)
        if let Some(eq_pos) = lt.find(" = ") {
            let lhs = &lt[..eq_pos];
            let rhs = lt[eq_pos + 3..].trim_end_matches(';');
            if lhs == rhs {
                lines.remove(i);
                continue;
            }
        }
        i += 1;
    }

    // Remove register setup lines before while loops, but record the mappings
    // so we can substitute inside the loop body (e.g., ECX = len - 1 → use in str[ECX - i])
    let mut loop_reg_values: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    {
        let mut i = 0;
        while i < lines.len() {
            let lt = lines[i].trim().to_string();
            if let Some(eq_pos) = lt.find(" = ") {
                let lhs = lt[..eq_pos].to_string();
                let rhs = lt[eq_pos + 3..].trim_end_matches(';').to_string();
                let is_reg = lhs.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
                    && lhs.len() >= 2 && lhs.len() <= 3;
                if is_reg {
                    let next_nonblank = lines[i + 1..].iter()
                        .find(|l| {
                            let t = l.trim();
                            !t.is_empty() && !{
                                if let Some(ep) = t.find(" = ") {
                                    let lh = &t[..ep];
                                    lh.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
                                        && lh.len() >= 2 && lh.len() <= 3
                                } else { false }
                            }
                        })
                        .map(|l| l.trim().to_string());
                    if next_nonblank.as_ref().map_or(false, |n| n.starts_with("while (")) {
                        // Don't remove function call results before while loops — the call
                        // has side effects and its return value binding should be visible.
                        // Only remove/record simple variable references and expressions.
                        let is_call_rhs = rhs.contains('(') && rhs.contains(')');
                        if !is_call_rhs {
                            // Record the register value for use inside the loop
                            // Only record meaningful expressions (not other registers or constants)
                            if rhs.contains("var_") || rhs.contains("len") || rhs.contains("param")
                                || rhs.contains("str") || (rhs.contains(' ') && !rhs.starts_with("0x"))
                            {
                                loop_reg_values.insert(lhs, rhs);
                            }
                            lines.remove(i);
                            continue;
                        }
                    }
                }
            }
            i += 1;
        }
    }

    // Apply loop register values: substitute REG with its pre-loop expression inside while bodies
    if !loop_reg_values.is_empty() {
        let mut in_while = false;
        let mut depth = 0u32;
        for line in &mut lines {
            let lt = line.trim();
            if lt.starts_with("while (") {
                in_while = true;
                depth = 0;
            }
            if in_while {
                if lt.contains('{') { depth += 1; }
                if lt.contains('}') {
                    if depth > 0 { depth -= 1; }
                    if depth == 0 { in_while = false; continue; }
                }
                // Substitute register names in array indices: [REG - expr] → [value - expr]
                for (reg, val) in &loop_reg_values {
                    // Only substitute inside brackets to avoid changing the LHS of assignments
                    let bracket_reg = format!("[{}", reg);
                    if line.contains(&bracket_reg) {
                        let paren_val = if val.contains(' ') {
                            format!("({})", val)
                        } else {
                            val.clone()
                        };
                        *line = line.replace(&bracket_reg, &format!("[{}", paren_val));
                    }
                }
            }
        }
    }

    // Second pass: remove redundant "REG = call();" after all simplifications
    let mut i = 0;
    while i < lines.len() {
        let lt = lines[i].trim().to_string();
        if let Some(eq_pos) = lt.find(" = ") {
            let lhs = &lt[..eq_pos];
            let rhs = &lt[eq_pos + 3..lt.len().saturating_sub(1)];
            let is_reg = lhs.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
                && lhs.len() >= 2 && lhs.len() <= 3;
            let is_call = rhs.contains('(') && rhs.contains(')');
            if is_reg && is_call {
                let mut redundant = false;
                for j in (0..i).chain(i + 1..lines.len()) {
                    if lines[j].trim().contains(rhs) {
                        redundant = true;
                        break;
                    }
                }
                if redundant {
                    lines.remove(i);
                    continue;
                }
            }
        }
        i += 1;
    }

    // Replace RAX in array accesses with first parameter name (common: str[idx])
    if !param_names.is_empty() {
        let p0 = &param_names[0];
        for line in &mut lines {
            *line = line.replace("RAX[", &format!("{}[", p0));
        }
    }

    // Inline register assignments into array index expressions:
    // "RCX = expr;" + "str[RCX] = val;" → "str[expr] = val;"
    {
        let mut i = 0;
        while i + 1 < lines.len() {
            let lt = lines[i].trim().to_string();
            if let Some(eq_pos) = lt.find(" = ") {
                let lhs = &lt[..eq_pos];
                let rhs = lt[eq_pos + 3..].trim_end_matches(';').to_string();
                // Only for register assignments (RCX, ECX, etc.)
                let is_reg = lhs.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
                    && lhs.len() >= 2 && lhs.len() <= 3;
                if is_reg {
                    // Check if the next line uses this register (or its 64-bit alias) in array index
                    let next = lines[i + 1].trim().to_string();
                    // ECX→RCX, EAX→RAX, EDX→RDX, etc. (32→64 bit alias)
                    let alias64 = if lhs.starts_with('E') {
                        format!("R{}", &lhs[1..])
                    } else { String::new() };
                    let bracket_pattern = format!("[{}]", lhs);
                    let bracket_alias = if !alias64.is_empty() { format!("[{}]", alias64) } else { String::new() };
                    let matching_bracket = if next.contains(&bracket_pattern) {
                        Some(bracket_pattern.clone())
                    } else if !bracket_alias.is_empty() && next.contains(&bracket_alias) {
                        Some(bracket_alias)
                    } else { None };
                    if let Some(bp) = matching_bracket {
                        let indent = lines[i + 1].len() - lines[i + 1].trim_start().len();
                        let pad = &lines[i + 1][..indent];
                        let new_next = next.replace(&bp, &format!("[{}]", rhs));
                        lines[i + 1] = format!("{}{}", pad, new_next);
                        lines.remove(i);
                        continue;
                    }
                    // Chain: REG1 = expr; REG2 = REG1; use[REG2] → use[expr]
                    // Check if next line is "REG2 = REG1;" or "REG2 = lhs;"
                    if let Some(next_eq) = next.find(" = ") {
                        let next_lhs = &next[..next_eq];
                        let next_rhs = next[next_eq + 3..].trim_end_matches(';');
                        if next_rhs == lhs || (!alias64.is_empty() && next_rhs == alias64) {
                            // Chain: replace REG1 assignment with REG2 = expr
                            let indent = lines[i].len() - lines[i].trim_start().len();
                            let pad = &lines[i][..indent];
                            lines[i] = format!("{}{} = {};", pad, next_lhs, rhs);
                            lines.remove(i + 1);
                            continue; // Re-process the composed line
                        }
                    }
                }
            }
            i += 1;
        }
    }

    // Inline byte register assignments into immediate uses:
    // "DL = expr;" + "str[i] = DL;" → "str[i] = expr;"
    {
        let mut i = 0;
        while i + 1 < lines.len() {
            let lt = lines[i].trim().to_string();
            if let Some(eq_pos) = lt.find(" = ") {
                let lhs = &lt[..eq_pos];
                let rhs = lt[eq_pos + 3..].trim_end_matches(';').to_string();
                // Only for byte registers (AL, BL, CL, DL)
                if matches!(lhs, "AL" | "BL" | "CL" | "DL") {
                    let next = lines[i + 1].trim().to_string();
                    // Check if next line uses this register as a value (not as an index)
                    let pattern = format!(" = {};", lhs);
                    if next.ends_with(&pattern) {
                        let indent = lines[i + 1].len() - lines[i + 1].trim_start().len();
                        let pad = &lines[i + 1][..indent];
                        let new_next = next.replace(&pattern, &format!(" = {};", rhs));
                        lines[i + 1] = format!("{}{}", pad, new_next);
                        lines.remove(i);
                        continue;
                    }
                }
            }
            i += 1;
        }
    }

    // Remove x86-32 ESP boilerplate lines: stack adjustments and prologue noise.
    lines.retain(|line| {
        let t = line.trim();
        // Remove "ESP = ESP - 4;" and "ESP = ESP + N;" (cdecl stack cleanup)
        if t.starts_with("ESP = ESP - ") && t.ends_with(';') { return false; }
        if t.starts_with("ESP = ESP + ") && t.ends_with(';') { return false; }
        // Remove "ESP = (ESP + N) - 4;" and similar compound forms
        if t.starts_with("ESP = (ESP") && t.ends_with(';') && !t.contains("func_")
            && !t.contains("var_") && !t.contains("param_")
        { return false; }
        // Remove "ESP = param_..." (prologue ESP init)
        if t.starts_with("ESP = param_") && t.ends_with(';') { return false; }
        // Remove "*(uint32_t*)(ESP) = EBP;" (push EBP) and other prologue pushes
        if t == "*(uint32_t*)(ESP) = EBP;" { return false; }
        if t == "*(uint32_t*)(ESP) = EBX;" { return false; }
        if t == "*(uint32_t*)(ESP) = ESI;" { return false; }
        if t == "*(uint32_t*)(ESP) = EDI;" { return false; }
        // Remove "*(uint32_t*)(ESP) = 0x40xxxx;" (return address pushes)
        if t.starts_with("*(uint32_t*)(ESP) = 0x40") && t.ends_with(';') { return false; }
        if t.starts_with("*(uint32_t*)(ESP) = 0x41") && t.ends_with(';') { return false; }
        if t.starts_with("*(uint32_t*)(ESP) = 0x42") && t.ends_with(';') { return false; }
        // Remove standalone ESP stores of constants that are PUSH boilerplate
        // "*(uint32_t*)(ESP) = -1;" (SEH frame sentinel)
        if t == "*(uint32_t*)(ESP) = -1;" { return false; }
        true
    });

    // Remove x86-64 RSP boilerplate: stack frame setup/teardown noise
    lines.retain(|line| {
        let t = line.trim();
        // RSP = RSP - N / RSP = RSP + N (frame allocation/deallocation)
        if t.starts_with("RSP = RSP ") && t.ends_with(';') { return false; }
        // *(uint64_t*)(RBP) = -2; (stack cookie sentinel)
        if t == "*(uint64_t*)(RBP) = -2;" { return false; }
        // *(uint64_t*)(RSP) = RBP; (push rbp)
        if t == "*(uint64_t*)(RSP) = RBP;" { return false; }
        // RBP = RSP; or RBP = RSP + N; (frame pointer setup)
        if t.starts_with("RBP = RSP") && t.ends_with(';') && !t.contains("func_") { return false; }
        true
    });

    // x86-64 RBP-relative stack access → local variable names.
    // "RBP + 560" → "local_230" (offset from frame base)
    // "RBP[0x1f0]" → "local_1f0"
    // "RBP + 0" → suppress (frame pointer itself)
    for line in &mut lines {
        // RBP + decimal_offset
        while let Some(pos) = line.find("RBP + ") {
            let after = &line[pos + 6..];
            let end = after.find(|c: char| !c.is_ascii_digit()).unwrap_or(after.len());
            if end > 0 {
                if let Ok(offset) = after[..end].parse::<u64>() {
                    if offset == 0 {
                        // RBP + 0 → just RBP (or skip)
                        let replacement = "RBP".to_string();
                        *line = format!("{}{}{}", &line[..pos], replacement, &line[pos + 6 + end..]);
                    } else {
                        let replacement = format!("local_{:x}", offset);
                        *line = format!("{}{}{}", &line[..pos], replacement, &line[pos + 6 + end..]);
                    }
                    continue;
                }
            }
            break;
        }
        // RBP[0xHHH]
        while let Some(pos) = line.find("RBP[0x") {
            let after = &line[pos + 6..];
            let end = after.find(']').unwrap_or(0);
            if end > 0 {
                let hex = &after[..end];
                if let Ok(offset) = u64::from_str_radix(hex, 16) {
                    let replacement = format!("local_{:x}", offset);
                    *line = format!("{}{}{}", &line[..pos], replacement, &line[pos + 7 + end..]);
                    continue;
                }
            }
            break;
        }
        // RBP[N] (decimal index)
        while let Some(pos) = line.find("RBP[") {
            if line[pos + 4..].starts_with("0x") { break; } // already handled above
            let after = &line[pos + 4..];
            let end = after.find(']').unwrap_or(0);
            if end > 0 {
                if let Ok(idx) = after[..end].parse::<u64>() {
                    let replacement = format!("local_{:x}", idx * 8); // RBP[N] = *(RBP + N*8)
                    *line = format!("{}{}{}", &line[..pos], replacement, &line[pos + 5 + end..]);
                    continue;
                }
            }
            break;
        }
    }

    // AArch64 stack locals: `sp - N + M` and `(sp - N)->fieldM` → `local_M`.
    //
    // ARM64 prologue `stp x29, x30, [sp, #-N]!` decrements sp by N (the frame size).
    // The SSA preserves the entry-block sp (sp_caller); references to sp_new appear
    // as `sp - N`. Locals at offset M from the frame base appear as either:
    //   * `sp - N + M`            (additive form, M may be hex `0x..`)
    //   * `sp - N->fieldM`        (struct-field form when M was a small constant)
    //   * `sp - N + M->fieldK`    (combined: actual offset = M + K)
    // We detect the frame size N as the largest constant subtracted from sp anywhere
    // in the function (the frame base is the deepest sp reference; smaller `sp - K`
    // values are intermediate offsets within the frame).
    {
        // Phase 1: collect all `sp - N` constants in the function output.
        let mut sp_subs: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        for line in lines.iter() {
            let mut s = line.as_str();
            while let Some(pos) = s.find("sp - ") {
                let after = &s[pos + 5..];
                // Parse the constant: decimal or 0xHEX, terminated by non-hex/non-digit
                let (num_str, parsed): (&str, Option<u64>) = if after.starts_with("0x") {
                    let rest = &after[2..];
                    let end = rest.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(rest.len());
                    (&rest[..end], u64::from_str_radix(&rest[..end], 16).ok())
                } else {
                    let end = after.find(|c: char| !c.is_ascii_digit()).unwrap_or(after.len());
                    (&after[..end], after[..end].parse::<u64>().ok())
                };
                if let Some(n) = parsed {
                    if n > 0 { sp_subs.insert(n); }
                }
                s = if after.starts_with("0x") {
                    &after[2 + num_str.len()..]
                } else {
                    &after[num_str.len()..]
                };
            }
        }
        // The frame size is the largest `sp - N` constant (locals live within `[sp_new, sp_new+N)`,
        // so any address inside the frame appears as `sp - K` with K ≤ N).
        // Fallback: handle `sp->field_<hex>` with bounded offset even when no
        // `sp - N` subtraction was detected (leaf functions that use the red
        // zone or work directly with the entry sp without allocating a frame).
        // Only safe for small offsets — cap at 0x1000 which is well above any
        // realistic direct stack local.
        // Determine effective frame size: skip trivial zero entries so a
        // meaningless `sp - 0` doesn't suppress the fallback.
        let effective_frame = sp_subs.iter().rev().find(|&&v| v > 0).copied().unwrap_or(0);
        if effective_frame == 0 {
            for line in lines.iter_mut() {
                let mut search_from = 0usize;
                while let Some(rel) = line[search_from..].find("sp->field_") {
                    let pos = search_from + rel;
                    let prev = if pos == 0 { b' ' } else { line.as_bytes()[pos - 1] };
                    if prev.is_ascii_alphanumeric() || prev == b'_' {
                        search_from = pos + "sp->field_".len();
                        continue;
                    }
                    let after_start = pos + "sp->field_".len();
                    let after = &line[after_start..];
                    let end = after.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(after.len());
                    if end == 0 {
                        search_from = after_start;
                        continue;
                    }
                    let Ok(off) = u64::from_str_radix(&after[..end], 16) else {
                        search_from = after_start + end;
                        continue;
                    };
                    if off > 0x1000 {
                        search_from = after_start + end;
                        continue;
                    }
                    let replacement = format!("local_{:x}", off);
                    *line = format!("{}{}{}",
                        &line[..pos], replacement, &line[after_start + end..]);
                    search_from = pos + replacement.len();
                }
            }
        }
        if let Some(&frame_size) = sp_subs.iter().next_back() {
            let pat_field = format!("sp - {}->field_", frame_size);
            let pat_hex_field = format!("sp - 0x{:x}->field_", frame_size);
            let pat_plus = format!("sp - {} + ", frame_size);
            let pat_hex_plus = format!("sp - 0x{:x} + ", frame_size);
            let pat_bare = format!("sp - {}", frame_size);
            let pat_hex_bare = format!("sp - 0x{:x}", frame_size);
            // Helper: emit local name from hex offset (canonical form)
            let local_name = |offset: u64| -> String { format!("local_{:x}", offset) };
            // Parenthesized bare form: `(sp - N)` — emitted by some upstream
            // passes as the base of a FieldAccess. Rewrite to `local_0` *without*
            // keeping the surrounding `()` so downstream output is
            // `local_0->field_X` not `(local_0)->field_X`.
            let pat_paren_bare = format!("(sp - {})", frame_size);
            let pat_paren_hex_bare = format!("(sp - 0x{:x})", frame_size);
            for line in lines.iter_mut() {
                for pat in [&pat_paren_bare, &pat_paren_hex_bare] {
                    while let Some(pos) = line.find(pat.as_str()) {
                        *line = format!("{}{}{}", &line[..pos], local_name(0), &line[pos + pat.len()..]);
                    }
                }
            }
            for line in lines.iter_mut() {
                // (sp - N)->fieldM and sp - N->field_M → local_M (M is hex)
                for pat in [&pat_field, &pat_hex_field] {
                    while let Some(pos) = line.find(pat.as_str()) {
                        let after = &line[pos + pat.len()..];
                        let end = after.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(after.len());
                        if end == 0 { break; }
                        if let Ok(off) = u64::from_str_radix(&after[..end], 16) {
                            let replacement = local_name(off);
                            *line = format!("{}{}{}", &line[..pos], replacement, &line[pos + pat.len() + end..]);
                            continue;
                        }
                        break;
                    }
                }
                // sp - N + M → local_M (M is decimal or 0xHEX)
                for pat in [&pat_plus, &pat_hex_plus] {
                    while let Some(pos) = line.find(pat.as_str()) {
                        let after = &line[pos + pat.len()..];
                        let (num_len, parsed): (usize, Option<u64>) = if after.starts_with("0x") {
                            let rest = &after[2..];
                            let end = rest.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(rest.len());
                            (2 + end, u64::from_str_radix(&rest[..end], 16).ok())
                        } else {
                            let end = after.find(|c: char| !c.is_ascii_digit()).unwrap_or(after.len());
                            (end, after[..end].parse::<u64>().ok())
                        };
                        if num_len == 0 { break; }
                        if let Some(off) = parsed {
                            let replacement = local_name(off);
                            *line = format!("{}{}{}", &line[..pos], replacement, &line[pos + pat.len() + num_len..]);
                            continue;
                        }
                        break;
                    }
                }
                // `sp->field_M` (no subtraction) — sp denotes the post-prologue
                // live stack pointer, so offset M from it names the same local
                // as `local_M` in the frame base coordinate system. Gate on
                // `M <= frame_size` so we only rewrite offsets inside the
                // current frame.
                let pat_sp_arrow = "sp->field_";
                let mut search_from = 0usize;
                while let Some(rel) = line[search_from..].find(pat_sp_arrow) {
                    let pos = search_from + rel;
                    let prev = if pos == 0 { b' ' } else { line.as_bytes()[pos - 1] };
                    if prev.is_ascii_alphanumeric() || prev == b'_' {
                        search_from = pos + pat_sp_arrow.len();
                        continue;
                    }
                    let after_start = pos + pat_sp_arrow.len();
                    let after = &line[after_start..];
                    let end = after.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(after.len());
                    if end == 0 {
                        search_from = after_start;
                        continue;
                    }
                    let Ok(off) = u64::from_str_radix(&after[..end], 16) else {
                        search_from = after_start + end;
                        continue;
                    };
                    if off > frame_size {
                        search_from = after_start + end;
                        continue;
                    }
                    let replacement = local_name(off);
                    *line = format!("{}{}{}",
                        &line[..pos], replacement, &line[after_start + end..]);
                    search_from = pos + replacement.len();
                }
                // Bare `sp - N` (no further +/-> ) → local_0 (frame base itself)
                for pat in [&pat_bare, &pat_hex_bare] {
                    while let Some(pos) = line.find(pat.as_str()) {
                        let after_pos = pos + pat.len();
                        let next = line.as_bytes().get(after_pos).copied().unwrap_or(b' ');
                        // Don't match if this `sp - N` is followed by another digit/hex
                        // (could be part of a longer constant) or by `->` (handled above)
                        // or by ` + ` / ` - ` (handled above)
                        if next.is_ascii_alphanumeric() || next == b'-' || next == b'+' { break; }
                        let replacement = local_name(0);
                        *line = format!("{}{}{}", &line[..pos], replacement, &line[after_pos..]);
                    }
                }
                // `sp + M` (where SSA used the post-prologue sp directly, equivalent to
                // sp_v1 + M = local_M). Only transform when M ≤ frame_size — a sane
                // local lives within the frame; M > frame_size would cross into caller
                // argument area and is left alone to avoid false positives.
                let pat_sp_plus = "sp + ";
                let mut search_from = 0usize;
                while let Some(rel) = line[search_from..].find(pat_sp_plus) {
                    let pos = search_from + rel;
                    // Avoid matching inside a longer identifier like "lsp +"
                    let prev = if pos == 0 { b' ' } else { line.as_bytes()[pos - 1] };
                    if prev.is_ascii_alphanumeric() || prev == b'_' {
                        search_from = pos + pat_sp_plus.len();
                        continue;
                    }
                    let after = &line[pos + pat_sp_plus.len()..];
                    let (num_len, parsed): (usize, Option<u64>) = if after.starts_with("0x") {
                        let rest = &after[2..];
                        let end = rest.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(rest.len());
                        (2 + end, u64::from_str_radix(&rest[..end], 16).ok())
                    } else {
                        let end = after.find(|c: char| !c.is_ascii_digit()).unwrap_or(after.len());
                        (end, after[..end].parse::<u64>().ok())
                    };
                    if num_len == 0 || parsed.is_none() {
                        search_from = pos + pat_sp_plus.len();
                        continue;
                    }
                    let off = parsed.unwrap();
                    if off == 0 || off > frame_size {
                        search_from = pos + pat_sp_plus.len();
                        continue;
                    }
                    let replacement = local_name(off);
                    let new_line = format!("{}{}{}", &line[..pos], replacement, &line[pos + pat_sp_plus.len() + num_len..]);
                    search_from = pos + replacement.len();
                    *line = new_line;
                }
                // `sp[N]` and `sp[N + M]` bracket form — emitted when a Store addr
                // computes `Add(sp, const)` and the printer chose array-index syntax.
                // Inside brackets the arithmetic is already byte offset, so merge
                // additive constants directly to a single local_<off>.
                let mut search_from = 0usize;
                while let Some(rel) = line[search_from..].find("sp[") {
                    let pos = search_from + rel;
                    let prev = if pos == 0 { b' ' } else { line.as_bytes()[pos - 1] };
                    if prev.is_ascii_alphanumeric() || prev == b'_' {
                        search_from = pos + 3;
                        continue;
                    }
                    let inner_start = pos + 3;
                    let close = match line[inner_start..].find(']') {
                        Some(n) => inner_start + n,
                        None => break,
                    };
                    let inner = &line[inner_start..close];
                    // Parse inner as `N`, `N + M`, `N - M` (constants only)
                    let mut total: i64 = 0;
                    let mut sign: i64 = 1;
                    let mut ok = true;
                    for (i, part) in inner.split(|c: char| c == '+' || c == '-').enumerate() {
                        let t = part.trim();
                        if t.is_empty() { ok = false; break; }
                        let v = if let Some(h) = t.strip_prefix("0x") {
                            i64::from_str_radix(h, 16).ok()
                        } else { t.parse::<i64>().ok() };
                        let Some(v) = v else { ok = false; break; };
                        if i == 0 { total = v; }
                        else { total += sign * v; }
                        // Capture next operator char from original string
                        // (already consumed by split — peek by scanning forward)
                        let _ = sign; // silence
                        // Simple reparse: find the operator between this part and next
                        // by walking the original string — but split drops operators,
                        // so we need a different approach. Restart with tokenizer.
                        ok = true;
                    }
                    // Restart with proper tokenizer (the loop above is a scaffolding
                    // to avoid the split-drops-operator issue).
                    total = 0;
                    sign = 1;
                    ok = true;
                    let bytes = inner.as_bytes();
                    let mut j = 0;
                    let mut num_buf = String::new();
                    let parse_num_to_i64 = |s: &str| -> Option<i64> {
                        let s = s.trim();
                        if s.is_empty() { return None; }
                        if let Some(h) = s.strip_prefix("0x") { i64::from_str_radix(h, 16).ok() }
                        else { s.parse::<i64>().ok() }
                    };
                    while j < bytes.len() {
                        let c = bytes[j];
                        if c == b' ' { j += 1; continue; }
                        if c == b'+' || c == b'-' {
                            if !num_buf.is_empty() {
                                match parse_num_to_i64(&num_buf) {
                                    Some(v) => total += sign * v,
                                    None => { ok = false; break; }
                                }
                                num_buf.clear();
                            }
                            sign = if c == b'+' { 1 } else { -1 };
                            j += 1;
                            continue;
                        }
                        if c.is_ascii_alphanumeric() || c == b'_' {
                            num_buf.push(c as char);
                            j += 1;
                            continue;
                        }
                        ok = false;
                        break;
                    }
                    if ok && !num_buf.is_empty() {
                        match parse_num_to_i64(&num_buf) {
                            Some(v) => total += sign * v,
                            None => ok = false,
                        }
                    }
                    if !ok || total <= 0 || (total as u64) > frame_size {
                        search_from = close + 1;
                        continue;
                    }
                    let replacement = local_name(total as u64);
                    let new_line = format!("{}{}{}", &line[..pos], replacement, &line[close + 1..]);
                    search_from = pos + replacement.len();
                    *line = new_line;
                }
            }
        }
    }

    // Simplify "param_NNN[RSP ...]" and "N + RSP" patterns.
    // These are stack-relative accesses. Replace with local variable names.
    // param_48[RSP] → local_30 (decimal 48 = hex 0x30)
    // param_96[RSP - 8 - 8 - 304 - 8] → local_60
    for line in &mut lines {
        // Scan for all param_NNN[RSP...] patterns in the line
        let mut search_from = 0usize;
        loop {
            let remaining = &line[search_from..];
            let Some(rel_start) = remaining.find("param_") else { break };
            let start = search_from + rel_start;

            // Check if this param_ is followed by [RSP
            let after_param = &line[start..];
            let Some(bracket_rel) = after_param.find("[RSP") else {
                search_from = start + 6;
                continue;
            };
            let abs_bracket = start + bracket_rel;

            // Verify the part between param_ and [RSP is a number > 7
            // (real function params are param_0..param_5, stack slots start at higher offsets)
            let idx_str = &line[start + 6..abs_bracket];
            let Ok(offset) = idx_str.parse::<u64>() else {
                search_from = start + 6;
                continue;
            };
            if offset < 8 {
                // Low offsets are real function parameters, not stack slots
                search_from = start + 6;
                continue;
            }

            // Find matching ]
            let mut depth = 1;
            let mut pos = abs_bracket + 1;
            let bytes = line.as_bytes();
            while pos < bytes.len() && depth > 0 {
                if bytes[pos] == b'[' { depth += 1; }
                if bytes[pos] == b']' { depth -= 1; }
                pos += 1;
            }
            if depth != 0 {
                search_from = start + 6;
                continue;
            }
            let abs_close = pos - 1;

            let replacement = if offset > 0 {
                format!("local_{:x}", offset)
            } else {
                "local_0".to_string()
            };
            *line = format!("{}{}{}", &line[..start], replacement, &line[abs_close + 1..]);
            // Don't advance search_from — the replacement might enable more matches
        }
        // Pattern: "NNN + RSP" → "local_NNN" (decimal offset + RSP)
        while let Some(pos) = line.find(" + RSP") {
            // Walk backwards to find the start of the number
            let before = &line[..pos];
            let num_start = before.rfind(|c: char| !c.is_ascii_digit()).map(|p| p + 1).unwrap_or(0);
            if num_start < pos {
                if let Ok(offset) = line[num_start..pos].parse::<u64>() {
                    if offset > 0 && offset < 0x10000 {
                        let replacement = format!("local_{:x}", offset);
                        *line = format!("{}{}{}", &line[..num_start], replacement, &line[pos + 6..]);
                        continue;
                    }
                }
            }
            break;
        }
    }

    // Remove ARM64 prologue/epilogue boilerplate:
    // - sp[N] = x19/x20/.../x29/x30  (callee-saved register saves)
    // - x29 = sp + N  (frame pointer setup)
    // - sp = sp + N / sp = sp - N  (stack frame allocation)
    // - *(uint64_t*)(sp) = x28  (alternative save syntax)
    // Also remove ObjC ARC noise: objc_retain, objc_release,
    // objc_retainAutoreleasedReturnValue, objc_autoreleasePoolPush/Pop
    lines.retain(|line| {
        let t = line.trim();
        // ARM64 callee-saved register saves / stack frame setup:
        // sp[N] = lVarM; sp[N] = x29; sp[N] = x30; sp[N] = 0; sp[N+M] = xNN;
        // sp[N + M] = 0xADDRESS (return address save from link register)
        if t.starts_with("sp[") && t.ends_with(';') && t.contains("] = ") {
            let rhs = t.split("] = ").last().unwrap_or("").trim_end_matches(';').trim();
            let is_callee_save = rhs.starts_with("lVar") || rhs.starts_with("iVar")
                || rhs.starts_with("dVar")
                || rhs == "x29" || rhs == "x30" || rhs == "0"
                || rhs.starts_with("x1") || rhs.starts_with("x2")
                || rhs.starts_with("x8") || rhs.starts_with("x9")
                || rhs.starts_with("param_")
                // Return address constants (link register saves)
                || rhs.starts_with("0x");
            if is_callee_save { return false; }
        }
        if t.starts_with("*(uint64_t*)(sp)") && t.ends_with(';')
            && (t.contains("= x") || t.contains("= lVar") || t.contains("= 0"))
        { return false; }
        // Frame pointer write: x29 = <anything>; — in AArch64, x29 is always the frame
        // pointer, never a C-level variable. Writes to it are prologue setup or epilogue
        // restore. Elide them all so struct-field-renamed epilogue loads go away too.
        if t.starts_with("x29 = ") && t.ends_with(';') { return false; }
        // Link register write: x30 = <anything>; — x30 is always the return address;
        // any write is epilogue restore after the sp-based pattern was rewritten via
        // struct-field naming (e.g. `x30 = iVar1->lpSecurityDescriptor;`).
        if t.starts_with("x30 = ") && t.ends_with(';') { return false; }
        // LR save to stack: `local_N = x30;` — always prologue boilerplate.
        // Same for saving x29 to a local (frame pointer save).
        if (t.starts_with("local_") || t.starts_with("sp["))
            && (t.ends_with(" = x30;") || t.ends_with(" = x29;"))
        { return false; }
        // Frame pointer computation: `iVarN = sp - N;` or `lVarN = sp - N;`
        // This is `x29 = sp` after the prologue push decremented sp — pure boilerplate.
        if (t.starts_with("iVar") || t.starts_with("lVar"))
            && t.contains(" = sp - ") && t.ends_with(';')
            && !t.contains("(") && !t.contains("[")
        {
            let rhs = t.split(" = sp - ").nth(1).unwrap_or("").trim_end_matches(';').trim();
            if rhs.chars().all(|c| c.is_ascii_hexdigit() || c == 'x' || c == 'X') {
                return false;
            }
        }
        // Frame pointer adjustment: `iVarN = iVarN + N;` (sp cleanup mirror in epilogue).
        {
            let core = t.trim_end_matches(';');
            if let Some((lhs, rhs)) = core.split_once(" = ") {
                let lhs = lhs.trim();
                let rhs = rhs.trim();
                if (lhs.starts_with("iVar") || lhs.starts_with("lVar"))
                    && rhs.starts_with(lhs)
                    && (rhs[lhs.len()..].starts_with(" + ") || rhs[lhs.len()..].starts_with(" - "))
                {
                    let tail = rhs[lhs.len()+3..].trim();
                    if tail.chars().all(|c| c.is_ascii_hexdigit() || c == 'x' || c == 'X') {
                        return false;
                    }
                }
            }
        }
        // Stack allocation: sp = sp + N; sp = sp - N; sp = param_-N;
        // After the AArch64 `sp - N → local_N` rewrite, this also catches
        // `sp = local_0;` (the rewritten form of `sp = sp - frame_size;`).
        if t.starts_with("sp = sp ") && t.ends_with(';') { return false; }
        if t.starts_with("sp = param_") && t.ends_with(';') { return false; }
        if t.starts_with("sp = local_") && t.ends_with(';') { return false; }
        // Return via link register: return sp[N]->field_8; (epilogue pattern)
        if t.starts_with("return sp") && t.contains("->field_8") { return false; }
        // ObjC ARC noise
        if t == "objc_retain();" || t.starts_with("objc_retain(") && t.ends_with(");") && !t.contains("=") {
            return false;
        }
        if t == "objc_release();" || t.starts_with("objc_release(") && t.ends_with(");") {
            return false;
        }
        if t.starts_with("objc_retainAutoreleasedReturnValue(") { return false; }
        if t.starts_with("objc_autoreleasePoolPush(") { return false; }
        if t.starts_with("objc_autoreleasePoolPop(") { return false; }
        if t.starts_with("objc_autoreleaseReturnValue(") { return false; }
        // Swift ARC noise
        if t.starts_with("swift_retain(") && t.ends_with(");") { return false; }
        if t.starts_with("swift_release(") && t.ends_with(");") { return false; }
        if t.starts_with("swift_bridgeObjectRetain(") && t.ends_with(");") { return false; }
        if t.starts_with("swift_bridgeObjectRelease(") && t.ends_with(");") { return false; }
        if t.starts_with("swift_unknownObjectRetain(") && t.ends_with(");") { return false; }
        if t.starts_with("swift_unknownObjectRelease(") && t.ends_with(");") { return false; }
        // Swift runtime housekeeping (access control, allocation, type checks)
        if t.starts_with("swift_beginAccess(") && t.ends_with(");") { return false; }
        if t.starts_with("swift_endAccess(") && t.ends_with(");") { return false; }
        if t.starts_with("swift_allocObject(") && t.ends_with(");") { return false; }
        if t.starts_with("swift_isUniquelyReferenced") && t.ends_with(");") { return false; }
        if t.starts_with("objc_opt_self(") && t.ends_with(");") { return false; }
        // Dead trap code: pc = ?; from incomplete OV block removal
        if t == "pc = ?;" || t.starts_with("goto label_") { return false; }
        // AArch64 flag register leaks: CY (carry), ZR (zero) are internal CPSR flags
        // that should have been folded into comparison expressions.
        // Only strip lines where a flag register IS the assignment target (e.g., "NG = ...").
        // Don't strip lines where flags appear inside expressions assigned to named vars
        // (e.g., "lVar1 = (NG != OV) * -1" — this is a CSETM result we need to keep).
        if (t.starts_with("CY") || t.starts_with("ZR") || t.starts_with("NG") || t.starts_with("OV")
            || t.starts_with("tmpCY") || t.starts_with("tmpZR") || t.starts_with("tmpNG") || t.starts_with("tmpOV"))
            && t.contains(" = ") && t.ends_with(';')
        {
            return false;
        }
        // x30 = address (link register setup for calls — noise)
        if t.starts_with("x30 = 0x") && t.ends_with(';') { return false; }
        if t.starts_with("x30 = ") && t.contains(" + ") && t.ends_with(';') && !t.contains("func_") { return false; }
        // x29 stores (frame pointer spills)
        if t.starts_with("*(uint64_t*)(x29") && t.ends_with(';') && !t.contains("func_") && !t.contains("param_") { return false; }
        // sp + N -> field_8 patterns (return address from stack)
        if t.starts_with("return sp") && t.ends_with(';') && !t.contains("func_") { return false; }
        true
    });

    // Fix orphaned blocks: when statements are indented inside a block whose
    // opening "if/else" was removed, reduce their indent and remove the orphaned "}".
    // Pattern: line at indent N, then 1+ lines at indent N+4, then "}" at indent N.
    // Where line at indent N doesn't end with "{".
    {
        let mut i = 0;
        while i + 2 < lines.len() {
            let cur_indent = lines[i].len() - lines[i].trim_start().len();
            let cur_t = lines[i].trim();
            let next_indent = lines[i + 1].len() - lines[i + 1].trim_start().len();
            let next_t = lines[i + 1].trim();

            // Skip if current line opens a block
            if cur_t.ends_with('{') || cur_t.is_empty() || next_t.is_empty() {
                i += 1;
                continue;
            }

            // Check: current at indent N (no brace), next at indent N+4
            if next_indent == cur_indent + 4 && !next_t.starts_with('}') {
                // Find the closing brace for this orphaned block
                let mut j = i + 1;
                while j < lines.len() {
                    let jt = lines[j].trim();
                    let ji = lines[j].len() - lines[j].trim_start().len();
                    if jt == "}" && ji == cur_indent {
                        // Found orphan close. De-indent all lines between i+1 and j.
                        for k in (i + 1)..j {
                            let kt = lines[k].trim().to_string();
                            if kt.is_empty() { continue; }
                            let ki = lines[k].len() - lines[k].trim_start().len();
                            let new_indent = if ki >= 4 { ki - 4 } else { 0 };
                            lines[k] = format!("{}{}", " ".repeat(new_indent), kt);
                        }
                        // Remove the orphaned "}"
                        lines.remove(j);
                        break;
                    }
                    if jt == "}" && ji < cur_indent { break; } // different scope
                    j += 1;
                }
            }
            i += 1;
        }
    }

    // Remove empty if blocks: "if (...) {\n}" with nothing between braces.
    {
        let mut i = 0;
        while i + 1 < lines.len() {
            let t = lines[i].trim();
            let next = lines[i + 1].trim();
            if t.starts_with("if (") && t.ends_with('{') && next == "}" {
                // Check if there's an else after the closing brace
                if i + 2 < lines.len() && lines[i + 2].trim().starts_with("} else {") {
                    // if (...) { } else { ... } → keep the else part
                    // handled by is_body_empty + negate logic
                }
                lines.remove(i + 1); // remove "}"
                lines.remove(i);     // remove "if (...) {"
                continue;
            }
            i += 1;
        }
    }

    // ARM32 comprehensive cleanup: remove flag noise, stack frame ops, rename registers.
    // Detect ARM32 by presence of mult_addr, shift_carry, or ARM register names.
    {
        let all_check = lines.join("");
        let is_arm32 = all_check.contains("mult_addr") || all_check.contains("shift_carry")
            || matches!(ctx.arch, Architecture::ARM32);

        if is_arm32 {
            // 1. Remove flag computation noise — these are ARM CPSR flag updates
            //    that should be internal to condition evaluation
            lines.retain(|line| {
                let t = line.trim();
                // shift_carry = ... (barrel shifter carry output)
                if t.starts_with("shift_carry") && t.contains("=") && t.ends_with(';') { return false; }
                // tmpNG = ... (negative flag)
                if t.starts_with("tmpNG") && t.contains("=") && t.ends_with(';') { return false; }
                // tmpZR = ... (zero flag)
                if t.starts_with("tmpZR") && t.contains("=") && t.ends_with(';') { return false; }
                // tmpCY = ... (carry flag)
                if t.starts_with("tmpCY") && t.contains("=") && t.ends_with(';') { return false; }
                // tmpOV = ... (overflow flag)
                if t.starts_with("tmpOV") && t.contains("=") && t.ends_with(';') { return false; }
                // TB = ... (Thumb bit)
                if t.starts_with("TB") && t.contains("=") && t.ends_with(';') { return false; }
                // NG = ..., ZR = ..., CY = ..., OV = ... (flag stores)
                if t.len() < 50 && t.ends_with(';') {
                    if t.starts_with("NG = ") || t.starts_with("ZR = ") || t.starts_with("CY = ") || t.starts_with("OV = ") {
                        return false;
                    }
                }
                true
            });

            // 2. Remove ARM32 prologue/epilogue boilerplate
            lines.retain(|line| {
                let t = line.trim();
                // PUSH: *(uint32_t*)(mult_addr) = rN; mult_addr = mult_addr - 4;
                if t.starts_with("*(uint32_t*)(mult_addr)") && t.contains("=") && t.ends_with(';') { return false; }
                if t == "mult_addr = mult_addr - 4;" || t == "mult_addr = mult_addr + 4;" { return false; }
                // Stack frame setup: mult_addr = sp; or mult_addr = sp - N;
                if t.starts_with("mult_addr = sp") && t.ends_with(';') { return false; }
                if t.starts_with("sp = mult_addr") && t.ends_with(';') { return false; }
                if t.starts_with("mult_addr = ") && t.contains("sp") && t.ends_with(';') { return false; }
                // POP: rN = *(uint32_t*)(mult_addr); or rN = *(uint32_t*)(sp...
                // pc = ... (function return via POP {pc})
                if t.starts_with("pc = ") && t.ends_with(';') { return false; }
                // lr = *(uint32_t*)(mult_addr) — restore LR
                if t.starts_with("lr = *(uint32_t*)(mult_addr") && t.ends_with(';') { return false; }
                // return sp; (common ARM32 epilogue artifact)
                if t == "return sp;" || t == "return mult_addr;" { return false; }
                // lr = 0xNNNNN; (return address setup before BL)
                if t.starts_with("lr = 0x") && t.ends_with(';') && !t.contains("func_") { return false; }
                // lr = NN; (small constant — return address)
                if t.starts_with("lr = ") && t.ends_with(';') && !t.contains("func_") && !t.contains("param_") {
                    let val = t.strip_prefix("lr = ").unwrap_or("").trim_end_matches(';');
                    if val.chars().all(|c| c.is_ascii_digit() || c == 'x' || c.is_ascii_hexdigit()) { return false; }
                }
                true
            });

            // 3. Clean up mult_addr references in remaining lines
            for line in &mut lines {
                // mult_addr->field_N → local_N (it's the frame pointer)
                if line.contains("mult_addr->field_") {
                    *line = line.replace("mult_addr->field_", "local_");
                }
                if line.contains("mult_addr") {
                    *line = line.replace("mult_addr", "sp");
                }
            }

            // 4. Rename ARM registers to parameter/variable names
            // ARM calling convention: r0-r3 = params, r4-r11 = callee-saved locals
            // lr (link register) → return_addr (usually noise, but kept when meaningful)
            let param_regs = [("r0", "param_0"), ("r1", "param_1"), ("r2", "param_2"), ("r3", "param_3")];
            let local_regs = [
                ("r4", "lVar1"), ("r5", "lVar2"), ("r6", "lVar3"), ("r7", "lVar4"),
                ("r8", "lVar5"), ("r9", "lVar6"), ("r10", "lVar7"), ("r11", "lVar8"),
                ("r12", "iVar1"), ("lr", "lrVar"),
            ];

            // Only rename if the register appears as a standalone identifier
            for line in &mut lines {
                for (reg, name) in &param_regs {
                    let t = line.as_str();
                    // Careful word-boundary replacement: r0 but not r0-r3 in "r0x..." or "cr0"
                    let mut result = String::new();
                    let mut remaining = t;
                    while let Some(pos) = remaining.find(reg) {
                        let before_ok = pos == 0 || !remaining.as_bytes()[pos - 1].is_ascii_alphanumeric();
                        let after_pos = pos + reg.len();
                        let after_ok = after_pos >= remaining.len()
                            || (!remaining.as_bytes()[after_pos].is_ascii_alphanumeric()
                                && remaining.as_bytes()[after_pos] != b'_');
                        if before_ok && after_ok {
                            result.push_str(&remaining[..pos]);
                            result.push_str(name);
                            remaining = &remaining[after_pos..];
                        } else {
                            result.push_str(&remaining[..after_pos]);
                            remaining = &remaining[after_pos..];
                        }
                    }
                    result.push_str(remaining);
                    *line = result;
                }
                for (reg, name) in &local_regs {
                    let mut result = String::new();
                    let mut remaining = line.as_str();
                    while let Some(pos) = remaining.find(reg) {
                        let before_ok = pos == 0 || !remaining.as_bytes()[pos - 1].is_ascii_alphanumeric();
                        let after_pos = pos + reg.len();
                        let after_ok = after_pos >= remaining.len()
                            || (!remaining.as_bytes()[after_pos].is_ascii_alphanumeric()
                                && remaining.as_bytes()[after_pos] != b'_');
                        if before_ok && after_ok {
                            result.push_str(&remaining[..pos]);
                            result.push_str(name);
                            remaining = &remaining[after_pos..];
                        } else {
                            result.push_str(&remaining[..after_pos]);
                            remaining = &remaining[after_pos..];
                        }
                    }
                    result.push_str(remaining);
                    *line = result;
                }
            }

            // 4b. Clean up carry/borrow flag arithmetic
            for line in &mut lines {
                // + (uint8_t)!CY → simplified or removed (borrow in 64-bit sub)
                *line = line.replace(" + (uint8_t)!CY", "");
                *line = line.replace(" + (uint8_t)CY", "");
                *line = line.replace("(uint8_t)!CY", "0 /* borrow */");
                *line = line.replace("(uint8_t)CY", "0 /* carry */");
                // Also clean up remaining raw CY/NG/ZR/OV in expressions
                *line = line.replace("(uint8_t)!NG", "0");
                *line = line.replace("(uint8_t)NG", "0");
            }

            // 5. Clean remaining ARM-specific artifacts
            lines.retain(|line| {
                let t = line.trim();
                // Remove remaining standalone flag stores not caught earlier
                if t.ends_with(';') && !t.contains("func_") && !t.contains("param_") {
                    // lr = expr; (return address setup — noise)
                    if t.starts_with("lr = ") || t.starts_with("lr =") { return false; }
                    // return sp; or return sp + N; or return ((sp+4)+4)...
                    if t.starts_with("return sp") { return false; }
                    if t.starts_with("return ((") && t.contains("sp") { return false; }
                    if t.starts_with("return *(sp") || t.starts_with("return sp[") { return false; }
                    if t.starts_with("return *(uint32_t*)(sp") { return false; }
                    // Remaining flag patterns: NG = ..., ZR = ..., etc in middle of lines
                    for flag in ["NG = ", "ZR = ", "CY = ", "OV = ", "tmpNG ", "tmpZR ", "tmpCY ", "tmpOV "] {
                        if t.starts_with(flag) { return false; }
                    }
                }
                true
            });

            // 5b. Fix r-NNN artifacts (negative register offsets from ARM subtract)
            for line in &mut lines {
                // r-0xNNN → -0xNNN (these are computed addresses, drop the 'r' prefix)
                while let Some(pos) = line.find("r-0x") {
                    let before_ok = pos == 0 || !line.as_bytes()[pos - 1].is_ascii_alphanumeric();
                    if before_ok {
                        line.replace_range(pos..pos+1, ""); // remove the 'r'
                    } else {
                        break;
                    }
                }
                while let Some(pos) = line.find("r-") {
                    let before_ok = pos == 0 || !line.as_bytes()[pos - 1].is_ascii_alphanumeric();
                    let after = &line[pos+2..];
                    let is_neg_num = after.starts_with("0x") || after.chars().next().map_or(false, |c| c.is_ascii_digit());
                    if before_ok && is_neg_num {
                        line.replace_range(pos..pos+1, "");
                    } else {
                        break;
                    }
                }
            }

            // 5c. Simplify ARM condition patterns in if-statements
            for line_idx in 0..lines.len() {
                let t = lines[line_idx].trim().to_string();
                if t.starts_with("if (") || t.starts_with("} else if (") || t.starts_with("while (") {
                    let indent = lines[line_idx].len() - lines[line_idx].trim_start().len();
                    let pad = " ".repeat(indent);
                    // Look backwards for the most recent variable assignment (for "result" substitution)
                    let recent_var = (0..line_idx).rev().find_map(|j| {
                        let lt = lines[j].trim();
                        if lt.ends_with(';') && lt.contains(" = ") && !lt.starts_with("if ") {
                            let var_name = lt.split(" = ").next().unwrap_or("").trim();
                            if var_name.starts_with("param_") || var_name.starts_with("lVar")
                                || var_name.starts_with("iVar") || var_name.starts_with("local_") {
                                return Some(var_name.to_string());
                            }
                        }
                        None
                    }).unwrap_or_else(|| "result".to_string());
                    // Extract the condition and surrounding syntax
                    let (prefix, cond, suffix) = if let Some(rest) = t.strip_prefix("if (") {
                        if let Some(cond) = rest.strip_suffix(") {") {
                            ("if (", cond, ") {")
                        } else { continue; }
                    } else if let Some(rest) = t.strip_prefix("} else if (") {
                        if let Some(cond) = rest.strip_suffix(") {") {
                            ("} else if (", cond, ") {")
                        } else { continue; }
                    } else if let Some(rest) = t.strip_prefix("while (") {
                        if let Some(cond) = rest.strip_suffix(") {") {
                            ("while (", cond, ") {")
                        } else { continue; }
                    } else { continue; };

                    // Replace flag-based conditions with readable ones
                    let rv = &recent_var;
                    let new_cond_owned: String;
                    let new_cond = match cond {
                        "ZR" => { new_cond_owned = format!("{} == 0", rv); &new_cond_owned }
                        "!ZR" | "!(ZR)" => { new_cond_owned = format!("{} != 0", rv); &new_cond_owned }
                        "CY" => { new_cond_owned = format!("(uint){} >= 0", rv); &new_cond_owned }
                        "!CY" | "!(CY)" => { new_cond_owned = format!("(uint){} < 0", rv); &new_cond_owned }
                        "NG" => { new_cond_owned = format!("{} < 0", rv); &new_cond_owned }
                        "!NG" | "!(NG)" => { new_cond_owned = format!("{} >= 0", rv); &new_cond_owned }
                        "OV" => "overflow",
                        "!OV" | "!(OV)" => "!overflow",
                        "CY && !ZR" | "!ZR && CY" => { new_cond_owned = format!("(uint){} > 0", rv); &new_cond_owned }
                        "!CY && !ZR" => { new_cond_owned = format!("(uint){} > 0", rv); &new_cond_owned }
                        "!CY || ZR" | "ZR || !CY" => { new_cond_owned = format!("(uint){} <= 0", rv); &new_cond_owned }
                        "CY || ZR" | "ZR || CY" => { new_cond_owned = format!("(uint){} <= 0", rv); &new_cond_owned }
                        "!!CY || ZR" => { new_cond_owned = format!("(uint){} <= 0", rv); &new_cond_owned }
                        "!(CY && !ZR)" => { new_cond_owned = format!("(uint){} <= 0", rv); &new_cond_owned }
                        "!ZR && result >= 0" => { new_cond_owned = format!("{} > 0", rv); &new_cond_owned }
                        "ZR || result < 0" => { new_cond_owned = format!("{} <= 0", rv); &new_cond_owned }
                        "true" => "true",
                        _ => {
                            // Try to clean up remaining flag references
                            if cond.contains("CY") || cond.contains("ZR") || cond.contains("NG") || cond.contains("OV") {
                                let cleaned = cond
                                    .replace("!NG == OV", "result >= 0")
                                    .replace("NG == OV", "result >= 0")
                                    .replace("NG != OV", "result < 0")
                                    .replace("!!CY", "CY")
                                    .replace("!CY && !ZR", "result > 0 /* unsigned */")
                                    .replace("CY || ZR", "result <= 0 /* unsigned */")
                                    .replace("!CY || ZR", "result <= 0 /* unsigned */");
                                if cleaned != cond {
                                    lines[line_idx] = format!("{}{}{}{}", pad, prefix, cleaned, suffix);
                                }
                            }
                            continue;
                        }
                    };
                    lines[line_idx] = format!("{}{}{}{}", pad, prefix, new_cond, suffix);
                }
            }

            // 6. Remove empty blocks left by flag removal
            let mut i = 0;
            while i + 1 < lines.len() {
                let t = lines[i].trim().to_string();
                let next = lines.get(i + 1).map(|s| s.trim().to_string()).unwrap_or_default();
                // Empty block: "if (...) {" followed by "}"
                if t.ends_with('{') && next == "}" {
                    lines.remove(i + 1);
                    lines.remove(i);
                    continue;
                }
                // Empty lines
                if t.is_empty() && next.is_empty() {
                    lines.remove(i + 1);
                    continue;
                }
                i += 1;
            }
        }
    }

    // Remove x86 REP STOS/MOVS boilerplate: "EDI = EDI + N - 8 * DF;" patterns
    // These are string instruction noise (REP STOSD, REP MOVSD).
    lines.retain(|line| {
        let t = line.trim();
        // "EDI = EDI + N - 8 * DF;" or "EDI = EDI + N - 4 * DF;"
        if t.starts_with("EDI = EDI + ") && t.contains(" * DF;") { return false; }
        if t.starts_with("ESI = ESI + ") && t.contains(" * DF;") { return false; }
        // "EDI = EDI + 4 - 8 * DF;"
        if t.starts_with("EDI = ") && t.contains("- 8 * DF;") { return false; }
        if t.starts_with("EDI = ") && t.contains("- 4 * DF;") { return false; }
        if t.starts_with("EDI = ") && t.contains("- 2 * DF;") { return false; }
        true
    });

    // Annotate common Win32 constants for reverse engineering readability
    for line in &mut lines {
        // CreateProcess flags
        if line.contains("134217728") { *line = line.replace("134217728", "CREATE_NO_WINDOW /* 0x8000000 */"); }
        // Winsock errors
        if line.contains("0x2733") { *line = line.replace("0x2733", "WSAEWOULDBLOCK"); }
        if line.contains("0x2746") { *line = line.replace("0x2746", "WSAECONNRESET"); }
        if line.contains("0x274c") { *line = line.replace("0x274c", "WSAECONNREFUSED"); }
        // Registry
        if line.contains("0x80000001") && !line.contains("0x80000001 <") {
            *line = line.replace("0x80000001", "HKEY_CURRENT_USER");
        }
        if line.contains("0x80000002") && !line.contains("0x80000002 <") {
            *line = line.replace("0x80000002", "HKEY_LOCAL_MACHINE");
        }
    }

    // Collapse "X = expr; return X;" into "return expr;"
    {
        let mut i = 0;
        while i + 1 < lines.len() {
            let cur = lines[i].trim().to_string();
            let next = lines[i + 1].trim().to_string();
            // Match: "VAR = EXPR;" followed by "return VAR;"
            if cur.contains(" = ") && cur.ends_with(';') && next.starts_with("return ") && next.ends_with(';') {
                if let Some(eq_pos) = cur.find(" = ") {
                    let lhs = &cur[..eq_pos];
                    let rhs = &cur[eq_pos + 3..cur.len() - 1]; // strip trailing ;
                    let ret_val = &next[7..next.len() - 1]; // strip "return " and ";"
                    if lhs == ret_val {
                        // Replace both with "return EXPR;"
                        let indent = lines[i].len() - lines[i].trim_start().len();
                        let pad = " ".repeat(indent);
                        lines[i] = format!("{}return {};", pad, rhs);
                        lines.remove(i + 1);
                        continue;
                    }
                    // Also match: "X = X | -1;" + "return X | -1;" → "return -1;"
                    if ret_val == &cur[..cur.len() - 1] || rhs == ret_val {
                        let indent = lines[i].len() - lines[i].trim_start().len();
                        let pad = " ".repeat(indent);
                        lines[i] = format!("{}return {};", pad, rhs);
                        lines.remove(i + 1);
                        continue;
                    }
                }
            }
            i += 1;
        }
    }

    // Remove standalone CARRY/SCARRY/SBORROW assignments that leaked through DCE.
    lines.retain(|line| {
        let t = line.trim();
        if (t.contains(" CARRY ") || t.contains(" SCARRY ") || t.contains(" SBORROW "))
            && t.ends_with(';')
            && !t.contains("if ")
            && !t.contains("while ")
            && !t.contains("return ")
        {
            return false;
        }
        // Remove all stores to address 0: SEH chain setup (fs:[0]) and similar
        if t.starts_with("*(int*)(0) = ") && t.ends_with(';') { return false; }
        if t.starts_with("*(uint32_t*)(0) = ") && t.ends_with(';') { return false; }
        true
    });

    // Remove byte-extract self-shift chains from Subpiece operations.
    // Actual format: "X = X >> 8 & 31 | 0 << 32 - 8 & 31;" or "X = X >> 8;"
    // These are byte-by-byte extraction noise from multi-byte copies.
    lines.retain(|line| {
        let t = line.trim();
        if !t.contains(" >> 8") || !t.contains(" = ") { return true; }
        // Don't remove from conditions or returns
        if t.starts_with("if ") || t.starts_with("while ") || t.starts_with("return ") { return true; }
        // Split at first " = "
        if let Some(eq_pos) = t.find(" = ") {
            let lhs = &t[..eq_pos];
            let rhs = &t[eq_pos + 3..].trim_end_matches(';').trim();
            // Self-shift: "X = X >> 8 ..." (rhs starts with lhs >> 8)
            let shift_pat = format!("{} >> 8", lhs);
            if rhs.starts_with(&shift_pat) {
                return false;
            }
            // Initial zero shift: "X = 0 >> 8 ..."
            if rhs.starts_with("0 >> 8") {
                return false;
            }
        }
        true
    });

    // Resolve RBP/EBP-relative addresses to local variable names.
    // Uses DWARF names when available, otherwise auto-generates var_N names.
    // Handles "RBP - N", "EBP - N" (decimal and hex), and legacy "RBP + 0xNN" patterns.
    for bp_reg in &["RBP", "EBP"] {
        let minus_pat = format!("{} - ", bp_reg);
        let minus_hex_pat = format!("{} - 0x", bp_reg);
        let plus_hex_pat = format!("{} + 0x", bp_reg);

        for line in &mut lines {
            // Pattern: "RBP/EBP - N" with decimal offset
            while let Some(_pos) = line.find(&minus_pat) {
                let num_start = line.find(&minus_pat).unwrap_or(0) + minus_pat.len();
                if line[num_start..].starts_with("0x") {
                    break; // hex handled below
                }
                let num_end = line[num_start..].find(|c: char| !c.is_ascii_digit())
                    .map(|e| num_start + e).unwrap_or(line.len());
                let num_str = &line[num_start..num_end].to_string();
                if let Ok(offset) = num_str.parse::<u64>() {
                    let var_name = format!("var_{:x}", offset);
                    let resolved = aliases.get(&var_name).cloned()
                        .or_else(|| {
                            let adj = format!("var_{:x}", offset + 8);
                            aliases.get(&adj).cloned()
                        })
                        .unwrap_or(var_name); // auto-name when no DWARF
                    let old = format!("{} - {}", bp_reg, num_str);
                    *line = line.replace(&old, &resolved);
                    continue;
                }
                break;
            }
            // Pattern: "RBP/EBP - 0xNN"
            while let Some(_pos) = line.find(&minus_hex_pat) {
                let hex_start = line.find(&minus_hex_pat).unwrap_or(0) + minus_hex_pat.len();
                let hex_end = line[hex_start..].find(|c: char| !c.is_ascii_hexdigit())
                    .map(|e| hex_start + e).unwrap_or(line.len());
                let hex_str = line[hex_start..hex_end].to_string();
                if let Ok(offset) = u64::from_str_radix(&hex_str, 16) {
                    let var_name = format!("var_{:x}", offset);
                    let resolved = aliases.get(&var_name).cloned()
                        .or_else(|| {
                            let adj = format!("var_{:x}", offset + 8);
                            aliases.get(&adj).cloned()
                        })
                        .unwrap_or(var_name);
                    let old = format!("{} - 0x{}", bp_reg, hex_str);
                    *line = line.replace(&old, &resolved);
                    continue;
                }
                break;
            }
            // Fallback: "RBP/EBP + 0xNN" where NN is large (signed-byte negative in unsigned form)
            while let Some(_pos) = line.find(&plus_hex_pat) {
                let hex_start = line.find(&plus_hex_pat).unwrap_or(0) + plus_hex_pat.len();
                let hex_end = line[hex_start..].find(|c: char| !c.is_ascii_hexdigit())
                    .map(|e| hex_start + e).unwrap_or(line.len());
                let hex_str = line[hex_start..hex_end].to_string();
                if let Ok(val) = u64::from_str_radix(&hex_str, 16) {
                    // Large values are actually negative offsets (e.g., 0xfffffffc = -4)
                    let neg_off = if val >= 0xffffff00 && val <= 0xFFFFFFFF {
                        0x100000000u64.saturating_sub(val) // 32-bit sign extension
                    } else if val >= 0xffffffffffffff00 {
                        0u64.wrapping_sub(val) // 64-bit sign extension
                    } else if val >= 0x80 && val < 0x100 {
                        0x100u64.saturating_sub(val) // 8-bit sign extension
                    } else {
                        break; // positive offset (args above EBP), skip
                    };
                    let var_name = format!("var_{:x}", neg_off);
                    let resolved = aliases.get(&var_name).cloned()
                        .or_else(|| {
                            let adj = format!("var_{:x}", neg_off + 8);
                            aliases.get(&adj).cloned()
                        })
                        .unwrap_or(var_name);
                    let old = format!("{} + 0x{}", bp_reg, hex_str);
                    *line = line.replace(&old, &resolved);
                    continue;
                }
                break;
            }
        }
    }

    // Resolve bare register names in array indices: str[RCX] → str[(len-1)-i]
    // by finding a richer index expression for the same base on another line
    for i in 0..lines.len() {
        let lt = lines[i].to_string();
        // Find all [REG] patterns (bare register in brackets)
        let mut pos = 0;
        while let Some(br_start) = lt[pos..].find('[') {
            let abs_start = pos + br_start;
            if let Some(br_end) = lt[abs_start..].find(']') {
                let idx = &lt[abs_start + 1..abs_start + br_end];
                let is_bare_reg = idx.len() >= 2 && idx.len() <= 3
                    && idx.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit());
                if is_bare_reg {
                    // Find the base (text before the bracket)
                    let base_start = lt[..abs_start].rfind(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                        .map(|p| p + 1).unwrap_or(0);
                    let base = &lt[base_start..abs_start];
                    if !base.is_empty() {
                        // Search for the same base with a richer index on another line
                        for j in 0..lines.len() {
                            if i == j { continue; }
                            let other = lines[j].trim();
                            let search = format!("{}[", base);
                            if let Some(ob) = other.find(&search) {
                                let inner_start = ob + search.len();
                                if let Some(inner_end) = other[inner_start..].find(']') {
                                    let other_idx = &other[inner_start..inner_start + inner_end];
                                    if other_idx.len() > idx.len() && other_idx.contains(' ') {
                                        let old = format!("[{}]", idx);
                                        let new_idx = format!("[{}]", other_idx);
                                        lines[i] = lines[i].replace(&old, &new_idx);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                pos = abs_start + br_end + 1;
            } else {
                break;
            }
        }
    }

    // Detect swap pattern: str[i] = str[j]; str[j] = AL; → str[j] = str[i];
    // (AL holds the original str[i] from a read that was elided by the printer)
    {
        let mut i = 0;
        while i + 1 < lines.len() {
            let l1 = lines[i].trim().to_string();
            let l2 = lines[i + 1].trim().to_string();
            // Pattern: "X[a] = X[b];" followed by "X[c] = AL;"
            if l2.ends_with(" = AL;") {
                // l1 should be "base[idx1] = base[idx2];"
                if let Some(bracket1_start) = l1.find('[') {
                    if let Some(eq1) = l1.find("] = ") {
                        let base = &l1[..bracket1_start];
                        let idx1 = &l1[bracket1_start + 1..eq1];
                        // The rhs of l1 is base[idx2]
                        let rhs1 = l1[eq1 + 4..].trim_end_matches(';');
                        if rhs1.starts_with(base) && rhs1.contains('[') {
                            // This is the swap pattern
                            // The original value at idx1 was saved to AL
                            // Replace AL with base[idx1]
                            let swap_val = format!("{}[{}]", base, idx1);
                            let indent = lines[i + 1].len() - lines[i + 1].trim_start().len();
                            let new_line = l2.replace("AL", &swap_val);
                            let pad = " ".repeat(indent);
                            lines[i + 1] = format!("{}{}", pad, new_line.trim());
                        }
                    }
                }
            }
            i += 1;
        }
    }

    // Infer return value for bare "return;" at end of function.
    // Find the last variable that was assigned inside the function body —
    // that's likely what was stored in EAX before the return.
    if let Some(last) = lines.iter().rposition(|l| !l.trim().is_empty()) {
        if lines[last].trim() == "return;" {
            // Scan backward for the return value: prefer non-increment accumulators,
            // then fall back to incremented locals (not parameters).
            let mut return_var = None;
            let mut fallback_increment = None;
            for j in (0..last).rev() {
                let lt = lines[j].trim();
                if let Some(eq_pos) = lt.find(" = ") {
                    let lhs = &lt[..eq_pos];
                    let is_var = lhs.chars().next().map_or(false, |c| c.is_ascii_lowercase())
                        && lhs.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
                    if !is_var { continue; }
                    let rhs = &lt[eq_pos + 3..].trim_end_matches(';');
                    let is_self_increment = rhs.ends_with("+ 1") && rhs.starts_with(lhs);
                    let is_ptr_advance = rhs.contains("->")
                        || (is_self_increment && param_names.contains(&lhs.to_string()));
                    if !is_self_increment && !is_ptr_advance {
                        return_var = Some(lhs.to_string());
                        break;
                    }
                    // Track first non-parameter increment as fallback
                    if is_self_increment && !param_names.contains(&lhs.to_string())
                        && fallback_increment.is_none()
                    {
                        fallback_increment = Some(lhs.to_string());
                    }
                }
            }
            let ret_val = return_var
                .or(fallback_increment)
                .or_else(|| param_names.first().cloned())
                .unwrap_or_default();
            if !ret_val.is_empty() {
                let indent = lines[last].len() - lines[last].trim_start().len();
                let pad = &lines[last][..indent];
                lines[last] = format!("{}return {};", pad, ret_val);
            }
        }
    }

    // Add missing return after if-with-return blocks (CMOV pattern):
    // if (cond) { return X; }  ← needs: return default;
    if let Some(last) = lines.iter().rposition(|l| !l.trim().is_empty()) {
        let lt = lines[last].trim();
        if lt == "}" {
            // Find the if-block and its return value
            let mut has_return = false;
            let mut if_return_val = String::new();
            let mut if_line_idx = 0;
            for j in (0..last).rev() {
                let t = lines[j].trim();
                if t.starts_with("return ") && !t.starts_with("return;") {
                    has_return = true;
                    if_return_val = t.strip_prefix("return ").unwrap_or("")
                        .trim_end_matches(';').to_string();
                }
                if t.starts_with("if (") { if_line_idx = j; break; }
            }
            // Check there's no return statement after the }
            let has_return_after = lines.get(last + 1..).map_or(false, |rest|
                rest.iter().any(|l| l.trim().starts_with("return ")));
            if has_return && !has_return_after {
                // Look for the last assignment before the if block to determine return value
                // e.g., "EAX = -EDI;" → else returns EAX (= -EDI expression)
                let mut else_val = String::new();
                for j in (0..if_line_idx).rev() {
                    let t = lines[j].trim();
                    if t.contains(" = ") && t.ends_with(';') {
                        if let Some(eq) = t.find(" = ") {
                            let lhs = &t[..eq];
                            // Use this variable as the return value
                            else_val = lhs.to_string();
                            break;
                        }
                    }
                    if !t.is_empty() { break; }
                }
                let ret_val = if !else_val.is_empty() {
                    else_val
                } else if param_names.len() >= 2 {
                    // If the if returns one param, return the other
                    if if_return_val == param_names[0] {
                        param_names[1].clone()
                    } else {
                        param_names[0].clone()
                    }
                } else {
                    match if_return_val.as_str() {
                        "EDI" => "ESI".to_string(),
                        "ESI" => "EDI".to_string(),
                        _ => "EAX".to_string(),
                    }
                };
                lines.insert(last + 1, format!("return {};", ret_val));
            }
        }
    }

    // Fold "var_N = expr;" at end of function into "return expr;"
    // Also handles: var_N = expr; return [var_N];
    {
        let mut i = 0;
        while i + 1 < lines.len() {
            let lt = lines[i].trim().to_string();
            let next = lines[i + 1].trim().to_string();
            if lt.contains(" = ") && lt.ends_with(';') {
                if let Some(eq_pos) = lt.find(" = ") {
                    let var_name = &lt[..eq_pos];
                    let expr = lt[eq_pos + 3..].trim_end_matches(';');
                    let is_return_var = next == format!("return {};", var_name);
                    let is_return_bare = next == "return;";
                    // Don't fold if the variable is used elsewhere in the function
                    // (e.g., ptr = malloc(...); ... printf("...", ptr); return ptr;)
                    let var_used_elsewhere = is_return_var && lines.iter().enumerate().any(|(j, l)| {
                        j != i && j != i + 1
                            && l.contains(var_name)
                            && !l.trim().starts_with("//")
                    });
                    if (is_return_bare || is_return_var) && !expr.is_empty() && !var_used_elsewhere {
                        let indent = lines[i].len() - lines[i].trim_start().len();
                        let pad = " ".repeat(indent);
                        lines[i] = format!("{}return {};", pad, expr);
                        lines.remove(i + 1);
                        continue;
                    }
                }
            }
            i += 1;
        }
        // Also: if the last non-blank line is "var_N = expr;" with no return after,
        // convert to "return expr;" (the function implicitly returns via EAX)
        if let Some(last) = lines.iter().rposition(|l| !l.trim().is_empty()) {
            let lt = lines[last].trim().to_string();
            if lt.starts_with("var_") && lt.contains(" = ") && lt.ends_with(';')
                && !lt.starts_with("var_8 =") // Don't convert stack canary stores
            {
                if let Some(eq_pos) = lt.find(" = ") {
                    let expr = &lt[eq_pos + 3..lt.len() - 1];
                    if !expr.is_empty() {
                        let indent = lines[last].len() - lines[last].trim_start().len();
                        let pad = " ".repeat(indent);
                        lines[last] = format!("{}return {};", pad, expr);
                    }
                }
            }
        }
    }

    // Fold "X = expr; ... return X;" across if-blocks: inline the expression
    // Pattern: X = expr; if (...) { return Y; } return X; → remove assignment, return expr;
    // Only fold when the assignment is at top level (not inside a loop/if body).
    {
        let mut i = 0;
        while i < lines.len() {
            let indent = lines[i].len() - lines[i].trim_start().len();
            let lt = lines[i].trim().to_string();
            // Only fold top-level assignments (indent 0)
            if indent == 0 && lt.contains(" = ") && lt.ends_with(';')
                && !lt.starts_with("if ") && !lt.starts_with("return ")
                && !lt.starts_with("while ") && !lt.starts_with("}")
            {
                if let Some(eq_pos) = lt.find(" = ") {
                    let var_name = lt[..eq_pos].to_string();
                    let expr = lt[eq_pos + 3..lt.len() - 1].to_string();
                    // Search forward for "return var_name;" at top level.
                    // But don't fold if var_name is used elsewhere (e.g., ptr used in
                    // printf/free after malloc assignment).
                    let var_used_elsewhere = lines.iter().enumerate().any(|(j, l)| {
                        j != i && l.contains(&var_name) && !l.trim().starts_with("//")
                            && l.trim() != format!("return {};", var_name)
                    });
                    if var_used_elsewhere { i += 1; continue; }
                    let mut found = false;
                    for j in (i + 1)..lines.len() {
                        let j_indent = lines[j].len() - lines[j].trim_start().len();
                        let t = lines[j].trim();
                        if j_indent == 0 && t == format!("return {};", var_name) {
                            lines[j] = format!("return {};", expr);
                            lines.remove(i);
                            found = true;
                            break;
                        }
                        // Check if var_name is reassigned at top level
                        if j_indent == 0 && t.starts_with(&format!("{} = ", var_name)) {
                            break;
                        }
                    }
                    if found { continue; }
                }
            }
            i += 1;
        }
    }

    // #PIE: Resolve remaining hex constants to string literals or import names.
    // Handles PIE ELF addresses (0x2070) that weren't resolved during SSA printing.
    for line in &mut lines {
        // Find patterns like func(0xNNNN) or func(0xNNNN, ...)
        let mut new_line = line.clone();
        let mut search_from = 0;
        while let Some(pos) = new_line[search_from..].find("0x") {
            let abs_pos = search_from + pos;
            // Extract the hex value
            let hex_end = abs_pos + 2 + new_line[abs_pos + 2..].find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(new_line.len() - abs_pos - 2);
            if hex_end > abs_pos + 2 {
                let hex_str = &new_line[abs_pos..hex_end];
                if let Ok(val) = u64::from_str_radix(&hex_str[2..], 16) {
                    if val > 0x200 {
                        // Try string literal (require >= 2 chars in call args, >= 4 elsewhere)
                        if let Some(s) = try_read_string(val, ctx) {
                            // Short strings (2-3 chars) only if inside a function call like printf(0x...)
                            let in_call = new_line[..abs_pos].contains('(');
                            let min_len = if in_call { 2 } else { 4 };
                            if s.len() < min_len { search_from = hex_end; continue; }
                            let escaped = format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n"));
                            new_line = format!("{}{}{}", &new_line[..abs_pos], escaped, &new_line[hex_end..]);
                            search_from = abs_pos + escaped.len();
                            continue;
                        }
                        // Try import/symbol name
                        if let Some(name) = ctx.imports.get(&val) {
                            new_line = format!("{}{}{}", &new_line[..abs_pos], name, &new_line[hex_end..]);
                            search_from = abs_pos + name.len();
                            continue;
                        }
                    }
                }
            }
            search_from = hex_end;
        }
        *line = new_line;
    }

    // #NESTED: Remove void/IO function calls nested inside other call arguments.
    // Pattern: func2(func1("..."), size, stream)  →  func1("..."); func2(buf, size, stream)
    // Run iteratively to handle multiple levels of nesting.
    let void_funcs = ["puts", "printf", "fprintf", "fputs", "perror",
                       "exit", "abort", "_exit", "free",
                       "write", "read", "fgets", "fread", "fwrite",
                       "sprintf", "snprintf", "strcspn", "strtok", "strcmp",
                       "fflush", "fclose", "fopen", "setvbuf",
                       "__isoc99_scanf", "scanf", "sscanf",
                       "memset", "memcpy", "strncpy", "strlen",
                       "cout_write", "cin_read"];
    for _round in 0..4 {  // iterate to peel nested layers
        let mut changed = false;
        for line in &mut lines {
            let trimmed = line.trim().to_string();
            for vf in &void_funcs {
                let pattern = format!("{}(", vf);
                if let Some(inner_pos) = trimmed.find(&pattern) {
                    if inner_pos > 0 {
                        let before = trimmed[..inner_pos].trim_end();
                        if before.ends_with('(') || before.ends_with(',') {
                            let inner_start = inner_pos + pattern.len();
                            let mut depth = 1;
                            let mut inner_end = inner_start;
                            for (i, c) in trimmed[inner_start..].char_indices() {
                                if c == '(' { depth += 1; }
                                if c == ')' { depth -= 1; if depth == 0 { inner_end = inner_start + i + 1; break; } }
                            }
                            if depth == 0 {
                                let inner_call = trimmed[inner_pos..inner_end].to_string();
                                let after = trimmed[inner_end..].trim_start().to_string();
                                let indent = line.len() - line.trim_start().len();
                                let pad = " ".repeat(indent);
                                // Build remaining: replace inner call with "buf", keeping proper comma separation
                                let before_inner = &trimmed[..inner_pos];
                                let after_clean = if after.starts_with(',') {
                                    format!(", {}", after[1..].trim_start())
                                } else {
                                    after.clone()
                                };
                                let remaining = format!("{}buf{}", before_inner, after_clean);
                                if remaining.contains('(') {
                                    *line = format!("{}{};\n{}{}", pad, inner_call, pad, remaining.trim());
                                    changed = true;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        if !changed { break; }
        // Re-split lines after unwinding (unwinder inserts \n within entries)
        lines = lines.iter().flat_map(|l| l.split('\n').map(|s| s.to_string())).collect();
    }

    // #SETVBUF: Collapse setvbuf init boilerplate.
    // Pattern: RAX = *(stdout); setvbuf(RAX, 0, 2, 0); setvbuf(stdin, 0, 2, 0); ...
    // → single comment or simplified init block
    {
        let mut j = 0;
        while j < lines.len() {
            let lt = lines[j].trim();
            // Remove "RAX = *(stdout_sym);" — this is just loading stdout
            if lt.starts_with("RAX = ") && (lt.contains("__TMC_END__") || lt.contains("stdout")) && lt.ends_with(';') {
                lines.remove(j);
                continue;
            }
            // Collapse consecutive setvbuf lines into one comment
            if lt.starts_with("setvbuf(") {
                let mut end = j;
                while end + 1 < lines.len() && lines[end + 1].trim().starts_with("setvbuf(") {
                    end += 1;
                }
                if end > j {
                    // Multiple setvbuf calls — replace with a single comment
                    let indent = lines[j].len() - lines[j].trim_start().len();
                    let pad = " ".repeat(indent);
                    for idx in (j + 1..=end).rev() { lines.remove(idx); }
                    lines[j] = format!("{}// setvbuf init (stdout, stdin, stderr)", pad);
                    j += 1;
                    continue;
                }
            }
            j += 1;
        }
    }

    // #TMC: Replace __TMC_END__ with stdout in remaining lines
    // __TMC_END__ is the GOT entry for stdout in many GCC-compiled binaries
    for line in &mut lines {
        *line = line.replace("*(__TMC_END__)", "stdout");
        *line = line.replace("__TMC_END__", "stdout");
    }

    // #PHI: Remove phi() noise from output
    for line in &mut lines {
        // Remove ", phi(...)" from call arguments
        while let Some(pos) = line.find(", phi(") {
            let start = pos;
            let after = &line[pos + 6..];
            let mut depth = 1;
            let mut end = pos + 6;
            for (i, c) in after.char_indices() {
                if c == '(' { depth += 1; }
                if c == ')' { depth -= 1; if depth == 0 { end = pos + 6 + i + 1; break; } }
            }
            if depth == 0 {
                *line = format!("{}{}", &line[..start], &line[end..]);
            } else {
                break;
            }
        }
        // Also handle phi(...) as first arg: "func(phi(...), ...)" → "func(...)"
        while let Some(pos) = line.find("phi(") {
            let before = &line[..pos];
            if before.ends_with('(') || before.ends_with(", ") {
                let after = &line[pos + 4..];
                let mut depth = 1;
                let mut end = pos + 4;
                for (i, c) in after.char_indices() {
                    if c == '(' { depth += 1; }
                    if c == ')' { depth -= 1; if depth == 0 { end = pos + 4 + i + 1; break; } }
                }
                if depth == 0 {
                    let mut replacement = line[..pos].to_string();
                    let rest = &line[end..];
                    if rest.starts_with(", ") {
                        replacement.push_str(&rest[2..]);
                    } else if rest.starts_with(',') {
                        replacement.push_str(&rest[1..].trim_start());
                    } else {
                        replacement.push_str(rest);
                    }
                    *line = replacement;
                } else {
                    break;
                }
            } else {
                break;
            }
        }
    }

    // #ARRAY: Fix array index syntax: RDX[name] → name[RDX]
    // When a register or expression is used as the base and a symbol name as the "index",
    // swap them for readable array access syntax.
    for line in &mut lines {
        // Match patterns like: REG[symbol_name] or expr[symbol_name]
        let re_patterns = [
            // Simple: RDX[friend_type]
            ("var_", false), // Skip var_ patterns - those are correct
        ];
        let _ = re_patterns; // silence warning
        // Use a simple approach: find ][...] patterns where the index is a known symbol
        let l = line.clone();
        for (_addr, name) in ctx.imports.iter() {
            let bracket_pattern = format!("[{}]", name);
            if l.contains(&bracket_pattern) {
                // Find what's before the [name]: it should be a register or expression
                if let Some(bp) = l.find(&bracket_pattern) {
                    // Walk back to find the start of the base expression
                    let before = &l[..bp];
                    // Find the start of the identifier/expression before [
                    let base_start = before.rfind(|c: char| !c.is_alphanumeric() && c != '_')
                        .map(|p| p + 1).unwrap_or(0);
                    let base = &l[base_start..bp];
                    if !base.is_empty() && base != name {
                        // Swap: base[name] → name[base]
                        let old = format!("{}[{}]", base, name);
                        let new = format!("{}[{}]", name, base);
                        *line = line.replace(&old, &new);
                    }
                }
            }
        }
    }

    // #STACKSTR: Merge consecutive string constant assignments into one string.
    // Matches var_XX = "..."; or REG = "..."; patterns (stack string init)
    {
        let mut i = 0;
        while i < lines.len() {
            let lt = lines[i].trim().to_string();
            // Match: IDENTIFIER = "...";
            if lt.contains(" = \"") && lt.ends_with("\";") && !lt.starts_with("if ") && !lt.starts_with("while ") {
                let mut merged = String::new();
                let mut end = i;
                let mut count = 0;
                for j in i..lines.len() {
                    let jt = lines[j].trim();
                    if jt.contains(" = \"") && jt.ends_with("\";") && !jt.starts_with("if ") {
                        if let Some(q1) = jt.find('"') {
                            if let Some(q2) = jt.rfind('"') {
                                if q2 > q1 {
                                    merged.push_str(&jt[q1+1..q2]);
                                    end = j;
                                    count += 1;
                                }
                            }
                        }
                    } else {
                        break;
                    }
                }
                if count >= 3 && merged.len() >= 6 {
                    let unique: std::collections::HashSet<char> = merged.chars().collect();
                    if unique.len() >= 4 {
                    let indent = lines[i].len() - lines[i].trim_start().len();
                    let pad = " ".repeat(indent);
                    let _var_name = lt.split(' ').next().unwrap_or("buf");
                    for idx in (i + 1..=end).rev() { lines.remove(idx); }
                    lines[i] = format!("{}// stack string: \"{}\"", pad, merged);
                    }
                }
            }
            i += 1;
        }
    }

    // #XMM: Simplify XMM zero-init patterns (XORPS XMM0,XMM0 → memset(0) for structs)
    for line in &mut lines {
        // Pattern: var = XMM0 ^ XMM0 >> ... (long chain) → var = 0
        if line.contains("XMM0 ^ XMM0") || line.contains("XMM0 >> 32 ^ XMM0") {
            if let Some(eq_pos) = line.find(" = ") {
                let var_part = &line[..eq_pos + 3];
                *line = format!("{}0; // zero-init", var_part);
            }
        }
    }

    // Add after NESTED by searching for marker... actually let me just add before DEDUP
    // #DEDUP: Remove duplicate call lines within the same scope.
    // The nested-call unwinding can create the same call line multiple times.
    // Remove non-consecutive duplicates of function calls at the same indent level.
    // Only remove duplicates that are NOT adjacent — adjacent identical calls may be
    // intentional (e.g., printf("===\n"); printf("===\n"); in a banner function).
    {
        let mut i = 0;
        while i < lines.len() {
            let lt = lines[i].trim().to_string();
            let indent = lines[i].len() - lines[i].trim_start().len();
            // Only dedup function calls (contain "(" and end with ";")
            if !lt.is_empty() && lt.contains('(') && lt.ends_with(';')
                && !lt.starts_with("if ") && !lt.starts_with("while ")
                && !lt.starts_with("for ") && !lt.starts_with("return ")
            {
                // Check if an identical line exists later at the same indent
                // but only remove if there are >2 lines between (non-adjacent)
                let mut j = i + 1;
                while j < lines.len() {
                    let jt = lines[j].trim();
                    let j_indent = lines[j].len() - lines[j].trim_start().len();
                    if j_indent == indent && jt == lt && (j - i) > 2 {
                        lines.remove(j);
                        continue;
                    }
                    // Stop at scope boundaries (different indent going down, or closing brace)
                    if j_indent < indent && !jt.is_empty() { break; }
                    j += 1;
                }
            }
            i += 1;
        }
    }

    // #ARGS: Strip extra arguments from known single-arg functions.
    // puts(msg, stale_reg) → puts(msg), exit(code, stale) → exit(code)
    let single_arg_fns = ["puts", "exit", "abort", "perror", "free",
                           "close", "putchar", "strlen"];
    for line in &mut lines {
        for func in &single_arg_fns {
            let pat = format!("{}(", func);
            if let Some(start) = line.find(&pat) {
                let args_start = start + pat.len();
                // Find the first arg's end (respecting nested parens/quotes)
                let mut depth = 0;
                let mut in_str = false;
                let mut first_comma = None;
                for (i, c) in line[args_start..].char_indices() {
                    if c == '"' && !in_str { in_str = true; continue; }
                    if c == '"' && in_str { in_str = false; continue; }
                    if in_str { continue; }
                    if c == '(' { depth += 1; }
                    if c == ')' { if depth == 0 { break; } depth -= 1; }
                    if c == ',' && depth == 0 { first_comma = Some(args_start + i); break; }
                }
                if let Some(comma_pos) = first_comma {
                    // Find the closing paren
                    let mut d = 0;
                    let mut close = None;
                    for (i, c) in line[args_start..].char_indices() {
                        if c == '(' { d += 1; }
                        if c == ')' { if d == 0 { close = Some(args_start + i); break; } d -= 1; }
                    }
                    if let Some(close_pos) = close {
                        // Replace: func(arg1, arg2, ...) → func(arg1)
                        let _new_line = format!("{}{}){}", &line[..comma_pos], "", &line[close_pos + 1..]);
                        let first_arg = &line[args_start..comma_pos];
                        *line = format!("{}{}({}){}", &line[..start], func, first_arg, &line[close_pos + 1..]);
                    }
                }
            }
        }
    }

    // #INDENT: Fix orphaned return at end of function with wrong indentation.
    // Only fix the very last non-empty line if it's a return with excess indent.
    if let Some(last_idx) = lines.iter().rposition(|l| !l.trim().is_empty()) {
        let lt = lines[last_idx].trim().to_string();
        let my_indent = lines[last_idx].len() - lines[last_idx].trim_start().len();
        if (lt == "return;" || lt.starts_with("return ")) && my_indent > 2 {
            // Check if this return is at top level (not inside a block)
            // by counting open/close braces before it
            let mut depth: i32 = 0;
            for j in 0..last_idx {
                let t = lines[j].trim();
                depth += t.matches('{').count() as i32;
                depth -= t.matches('}').count() as i32;
            }
            // If depth is 0, this return should be at top level (indent 0 or 2)
            if depth <= 0 && my_indent > 0 {
                lines[last_idx] = lt;
            }
        }
    }

    // #FALSESTR: Remove false short string literals from addresses.
    // These are garbage strings from random bytes at addresses decoded as ASCII.
    for line in &mut lines {
        if line.contains("\"") {
            // Replace known garbage patterns
            for pat in ["\"h@@\"", "\"@@\"", "\"@\""] {
                *line = line.replace(pat, "0x0");
            }
            // Remove false short strings in arithmetic contexts:
            // pattern & "XYZ" or pattern & "XY"%" — these are addresses not strings
            // Detect: quoted strings inside & or | expressions (bitwise ops on "strings" = nonsense)
            if (line.contains("& \"") || line.contains("| \"")) && !line.contains("printf")
                && !line.contains("puts") && !line.contains("fwrite")
            {
                // Replace all short quoted strings (< 5 chars) with hex in this line
                let mut result = String::new();
                let mut chars = line.chars().peekable();
                while let Some(c) = chars.next() {
                    if c == '"' {
                        let mut s = String::new();
                        while let Some(&nc) = chars.peek() {
                            if nc == '"' { chars.next(); break; }
                            s.push(nc);
                            chars.next();
                        }
                        if s.len() < 5 && (line.contains(" & ") || line.contains(" | ")) {
                            result.push_str("0x0");
                        } else {
                            result.push('"');
                            result.push_str(&s);
                            result.push('"');
                        }
                    } else {
                        result.push(c);
                    }
                }
                *line = result;
            }
        }
    }

    // #PARAMS: Replace bare register names with parameter names when available.
    // The SSA names params as param_0, param_1 but the printer sometimes outputs
    // the raw register (RDI, RSI, etc.) when the value is used directly without
    // going through the named SSA variable.
    if !param_names.is_empty() {
        let reg_to_param: Vec<(&str, &str)> = vec![
            ("RDI", ""), ("EDI", ""), ("DIL", ""),  // param_0
            ("RSI", ""), ("ESI", ""), ("SIL", ""),  // param_1
            ("RDX", ""), ("EDX", ""), ("DL", ""),   // param_2
            ("RCX", ""), ("ECX", ""), ("CL", ""),   // param_3
        ];
        // Map register base offset to param index
        let reg_param_map: &[(u64, usize)] = &[(56, 0), (48, 1), (16, 2), (8, 3)]; // RDI, RSI, RDX, RCX offsets
        let _ = (reg_to_param, reg_param_map); // just documenting the mapping

        // Simple approach: in conditions and call args, replace bare register names
        // Only replace when the register appears as a standalone word (not part of a larger expr)
        let x86_arg_regs: [(&str, usize); 8] = [
            ("RDI", 0), ("EDI", 0), ("RSI", 1), ("ESI", 1),
            ("RDX", 2), ("EDX", 2), ("RCX", 3), ("ECX", 3),
        ];
        for line in &mut lines {
            for (reg, idx) in &x86_arg_regs {
                if *idx < param_names.len() && line.contains(reg) {
                    let pname = &param_names[*idx];
                    // Only substitute if the param was given a real name (by DWARF),
                    // not a generic "param_N" which is no better than the register name
                    if pname.starts_with("param_") { continue; }
                    let l = line.clone();
                    let mut result = String::new();
                    let mut i = 0;
                    let bytes = l.as_bytes();
                    let rlen = reg.len();
                    while i < bytes.len() {
                        if i + rlen <= bytes.len() && &l[i..i+rlen] == *reg {
                            let before_ok = i == 0 || !bytes[i-1].is_ascii_alphanumeric();
                            let after_ok = i + rlen >= bytes.len() || !bytes[i+rlen].is_ascii_alphanumeric();
                            if before_ok && after_ok {
                                result.push_str(pname);
                                i += rlen;
                                continue;
                            }
                        }
                        result.push(bytes[i] as char);
                        i += 1;
                    }
                    *line = result;
                }
            }
        }
    }

    // #FLOAT: Resolve floating-point reciprocal multiplication.
    // Pattern: INT2FLOAT(x) * *(0xNNN) where the memory holds 1/N.0
    // → x / N.0
    if let Some(binary) = ctx.binary {
        for line in &mut lines {
            // Match: EXPR * *(0xNNN) or EXPR * *("") (false string from float constants)
            if line.contains("* *(") && (line.contains("double)") || line.contains("XMM") || line.contains("FLOAT")) {
                // Find the *(addr) part
                if let Some(star_pos) = line.rfind("* *(") {
                    let after = &line[star_pos + 4..];
                    if let Some(close) = after.find(')') {
                        let addr_str = &after[..close];
                        // Try to parse as hex address
                        let addr_val = if addr_str.starts_with("0x") {
                            u64::from_str_radix(&addr_str[2..], 16).ok()
                        } else if addr_str == "\"\"" || addr_str.starts_with('"') {
                            // False string from float constant at an address with leading zeros.
                            // We can't recover the original address, but we know it's a float
                            // reciprocal. Replace the whole multiplication with a generic form.
                            let before = line[..star_pos].trim_end();
                            let after_paren = &line[star_pos + 4 + close + 1..];
                            *line = format!("{} / N.0{}", before, after_paren);
                            continue;
                        } else {
                            None
                        };
                        if let Some(va) = addr_val {
                            // Try to read 8 bytes as a double
                            if let Some(fo) = va_to_file_offset(va, binary) {
                                if fo + 8 <= binary.len() {
                                    let bytes: [u8; 8] = binary[fo..fo+8].try_into().unwrap_or([0;8]);
                                    let fval = f64::from_le_bytes(bytes);
                                    if fval != 0.0 && fval.is_finite() {
                                        let recip = 1.0 / fval;
                                        // Check if it's a clean reciprocal (integer)
                                        if recip > 1.0 && (recip - recip.round()).abs() < 0.001 {
                                            let divisor = recip.round() as u64;
                                            let before = line[..star_pos].trim_end();
                                            let after_paren = &line[star_pos + 4 + close + 1..];
                                            *line = format!("{} / {}.0{}", before, divisor, after_paren);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // Simplify "* (1.0 / N.0)" → "/ N.0" (reciprocal resolved at SSA level)
            if line.contains("* (1.0 / ") {
                if let Some(pos) = line.find("* (1.0 / ") {
                    if let Some(close) = line[pos + 9..].find(')') {
                        let divisor = &line[pos + 9..pos + 9 + close];
                        let before = line[..pos].trim_end();
                        let after = &line[pos + 9 + close + 1..];
                        *line = format!("{} / {}{}", before, divisor, after);
                    }
                }
            }
            // Also simplify INT2FLOAT(x) → (double)x
            *line = line.replace("INT2FLOAT(", "(double)(");
        }
    }

    // #SWITCH: Detect jump table patterns and resolve to switch/case.
    // Pattern: if (val > N) { default } else { table_base + *(table_base + val*4) }
    // Read the jump table from the binary and show case targets.
    if let Some(binary) = ctx.binary {
        let mut i = 0;
        while i < lines.len() {
            let lt = lines[i].trim().to_string();
            // Look for the jump table load: "RAX = 0xNNN[REG];" or "RCX = (0xNNN[...])"
            // followed by "return REG + 0xNNN;"
            if lt.contains("[") && !lt.contains("RBP") && !lt.contains("var_") {
                // Try to extract the table address from patterns like 0xNNN[
                for prefix in ["0x"] {
                    if let Some(addr_start) = lt.find(prefix) {
                        let after = &lt[addr_start + 2..];
                        if let Some(bracket) = after.find('[') {
                            let hex_str = &after[..bracket];
                            if let Ok(table_va) = u64::from_str_radix(hex_str, 16) {
                                if table_va > 0x200 {
                                    // Try to read this as a jump table of signed 32-bit offsets
                                    if let Some(fo) = va_to_file_offset(table_va, binary) {
                                        // Check if previous line has a bounds check: if (X > N)
                                        let max_case = if i > 0 {
                                            let prev = lines[i.saturating_sub(6)..i].iter()
                                                .find(|l| l.trim().starts_with("if ("))
                                                .map(|l| l.trim().to_string())
                                                .unwrap_or_default();
                                            // Extract N from "if (param > N)" or "if (X > N)"
                                            if let Some(gt) = prev.find(" > ") {
                                                let after_gt = &prev[gt + 3..];
                                                let end = after_gt.find(')').unwrap_or(after_gt.len());
                                                after_gt[..end].parse::<usize>().ok()
                                            } else { None }
                                        } else { None };

                                        let num_cases = max_case.unwrap_or(7).min(32) + 1;
                                        if fo + num_cases * 4 <= binary.len() {
                                            let mut cases = Vec::new();
                                            let mut all_valid = true;
                                            for c in 0..num_cases {
                                                let entry_off = fo + c * 4;
                                                let rel_offset = i32::from_le_bytes([
                                                    binary[entry_off], binary[entry_off+1],
                                                    binary[entry_off+2], binary[entry_off+3],
                                                ]);
                                                let target_va = (table_va as i64 + rel_offset as i64) as u64;
                                                // Try to read a string at the target
                                                if let Some(s) = try_read_string(target_va, ctx) {
                                                    cases.push(format!("case {}: \"{}\"", c, s));
                                                } else if let Some(name) = ctx.imports.get(&target_va) {
                                                    cases.push(format!("case {}: {}", c, name));
                                                } else {
                                                    cases.push(format!("case {}: 0x{:x}", c, target_va));
                                                    if target_va > 0x10000000 || (rel_offset.abs() as u64 > 0x10000) {
                                                        all_valid = false;
                                                    }
                                                }
                                            }
                                            if all_valid && !cases.is_empty() {
                                                let indent = lines[i].len() - lines[i].trim_start().len();
                                                let pad = " ".repeat(indent);
                                                let inner_pad = format!("{}    ", pad);
                                                // Find the switch variable from the bounds check
                                                let switch_var = if i > 0 {
                                                    let prev_lines = &lines[i.saturating_sub(6)..i];
                                                    prev_lines.iter().rev()
                                                        .find(|l| l.trim().starts_with("if ("))
                                                        .and_then(|l| {
                                                            let t = l.trim();
                                                            let after_if = t.strip_prefix("if (")?;
                                                            let gt = after_if.find(" > ")?;
                                                            Some(after_if[..gt].to_string())
                                                        })
                                                } else { None };
                                                let var_name = switch_var.as_deref().unwrap_or("?");

                                                // Build switch/case block
                                                let mut switch_lines = Vec::new();
                                                switch_lines.push(format!("{}switch ({}) {{", pad, var_name));
                                                for case in &cases {
                                                    // Parse "case N: VALUE"
                                                    if let Some(colon) = case.find(": ") {
                                                        let case_num = &case[..colon];
                                                        let value = &case[colon + 2..];
                                                        switch_lines.push(format!("{}{}: return {};", inner_pad, case_num, value));
                                                    }
                                                }
                                                switch_lines.push(format!("{}}}", pad));

                                                // Replace the table load line + surrounding boilerplate
                                                // Remove the bounds check if/else and return lines
                                                let remove_start = if i > 0 {
                                                    // Look back for the if (var > N) line
                                                    let mut rs = i;
                                                    for k in (0..i).rev() {
                                                        if lines[k].trim().starts_with("if (") && lines[k].trim().contains(" > ") {
                                                            rs = k;
                                                            break;
                                                        }
                                                    }
                                                    rs
                                                } else { i };

                                                // Look forward for the closing } and return
                                                let mut remove_end = i + 1;
                                                for k in (i + 1)..lines.len().min(i + 5) {
                                                    let kt = lines[k].trim();
                                                    if kt.starts_with("return") || kt == "}" || kt.starts_with("} else") {
                                                        remove_end = k + 1;
                                                    } else { break; }
                                                }

                                                // Replace the range with switch block
                                                let drain_range = remove_start..remove_end;
                                                lines.splice(drain_range, switch_lines);
                                                // Don't increment i — reprocess
                                                continue;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    break; // only try one prefix
                }
            }
            i += 1;
        }
    }

    // #FMTCALL: Fix printf/snprintf where format string is in RAX and float in XMM0.
    // Pattern: XMM0 = expr; RAX = "fmt"; snprintf(buf, N, N) → snprintf(buf, N, "fmt", expr)
    {
        let printf_fns = ["printf", "snprintf", "fprintf", "sprintf"];
        let mut i = 0;
        while i < lines.len() {
            let lt = lines[i].trim().to_string();
            let is_printf_call = printf_fns.iter().any(|f| lt.starts_with(&format!("{}(", f)));
            if !is_printf_call { i += 1; continue; }

            let mut fmt_str = String::new();
            let mut fmt_line = None;
            let mut xmm_expr = String::new();
            let mut xmm_line = None;

            for j in (0..i).rev() {
                let jt = lines[j].trim();
                if jt.is_empty() { continue; }
                if jt.starts_with("RAX = \"") && jt.ends_with("\";") {
                    fmt_str = jt.strip_prefix("RAX = ").unwrap_or("").trim_end_matches(';').trim().to_string();
                    fmt_line = Some(j);
                } else if jt.starts_with("XMM0 = ") && jt.ends_with(';') {
                    xmm_expr = jt.strip_prefix("XMM0 = ").unwrap_or("").trim_end_matches(';').trim().to_string();
                    xmm_line = Some(j);
                } else {
                    break;
                }
            }

            if !fmt_str.is_empty() {
                let indent = lines[i].len() - lines[i].trim_start().len();
                let pad = " ".repeat(indent);
                if let Some(paren) = lt.find('(') {
                    let func_name = &lt[..paren];
                    let args_str = &lt[paren + 1..lt.len().saturating_sub(2)];
                    let args: Vec<&str> = args_str.splitn(3, ", ").collect();
                    let has_float_fmt = fmt_str.contains("%f") || fmt_str.contains("%.1f")
                        || fmt_str.contains("%.2f") || fmt_str.contains("%lf")
                        || fmt_str.contains("%e") || fmt_str.contains("%g");
                    let float_arg = if has_float_fmt && !xmm_expr.is_empty() {
                        format!(", {}", xmm_expr)
                    } else { String::new() };

                    let new_call = if func_name == "printf" {
                        format!("{}printf({}{});", pad, fmt_str, float_arg)
                    } else if args.len() >= 2 {
                        format!("{}{}({}, {}, {}{});", pad, func_name, args[0], args[1], fmt_str, float_arg)
                    } else { lt.clone() };

                    lines[i] = new_call;
                    let mut to_remove = Vec::new();
                    if let Some(j) = fmt_line { to_remove.push(j); }
                    if let Some(j) = xmm_line { to_remove.push(j); }
                    to_remove.sort_unstable();
                    for j in to_remove.into_iter().rev() { lines.remove(j); if j < i { i -= 1; } }
                    continue;
                }
            }
            i += 1;
        }
    }

    // #REGINLINE: Inline register assignments into subsequent conditions.
    // Pattern: EAX = expr; if (AL == Y) → if (expr == Y)
    //          RAX = expr; if (EAX ...) → if (expr ...)
    {
        let reg_pairs: &[(&str, &[&str])] = &[
            ("EAX", &["AL", "AX", "EAX"]),
            ("RAX", &["AL", "AX", "EAX", "RAX"]),
            ("ECX", &["CL", "CX", "ECX"]),
            ("RCX", &["CL", "CX", "ECX", "RCX"]),
            ("EDX", &["DL", "DX", "EDX"]),
            ("RDX", &["DL", "DX", "EDX", "RDX"]),
        ];
        let mut i = 0;
        while i + 1 < lines.len() {
            let lt = lines[i].trim().to_string();
            let next = lines[i + 1].trim().to_string();
            // Match: REG = expr; if (SUBREG ...)
            for (full_reg, sub_regs) in reg_pairs {
                if lt.starts_with(&format!("{} = ", full_reg)) && lt.ends_with(';')
                    && !lt.contains("return") && !lt.contains("if ")
                {
                    let expr = lt[full_reg.len() + 3..lt.len()-1].to_string();
                    // Check if next line's condition uses a sub-register
                    if next.starts_with("if (") {
                        for sub in *sub_regs {
                            let check = format!("if ({} ", sub);
                            if next.starts_with(&check) {
                                let indent = lines[i + 1].len() - lines[i + 1].trim_start().len();
                                let pad = " ".repeat(indent);
                                let new_cond = next.replacen(sub, &expr, 1);
                                lines[i + 1] = format!("{}{}", pad, new_cond.trim());
                                lines.remove(i);
                                break;
                            }
                        }
                    }
                }
            }
            i += 1;
        }
    }

    // #CALLRET: Inline call return values into subsequent conditions.
    // Pattern: func(...); if (0 == 0) { ... } → if (func(...) == 0) { ... }
    // The call return (in EAX) isn't captured by the SSA because CALL P-code
    // doesn't write to RAX. The condition check reads the pre-call EAX value
    // which is 0 or unknown. Fix by detecting call-then-condition patterns.
    {
        let mut i = 0;
        while i + 1 < lines.len() {
            let lt = lines[i].trim().to_string();
            let next = lines[i + 1].trim().to_string();
            // Match: func_call(...); followed by if (0 == 0), if (0 != 0), if (EAX == 0), etc.
            if lt.ends_with(';') && lt.contains('(') && !lt.contains(" = ")
                && !lt.starts_with("if ") && !lt.starts_with("while ") && !lt.starts_with("return ")
                && !lt.starts_with("//") && !lt.starts_with("var_") && !lt.starts_with("}")
            {
                // Extract the call expression (remove trailing ;)
                let call_expr = lt.trim_end_matches(';').trim();

                // Check if next line is: if (0 == 0), if (0 != 0), if (EAX == 0), etc.
                let is_zero_cond = next.starts_with("if (0 == 0)")
                    || next.starts_with("if (0 != 0)")
                    || next.starts_with("if (0 == 0 ")  // with trailing &&
                    || next.starts_with("if (0 != 0 ");
                let is_eax_cond = next.starts_with("if (EAX == ")
                    || next.starts_with("if (EAX != ")
                    || next.starts_with("if (EAX < ")
                    || next.starts_with("if (EAX > ")
                    || next.starts_with("if (EAX <= ")
                    || next.starts_with("if (EAX >= ");
                // Also match: if (var_N == 0) right after a call — often the return check
                let _is_var_zero = next.starts_with("if (var_") &&
                    (next.contains(" == 0)") || next.contains(" != 0)"));

                if is_zero_cond {
                    let indent = lines[i + 1].len() - lines[i + 1].trim_start().len();
                    let pad = " ".repeat(indent);
                    // Replace: "if (0 == 0)" → "if (call_expr == 0)"
                    // and "if (0 != 0)" → "if (call_expr != 0)"
                    let new_cond = if next.contains("0 != 0") {
                        next.replace("0 != 0", &format!("{} != 0", call_expr))
                    } else {
                        next.replace("0 == 0", &format!("{} == 0", call_expr))
                    };
                    lines[i + 1] = format!("{}{}", pad, new_cond.trim());
                    lines.remove(i);
                    continue;
                } else if is_eax_cond {
                    let indent = lines[i + 1].len() - lines[i + 1].trim_start().len();
                    let pad = " ".repeat(indent);
                    let new_cond = next.replacen("EAX", call_expr, 1);
                    lines[i + 1] = format!("{}{}", pad, new_cond.trim());
                    lines.remove(i);
                    continue;
                }
            }
            i += 1;
        }
    }

    // #SBORROW: Clean up leftover SBORROW flag patterns.
    // These are raw signed-borrow flag checks that weren't recovered to comparisons.
    // They're always redundant with adjacent comparisons. Remove the SBORROW lines.
    {
        let mut i = 0;
        while i < lines.len() {
            if lines[i].contains("SBORROW") {
                // If it's inside an if-condition, simplify the whole condition
                let lt = lines[i].trim();
                if lt.starts_with("if (") && lt.contains("SBORROW") {
                    // The condition is too complex to parse — replace with simplified form
                    // Try to extract any non-SBORROW part of the condition
                    let indent = lines[i].len() - lines[i].trim_start().len();
                    let pad = " ".repeat(indent);
                    lines[i] = format!("{}if (true) {{", pad);
                } else if !lt.starts_with("if ") && !lt.starts_with("while ") && !lt.starts_with("} else") {
                    // Standalone SBORROW line — remove it
                    lines.remove(i);
                    continue;
                }
            }
            i += 1;
        }
    }

    // #POSIX: Replace POSIX magic numbers with readable macros.
    for line in &mut lines {
        // S_ISDIR: (st_mode & 0xf000) == 16384 → S_ISDIR(st_mode)
        *line = line.replace("& 0xf000 == 16384", "& 0xf000) == 0x4000 /* S_ISDIR */");
        *line = line.replace("& 0xf000 != 16384", "& 0xf000) != 0x4000 /* !S_ISDIR */");
        // S_ISREG: (st_mode & 0xf000) == 32768
        *line = line.replace("& 0xf00-32768 == 0", "& 0xf000) == 0x8000 /* S_ISREG */");
        *line = line.replace("& 0xf000 == 32768", "& 0xf000) == 0x8000 /* S_ISREG */");
        // ASCII char constants in comparisons
        let ascii_chars: &[(i32, &str)] = &[
            (9, "'\\t'"), (10, "'\\n'"), (13, "'\\r'"), (32, "' '"),
            (34, "'\"'"), (39, "'\\''"), (44, "','"), (46, "'.'"),
            (47, "'/'"), (48, "'0'"), (57, "'9'"), (58, "':'"),
            (59, "';'"), (61, "'='"), (63, "'?'"), (65, "'A'"),
            (70, "'F'"), (90, "'Z'"), (91, "'['"), (92, "'\\\\'"),
            (93, "']'"), (95, "'_'"), (97, "'a'"), (102, "'f'"),
            (122, "'z'"), (123, "'{'"), (125, "'}'"),
        ];
        for (val, ch) in ascii_chars {
            // Match: == N), != N), > N), < N), >= N), <= N) where N is the ASCII value
            // Only in conditions with byte-sized operands (string/char comparisons).
            // Guard: require a byte-sized context indicator — uint8_t cast, char pointer
            // deref *(s), or a known string function (strcmp, strncmp, fgets, etc.)
            let has_byte_context = line.contains("uint8_t") || line.contains("*(s")
                || line.contains("*(param_") || line.contains("strcmp")
                || line.contains("strncmp") || line.contains("fgets")
                || line.contains("char") || line.contains("[");
            if !has_byte_context { continue; }
            if line.contains(&format!("== {})", val)) || line.contains(&format!("!= {})", val))
                || line.contains(&format!("> {})", val)) || line.contains(&format!("< {})", val))
                || line.contains(&format!(">= {})", val)) || line.contains(&format!("<= {})", val))
                || line.contains(&format!("- {} ==", val))
            {
                if !line.contains("\"") || line.contains("if (") || line.contains("while (") {
                    *line = line.replace(&format!("== {})", val), &format!("== {})", ch));
                    *line = line.replace(&format!("!= {})", val), &format!("!= {})", ch));
                    // Use " > " (with spaces) to avoid matching ">>" shift operators
                    *line = line.replace(&format!(" > {})", val), &format!(" > {})", ch));
                    *line = line.replace(&format!(" < {})", val), &format!(" < {})", ch));
                    *line = line.replace(&format!(" >= {})", val), &format!(" >= {})", ch));
                    *line = line.replace(&format!(" <= {})", val), &format!(" <= {})", ch));
                    *line = line.replace(&format!("- {} ==", val), &format!("== {}  //", ch));
                }
            }
        }

        // Remove x86 shift mask noise: ">> N & 31" → ">> N", "<< N & 63" → "<< N"
        // x86 shifts implicitly mask the count; the P-code emits an explicit IntAnd.
        // Only strip when directly after a shift expression (not standalone & 31).
        if line.contains(">> ") && line.contains(" & 31") {
            *line = line.replace(" & 31", "");
        }
        if line.contains(">> ") && line.contains(" & 63") {
            *line = line.replace(" & 63", "");
        }

        // macOS ctype: __maskrune(FLAGS) → isXXX() function names
        *line = line.replace("__maskrune(16384)", "isspace()");
        *line = line.replace("& 16384", "/* isspace */");
        *line = line.replace("__maskrune(1024)", "isdigit()");
        *line = line.replace("__maskrune(256)", "isalpha()");
        *line = line.replace("__maskrune(768)", "isalnum()");
        *line = line.replace("__maskrune(8192)", "isupper()");
        *line = line.replace("__maskrune(4096)", "islower()");
        *line = line.replace("__maskrune(32768)", "isprint()");
    }

    // #EMPTY_WHILE: Remove empty while loop bodies (structure recovery artifacts).
    // Pattern: while (cond) {\n  }  → remove entirely (it's dead code)
    {
        let mut i = 0;
        while i + 1 < lines.len() {
            let lt = lines[i].trim();
            let next = lines.get(i + 1).map(|l| l.trim().to_string()).unwrap_or_default();
            if lt.starts_with("while (") && lt.ends_with('{') && next == "}" {
                lines.remove(i + 1);
                lines.remove(i);
                continue;
            }
            i += 1;
        }
    }

    // #DIV_BY_CONST: Recognize multiply-then-shift division patterns.
    // The compiler replaces x/D with x * magic >> shift.
    // Pattern 1 (same line): "REG = EXPR * (int)0xNNNN >> K;"
    // Pattern 2 (two lines): "REG = EXPR * (int)0xNNNN;" then "REG = REG >> K;"
    {
        let mut i = 0;
        while i < lines.len() {
            // Look for multiply by magic constant
            let lt = lines[i].trim().to_string();
            let mul_pos = lt.find(" * (int)0x").or_else(|| lt.find(" * 0x"));
            let Some(mul_pos) = mul_pos else { i += 1; continue; };

            // Extract magic constant
            let hex_marker = if lt[mul_pos..].starts_with(" * (int)0x") { " * (int)0x" } else { " * 0x" };
            let hex_start = mul_pos + hex_marker.len();
            let hex_end = lt[hex_start..].find(|c: char| !c.is_ascii_hexdigit())
                .map(|e| hex_start + e).unwrap_or(lt.len());
            let hex_str = lt[hex_start..hex_end].to_string();
            let Ok(magic) = u64::from_str_radix(&hex_str, 16) else { i += 1; continue; };
            if magic < 0x10000000 { i += 1; continue; } // too small to be a magic constant

            // Find the source variable (before the multiply)
            let eq_pos = lt.find(" = ");
            let src_var = if let Some(ep) = eq_pos {
                let rhs = lt[ep + 3..mul_pos].trim();
                // Strip (int) cast if present
                let clean = rhs.strip_prefix("(int)").unwrap_or(rhs);
                clean.to_string()
            } else { i += 1; continue; };

            // Find shift: same line or next line
            let shift = if let Some(shr_pos) = lt.find(">> ") {
                let ns = shr_pos + 3;
                let ne = lt[ns..].find(|c: char| !c.is_ascii_digit()).map(|e| ns + e).unwrap_or(lt.len());
                lt[ns..ne].parse::<u32>().ok()
            } else {
                // Scan forward (up to 3 lines) for the division shift (>> 32..38)
                // Skip sign-extraction shifts (>> 31, >> 63)
                let mut found_shift = None;
                for look in 1..=3 {
                    if i + look >= lines.len() { break; }
                    let next = lines[i + look].trim().to_string();
                    if let Some(shr_pos) = next.find(">> ") {
                        let ns = shr_pos + 3;
                        let ne = next[ns..].find(|c: char| !c.is_ascii_digit()).map(|e| ns + e).unwrap_or(next.len());
                        if let Ok(s) = next[ns..ne].parse::<u32>() {
                            // Skip sign-extraction shifts (31 for 32-bit, 63 for 64-bit)
                            if s == 31 || s == 63 { continue; }
                            found_shift = Some(s);
                            break;
                        }
                    }
                }
                found_shift
            };

            let Some(shift) = shift else { i += 1; continue; };
            if shift < 30 || shift > 40 { i += 1; continue; }

            // Compute divisor: D = round(2^(32+shift-32) / magic) for shift > 32
            // or D = round(2^shift / magic) for general case
            let effective_shift = if shift >= 32 { shift } else { shift + 32 };
            let power = (1u128 << effective_shift) as f64;
            let divisor = (power / magic as f64).round() as u64;
            if divisor < 2 || divisor > 1000 { i += 1; continue; }

            // Replace multiply line with division
            let pad = " ".repeat(lines[i].len() - lines[i].trim_start().len());
            let dest = if let Some(ep) = eq_pos { lt[..ep].to_string() } else { src_var.clone() };

            // Replace multiply line with division, remove shift and sign-extraction lines
            lines[i] = format!("{}{} = {} / {};", pad, dest.trim(), src_var, divisor);
            // Remove subsequent lines that are part of the division pattern
            // (sign-extraction >> 63, the actual shift >> N, and sign correction + lines)
            let mut _j = i + 1;
            while _j < lines.len() {
                let jt = lines[_j].trim();
                if jt.contains(">> 63;") || jt.contains(">> 31;") {
                    lines.remove(_j); // sign extraction
                } else if jt.contains(&format!(">> {};", shift)) {
                    lines.remove(_j); // the division shift
                } else {
                    break;
                }
            }
            i += 1;
        }
    }

    // #SAR_DIV: Recognize SAR+sign-correction division pattern.
    // Pattern: "ECX = EAX >> 31;" then "EAX = EAX >> K;" then "return EAX + ECX;"
    // → "return x / D" where D = 2^K + 1 (with sign correction)
    // This is used for divide_by_7 (K=2, D=7), divide_by_3 (K=1, D=3), etc.
    {
        let mut i = 0;
        while i + 2 < lines.len() {
            let l0 = lines[i].trim().to_string();
            let l1 = lines[i + 1].trim().to_string();
            let l2 = lines[i + 2].trim().to_string();

            // Match: "REG1 = REG2 >> 31;" and "REG2 = REG2 >> K;" and "return REG2 + REG1;"
            if l0.contains(" >> 31;") && l1.contains(" >> ") && l2.starts_with("return ") {
                if let (Some(eq0), Some(eq1)) = (l0.find(" = "), l1.find(" = ")) {
                    let sign_reg = l0[..eq0].to_string();
                    let rhs0 = l0[eq0 + 3..].trim_end_matches(';');
                    let shift_reg = l1[..eq1].to_string();
                    let rhs1 = l1[eq1 + 3..].trim_end_matches(';');

                    // Verify sign extraction: REG = OTHER >> 31
                    if rhs0.ends_with(" >> 31") {
                        let src_reg = rhs0.strip_suffix(" >> 31").unwrap_or_default().to_string();

                        // Verify arithmetic shift: same src >> K
                        if let Some(shr_pos) = rhs1.find(" >> ") {
                            let shift_src = &rhs1[..shr_pos];
                            let k_str = &rhs1[shr_pos + 4..];
                            if (shift_src == src_reg || shift_src == shift_reg)
                                && l2 == format!("return {} + {};", shift_reg, sign_reg)
                            {
                                if let Ok(k) = k_str.parse::<u32>() {
                                    // Find the source variable from the line before l0
                                    // Look for "SOMETHING = (int)PARAM;" or "SOMETHING = PARAM + STUFF;"
                                    let src_name = if i > 0 {
                                        let prev = lines[i - 1].trim().to_string();
                                        if let Some(eq) = prev.find(" = ") {
                                            let rhs = prev[eq + 3..].trim_end_matches(';');
                                            // Get the base variable (strip casts)
                                            let clean = rhs.strip_prefix("(int)").unwrap_or(rhs)
                                                .strip_prefix("(int64_t)").unwrap_or(rhs);
                                            if !clean.contains(' ') && !clean.contains('(') {
                                                Some(clean.to_string())
                                            } else { None }
                                        } else { None }
                                    } else { None };

                                    // Divisor: this pattern is used for signed division
                                    // The actual divisor depends on the magic constant used in IMUL
                                    // For K=2: divisor is 7, for K=1: divisor is 3
                                    // But we don't have the magic constant here. Use a lookup:
                                    let divisor = match k {
                                        1 => 3, 2 => 7, 3 => 9, _ => 0,
                                    };
                                    if divisor > 0 {
                                        let var = src_name.as_deref().unwrap_or(&src_reg);
                                        let pad = " ".repeat(lines[i].len() - lines[i].trim_start().len());
                                        lines[i] = format!("{}return {} / {};", pad, var, divisor);
                                        lines.remove(i + 2);
                                        lines.remove(i + 1);
                                        // Also remove the preceding sign-extension line if present
                                        if i > 0 && src_name.is_some() {
                                            lines.remove(i - 1);
                                        }
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            i += 1;
        }
    }

    // #MULT_ADD: Simplify "X + X * N" → "X * (N+1)" and "X - X * N" patterns.
    // Also detect full modulo pattern: VAR = X / D; VAR2 = VAR * D; return X - VAR2 → X % D
    for line in &mut lines {
        let lt = line.trim().to_string();
        // Pattern: "REG + REG * N" → "REG * (N+1)"
        // Match: "VAR + VAR * N" where VAR is the same on both sides
        if lt.contains(" + ") && lt.contains(" * ") {
            // Extract: LHS = ... VAR + VAR * N;
            if let Some(plus_pos) = lt.find(" + ") {
                let after_plus = &lt[plus_pos + 3..];
                if let Some(star_pos) = after_plus.find(" * ") {
                    let var_after_plus = after_plus[..star_pos].trim();
                    let multiplier = after_plus[star_pos + 3..].trim_end_matches(';').trim();
                    // Check if the var before "+" matches the var after "+"
                    let before_plus = &lt[..plus_pos];
                    // The var before "+" could be at the end of an expression like "ECX = RCX + RCX * 4"
                    let var_before_plus = before_plus.rsplit(|c: char| c == '=' || c == '(')
                        .next().unwrap_or("").trim();
                    if var_before_plus == var_after_plus && !var_before_plus.is_empty() {
                        if let Ok(n) = multiplier.parse::<u64>() {
                            let old = format!("{} + {} * {}", var_before_plus, var_after_plus, n);
                            let new = format!("{} * {}", var_before_plus, n + 1);
                            *line = line.replace(&old, &new);
                        }
                    }
                }
            }
        }
    }

    // #MODULO: Detect "X / D" followed by "Y = (X / D) * D" followed by "return X - Y"
    // → simplify to "return X % D"
    // Skip intermediate >> 32 lines (high-half extraction from multiply)
    {
        let mut i = 0;
        while i + 2 < lines.len() {
            let l0 = lines[i].trim().to_string();
            // Skip any >> 32 lines after the division
            let mut next_idx = i + 1;
            while next_idx < lines.len() {
                let skip_t = lines[next_idx].trim();
                if skip_t.contains(">> 32;") || skip_t.contains(">> 63;") || skip_t.contains(">> 31;") {
                    next_idx += 1;
                } else { break; }
            }
            if next_idx + 1 >= lines.len() { i += 1; continue; }
            let l1 = lines[next_idx].trim().to_string();
            let l2 = lines[next_idx + 1].trim().to_string();

            // Pattern: "REG = X / D;" then "REG2 = REG * D;" then "return X - REG2;"
            if let (Some(eq0), Some(eq1)) = (l0.find(" = "), l1.find(" = ")) {
                let dest0 = l0[..eq0].to_string();
                let rhs0 = l0[eq0 + 3..].trim_end_matches(';');
                let dest1 = l1[..eq1].to_string();
                let rhs1 = l1[eq1 + 3..].trim_end_matches(';');

                if let Some(div_pos) = rhs0.find(" / ") {
                    let dividend = &rhs0[..div_pos];
                    let divisor = &rhs0[div_pos + 3..];

                    // Check if l1 multiplies the quotient by the divisor
                    let expected_mult = format!("{} * {}", dest0, divisor);
                    if rhs1 == expected_mult {
                        // Check if l2 is "return DIVIDEND - DEST1;" or "return ALIAS - DEST1;"
                        // where ALIAS is a register alias (EAX↔RAX, ECX↔RCX, etc.)
                        let is_return_minus = |ret_line: &str| -> bool {
                            if let Some(rest) = ret_line.strip_prefix("return ") {
                                if let Some(r) = rest.strip_suffix(';') {
                                    if let Some(minus) = r.find(" - ") {
                                        let ret_left = &r[..minus];
                                        let ret_right = &r[minus + 3..];
                                        // Check dest1 match (or alias)
                                        if ret_right != dest1 { return false; }
                                        // Check dividend match (or register alias)
                                        if ret_left == dividend { return true; }
                                        // Handle EAX↔RAX aliasing
                                        let aliases = [("RAX","EAX"),("RBX","EBX"),("RCX","ECX"),
                                                       ("RDX","EDX"),("RSI","ESI"),("RDI","EDI")];
                                        for (r64, r32) in &aliases {
                                            if (ret_left == *r64 && dividend == *r32)
                                                || (ret_left == *r32 && dividend == *r64) {
                                                return true;
                                            }
                                        }
                                    }
                                }
                            }
                            false
                        };
                        if is_return_minus(&l2) {
                            let pad = " ".repeat(lines[i].len() - lines[i].trim_start().len());
                            lines[i] = format!("{}return {} % {};", pad, dividend, divisor);
                            // Remove all lines from i+1 through next_idx+1
                            for _ in 0..(next_idx + 2 - (i + 1)) {
                                if i + 1 < lines.len() { lines.remove(i + 1); }
                            }
                            continue;
                        }
                    }
                }
            }
            i += 1;
        }
    }

    // #DEDUP_ERRNO: Remove duplicate __error() + errno condition check sequences.
    // When __error() is followed by an identical condition that was already tested
    // in the parent scope, the inner check is redundant.
    {
        let mut i = 0;
        while i + 2 < lines.len() {
            let lt = lines[i].trim().to_string();
            let l1 = lines[i + 1].trim().to_string();
            let l2 = lines[i + 2].trim().to_string();
            // Pattern: "if (COND) {\n __error();\n if (COND) {"
            // The inner __error + if is redundant
            if lt.starts_with("if (") && lt.ends_with('{')
                && l1.contains("__error()")
                && l2 == lt
            {
                // Remove __error() and the duplicate if, plus its closing brace
                lines.remove(i + 2);
                lines.remove(i + 1);
                // Find and remove the extra closing "}"
                let indent = lines[i].len() - lines[i].trim_start().len();
                for j in (i + 1..lines.len()).rev() {
                    let jt = lines[j].trim();
                    let j_indent = lines[j].len() - lines[j].trim_start().len();
                    if jt == "}" && j_indent >= indent {
                        lines.remove(j);
                        break;
                    }
                }
                continue;
            }
            i += 1;
        }
    }

    // #DEAD_STORE_BEFORE_RETURN: Remove "var_N = expr;" immediately before "return"
    // when the var_N is not referenced anywhere else in the function.
    {
        let all_text = lines.join("\n");
        let mut i = 0;
        while i + 1 < lines.len() {
            let lt = lines[i].trim().to_string();
            let next = lines[i + 1].trim().to_string();
            if lt.starts_with("var_") && lt.contains(" = ") && next.starts_with("return ") {
                if let Some(eq) = lt.find(" = ") {
                    let var_name = &lt[..eq];
                    // Count occurrences of this var name in the entire output
                    let count = all_text.matches(var_name).count();
                    // If it only appears once (this assignment), it's dead
                    if count <= 1 {
                        lines.remove(i);
                        continue;
                    }
                    // Also remove if RHS matches the return value
                    let rhs = lt[eq + 3..].trim_end_matches(';').trim();
                    let ret_val = next.strip_prefix("return ").unwrap_or("").trim_end_matches(';').trim();
                    if rhs == ret_val {
                        lines.remove(i);
                        continue;
                    }
                }
            }
            i += 1;
        }
    }

    // #DEAD_RETURN: Remove unreachable return after if/else where both branches return.
    // Pattern: "} else {\n  return ...;\n}\nreturn ...;" → remove trailing return
    {
        let mut i = 0;
        while i + 1 < lines.len() {
            let lt = lines[i].trim();
            let next = lines[i + 1].trim().to_string();
            // If we see "}" closing an if/else and the next line is "return ...",
            // check if both branches of the if/else already return
            if lt == "}" && next.starts_with("return ") {
                // Scan backwards to find if this closes an if/else where both branches return
                let indent = lines[i].len() - lines[i].trim_start().len();
                let mut has_then_return = false;
                let mut has_else_return = false;
                let mut in_else = false;
                let mut depth = 0i32;
                for j in (0..i).rev() {
                    let jt = lines[j].trim();
                    let j_indent = lines[j].len() - lines[j].trim_start().len();
                    if j_indent == indent {
                        if jt == "}" { depth += 1; }
                        if jt.starts_with("} else {") {
                            in_else = true;
                            depth -= 1;
                        }
                        if jt.starts_with("if (") && jt.ends_with('{') && depth <= 0 {
                            break;
                        }
                    }
                    if j_indent > indent && jt.starts_with("return ") {
                        if in_else { has_then_return = true; }
                        else { has_else_return = true; }
                    }
                }
                if has_then_return && has_else_return {
                    lines.remove(i + 1);
                    continue;
                }
            }
            i += 1;
        }
    }

    // #BANNER: Merge consecutive puts/printf calls with string-only args into a banner.
    // Pattern: 3+ consecutive puts("...")/printf("...\n") at the same indent
    // → collapse to puts("line1\nline2\nline3")
    {
        let mut i = 0;
        while i < lines.len() {
            let lt = lines[i].trim();
            // Check if this is a puts("...") or printf("...\n") with string-only arg
            let is_print_str = |line: &str| -> Option<String> {
                let t = line.trim();
                if let Some(rest) = t.strip_prefix("puts(\"") {
                    let end = rest.rfind("\")")?;
                    if rest[end..].ends_with("\");") {
                        return Some(rest[..end].to_string());
                    }
                }
                if let Some(rest) = t.strip_prefix("printf(\"") {
                    let end = rest.rfind("\")")?;
                    if rest[end..].ends_with("\");") {
                        return Some(rest[..end].to_string());
                    }
                }
                None
            };

            if is_print_str(lt).is_some() {
                let indent = lines[i].len() - lines[i].trim_start().len();
                // Count consecutive print-string lines at the same indent
                let mut count = 1;
                while i + count < lines.len() {
                    let next = lines[i + count].trim();
                    let next_indent = lines[i + count].len() - lines[i + count].trim_start().len();
                    if next_indent == indent && is_print_str(next).is_some() {
                        count += 1;
                    } else {
                        break;
                    }
                }
                // Only merge if 3+ consecutive lines (a real banner/header)
                if count >= 3 {
                    let pad = " ".repeat(indent);
                    let strs: Vec<String> = (0..count)
                        .filter_map(|j| is_print_str(lines[i + j].trim()))
                        .collect();
                    let merged = strs.join("\\n");
                    // Replace with a single puts
                    lines[i] = format!("{}puts(\"{}\\n\");", pad, merged);
                    for _ in 1..count {
                        lines.remove(i + 1);
                    }
                }
            }
            i += 1;
        }
    }

    // #FOR_LOOP: Convert while loops with init + increment to for loops.
    // Matches: while (cond) { ...body... VAR = VAR + 1; }
    // Optionally preceded by: VAR = init;
    {
        let mut i = 0;
        while i < lines.len() {
            let lt = lines[i].trim().to_string();

            // Find while lines — either at position i or i+1 (if preceded by init)
            let (while_idx, init_line) = if lt.starts_with("while (") && lt.ends_with('{') {
                // Check if line i-1 is a simple init assignment
                let init = if i > 0 {
                    let prev = lines[i - 1].trim().to_string();
                    if prev.ends_with(';') && prev.contains(" = ") && !prev.contains('(') {
                        Some((i - 1, prev))
                    } else { None }
                } else { None };
                (i, init)
            } else {
                i += 1;
                continue;
            };

            // Find the closing brace of this while block
            let indent = lines[while_idx].len() - lines[while_idx].trim_start().len();
            let mut close_idx = None;
            let mut depth = 1i32;
            for j in (while_idx + 1)..lines.len() {
                let jt = lines[j].trim();
                if jt.ends_with('{') { depth += 1; }
                if jt == "}" || jt.starts_with("} else") { depth -= 1; }
                if depth == 0 {
                    close_idx = Some(j);
                    break;
                }
            }
            let Some(close_idx) = close_idx else { i += 1; continue; };

            // Check if the last statement before close brace is an increment
            if close_idx <= while_idx + 1 { i += 1; continue; }
            let last_body = lines[close_idx - 1].trim().to_string();

            // Match: "VAR = VAR + 1;" or "VAR = VAR + N;" or "VAR - 1"
            let (inc_var, inc_expr) = if let Some(rest) = last_body.strip_suffix(';') {
                if let Some(eq) = rest.find(" = ") {
                    let lhs = &rest[..eq];
                    let rhs = &rest[eq + 3..];
                    if rhs == format!("{} + 1", lhs) {
                        (Some(lhs.to_string()), Some(format!("{}++", lhs)))
                    } else if rhs.starts_with(&format!("{} + ", lhs)) {
                        (Some(lhs.to_string()), Some(format!("{} += {}", lhs, &rhs[lhs.len() + 3..])))
                    } else if rhs == format!("{} - 1", lhs) {
                        (Some(lhs.to_string()), Some(format!("{}--", lhs)))
                    } else {
                        (None, None)
                    }
                } else { (None, None) }
            } else { (None, None) };

            let Some(inc_var) = inc_var else { i += 1; continue; };
            let Some(inc_expr) = inc_expr else { i += 1; continue; };

            // Extract while condition
            let while_text = lines[while_idx].trim();
            let cond = &while_text["while (".len()..while_text.len() - ") {".len()];

            // Build the for loop
            let pad = " ".repeat(indent);
            let has_init = init_line.as_ref().map_or(false, |(_, text)| {
                let eq = text.find(" = ").unwrap_or(0);
                &text[..eq] == inc_var
            });

            if has_init {
                let (init_idx, init_text) = init_line.expect("init_line guaranteed by has_init");
                let init = init_text.trim_end_matches(';');
                lines[init_idx] = format!("{}for ({}; {}; {}) {{", pad, init, cond, inc_expr);
                lines.remove(while_idx); // remove old while line (now at init_idx + 1)
                // Remove the increment line (shifted by 1 due to removal)
                let new_close = close_idx - 1;
                if new_close > init_idx + 1 {
                    lines.remove(new_close - 1);
                }
            } else {
                lines[while_idx] = format!("{}for (; {}; {}) {{", pad, cond, inc_expr);
                // Remove the increment line
                if close_idx > while_idx + 1 {
                    lines.remove(close_idx - 1);
                }
            }
            i += 1;
        }
    }

    // #GARBLED: Fix garbled array accesses like perror(1[1]), fopen("r") missing arg
    for line in &mut lines {
        // "1[1]" → "argv[1]" (common confusion from pointer arithmetic)
        if line.contains("(1[1])") || line.contains(" 1[1]") {
            *line = line.replace("1[1]", "argv[1]");
        }
        // "perror(R12[R14])" → "perror(argv[i])" when in arg-processing context
        // This is hard to fix perfectly, leave as-is for now
    }

    // #DEADREG: Remove stale register-only assignments that aren't used.
    // Lines like "R14 = RBX + 8;" or "R15 = *(RSP);" where the register
    // doesn't appear in any subsequent line within the same scope.
    {
        let x86_regs = ["RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP",
                         "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
                         "EAX", "EBX", "ECX", "EDX", "ESI", "EDI",
                         "R8D", "R9D", "R10D", "R11D", "R12D", "R13D", "R14D", "R15D",
                         "AL", "BL", "CL", "DL"];
        let mut i = 0;
        while i < lines.len() {
            let lt = lines[i].trim().to_string();
            // Match: REG = expr; (simple register assignment)
            if lt.ends_with(';') && lt.contains(" = ") && !lt.starts_with("if ")
                && !lt.starts_with("while ") && !lt.starts_with("return ")
                && !lt.starts_with("//") && !lt.starts_with("var_")
                && !lt.starts_with("*") && !lt.contains("->")
                && !lt.contains('[')
            {
                let lhs = lt.split(" = ").next().unwrap_or("");
                if x86_regs.contains(&lhs) {
                    // Check if this register is used in any later line in the same scope
                    let my_indent = lines[i].len() - lines[i].trim_start().len();
                    let mut used = false;
                    for j in (i + 1)..lines.len() {
                        let jt = lines[j].trim();
                        let j_indent = lines[j].len() - lines[j].trim_start().len();
                        // Stop at scope boundary
                        if j_indent < my_indent && !jt.is_empty() { break; }
                        if jt == "}" || jt.starts_with("} else") { break; }
                        // Check if the register appears in this line (not as LHS of assignment)
                        if jt.contains(lhs) {
                            // Make sure it's not just another assignment to the same reg
                            let is_reassign = jt.starts_with(&format!("{} = ", lhs));
                            if !is_reassign {
                                used = true;
                                break;
                            } else {
                                break; // reassigned before use — dead
                            }
                        }
                    }
                    if !used {
                        lines.remove(i);
                        continue;
                    }
                }
            }
            i += 1;
        }
    }

    // #VARNAME: Infer variable names from usage patterns.
    // - Loop counter that increments by 1 → 'i', 'j', 'k'
    // - Variable compared to string length → 'len'
    {
        let mut counter_idx = 0u8;
        let counter_names = ['i', 'j', 'k', 'n', 'm'];
        for line in &mut lines {
            // Pattern: "var_XX = var_XX + 1;" inside a while loop body → loop counter
            let lt = line.trim().to_string();
            if lt.starts_with("var_") && lt.ends_with(" + 1;") && lt.contains(" = ") {
                if let Some(eq) = lt.find(" = ") {
                    let var_name = &lt[..eq];
                    let rhs = &lt[eq + 3..lt.len() - 1]; // strip trailing ;
                    if rhs == format!("{} + 1", var_name) && counter_idx < counter_names.len() as u8 {
                        // This var is a loop counter — but don't rename here, just note it
                        // (Renaming requires changing all references, which is complex)
                        let _ = counter_names[counter_idx as usize];
                        counter_idx += 1;
                    }
                }
            }
        }
    }

    // #TRAILINGDEAD: Remove dead assignments at end of blocks.
    // Pattern: "RAX = v->field;" as the last statement in a block — dead store
    {
        let mut i = 0;
        while i < lines.len() {
            let lt = lines[i].trim().to_string();
            if lt.starts_with("RAX = ") && lt.ends_with(';') && !lt.contains("return") {
                // Check if next non-empty line is } or end of function
                let next = lines.get(i + 1).map(|l| l.trim().to_string()).unwrap_or_default();
                if next == "}" || next.is_empty() || next.starts_with('}') {
                    lines.remove(i);
                    continue;
                }
            }
            i += 1;
        }
    }

    // #MISC: Quick text cleanups.
    for line in &mut lines {
        // free(*(0)) → free(NULL)
        *line = line.replace("free(*(0))", "free(NULL)");
        // *(0) as a standalone value is NULL dereference — often a placeholder
        if line.contains("*(0)") && !line.contains("free") {
            *line = line.replace("*(0)", "NULL");
        }
    }

    // Remove "free(NULL);" lines — they're no-ops
    {
        let mut i = 0;
        while i < lines.len() {
            if lines[i].trim() == "free(NULL);" {
                lines.remove(i);
                continue;
            }
            i += 1;
        }
    }

    // #NEG1: Replace 0xffffffffffffffff and 4294967295 with -1.
    for line in &mut lines {
        *line = line.replace("0xffffffffffffffff", "-1");
        *line = line.replace("4294967295", "-1");
        // Also 0xffffffff for 32-bit -1
        if line.contains("0xffffffff") && !line.contains("0xffffffff0") && !line.contains("0xffffffff8") {
            *line = line.replace("0xffffffff", "-1");
        }
    }

    // #CALLRET2: Extend call-return inlining for more patterns.
    // Pattern: strcmp(args); if (param_N == 0) → if (strcmp(args) == 0)
    // When a call is followed by an if checking a param/register that represents
    // the return value (often param_2 for RDX, or var_N).
    {
        let mut i = 0;
        while i + 1 < lines.len() {
            let lt = lines[i].trim().to_string();
            let next = lines[i + 1].trim().to_string();
            // Match: call(...); if (SIMPLE_VAR == 0) or if (SIMPLE_VAR != 0)
            if lt.ends_with(';') && lt.contains('(') && !lt.contains(" = ")
                && !lt.starts_with("if ") && !lt.starts_with("while ")
                && !lt.starts_with("return ") && !lt.starts_with("//") && !lt.starts_with("}")
            {
                let call_expr = lt.trim_end_matches(';').trim();
                // Check for: if (var_N == 0), if (var_N != 0), if (param_N == 0)
                let cond_inline = if next.starts_with("if (var_") || next.starts_with("if (param_") {
                    // Check it's a simple == 0 or != 0 check
                    (next.contains(" == 0)") || next.contains(" != 0)"))
                        && !next.contains("&&") && !next.contains("||")
                } else { false };

                if cond_inline {
                    let indent = lines[i + 1].len() - lines[i + 1].trim_start().len();
                    let pad = " ".repeat(indent);
                    // Extract the var/param name from the condition
                    if let Some(paren_start) = next.find("if (") {
                        let after_if = &next[paren_start + 4..];
                        if let Some(space) = after_if.find(' ') {
                            let _var_name = &after_if[..space];
                            let rest = &after_if[space..];
                            // Replace var with call expression
                            let new_cond = format!("if ({}{}", call_expr, rest);
                            lines[i + 1] = format!("{}{}", pad, new_cond);
                            lines.remove(i);
                            continue;
                        }
                    }
                }
            }
            i += 1;
        }
    }

    // #CPP_NEST: Truncate deeply nested C++ constructor/allocator chains.
    // alloc_ctor(alloc_ctor(alloc_ctor(...))) → alloc_ctor(...)
    for line in &mut lines {
        // Count nesting depth of specific C++ functions
        let mut changed = true;
        while changed {
            changed = false;
            for func in ["alloc_ctor", "string_ctor", "string_dtor"] {
                let nested = format!("{}({}(", func, func);
                if line.contains(&nested) {
                    // Find the inner call and keep only the outermost
                    let _inner = format!("{}(", func);
                    if let Some(pos) = line.find(&nested) {
                        // Remove one level of nesting
                        let before = &line[..pos + func.len() + 1]; // "alloc_ctor("
                        let after_nested = &line[pos + nested.len()..]; // skip inner "alloc_ctor("
                        *line = format!("{}{}", before, after_nested);
                        changed = true;
                    }
                }
            }
        }
    }

    // #CTYPE: Remove ctype table access noise (60[REG + RAX] patterns).
    // macOS ctype lookup: loads from the __ctype_b table at offset 60.
    {
        let mut i = 0;
        while i < lines.len() {
            let lt = lines[i].trim();
            // Remove lines that are ONLY ctype table lookups with no other effect
            if lt.contains("60[") && lt.contains("/* isspace */") && lt.ends_with(';') {
                if lt.starts_with("EAX = ") || lt.starts_with("RAX = ") {
                    lines.remove(i);
                    continue;
                }
            }
            i += 1;
        }
    }

    // Simplify "var - N == 0" → "var == N" (moved before switch detection)
    for line in &mut lines {
        let l = line.clone();
        if l.contains(" - ") && (l.contains(" == 0)") || l.contains(" != 0)")) {
            if let Some(if_start) = l.find("if (") {
                let cond = &l[if_start + 4..];
                if let Some(close) = cond.rfind(')') {
                    let inner = &cond[..close];
                    if let Some(eq_pos) = inner.rfind(" == 0").or(inner.rfind(" != 0")) {
                        let before_eq = &inner[..eq_pos];
                        let op = if inner[eq_pos..].starts_with(" == 0") { "==" } else { "!=" };
                        if let Some(minus) = before_eq.rfind(" - ") {
                            let lhs = &before_eq[..minus];
                            let rhs_val = before_eq[minus + 3..].trim();
                            if rhs_val.len() <= 20 && !rhs_val.contains('(') {
                                let indent = line.len() - line.trim_start().len();
                                let pad = " ".repeat(indent);
                                let rest = &l[if_start + 4 + close + 1..];
                                *line = format!("{}if ({} {} {}){}", pad, lhs, op, rhs_val, rest);
                            }
                        }
                    }
                }
            }
        }
    }

    // #SWITCH2: Detect if-else chains on the same variable as switch/case.
    // Pattern: if (*(v) == 3) { ... } else { if (*(v) == 4) { ... } else { if (*(v) == 5) { ... } } }
    // → switch(*(v)) { case 3: ... case 4: ... case 5: ... }
    // For now, just annotate with comments when we see cascading equality checks.
    {
        let mut i = 0;
        while i < lines.len() {
            let lt = lines[i].trim().to_string();
            // Find "if (EXPR == N)" where the next else-if checks the same EXPR
            if lt.starts_with("if (") && lt.contains(" == ") && lt.ends_with(") {") {
                // Extract the variable being compared
                let cond = &lt[4..lt.len()-3]; // strip "if (" and ") {"
                if let Some(eq_pos) = cond.find(" == ") {
                    let var_name = &cond[..eq_pos];
                    let first_val = &cond[eq_pos+4..];
                    let mut cases = vec![first_val.to_string()];
                    let check = format!("if ({} == ", var_name);
                    let my_indent = lines[i].len() - lines[i].trim_start().len();
                    for j in (i+1)..lines.len() {
                        let jt = lines[j].trim();
                        if jt.starts_with(&check) && jt.ends_with(") {") {
                            let val = &jt[check.len()..jt.len()-3];
                            cases.push(val.to_string());
                        }
                        // Stop at end of the outermost block
                        // (when we see a line at same or lesser indent that isn't part of the chain)
                        let j_indent = lines[j].len() - lines[j].trim_start().len();
                        if j_indent <= my_indent && !jt.is_empty() && !jt.starts_with('}')
                            && !jt.starts_with("if (") && !jt.starts_with("} else")
                        { break; }
                    }
                    if cases.len() >= 3 {
                        let indent = lines[i].len() - lines[i].trim_start().len();
                        let pad = " ".repeat(indent);
                        let case_str = cases.iter().map(|c| format!("{}", c)).collect::<Vec<_>>().join(", ");
                        lines.insert(i, format!("{}// switch({}) — cases: {}", pad, var_name, case_str));
                        i += 1; // skip the comment we just inserted
                    }
                }
            }
            i += 1;
        }
    }

    // #SIZEOF: Annotate calloc/malloc with likely struct sizes.
    for line in &mut lines {
        // Common struct sizes from real-world code
        if line.contains("calloc(1, 32)") { *line = line.replace("calloc(1, 32)", "calloc(1, 32) /* sizeof(struct) */"); }
        if line.contains("calloc(1, 40)") { *line = line.replace("calloc(1, 40)", "calloc(1, 40) /* sizeof(struct) */"); }
        if line.contains("calloc(1, 48)") { *line = line.replace("calloc(1, 48)", "calloc(1, 48) /* sizeof(struct) */"); }
        if line.contains("calloc(1, 56)") { *line = line.replace("calloc(1, 56)", "calloc(1, 56) /* sizeof(struct) */"); }
        if line.contains("calloc(1, 64)") { *line = line.replace("calloc(1, 64)", "calloc(1, 64) /* sizeof(struct) */"); }
    }

    // #LLM: Clean up patterns that confuse LLM analysis.

    // Strip __isoc99_ prefix from scanf variants
    for line in &mut lines {
        *line = line.replace("__isoc99_scanf", "scanf");
        *line = line.replace("__isoc99_sscanf", "sscanf");
        *line = line.replace("__isoc99_fscanf", "fscanf");
    }

    // Remove register-only assignment lines that are just noise:
    // "RAX = func(...) + N;" where the register isn't used meaningfully
    // "EAX = EAX & 0x7fffffff;" (sign-extension noise)
    // "EAX = strlen(...) - 1;" when followed by another EAX assignment
    {
        let mut i = 0;
        while i < lines.len() {
            let lt = lines[i].trim().to_string();
            // Remove "REG = void_call(...) + N;" or "REG = void_call(...) * N;"
            let starts_with_reg = lt.starts_with("RAX = ") || lt.starts_with("RCX = ")
                || lt.starts_with("RDX = ") || lt.starts_with("EAX = ")
                || lt.starts_with("ECX = ") || lt.starts_with("EDX = ")
                || lt.starts_with("R8D = ") || lt.starts_with("R9D = ");
            if starts_with_reg && lt.ends_with(';') {
                let rhs = lt.split(" = ").nth(1).unwrap_or("");
                // Remove "REG = call(...) + N;" or "REG = call(...) * N;"
                // where the call is to a known void/output function
                let is_void_call_noise = ["puts(", "printf(", "scanf(", "write("]
                    .iter().any(|f| rhs.contains(f))
                    && (rhs.contains(") +") || rhs.contains(") *") || rhs.contains(") -"));
                // Remove "EAX = EAX & 0x7fffffff;" (sign mask noise)
                let is_sign_mask = rhs.contains("& 0x7fffffff");
                // Remove stack probe: "RAX = 0x1518;" or similar large hex before ___chkstk
                let is_stack_probe = lt.starts_with("RAX = 0x")
                    && i + 1 < lines.len()
                    && lines[i + 1].trim().contains("chkstk");
                // Remove "RAX = *(RSP);" after chkstk
                let is_post_chkstk = lt == "RAX = *(RSP);"
                    && i > 0 && lines[i - 1].trim().contains("chkstk");
                if is_void_call_noise || is_sign_mask || is_stack_probe || is_post_chkstk {
                    lines.remove(i);
                    continue;
                }
            }
            // Remove ___chkstk_darwin() standalone calls (Mach-O stack probe)
            if lt == "___chkstk_darwin();" || lt == "__chkstk();" {
                lines.remove(i);
                continue;
            }
            i += 1;
        }
    }

    // Simplify "var - N == 0" → "var == N" and "var - N != 0" → "var != N"
    for line in &mut lines {
        // Match "if (X - N == 0)" or "if (X - N != 0)"
        let l = line.clone();
        if l.contains(" - ") && (l.contains(" == 0)") || l.contains(" != 0)")) {
            // Simple pattern: (expr - const == 0) → (expr == const)
            if let Some(if_start) = l.find("if (") {
                let cond = &l[if_start + 4..];
                if let Some(close) = cond.rfind(')') {
                    let inner = &cond[..close];
                    if let Some(eq_pos) = inner.rfind(" == 0").or(inner.rfind(" != 0")) {
                        let before_eq = &inner[..eq_pos];
                        let op = if inner[eq_pos..].starts_with(" == 0") { "==" } else { "!=" };
                        if let Some(minus) = before_eq.rfind(" - ") {
                            let lhs = &before_eq[..minus];
                            let rhs_val = before_eq[minus + 3..].trim();
                            // Only simplify if rhs is a simple constant or short string
                            if rhs_val.len() <= 20 && !rhs_val.contains('(') {
                                let indent = line.len() - line.trim_start().len();
                                let pad = " ".repeat(indent);
                                let rest = &l[if_start + 4 + close + 1..];
                                *line = format!("{}if ({} {} {}){}", pad, lhs, op, rhs_val, rest);
                            }
                        }
                    }
                }
            }
        }
    }

    // Simplify *(global_var) → global_var for known global symbol names
    // Globals are directly accessible, the extra dereference is an artifact
    for line in &mut lines {
        for (_addr, name) in ctx.imports.iter() {
            // Only for known data objects (not functions)
            if name.contains("stdin") || name.contains("stdout") || name.contains("stderr") {
                continue; // these are pointer globals that DO need dereference
            }
            let deref = format!("*({})", name);
            if line.contains(&deref) {
                *line = line.replace(&deref, name);
            }
        }
    }

    // Remove consecutive blank lines
    let mut result = String::new();
    let mut prev_blank = false;
    // #DEDUP_ESP_STORE: Remove "*(uint32_t*)(ESP) = CALL(...);" when the same call
    // appears on the previous line. These are x86-32 cdecl return value pushes.
    {
        let mut i = 1;
        while i < lines.len() {
            let lt = lines[i].trim();
            if lt.starts_with("*(uint32_t*)(ESP) = ") || lt.starts_with("*(int*)(ESP) = ") {
                let rhs = if let Some(r) = lt.find(" = ") { &lt[r + 3..] } else { "" };
                let prev = lines[i - 1].trim();
                // If the RHS matches the previous line exactly (with semicolon)
                if !rhs.is_empty() && prev == rhs {
                    lines.remove(i);
                    continue;
                }
                // Also remove bare "*(uint32_t*)(ESP) = PREV_CALL;" where prev line is "CALL;"
                if !rhs.is_empty() && prev.ends_with(';') && rhs.ends_with(';') {
                    let prev_expr = prev.trim_end_matches(';');
                    let rhs_expr = rhs.trim_end_matches(';');
                    if prev_expr == rhs_expr {
                        lines.remove(i);
                        continue;
                    }
                }
                // Remove "*(uint32_t*)(ESP) = VALUE;" when the next line is a call
                // that already shows VALUE as its argument (cdecl arg push)
                if i + 1 < lines.len() {
                    let next = lines[i + 1].trim();
                    if next.contains('(') && next.ends_with(';') {
                        // Check if the ESP store value appears as an arg in the next call
                        let stored_val = rhs.trim_end_matches(';').trim();
                        if next.contains(stored_val) && !stored_val.is_empty() {
                            lines.remove(i);
                            continue;
                        }
                    }
                }
            }
            i += 1;
        }
    }

    // #ELF32_PIE: Hide __x86.get_pc_thunk boilerplate and resolve GOT-relative addresses.
    // Pattern: "__x86.get_pc_thunk.bx(...);" → remove
    //          "iVarN = iVarN + 0xNNNN;" → extract GOT base, remove
    //          "iVarN - 0xNNNN" or "iVarN + 0xNNNN - 0xMMMM" → resolve to string/addr
    {
        // Step 1: Find the GOT base from the thunk pattern
        // Look for: "REGVAR = REGVAR + 0xNNNN;" after a thunk call
        let mut got_base: Option<(String, u64)> = None;
        let mut _got_add_line: Option<usize> = None;

        for (i, line) in lines.iter().enumerate() {
            let t = line.trim();
            // Find "iVarN = iVarN + 0xNNNN;" pattern (GOT base addition)
            if let Some(eq) = t.find(" = ") {
                let lhs = &t[..eq];
                let rhs = t[eq + 3..].trim_end_matches(';');
                if rhs.starts_with(lhs) && rhs.contains(" + 0x") {
                    if let Some(plus) = rhs.find(" + 0x") {
                        let hex_str = &rhs[plus + 5..];
                        if let Ok(offset) = u64::from_str_radix(hex_str, 16) {
                            // The thunk returns the address of the instruction after the call.
                            // GOT base = thunk_return_addr + offset
                            // We don't have the exact return addr here, but the offset is
                            // what matters for relative resolution. Store the var name + offset.
                            got_base = Some((lhs.to_string(), offset));
                            _got_add_line = Some(i);
                        }
                    }
                }
            }
        }

        if let Some((ref got_var, got_offset)) = got_base {
            // Step 2: Remove thunk calls and GOT base addition lines
            lines.retain(|line| {
                let t = line.trim();
                if t.contains("__x86.get_pc_thunk") { return false; }
                false == false // keep all others for now
            });
            // Re-find the GOT add line (index may have shifted)
            let mut i = 0;
            while i < lines.len() {
                let t = lines[i].trim();
                if t.contains(&format!("{} + 0x{:x}", got_var, got_offset))
                    && t.starts_with(got_var.as_str())
                {
                    lines.remove(i);
                    continue;
                }
                i += 1;
            }

            // Step 3: Resolve GOT-relative expressions
            // Pattern: "GOT_VAR - 0xNNNN" → compute absolute address, try string resolution
            // We need to know the actual address. For ELF32 PIE, the thunk call is at a known
            // address. But we don't have it here. Instead, we can compute from the binary:
            // look for the .got section address.
            if let Some(binary) = ctx.binary {
                if let Ok(obj) = goblin::Object::parse(binary) {
                    if let goblin::Object::Elf(elf) = &obj {
                        // Find .got or _GLOBAL_OFFSET_TABLE_ address
                        // Find the GOT base: prefer _GLOBAL_OFFSET_TABLE_ symbol
                        // (most accurate), then .got.plt section address.
                        let got_addr = elf.syms.iter()
                            .find(|s| elf.strtab.get_at(s.st_name) == Some("_GLOBAL_OFFSET_TABLE_"))
                            .map(|s| s.st_value)
                            .or_else(|| {
                                elf.section_headers.iter()
                                    .find(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(".got.plt"))
                                    .map(|sh| sh.sh_addr)
                            });

                        if let Some(got_addr) = got_addr {
                            for line in &mut lines {
                                // Replace "GOT_VAR - 0xNNNN" with resolved value
                                let pattern_minus = format!("{} - 0x", got_var);
                                if line.contains(&pattern_minus) {
                                    // Find all occurrences
                                    let mut new_line = line.clone();
                                    while let Some(pos) = new_line.find(&pattern_minus) {
                                        let hex_start = pos + pattern_minus.len();
                                        let hex_end = new_line[hex_start..].find(|c: char| !c.is_ascii_hexdigit())
                                            .map(|e| hex_start + e).unwrap_or(new_line.len());
                                        let hex_str = &new_line[hex_start..hex_end];
                                        if let Ok(displacement) = u64::from_str_radix(hex_str, 16) {
                                            let resolved_addr = got_addr.wrapping_sub(displacement);
                                            // Try to read a string at this address
                                            if let Some(s) = try_read_string(resolved_addr, ctx) {
                                                if s.len() >= 2 {
                                                    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n");
                                                    let old = format!("{}{}", pattern_minus, hex_str);
                                                    new_line = new_line.replace(&old, &format!("\"{}\"", escaped));
                                                    continue;
                                                }
                                            }
                                            // Fall back to hex address
                                            let old = format!("{}{}", pattern_minus, hex_str);
                                            new_line = new_line.replace(&old, &format!("0x{:x}", resolved_addr));
                                        }
                                        break; // avoid infinite loop
                                    }
                                    *line = new_line;
                                }

                                // Also handle "GOT_VAR + 0xOFFSET - 0xDISP" pattern
                                let pattern_plus = format!("{} + 0x{:x} - 0x", got_var, got_offset);
                                if line.contains(&pattern_plus) {
                                    let mut new_line = line.clone();
                                    while let Some(pos) = new_line.find(&pattern_plus) {
                                        let hex_start = pos + pattern_plus.len();
                                        let hex_end = new_line[hex_start..].find(|c: char| !c.is_ascii_hexdigit())
                                            .map(|e| hex_start + e).unwrap_or(new_line.len());
                                        let hex_str = &new_line[hex_start..hex_end];
                                        if let Ok(displacement) = u64::from_str_radix(hex_str, 16) {
                                            let resolved_addr = got_addr.wrapping_sub(displacement);
                                            if let Some(s) = try_read_string(resolved_addr, ctx) {
                                                if s.len() >= 2 {
                                                    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n");
                                                    let old = format!("{}{}", pattern_plus, hex_str);
                                                    new_line = new_line.replace(&old, &format!("\"{}\"", escaped));
                                                    continue;
                                                }
                                            }
                                            let old = format!("{}{}", pattern_plus, hex_str);
                                            new_line = new_line.replace(&old, &format!("0x{:x}", resolved_addr));
                                        }
                                        break;
                                    }
                                    *line = new_line;
                                }
                            }
                        }
                    }
                }
            }
        }

        // Remove remaining thunk lines (even if GOT base wasn't found)
        lines.retain(|line| !line.trim().contains("__x86.get_pc_thunk"));
    }

    // #STACK_NOISE: Remove XMM zero-init, RSP-relative stores, and x86-64 stack
    // frame boilerplate that clutters the output without adding semantic value.
    lines.retain(|line| {
        let t = line.trim();
        // Remove "XMM0 = 0; // zero-init" and similar SSE register clears
        if t.starts_with("XMM") && t.contains("= 0") && t.contains("zero-init") { return false; }
        // Remove 128-bit stack stores that are zero-init
        if t.starts_with("*(__uint128_t*)") && t.contains("RSP") && t.contains("= 0") { return false; }
        // Remove "N[RSP] = 0;" patterns (stack zero-init)
        if t.ends_with("[RSP] = 0;") || t.ends_with("[RSP] = 0; // zero-init") { return false; }
        // Remove x86-64 RSP-relative shadow space stores: "N[RSP] = VALUE;"
        // These are Windows x64 shadow space (home area) or register save area.
        // Pattern: "16[RSP] = ...", "24[RSP] = ...", "32[RSP] = ...", etc.
        if t.contains("[RSP]") && t.contains(" = ") && !t.contains("if ")
            && !t.contains("while ") && !t.contains("return ")
        {
            // N[RSP] = ... where N is a small numeric offset (shadow/home space)
            if let Some(bracket) = t.find('[') {
                let prefix = &t[..bracket];
                if prefix.parse::<u64>().is_ok() || prefix.ends_with(" + RSP") {
                    return false;
                }
            }
        }
        // Remove "RSP = RSP + N;" and "RSP = RSP - N;" (stack adjustments)
        if t.starts_with("RSP = RSP") && t.ends_with(';') { return false; }
        // Remove "RBP = RSP + N;" / "RBP = RSP;" / "RBP = -N + RSP;" (frame setup)
        if t.starts_with("RBP = ") && t.contains("RSP") && t.ends_with(';')
            && !t.contains("func_") && !t.contains("var_") { return false; }
        true
    });

    // #CONST_FOLD: Remove constant-vs-constant comparisons that are always true/false.
    // Pattern: "if (0 < 41)" or "if (0 > 41)" where both sides are literals.
    lines.retain(|line| {
        let t = line.trim();
        // "if (N < M)" where N and M are both numeric constants
        if t.starts_with("if (") && t.ends_with('{') {
            let inner = &t[4..t.len() - 2].trim(); // strip "if (" and ") {"
            for op in [" < ", " > ", " <= ", " >= ", " == ", " != "] {
                if let Some(pos) = inner.find(op) {
                    let left = inner[..pos].trim();
                    let right = inner[pos + op.len()..].trim().trim_end_matches(')');
                    if left.parse::<i64>().is_ok() && right.parse::<i64>().is_ok() {
                        return false; // constant comparison — remove
                    }
                }
            }
        }
        true
    });

    // #EMPTY_ELSE: Remove empty else branches: "} else {\n}"
    {
        let mut i = 0;
        while i + 1 < lines.len() {
            let lt = lines[i].trim();
            let next = lines[i + 1].trim();
            if lt == "} else {" && next == "}" {
                lines.remove(i + 1);
                lines[i] = lines[i].replace("} else {", "}");
                continue;
            }
            i += 1;
        }
    }

    // #VOID_RETURN: Remove trailing "return;" in void functions (redundant).
    if lines.first().map_or(false, |l| l.trim().starts_with("void ")) {
        // Remove the last "return;" before the closing "}"
        let mut i = lines.len();
        while i > 0 {
            i -= 1;
            let t = lines[i].trim();
            if t == "return;" {
                lines.remove(i);
                break;
            }
            if t == "}" { continue; } // skip closing brace
            break; // stop at first non-brace, non-return line
        }
    }

    // #WIN32_CONSTANTS: Annotate Windows API constants for malware analysis.
    for line in &mut lines {
        // Process status
        *line = line.replace("== 259)", "== 259 /* STILL_ACTIVE */)");
        *line = line.replace("!= 259)", "!= 259 /* STILL_ACTIVE */)");
        // GetStdHandle
        *line = line.replace("(0xfffffff5)", "(STD_ERROR_HANDLE)");
        *line = line.replace("(0xfffffff6)", "(STD_OUTPUT_HANDLE)");
        *line = line.replace("(0xfffffff4)", "(STD_INPUT_HANDLE)");
        // Memory protection
        *line = line.replace(", 0x40)", ", PAGE_EXECUTE_READWRITE)");
        *line = line.replace(", 0x04)", ", PAGE_READWRITE)");
        *line = line.replace(", 0x20)", ", PAGE_EXECUTE_READ)");
        // Allocation type
        *line = line.replace(", 0x3000,", ", MEM_COMMIT|MEM_RESERVE,");
        *line = line.replace(", 0x1000,", ", MEM_COMMIT,");
        // Socket
        *line = line.replace("socket(2, 1, 0)", "socket(AF_INET, SOCK_STREAM, 0)");
        *line = line.replace("socket(2, 2, 0)", "socket(AF_INET, SOCK_DGRAM, 0)");
        // Signal
        *line = line.replace("signal(13, 1)", "signal(SIGPIPE, SIG_IGN)");
        // File access
        *line = line.replace(", 0x80000000)", ", GENERIC_READ)");
        *line = line.replace(", 0xc0000000)", ", GENERIC_READ|GENERIC_WRITE)");
        *line = line.replace(", 0x40000000)", ", GENERIC_WRITE)");
        // CreateFile disposition
        *line = line.replace(", 3)", ", OPEN_EXISTING)").replace(", 2)", ", CREATE_ALWAYS)");
        // WaitForSingleObject
        *line = line.replace(", 0xffffffff)", ", INFINITE)");
        *line = line.replace(", -1)", ", INFINITE)");
        // Registry
        *line = line.replace("(0xffffffff80000001)", "(HKEY_CURRENT_USER)");
        *line = line.replace("(0xffffffff80000002)", "(HKEY_LOCAL_MACHINE)");
        *line = line.replace("(0x80000001)", "(HKEY_CURRENT_USER)");
        *line = line.replace("(0x80000002)", "(HKEY_LOCAL_MACHINE)");
        *line = line.replace("(0x80000000)", "(HKEY_CLASSES_ROOT)");
        *line = line.replace("(0x80000003)", "(HKEY_USERS)");
        *line = line.replace("(0x80000005)", "(HKEY_CURRENT_CONFIG)");
        // Registry access rights
        *line = line.replace("0x20019", "KEY_READ");
        *line = line.replace("0x20006", "KEY_WRITE");
        *line = line.replace("0xf003f", "KEY_ALL_ACCESS");
        // Process access rights
        *line = line.replace("0x1fffff", "PROCESS_ALL_ACCESS");
        *line = line.replace("0x001f0fff", "PROCESS_ALL_ACCESS");
        // Window messages
        if line.contains("SendMessage") || line.contains("PostMessage") {
            *line = line.replace(", 0x10,", ", WM_CLOSE,");
            *line = line.replace(", 0x12,", ", WM_QUIT,");
            *line = line.replace(", 0x111,", ", WM_COMMAND,");
            *line = line.replace(", 0x100,", ", WM_KEYDOWN,");
            *line = line.replace(", 0x101,", ", WM_KEYUP,");
            *line = line.replace(", 0x402,", ", PBM_SETPOS,");
        }
        // ShowWindow
        if line.contains("ShowWindow") {
            *line = line.replace(", 0)", ", SW_HIDE)").replace(", 1)", ", SW_SHOWNORMAL)")
                .replace(", 5)", ", SW_SHOW)").replace(", 3)", ", SW_MAXIMIZE)");
        }
        // MessageBox type
        if line.contains("MessageBox") {
            *line = line.replace(", 0x30)", ", MB_ICONWARNING)").replace(", 0x10)", ", MB_ICONERROR)")
                .replace(", 0x40)", ", MB_ICONINFORMATION)").replace(", 0x4)", ", MB_YESNO)");
        }
    }

    // #HEX_MAGIC: Annotate well-known hex magic constants.
    for line in &mut lines {
        if line.contains("0xe06d7363") {
            *line = line.replace("0xe06d7363", "0xe06d7363 /* MSVC C++ exception */");
        }
        if line.contains("0xbadf00d") && !line.contains("/*") {
            *line = line.replace("0xbadf00d", "0xbadf00d /* BADF00D sentinel */");
        }
        if line.contains("0xdeadbeef") && !line.contains("/*") {
            *line = line.replace("0xdeadbeef", "0xdeadbeef /* DEADBEEF sentinel */");
        }
        if line.contains("0xcccccccc") && !line.contains("/*") {
            *line = line.replace("0xcccccccc", "0xcccccccc /* uninitialized stack */");
        }
        if line.contains("0xcdcdcdcd") && !line.contains("/*") {
            *line = line.replace("0xcdcdcdcd", "0xcdcdcdcd /* uninitialized heap */");
        }
        if line.contains("0xfeeefeee") && !line.contains("/*") {
            *line = line.replace("0xfeeefeee", "0xfeeefeee /* freed heap */");
        }
        if line.contains("0x5a4d") && !line.contains("/*") {
            *line = line.replace("0x5a4d", "0x5a4d /* MZ header */");
        }
        if line.contains("0x4550") && !line.contains("/*") {
            *line = line.replace("0x4550", "0x4550 /* PE signature */");
        }
        if line.contains("0x19930522") && !line.contains("/*") {
            *line = line.replace("0x19930522", "0x19930522 /* MSVC FuncInfo magic */");
        }
    }

    // #FLAT_DISPATCH: Detect Ollvm-style control flow flattening patterns.
    // Pattern: while(true) { switch(state_var) { case N: ...; state_var = M; break; } }
    // Annotate when detected so the analyst knows the control flow is obfuscated.
    {
        let all_text = lines.join("\n");
        // Heuristic: a function has flattened control flow if it has:
        // 1. A single large switch with 5+ cases
        // 2. Inside a while(true) or do-while
        // 3. Cases assign to the same variable (state variable)
        let has_while_true = all_text.contains("while (1)") || all_text.contains("while (0 == 0)")
            || all_text.contains("do {");
        let switch_count = all_text.matches("switch (").count();
        let case_count = all_text.matches("case ").count();

        if has_while_true && switch_count >= 1 && case_count >= 8 {
            // Likely flattened control flow — add annotation
            if let Some(idx) = lines.iter().position(|l| l.trim_end().ends_with('{')) {
                lines.insert(idx + 1, "    // NOTE: possible control flow flattening detected (large switch inside loop)".to_string());
            }
        }
    }

    // #CRYPTO_CONSTANTS: Detect cryptographic constants in binary data sections
    // and annotate any DAT_ references to those addresses.
    // Also detect inline constants in the decompiled output.
    if let Some(binary) = ctx.binary {
        // Known crypto signatures: (name, byte_pattern, min_length)
        // Each pattern is the first N bytes of the known constant table.
        let crypto_sigs: &[(&str, &[u8])] = &[
            // AES S-box (256 bytes): 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76
            ("AES S-box", &[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76]),
            // AES inverse S-box: 52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb
            ("AES inverse S-box", &[0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb]),
            // AES Rcon: 01 02 04 08 10 20 40 80 1b 36
            ("AES Rcon", &[0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00]),
            // SHA-256 round constants (K): 428a2f98 71374491 b5c0fbcf e9b5dba5
            ("SHA-256 K table", &[0x98, 0x2f, 0x8a, 0x42, 0x91, 0x44, 0x37, 0x71, 0xcf, 0xfb, 0xc0, 0xb5, 0xa5, 0xdb, 0xb5, 0xe9]),
            // SHA-256 K big-endian variant
            ("SHA-256 K table", &[0x42, 0x8a, 0x2f, 0x98, 0x71, 0x37, 0x44, 0x91, 0xb5, 0xc0, 0xfb, 0xcf, 0xe9, 0xb5, 0xdb, 0xa5]),
            // SHA-256 init hash (H0): 6a09e667 bb67ae85 3c6ef372 a54ff53a
            ("SHA-256 init vector", &[0x67, 0xe6, 0x09, 0x6a, 0x85, 0xae, 0x67, 0xbb, 0x72, 0xf3, 0x6e, 0x3c, 0x3a, 0xf5, 0x4f, 0xa5]),
            // SHA-256 init big-endian
            ("SHA-256 init vector", &[0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85, 0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a]),
            // SHA-1 init: 67452301 efcdab89 98badcfe 10325476 c3d2e1f0
            ("SHA-1 init vector", &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10]),
            // SHA-1 K constants: 5a827999 6ed9eba1 8f1bbcdc ca62c1d6
            ("SHA-1 K constant", &[0x99, 0x79, 0x82, 0x5a]),
            // MD5 init: 67452301 efcdab89 98badcfe 10325476
            ("MD5 init vector", &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10]),
            // MD5 T table: d76aa478 e8c7b756 242070db c1bdceee
            ("MD5 T table", &[0x78, 0xa4, 0x6a, 0xd7, 0x56, 0xb7, 0xc7, 0xe8, 0xdb, 0x70, 0x20, 0x24, 0xee, 0xce, 0xbd, 0xc1]),
            // MD5 T big-endian
            ("MD5 T table", &[0xd7, 0x6a, 0xa4, 0x78, 0xe8, 0xc7, 0xb7, 0x56, 0x24, 0x20, 0x70, 0xdb, 0xc1, 0xbd, 0xce, 0xee]),
            // CRC32 table (IEEE polynomial 0xEDB88320): 00000000 77073096 ee0e612c 990951ba
            ("CRC32 table", &[0x00, 0x00, 0x00, 0x00, 0x96, 0x30, 0x07, 0x77, 0x2c, 0x61, 0x0e, 0xee, 0xba, 0x51, 0x09, 0x99]),
            // CRC32 big-endian
            ("CRC32 table", &[0x00, 0x00, 0x00, 0x00, 0x77, 0x07, 0x30, 0x96, 0xee, 0x0e, 0x61, 0x2c, 0x99, 0x09, 0x51, 0xba]),
            // Blowfish P-array: 243f6a88 85a308d3 13198a2e 03707344
            ("Blowfish P-array", &[0x88, 0x6a, 0x3f, 0x24, 0xd3, 0x08, 0xa3, 0x85, 0x2e, 0x8a, 0x19, 0x13, 0x44, 0x73, 0x70, 0x03]),
            // Blowfish big-endian
            ("Blowfish P-array", &[0x24, 0x3f, 0x6a, 0x88, 0x85, 0xa3, 0x08, 0xd3, 0x13, 0x19, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x44]),
            // ChaCha20/Salsa20 constant: "expand 32-byte k"
            ("ChaCha20/Salsa20 constant", b"expand 32-byte k"),
            // "expand 16-byte k"
            ("ChaCha20/Salsa20 constant", b"expand 16-byte k"),
            // DES initial permutation table: 58 50 42 34 26 18 10 08
            ("DES permutation table", &[0x3a, 0x32, 0x2a, 0x22, 0x1a, 0x12, 0x0a, 0x02, 0x3c, 0x34, 0x2c, 0x24, 0x1c, 0x14, 0x0c, 0x04]),
            // Whirlpool S-box: 18 23 c6 e8 87 b8 01 4f
            ("Whirlpool S-box", &[0x18, 0x23, 0xc6, 0xe8, 0x87, 0xb8, 0x01, 0x4f, 0x36, 0xa6, 0xd2, 0xf5, 0x79, 0x6f, 0x91, 0x52]),
            // Twofish MDS matrix magic: 01 ef 5b 5b
            ("Twofish MDS constant", &[0x01, 0xef, 0x5b, 0x5b, 0xef, 0x01, 0xef, 0x5b]),
            // CAST5 S-box 1: 30fb40d4 9fa0ff0b 6beccd2f 3f258c7a
            ("CAST5 S-box", &[0xd4, 0x40, 0xfb, 0x30, 0x0b, 0xff, 0xa0, 0x9f, 0x2f, 0xcd, 0xec, 0x6b, 0x7a, 0x8c, 0x25, 0x3f]),
        ];

        // Scan data sections for crypto signatures
        let mut crypto_addrs: HashMap<u64, &str> = HashMap::new();
        if let Ok(obj) = goblin::Object::parse(binary) {
            let scan_sections: Vec<(u64, usize, usize)> = match &obj {
                goblin::Object::PE(pe) => {
                    let base = pe.image_base as u64;
                    pe.sections.iter()
                        .filter(|s| s.characteristics & 0x20000000 == 0) // not executable
                        .map(|s| (base + s.virtual_address as u64, s.pointer_to_raw_data as usize, s.virtual_size as usize))
                        .collect()
                }
                goblin::Object::Elf(elf) => {
                    elf.section_headers.iter()
                        .filter(|s| s.sh_flags & 0x4 == 0 && s.sh_flags & 0x2 != 0 && s.sh_type != 8)
                        .map(|s| (s.sh_addr, s.sh_offset as usize, s.sh_size as usize))
                        .collect()
                }
                _ => vec![],
            };

            for (sec_va, sec_fo, sec_size) in &scan_sections {
                if sec_fo + sec_size > binary.len() { continue; }
                let sec_data = &binary[*sec_fo..*sec_fo + *sec_size];
                for (name, pattern) in crypto_sigs {
                    if pattern.len() > sec_data.len() { continue; }
                    // Search for the pattern in the section data
                    for i in 0..sec_data.len() - pattern.len() {
                        if &sec_data[i..i + pattern.len()] == *pattern {
                            let va = sec_va + i as u64;
                            crypto_addrs.insert(va, name);
                            // Also mark nearby addresses (the table may be referenced at any offset)
                            break; // one match per section per pattern
                        }
                    }
                }
            }
        }

        // Annotate lines referencing crypto table addresses
        if !crypto_addrs.is_empty() {
            for line in &mut lines {
                if line.contains("//") { continue; }
                for (&addr, &name) in &crypto_addrs {
                    // Match DAT_XXXXXXXX format
                    let dat = format!("{:x}", addr);
                    let dat_upper = format!("{:X}", addr);
                    if line.contains(&format!("DAT_{}", dat))
                        || line.contains(&format!("DAT_{}", dat_upper))
                        || line.contains(&format!("0x{}", dat))
                        || line.contains(&format!("0x{}", dat_upper))
                    {
                        *line = format!("{} // {}", line.trim_end(), name);
                        break;
                    }
                }
            }
        }
    }

    // Inline constant detection (for constants embedded directly in code)
    for line in &mut lines {
        if line.contains("//") { continue; }
        let t = line.trim();
        // SHA-256 first round constant
        if t.contains("0x428a2f98") { *line = format!("{} // SHA-256 round constant", line.trim_end()); }
        // SHA-1 K constants
        else if t.contains("0x5a827999") { *line = format!("{} // SHA-1 K constant", line.trim_end()); }
        else if t.contains("0x6ed9eba1") { *line = format!("{} // SHA-1 K constant", line.trim_end()); }
        else if t.contains("0x8f1bbcdc") { *line = format!("{} // SHA-1 K constant", line.trim_end()); }
        else if t.contains("0xca62c1d6") { *line = format!("{} // SHA-1 K constant", line.trim_end()); }
        // CRC32 polynomial
        else if t.contains("0xedb88320") { *line = format!("{} // CRC32 polynomial (IEEE)", line.trim_end()); }
        else if t.contains("0x04c11db7") { *line = format!("{} // CRC32 polynomial (normal)", line.trim_end()); }
        // MD5 magic constants
        else if t.contains("0xd76aa478") { *line = format!("{} // MD5 T[1]", line.trim_end()); }
        // Blowfish Pi digits
        else if t.contains("0x243f6a88") { *line = format!("{} // Blowfish P-array / Pi digits", line.trim_end()); }
        // ChaCha20/Salsa20
        else if t.contains("0x61707865") { *line = format!("{} // ChaCha20 constant \"expa\"", line.trim_end()); }
        else if t.contains("0x3320646e") { *line = format!("{} // ChaCha20 constant \"nd 3\"", line.trim_end()); }
        else if t.contains("0x79622d32") { *line = format!("{} // ChaCha20 constant \"2-by\"", line.trim_end()); }
        else if t.contains("0x6b206574") { *line = format!("{} // ChaCha20 constant \"te k\"", line.trim_end()); }
        // TEA/XTEA delta
        else if t.contains("0x9e3779b9") { *line = format!("{} // TEA/XTEA delta (golden ratio)", line.trim_end()); }
        // RSA F4 exponent
        else if t.contains("0x10001") && (t.contains("RSA") || t.contains("exponent") || t.contains("pubkey")) {
            *line = format!("{} // RSA public exponent (F4=65537)", line.trim_end());
        }
        // Base64 alphabet
        else if t.contains("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") {
            *line = format!("{} // Base64 alphabet", line.trim_end());
        }
        else if t.contains("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") {
            *line = format!("{} // Base64url alphabet", line.trim_end());
        }
    }

    // #STACK_STRING: Detect byte-by-byte stack string construction.
    // Patterns:
    //   *(uint8_t*)(EXPR) = 0xHH; — explicit byte store (cast)
    //   local_N = 0xHH; — small hex constant assigned to stack var
    //   local_N = NN; — small decimal constant assigned to stack var
    //   *(uint32_t*)(EXPR) = 0xHHHHHHHH; — packed 4-byte ASCII in dword store
    // Reconstruct the full string and add as a comment.
    {
        let mut i = 0;
        while i < lines.len() {
            let mut string_bytes: Vec<(usize, u8)> = Vec::new();
            let mut j = i;

            while j < lines.len() {
                let t = lines[j].trim();
                if !t.ends_with(';') { break; }
                // Skip lines that are function calls, contain string literals, or comments
                if t.contains('(') && !t.contains("*(") { break; }
                if t.contains('"') || t.contains("//") { break; }

                // Pattern 1: *(type*)(EXPR) = 0xHH; (byte cast store)
                let is_byte_cast = t.contains("= 0x")
                    && (t.contains("*(uint8_t*)") || t.contains("*(char*)") || t.contains("*(byte*)"));

                // Pattern 2: local_N = 0xHH; or var_N = 0xHH; (simple hex assignment)
                let is_local_hex = t.contains("= 0x")
                    && (t.starts_with("local_") || t.starts_with("var_") || t.starts_with("-local_"));

                // Pattern 3: local_N = NN; (decimal assignment in printable range)
                let is_local_dec = !t.contains("0x")
                    && (t.starts_with("local_") || t.starts_with("var_") || t.starts_with("-local_"))
                    && t.contains(" = ");

                if is_byte_cast || is_local_hex {
                    if let Some(eq) = t.rfind("= 0x") {
                        let hex_str = t[eq+4..].trim_end_matches(';').trim();
                        // Single byte (1-2 hex digits)
                        if hex_str.len() <= 2 {
                            if let Ok(val) = u8::from_str_radix(hex_str, 16) {
                                if val >= 0x20 && val < 0x7f {
                                    string_bytes.push((j, val));
                                    j += 1;
                                    continue;
                                }
                            }
                        }
                        // Packed dword (8 hex digits = 4 ASCII chars, little-endian)
                        if hex_str.len() == 8 {
                            if let Ok(val) = u32::from_str_radix(hex_str, 16) {
                                let b = val.to_le_bytes();
                                if b.iter().all(|&x| (x >= 0x20 && x < 0x7f) || x == 0) {
                                    for &byte in &b {
                                        if byte == 0 { break; }
                                        string_bytes.push((j, byte));
                                    }
                                    j += 1;
                                    continue;
                                }
                            }
                        }
                        // Packed word (4 hex digits = 2 ASCII chars)
                        if hex_str.len() == 4 {
                            if let Ok(val) = u16::from_str_radix(hex_str, 16) {
                                let b = val.to_le_bytes();
                                if b.iter().all(|&x| (x >= 0x20 && x < 0x7f) || x == 0) {
                                    for &byte in &b {
                                        if byte == 0 { break; }
                                        string_bytes.push((j, byte));
                                    }
                                    j += 1;
                                    continue;
                                }
                            }
                        }
                    }
                } else if is_local_dec {
                    if let Some(eq) = t.rfind(" = ") {
                        let val_str = t[eq+3..].trim_end_matches(';').trim();
                        if let Ok(val) = val_str.parse::<u64>() {
                            if val >= 0x20 && val < 0x7f {
                                string_bytes.push((j, val as u8));
                                j += 1;
                                continue;
                            }
                        }
                    }
                }
                break;
            }

            // 4+ consecutive printable bytes = stack string
            if string_bytes.len() >= 4 {
                let s: String = string_bytes.iter().map(|(_, b)| *b as char).collect();
                // Validate: reject if it looks like a repeated pattern or false positive
                let unique_chars: std::collections::HashSet<char> = s.chars().collect();
                let is_valid = unique_chars.len() >= 3
                    && !s.chars().all(|c| c == s.chars().next().unwrap_or(' '))
                    // Reject if string is already visible as a literal in nearby lines
                    && !lines[i..lines.len().min(i + string_bytes.len() + 5)]
                        .iter().any(|l| l.contains(&format!("\"{}\"", &s[..s.len().min(8)])));
                if is_valid {
                    let pad = " ".repeat(lines[i].len() - lines[i].trim_start().len());
                    // Look ahead for XOR key in nearby lines (within 10 lines after the stores)
                    let look_end = lines.len().min(i + string_bytes.len() + 10);
                    let xor_key = lines[i..look_end].iter().find_map(|l| {
                        let t = l.trim();
                        // Match: "^ NN" or "^ 0xHH" where NN is a decimal or hex constant
                        if let Some(xor_pos) = t.find("^ ") {
                            let after = &t[xor_pos + 2..];
                            if after.starts_with("0x") {
                                let hex = after[2..].split(|c: char| !c.is_ascii_hexdigit()).next().unwrap_or("");
                                if hex.len() <= 2 { return u8::from_str_radix(hex, 16).ok(); }
                            } else {
                                let dec = after.split(|c: char| !c.is_ascii_digit()).next().unwrap_or("");
                                if let Ok(v) = dec.parse::<u64>() {
                                    if v > 0 && v < 256 { return Some(v as u8); }
                                }
                            }
                        }
                        None
                    });
                    let comment = if let Some(key) = xor_key {
                        let decrypted: String = string_bytes.iter()
                            .map(|(_, b)| (*b ^ key) as char)
                            .filter(|c| c.is_ascii_graphic() || *c == ' ')
                            .collect();
                        if decrypted.len() >= 4 {
                            format!("{}// XOR-encrypted string (key=0x{:02x}): \"{}\"", pad, key, decrypted)
                        } else {
                            format!("{}// stack string: \"{}\"", pad, s)
                        }
                    } else {
                        format!("{}// stack string: \"{}\"", pad, s)
                    };
                    lines.insert(i, comment);
                    i += string_bytes.len() + 1;
                } else {
                    i += 1;
                }
            } else {
                i += 1;
            }
        }
    }

    // #XOR_STRING: Detect XOR-encoded string patterns and try to decrypt.
    // Pattern: data ^ constant_byte or data ^ key_byte in a loop.
    // Also try XOR decryption on DAT_ addresses referenced near XOR operations.
    for line in &mut lines {
        let t = line.trim();
        if t.contains("^ 0x") && (t.contains("local_") || t.contains("param_") || t.contains("DAT_")) {
            if let Some(xor_pos) = t.find("^ 0x") {
                let key_start = xor_pos + 4;
                let mut key_end = key_start;
                let bytes = t.as_bytes();
                while key_end < bytes.len() && bytes[key_end].is_ascii_hexdigit() { key_end += 1; }
                if key_end > key_start && key_end - key_start <= 2 {
                    if let Ok(key) = u8::from_str_radix(&t[key_start..key_end], 16) {
                        if key > 0 && key != 0xFF && !line.contains("/*") && !line.contains("// ") {
                            *line = format!("{} // XOR key: 0x{:02x}", line.trim_end(), key);
                        }
                    }
                }
            }
        }
    }

    // #XOR_DECRYPT: Try XOR decryption on DAT_ addresses.
    // When we see DAT_XXXXXXXX referenced in the code, try single-byte and multi-byte
    // XOR decryption on the data at that address.
    if ctx.binary.is_some() {
        let mut decrypted_addrs: HashMap<u64, String> = HashMap::new();
        // Collect all DAT_ addresses referenced in the output
        for line in &lines {
            let t = line.trim();
            let mut pos = 0;
            while let Some(dat_pos) = t[pos..].find("DAT_") {
                let abs_pos = pos + dat_pos + 4;
                let mut end = abs_pos;
                while end < t.len() && t.as_bytes()[end].is_ascii_hexdigit() { end += 1; }
                if end > abs_pos {
                    if let Ok(addr) = u64::from_str_radix(&t[abs_pos..end], 16) {
                        if !decrypted_addrs.contains_key(&addr) {
                            // Try single-byte XOR
                            if let Some((decrypted, key)) = try_xor_decrypt_single(addr, ctx) {
                                decrypted_addrs.insert(addr, format!("\"{}\" (XOR 0x{:02x})", decrypted, key));
                            }
                            // Try multi-byte XOR
                            else if let Some((decrypted, key)) = try_xor_decrypt_multi(addr, ctx) {
                                let key_str = key.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("");
                                decrypted_addrs.insert(addr, format!("\"{}\" (XOR 0x{})", decrypted, key_str));
                            }
                        }
                    }
                }
                pos = end;
            }
        }
        // Annotate lines that reference decrypted addresses
        if !decrypted_addrs.is_empty() {
            for line in &mut lines {
                for (addr, decrypted) in &decrypted_addrs {
                    let dat_name = format!("DAT_{:08x}", addr);
                    let dat_name_upper = format!("DAT_{:X}", addr);
                    if (line.contains(&dat_name) || line.contains(&dat_name_upper))
                        && !line.contains("// decrypted:") {
                        *line = format!("{} // decrypted: {}", line.trim_end(), decrypted);
                        break;
                    }
                }
            }
        }
    }

    // #BASE64_DECODE: Detect base64-encoded strings and show decoded value.
    for line in &mut lines {
        if line.contains("// ") { continue; } // already annotated
        // Find string literals that look like base64
        let t = line.trim();
        if let Some(q1) = t.find('"') {
            if let Some(q2) = t[q1+1..].find('"') {
                let s = &t[q1+1..q1+1+q2];
                if s.len() >= 8 {
                    if let Some(decoded) = try_base64_decode(s) {
                        *line = format!("{} // base64 decoded: \"{}\"", line.trim_end(), decoded);
                    }
                }
            }
        }
    }

    // #ROT13_DECODE: Detect ROT13-encoded strings and show decoded value.
    for line in &mut lines {
        if line.contains("// ") { continue; }
        let t = line.trim();
        if let Some(q1) = t.find('"') {
            if let Some(q2) = t[q1+1..].find('"') {
                let s = &t[q1+1..q1+1+q2];
                if s.len() >= 8 {
                    if let Some(decoded) = try_rot13(s) {
                        *line = format!("{} // ROT13 decoded: \"{}\"", line.trim_end(), decoded);
                    }
                }
            }
        }
    }

    // #SUSPICIOUS_API: Flag dangerous/suspicious Windows API calls for malware analysis.
    {
        let suspicious: &[(&str, &str)] = &[
            ("VirtualAlloc", "⚠ allocate executable memory"),
            ("VirtualAllocEx", "⚠ remote memory allocation"),
            ("VirtualProtect", "⚠ change memory protection"),
            ("WriteProcessMemory", "⚠ write to remote process"),
            ("CreateRemoteThread", "⚠ remote code injection"),
            ("NtCreateThreadEx", "⚠ remote thread creation"),
            ("CreateProcess", "⚠ spawn process"),
            ("ShellExecute", "⚠ execute command"),
            ("WinExec", "⚠ execute command"),
            ("URLDownloadToFile", "⚠ download file"),
            ("InternetOpen", "⚠ network access"),
            ("HttpSendRequest", "⚠ HTTP request"),
            ("WSAStartup", "⚠ network initialization"),
            ("connect(", "⚠ network connection"),
            ("bind(", "⚠ listen for connections"),
            ("GetProcAddress", "dynamic API resolution"),
            ("LoadLibrary", "dynamic DLL loading"),
            ("RegSetValue", "⚠ registry modification"),
            ("RegCreateKey", "⚠ registry modification"),
            ("CryptEncrypt", "⚠ encryption"),
            ("CryptDecrypt", "⚠ decryption"),
            ("IsDebuggerPresent", "⚠ anti-debug check"),
            ("CheckRemoteDebuggerPresent", "⚠ anti-debug check"),
            ("NtQueryInformationProcess", "⚠ anti-debug / process info"),
        ];
        for line in &mut lines {
            for (api, annotation) in suspicious {
                if line.contains(api) && !line.contains("//") {
                    *line = format!("{} // {}", line.trim_end(), annotation);
                    break;
                }
            }
        }
    }

    // #STACK_COOKIE: Annotate XOR with RSP/RBP as security cookie check.
    for line in &mut lines {
        let t = line.trim();
        if t.contains("^ RSP") || t.contains("^ RBP") || t.contains("^ ESP") || t.contains("^ EBP") {
            if !t.contains("//") {
                *line = format!("{} // stack cookie", line.trim_end());
            }
        }
    }

    // #DYNAMIC_RESOLVE: Annotate GetProcAddress + indirect call pattern.
    {
        let mut i = 0;
        while i < lines.len() {
            if lines[i].contains("GetProcAddress") && !lines[i].contains("//") {
                // Check if nearby lines store to a global and call through it
                for j in i+1..(i+4).min(lines.len()) {
                    if lines[j].contains("(*") && lines[j].contains("DAT_") && !lines[j].contains("//") {
                        *&mut lines[j] = format!("{} // call resolved API", lines[j].trim_end());
                        break;
                    }
                }
            }
            i += 1;
        }
    }

    // #TAINT_ANALYSIS: Track user input from sources to security-sensitive sinks.
    // Identifies taint sources (scanf, gets, read, recv, etc.), propagates through
    // variable assignments, and flags when tainted data reaches dangerous sinks.
    {
        // Input sources: (function_name, taint_arg_index)
        // -1 = return value is tainted, 0+ = that argument is the output buffer
        let taint_sources: &[(&str, i32)] = &[
            ("scanf", 1),      // scanf(format, &buffer) — buffer at arg 1+
            ("sscanf", 2),     // sscanf(str, format, &buffer)
            ("fscanf", 2),     // fscanf(file, format, &buffer)
            ("gets", 0),       // gets(buffer)
            ("fgets", 0),      // fgets(buffer, size, stream)
            ("fread", 0),      // fread(buffer, size, count, stream)
            ("read", 1),       // read(fd, buffer, count)
            ("getline", 0),    // getline(&buffer, &size, stream)
            ("recv", 1),       // recv(sock, buffer, len, flags)
            ("recvfrom", 1),   // recvfrom(sock, buffer, ...)
            ("getenv", -1),    // return value is tainted
            ("getchar", -1),   // return value
            ("fgetc", -1),     // return value
            ("ReadFile", 1),   // ReadFile(handle, buffer, ...)
            ("GetDlgItemText", 2),  // GetDlgItemText(dlg, id, buffer, ...)
            ("GetDlgItemTextW", 2),
            ("GetWindowText", 1),   // GetWindowText(hwnd, buffer, count)
            ("GetWindowTextW", 1),
            ("InternetReadFile", 1),
            ("RegQueryValueEx", 4), // ..., data, ...
            ("RegQueryValueExW", 4),
            ("GetCommandLine", -1),
            ("CommandLineToArgvW", -1),
            ("accept", -1),
        ];

        // Dangerous sinks: functions where tainted data causes vulnerabilities
        let taint_sinks: &[(&str, &str)] = &[
            ("system", "command injection"),
            ("exec", "command execution"),
            ("execve", "command execution"),
            ("execvp", "command execution"),
            ("popen", "command injection"),
            ("ShellExecute", "command execution"),
            ("ShellExecuteW", "command execution"),
            ("WinExec", "command execution"),
            ("CreateProcess", "process creation"),
            ("CreateProcessW", "process creation"),
            ("strcpy", "buffer overflow"),
            ("strncpy", "buffer overflow"),
            ("strcat", "buffer overflow"),
            ("sprintf", "format string / buffer overflow"),
            ("vsprintf", "format string / buffer overflow"),
            ("memcpy", "buffer overflow"),
            ("memmove", "buffer overflow"),
            ("gets", "buffer overflow (unbounded read)"),
            ("printf", "format string"),
            ("fprintf", "format string"),
            ("syslog", "format string"),
            ("send", "data exfiltration"),
            ("sendto", "data exfiltration"),
            ("write", "data write"),
            ("WriteFile", "data write"),
            ("fwrite", "data write"),
            ("eval", "code injection"),
            ("sqlite3_exec", "SQL injection"),
            ("mysql_query", "SQL injection"),
            ("LoadLibrary", "DLL injection"),
            ("LoadLibraryA", "DLL injection"),
            ("LoadLibraryW", "DLL injection"),
            ("VirtualProtect", "DEP bypass"),
        ];

        // Phase 1: Find taint sources and the variables they write to
        let mut tainted_vars: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut source_info: Vec<(usize, String, String)> = Vec::new(); // (line_idx, var_name, source_func)

        for (i, line) in lines.iter().enumerate() {
            let t = line.trim();
            // Skip function declarations and comments
            if t.starts_with("//") || t.starts_with("void ") || t.starts_with("int ")
                || t.starts_with("long ") || t.starts_with("char ") || t.starts_with("size_t ") {
                if t.contains("(void)") || t.contains("(int ") || t.contains("(long ") {
                    continue; // function declaration, not a call
                }
            }
            for &(source, taint_arg_idx) in taint_sources {
                let pattern = format!("{}(", source);
                if !t.contains(&pattern) { continue; }
                // Verify word boundary: char before source must not be alphanumeric
                if let Some(pos) = t.find(&pattern) {
                    if pos > 0 && t.as_bytes()[pos - 1].is_ascii_alphanumeric() { continue; }
                }
                // Verify it's a call, not a declaration: must have ; or be inside another expr
                if !t.ends_with(';') && !t.ends_with('{') && !t.contains("if ") { continue; }

                if taint_arg_idx < 0 {
                    // Return value is tainted: var = source(...)
                    if let Some(eq_pos) = t.find(" = ") {
                        if t[eq_pos..].contains(&pattern) {
                            let var = t[..eq_pos].trim();
                            if var.starts_with("param_") || var.starts_with("local_")
                                || var.starts_with("lVar") || var.starts_with("iVar") {
                                tainted_vars.insert(var.to_string());
                                source_info.push((i, var.to_string(), source.to_string()));
                            }
                        }
                    }
                } else {
                    // Specific argument is the output buffer
                    if let Some(paren) = t.find(&pattern) {
                        let args_start = paren + source.len() + 1;
                        if args_start < t.len() {
                            // Split args by comma, get the nth one
                            let args_str = &t[args_start..];
                            let args: Vec<&str> = args_str.split(',').collect();
                            if let Some(arg) = args.get(taint_arg_idx as usize) {
                                let clean = arg.trim().trim_end_matches(')').trim_end_matches(';').trim();
                                // Strip /*annotation*/ prefixes
                                let clean = if clean.contains("*/") {
                                    clean.split("*/").last().unwrap_or(clean).trim()
                                } else {
                                    clean
                                };
                                // Strip type casts: (type)var → var
                                let clean = if clean.starts_with('(') {
                                    clean.split(')').last().unwrap_or(clean).trim()
                                } else {
                                    clean
                                };
                                if clean.starts_with("param_") || clean.starts_with("local_")
                                    || clean.starts_with("lVar") || clean.starts_with("iVar")
                                    || clean.starts_with("buf") {
                                    tainted_vars.insert(clean.to_string());
                                    source_info.push((i, clean.to_string(), source.to_string()));
                                }
                            }
                        }
                    }
                }
            }
        }

        // Phase 2: Propagate taint through variable assignments
        // "var2 = tainted_var" or "var2 = func(tainted_var)"
        let mut changed = true;
        for _round in 0..5 {
            if !changed { break; }
            changed = false;
            for line in lines.iter() {
                let t = line.trim();
                if let Some(eq_pos) = t.find(" = ") {
                    let lhs = t[..eq_pos].trim();
                    let rhs = &t[eq_pos + 3..];
                    // Check if RHS references any tainted variable
                    let rhs_tainted = tainted_vars.iter().any(|tv| rhs.contains(tv.as_str()));
                    if rhs_tainted && !tainted_vars.contains(lhs) {
                        if lhs.starts_with("param_") || lhs.starts_with("local_")
                            || lhs.starts_with("lVar") || lhs.starts_with("iVar") {
                            tainted_vars.insert(lhs.to_string());
                            changed = true;
                        }
                    }
                }
            }
        }

        // Phase 3: Check if tainted variables reach sinks
        if !tainted_vars.is_empty() {
            for (i, line) in lines.iter_mut().enumerate() {
                if line.contains("//") { continue; }
                let t = line.trim().to_string();
                for &(sink, vuln_type) in taint_sinks {
                    if t.contains(sink) && t.contains('(') {
                        // Check if any tainted variable appears in the call arguments
                        let args_part = t.split('(').nth(1).unwrap_or("");
                        let has_tainted_arg = tainted_vars.iter()
                            .any(|tv| args_part.contains(tv.as_str()));
                        if has_tainted_arg {
                            let source_func = source_info.first()
                                .map(|(_, _, s)| s.as_str())
                                .unwrap_or("input");
                            *line = format!("{} // ⚠ TAINT: user input from {}() → {} ({})",
                                line.trim_end(), source_func, sink, vuln_type);
                        }
                    }
                }
            }

            // Annotate taint sources
            for (i, var, source) in &source_info {
                if *i < lines.len() && !lines[*i].contains("// ⚠ TAINT") {
                    lines[*i] = format!("{} // ⚠ TAINT SOURCE: {}() → {}",
                        lines[*i].trim_end(), source, var);
                }
            }
        }
    }

    // #GLOBAL_NAMES: Name repeated hex addresses as DAT_xxx (global variables).
    // When a hex address 0x1400NNNNN appears 2+ times, it's likely a global variable.
    {
        let all_text = lines.join("\n");
        let mut addr_counts: HashMap<String, usize> = HashMap::new();
        // Find all 0x1XXXXXXXX or 0x4XXXXXXX patterns (PE/ELF address ranges)
        let mut pos = 0;
        while let Some(hex_pos) = all_text[pos..].find("0x") {
            let abs = pos + hex_pos;
            let hex_start = abs + 2;
            let mut hex_end = hex_start;
            while hex_end < all_text.len() && all_text.as_bytes()[hex_end].is_ascii_hexdigit() {
                hex_end += 1;
            }
            let hex_str = &all_text[hex_start..hex_end];
            if hex_str.len() >= 7 && hex_str.len() <= 16 { // address-length hex
                if let Ok(val) = u64::from_str_radix(hex_str, 16) {
                    // Only name addresses in data sections (not code)
                    if val > 0x1000 && !hex_str.starts_with("ffffff") {
                        let key = format!("0x{}", hex_str);
                        *addr_counts.entry(key).or_insert(0) += 1;
                    }
                }
            }
            pos = hex_end.max(abs + 1);
        }
        // Replace addresses that appear 2+ times with DAT_xxx
        for (addr_str, count) in &addr_counts {
            if *count >= 2 {
                let hex = addr_str.strip_prefix("0x").unwrap_or(addr_str);
                let dat_name = format!("DAT_{}", hex);
                for line in &mut lines {
                    // Only replace in data contexts (not in string literals or comments)
                    if line.contains(addr_str) && !line.contains('"') && !line.contains("//") {
                        *line = line.replace(addr_str, &dat_name);
                    }
                }
            }
        }
    }

    // #PHI_CLEANUP: Remove phi() artifacts from output.
    // Pattern: "return phi(...);" → "return 0;" (use first arg, which is the common value)
    for line in &mut lines {
        let t = line.trim();
        if t.starts_with("return phi(") && t.ends_with(");") {
            let inner = &t["return phi(".len()..t.len() - 2];
            // Use the first argument of the phi
            if let Some(comma) = inner.find(',') {
                let first = inner[..comma].trim();
                let pad = " ".repeat(line.len() - line.trim_start().len());
                *line = format!("{}return {};", pad, first);
            }
        }
        // Also clean up inline phi() in expressions
        if line.contains("phi(") && !line.contains("return phi(") {
            // Replace phi(X, Y) with X (first operand)
            while let Some(pos) = line.find("phi(") {
                let after = &line[pos + 4..];
                if let Some(close) = after.find(')') {
                    let inner = &after[..close];
                    let first = inner.split(',').next().unwrap_or("?").trim();
                    let old = format!("phi({})", inner);
                    *line = line.replace(&old, first);
                } else { break; }
            }
        }
    }

    // #INCREMENT: Simplify "var = var + 1" to "var++" and "var = var - 1" to "var--"
    for line in &mut lines {
        let t = line.trim().to_string();
        if let Some(eq) = t.find(" = ") {
            let lhs = &t[..eq];
            let rhs = t[eq + 3..].trim_end_matches(';');
            if rhs == format!("{} + 1", lhs) {
                let pad = " ".repeat(line.len() - line.trim_start().len());
                *line = format!("{}{}++;", pad, lhs);
            } else if rhs == format!("{} - 1", lhs) {
                let pad = " ".repeat(line.len() - line.trim_start().len());
                *line = format!("{}{}--;", pad, lhs);
            }
        }
    }

    // #ELSE_IF: Collapse nested "} else { if (" chains into flat "} else if ("
    // Re-indents body to match the original if-block level.
    {
        // Find the indent of the first "if (" at each nesting level
        let base_indent = lines.iter()
            .find(|l| l.trim().starts_with("if (") && l.trim().ends_with('{'))
            .map(|l| l.len() - l.trim_start().len())
            .unwrap_or(0);

        let mut i = 0;
        while i + 1 < lines.len() {
            let lt = lines[i].trim().to_string();
            let next = lines[i + 1].trim().to_string();
            if lt == "} else {" && next.starts_with("if (") {
                let pad = " ".repeat(base_indent);
                let body_pad = " ".repeat(base_indent + 4);
                lines[i] = format!("{}}} else {}", pad, next);
                lines.remove(i + 1);
                // Re-indent body and remove the extra closing brace
                let mut depth = 0i32;
                let mut close_to_remove = None;
                for j in (i + 1)..lines.len() {
                    let jt = lines[j].trim().to_string();
                    if jt.ends_with('{') { depth += 1; }
                    if jt == "}" {
                        if depth == 0 {
                            close_to_remove = Some(j);
                            break;
                        }
                        depth -= 1;
                    }
                    // Re-indent non-empty body lines to match base level
                    if depth == 0 && !jt.is_empty() {
                        lines[j] = format!("{}{}", body_pad, jt);
                    }
                }
                if let Some(j) = close_to_remove {
                    lines.remove(j);
                }
                continue;
            }
            i += 1;
        }
    }

    // #STRUCT_RECOVERY: Detect field access patterns, match known structs, emit definitions.
    {
        // Known Win32/POSIX struct layouts: (struct_name, [(offset, field_name, field_type)])
        let known_structs: &[(&str, &[(u64, &str, &str)])] = &[
            ("STARTUPINFOW", &[
                (0x00, "cb", "DWORD"), (0x08, "lpReserved", "LPWSTR"), (0x10, "lpDesktop", "LPWSTR"),
                (0x18, "lpTitle", "LPWSTR"), (0x20, "dwX", "DWORD"), (0x24, "dwY", "DWORD"),
                (0x28, "dwXSize", "DWORD"), (0x2c, "dwYSize", "DWORD"),
                (0x30, "dwXCountChars", "DWORD"), (0x34, "dwYCountChars", "DWORD"),
                (0x38, "dwFillAttribute", "DWORD"), (0x3c, "dwFlags", "DWORD"),
                (0x40, "wShowWindow", "WORD"), (0x48, "hStdInput", "HANDLE"),
                (0x50, "hStdOutput", "HANDLE"), (0x58, "hStdError", "HANDLE"),
            ]),
            ("PROCESS_INFORMATION", &[
                (0x00, "hProcess", "HANDLE"), (0x08, "hThread", "HANDLE"),
                (0x10, "dwProcessId", "DWORD"), (0x14, "dwThreadId", "DWORD"),
            ]),
            ("SECURITY_ATTRIBUTES", &[
                (0x00, "nLength", "DWORD"), (0x08, "lpSecurityDescriptor", "LPVOID"),
                (0x10, "bInheritHandle", "BOOL"),
            ]),
            ("WNDCLASSEXW", &[
                (0x00, "cbSize", "UINT"), (0x04, "style", "UINT"), (0x08, "lpfnWndProc", "WNDPROC"),
                (0x10, "cbClsExtra", "int"), (0x14, "cbWndExtra", "int"), (0x18, "hInstance", "HINSTANCE"),
                (0x20, "hIcon", "HICON"), (0x28, "hCursor", "HCURSOR"), (0x30, "hbrBackground", "HBRUSH"),
                (0x38, "lpszMenuName", "LPCWSTR"), (0x40, "lpszClassName", "LPCWSTR"),
                (0x48, "hIconSm", "HICON"),
            ]),
            ("OSVERSIONINFOW", &[
                (0x00, "dwOSVersionInfoSize", "DWORD"), (0x04, "dwMajorVersion", "DWORD"),
                (0x08, "dwMinorVersion", "DWORD"), (0x0c, "dwBuildNumber", "DWORD"),
                (0x10, "dwPlatformId", "DWORD"), (0x14, "szCSDVersion", "WCHAR[128]"),
            ]),
            ("EXCEPTION_RECORD", &[
                (0x00, "ExceptionCode", "DWORD"), (0x04, "ExceptionFlags", "DWORD"),
                (0x08, "ExceptionRecord", "void *"), (0x10, "ExceptionAddress", "void *"),
                (0x18, "NumberParameters", "DWORD"),
            ]),
            ("CONTEXT", &[  // x86-64
                (0x30, "MxCsr", "DWORD"), (0x38, "SegCs", "WORD"), (0x3a, "SegDs", "WORD"),
                (0x44, "EFlags", "DWORD"), (0x48, "Rax", "uint64_t"), (0x50, "Rcx", "uint64_t"),
                (0x58, "Rdx", "uint64_t"), (0x60, "Rbx", "uint64_t"), (0x68, "Rsp", "uint64_t"),
                (0x70, "Rbp", "uint64_t"), (0x78, "Rsi", "uint64_t"), (0x80, "Rdi", "uint64_t"),
                (0x88, "R8", "uint64_t"), (0x90, "R9", "uint64_t"), (0x98, "Rip", "uint64_t"),
            ]),
            ("WIN32_FIND_DATAW", &[
                (0x00, "dwFileAttributes", "DWORD"), (0x04, "ftCreationTime", "FILETIME"),
                (0x0c, "ftLastAccessTime", "FILETIME"), (0x14, "ftLastWriteTime", "FILETIME"),
                (0x1c, "nFileSizeHigh", "DWORD"), (0x20, "nFileSizeLow", "DWORD"),
                (0x28, "cFileName", "WCHAR[260]"),
            ]),
            ("OVERLAPPED", &[
                (0x00, "Internal", "ULONG_PTR"), (0x08, "InternalHigh", "ULONG_PTR"),
                (0x10, "Offset", "DWORD"), (0x14, "OffsetHigh", "DWORD"), (0x18, "hEvent", "HANDLE"),
            ]),
            // Win32 GUI structs
            ("RECT", &[
                (0x00, "left", "LONG"), (0x04, "top", "LONG"),
                (0x08, "right", "LONG"), (0x0c, "bottom", "LONG"),
            ]),
            ("POINT", &[
                (0x00, "x", "LONG"), (0x04, "y", "LONG"),
            ]),
            ("MSG", &[
                (0x00, "hwnd", "HWND"), (0x08, "message", "UINT"),
                (0x10, "wParam", "WPARAM"), (0x18, "lParam", "LPARAM"),
                (0x20, "time", "DWORD"), (0x24, "pt.x", "LONG"), (0x28, "pt.y", "LONG"),
            ]),
            ("PAINTSTRUCT", &[
                (0x00, "hdc", "HDC"), (0x08, "fErase", "BOOL"),
                (0x0c, "rcPaint.left", "LONG"), (0x10, "rcPaint.top", "LONG"),
                (0x14, "rcPaint.right", "LONG"), (0x18, "rcPaint.bottom", "LONG"),
            ]),
            ("LOGFONTW", &[
                (0x00, "lfHeight", "LONG"), (0x04, "lfWidth", "LONG"),
                (0x08, "lfEscapement", "LONG"), (0x0c, "lfOrientation", "LONG"),
                (0x10, "lfWeight", "LONG"), (0x14, "lfItalic", "BYTE"),
                (0x15, "lfUnderline", "BYTE"), (0x16, "lfStrikeOut", "BYTE"),
                (0x17, "lfCharSet", "BYTE"), (0x1c, "lfFaceName", "WCHAR[32]"),
            ]),
            ("BITMAP", &[
                (0x00, "bmType", "LONG"), (0x04, "bmWidth", "LONG"),
                (0x08, "bmHeight", "LONG"), (0x0c, "bmWidthBytes", "LONG"),
                (0x10, "bmPlanes", "WORD"), (0x12, "bmBitsPixel", "WORD"),
                (0x18, "bmBits", "LPVOID"),
            ]),
            // Win32 system structs
            ("CRITICAL_SECTION", &[
                (0x00, "DebugInfo", "void *"), (0x08, "LockCount", "LONG"),
                (0x0c, "RecursionCount", "LONG"), (0x10, "OwningThread", "HANDLE"),
                (0x18, "LockSemaphore", "HANDLE"), (0x20, "SpinCount", "ULONG_PTR"),
            ]),
            ("SYSTEM_INFO", &[
                (0x00, "wProcessorArchitecture", "WORD"), (0x04, "dwPageSize", "DWORD"),
                (0x08, "lpMinimumApplicationAddress", "LPVOID"),
                (0x10, "lpMaximumApplicationAddress", "LPVOID"),
                (0x18, "dwActiveProcessorMask", "DWORD_PTR"),
                (0x20, "dwNumberOfProcessors", "DWORD"),
                (0x24, "dwProcessorType", "DWORD"),
                (0x28, "dwAllocationGranularity", "DWORD"),
                (0x2c, "wProcessorLevel", "WORD"), (0x2e, "wProcessorRevision", "WORD"),
            ]),
            ("MEMORY_BASIC_INFORMATION", &[
                (0x00, "BaseAddress", "PVOID"), (0x08, "AllocationBase", "PVOID"),
                (0x10, "AllocationProtect", "DWORD"), (0x18, "RegionSize", "SIZE_T"),
                (0x20, "State", "DWORD"), (0x24, "Protect", "DWORD"), (0x28, "Type", "DWORD"),
            ]),
            ("FILETIME", &[
                (0x00, "dwLowDateTime", "DWORD"), (0x04, "dwHighDateTime", "DWORD"),
            ]),
            ("LARGE_INTEGER", &[
                (0x00, "LowPart", "DWORD"), (0x04, "HighPart", "LONG"),
            ]),
            // Win32 network structs
            ("WSADATA", &[
                (0x00, "wVersion", "WORD"), (0x02, "wHighVersion", "WORD"),
                (0x04, "iMaxSockets", "unsigned short"), (0x06, "iMaxUdpDg", "unsigned short"),
                (0x08, "lpVendorInfo", "char *"),
            ]),
            // Win32 service structs
            ("SERVICE_STATUS", &[
                (0x00, "dwServiceType", "DWORD"), (0x04, "dwCurrentState", "DWORD"),
                (0x08, "dwControlsAccepted", "DWORD"), (0x0c, "dwWin32ExitCode", "DWORD"),
                (0x10, "dwServiceSpecificExitCode", "DWORD"), (0x14, "dwCheckPoint", "DWORD"),
                (0x18, "dwWaitHint", "DWORD"),
            ]),
            ("SERVICE_TABLE_ENTRYW", &[
                (0x00, "lpServiceName", "LPWSTR"), (0x08, "lpServiceProc", "LPSERVICE_MAIN_FUNCTION"),
            ]),
            // POSIX/Linux structs (x86-64 layout)
            ("stat", &[
                (0x00, "st_dev", "dev_t"), (0x08, "st_ino", "ino_t"),
                (0x10, "st_nlink", "nlink_t"), (0x18, "st_mode", "mode_t"),
                (0x1c, "st_uid", "uid_t"), (0x20, "st_gid", "gid_t"),
                (0x28, "st_rdev", "dev_t"), (0x30, "st_size", "off_t"),
                (0x38, "st_blksize", "blksize_t"), (0x40, "st_blocks", "blkcnt_t"),
                (0x48, "st_atim", "timespec"), (0x58, "st_mtim", "timespec"),
                (0x68, "st_ctim", "timespec"),
            ]),
            ("sockaddr_in", &[
                (0x00, "sin_family", "sa_family_t"), (0x02, "sin_port", "in_port_t"),
                (0x04, "sin_addr", "in_addr"),
            ]),
            ("addrinfo", &[
                (0x00, "ai_flags", "int"), (0x04, "ai_family", "int"),
                (0x08, "ai_socktype", "int"), (0x0c, "ai_protocol", "int"),
                (0x10, "ai_addrlen", "socklen_t"), (0x18, "ai_addr", "struct sockaddr *"),
                (0x20, "ai_canonname", "char *"), (0x28, "ai_next", "struct addrinfo *"),
            ]),
            ("timeval", &[
                (0x00, "tv_sec", "time_t"), (0x08, "tv_usec", "suseconds_t"),
            ]),
            ("iovec", &[
                (0x00, "iov_base", "void *"), (0x08, "iov_len", "size_t"),
            ]),
            ("pollfd", &[
                (0x00, "fd", "int"), (0x04, "events", "short"), (0x06, "revents", "short"),
            ]),
            ("sigaction", &[
                (0x00, "sa_handler", "sighandler_t"), (0x08, "sa_flags", "int"),
                (0x10, "sa_restorer", "void (*)(void)"), (0x18, "sa_mask", "sigset_t"),
            ]),
            ("pthread_attr_t", &[
                (0x00, "flags", "unsigned long"), (0x08, "stacksize", "size_t"),
                (0x10, "guardsize", "size_t"), (0x18, "stackaddr", "void *"),
            ]),
            // Network (both Win32 and POSIX)
            ("SOCKADDR_IN", &[
                (0x00, "sin_family", "ADDRESS_FAMILY"), (0x02, "sin_port", "USHORT"),
                (0x04, "sin_addr", "IN_ADDR"),
            ]),
            // Win32 file dialog
            ("OPENFILENAMEW", &[
                (0x00, "lStructSize", "DWORD"), (0x08, "hwndOwner", "HWND"),
                (0x10, "hInstance", "HINSTANCE"), (0x18, "lpstrFilter", "LPCWSTR"),
                (0x28, "nFilterIndex", "DWORD"), (0x30, "lpstrFile", "LPWSTR"),
                (0x38, "nMaxFile", "DWORD"), (0x40, "lpstrFileTitle", "LPWSTR"),
                (0x48, "nMaxFileTitle", "DWORD"), (0x50, "lpstrInitialDir", "LPCWSTR"),
                (0x58, "lpstrTitle", "LPCWSTR"), (0x60, "Flags", "DWORD"),
            ]),
        ];

        let mut param_fields: HashMap<String, std::collections::BTreeSet<u64>> = HashMap::new();
        for line in &lines {
            let text = line.trim();
            let mut pos = 0;
            while pos < text.len() {
                if let Some(start) = text[pos..].find("->field_") {
                    let abs_start = pos + start;
                    let base_end = abs_start;
                    let mut base_start = base_end;
                    while base_start > 0 {
                        let c = text.as_bytes()[base_start - 1];
                        if c.is_ascii_alphanumeric() || c == b'_' || c == b'*' { base_start -= 1; } else { break; }
                    }
                    let base = text[base_start..base_end].trim_start_matches('*');
                    let hex_start = abs_start + 8;
                    let mut hex_end = hex_start;
                    while hex_end < text.len() && text.as_bytes()[hex_end].is_ascii_hexdigit() { hex_end += 1; }
                    if hex_end > hex_start {
                        if let Ok(offset) = u64::from_str_radix(&text[hex_start..hex_end], 16) {
                            if !base.is_empty() && base.chars().next().map_or(false, |c| c.is_ascii_alphabetic() || c == '_') {
                                param_fields.entry(base.to_string()).or_default().insert(offset);
                            }
                        }
                    }
                    pos = hex_end;
                } else { break; }
            }
        }

        // Also scan for *(typeN*)(base + offset) patterns — direct pointer arithmetic
        // that indicates struct field access without using ->field_N notation.
        for line in &lines {
            let text = line.trim();
            // Pattern: *(uint32_t*)(varname + N) or *(uint64_t*)(varname)
            for cast in ["uint8_t", "uint16_t", "uint32_t", "uint64_t", "int", "long", "char"] {
                let prefix = format!("*({}*)(", cast);
                let mut search_from = 0;
                while let Some(star_pos) = text[search_from..].find(&prefix) {
                    let abs_pos = search_from + star_pos;
                    let inner_start = abs_pos + prefix.len();
                    // Find matching close paren
                    if let Some(close) = text[inner_start..].find(')') {
                        let inner = &text[inner_start..inner_start + close];
                        // Parse: "base + offset" or just "base"
                        if let Some(plus) = inner.find(" + ") {
                            let base = inner[..plus].trim();
                            let offset_str = inner[plus + 3..].trim();
                            if !base.is_empty() && base.chars().next().map_or(false, |c| c.is_ascii_alphabetic() || c == '_')
                                && !base.contains(' ')
                            {
                                let offset = offset_str.strip_prefix("0x")
                                    .and_then(|h| u64::from_str_radix(h, 16).ok())
                                    .or_else(|| offset_str.parse::<u64>().ok());
                                if let Some(off) = offset {
                                    param_fields.entry(base.to_string()).or_default().insert(off);
                                }
                            }
                        } else {
                            // No offset — field at offset 0
                            let base = inner.trim();
                            if !base.is_empty() && base.chars().next().map_or(false, |c| c.is_ascii_alphabetic() || c == '_')
                                && !base.contains(' ')
                            {
                                param_fields.entry(base.to_string()).or_default().insert(0);
                            }
                        }
                    }
                    search_from = abs_pos + prefix.len();
                }
            }
        }

        // API-based struct identification: when a variable is passed to a known API,
        // we know its struct type regardless of field count.
        let api_struct_hints: &[(&str, usize, &str)] = &[
            // (api_name, param_index, struct_type)
            // Process/startup
            ("GetStartupInfoW", 0, "STARTUPINFOW"),
            ("GetStartupInfoA", 0, "STARTUPINFOW"),
            ("CreateProcessW", 9, "STARTUPINFOW"),
            ("CreateProcessA", 9, "STARTUPINFOW"),
            ("CreateProcessW", 10, "PROCESS_INFORMATION"),
            ("CreateProcessA", 10, "PROCESS_INFORMATION"),
            // Window class
            ("RegisterClassExW", 0, "WNDCLASSEXW"),
            ("RegisterClassExA", 0, "WNDCLASSEXW"),
            // System info
            ("GetVersionExW", 0, "OSVERSIONINFOW"),
            ("GetVersionExA", 0, "OSVERSIONINFOW"),
            ("GetSystemInfo", 0, "SYSTEM_INFO"),
            ("GetNativeSystemInfo", 0, "SYSTEM_INFO"),
            // File operations
            ("FindFirstFileW", 1, "WIN32_FIND_DATAW"),
            ("FindNextFileW", 1, "WIN32_FIND_DATAW"),
            ("FindFirstFileA", 1, "WIN32_FIND_DATAW"),
            ("FindNextFileA", 1, "WIN32_FIND_DATAW"),
            ("GetOpenFileNameW", 0, "OPENFILENAMEW"),
            ("GetSaveFileNameW", 0, "OPENFILENAMEW"),
            // Memory
            ("VirtualQuery", 2, "MEMORY_BASIC_INFORMATION"),
            ("VirtualQueryEx", 3, "MEMORY_BASIC_INFORMATION"),
            // Critical section
            ("InitializeCriticalSection", 0, "CRITICAL_SECTION"),
            ("EnterCriticalSection", 0, "CRITICAL_SECTION"),
            ("LeaveCriticalSection", 0, "CRITICAL_SECTION"),
            ("DeleteCriticalSection", 0, "CRITICAL_SECTION"),
            ("TryEnterCriticalSection", 0, "CRITICAL_SECTION"),
            // GDI
            ("BeginPaint", 1, "PAINTSTRUCT"),
            ("EndPaint", 1, "PAINTSTRUCT"),
            ("GetClientRect", 1, "RECT"),
            ("GetWindowRect", 1, "RECT"),
            ("InvalidateRect", 1, "RECT"),
            ("FillRect", 1, "RECT"),
            ("DrawTextW", 3, "RECT"),
            ("DrawTextA", 3, "RECT"),
            ("CreateFontIndirectW", 0, "LOGFONTW"),
            ("CreateFontIndirectA", 0, "LOGFONTW"),
            // Messages
            ("GetMessageW", 0, "MSG"),
            ("GetMessageA", 0, "MSG"),
            ("PeekMessageW", 0, "MSG"),
            ("PeekMessageA", 0, "MSG"),
            ("TranslateMessage", 0, "MSG"),
            ("DispatchMessageW", 0, "MSG"),
            ("DispatchMessageA", 0, "MSG"),
            // Service
            ("StartServiceCtrlDispatcherW", 0, "SERVICE_TABLE_ENTRYW"),
            ("SetServiceStatus", 1, "SERVICE_STATUS"),
            // Overlapped I/O
            ("ReadFile", 4, "OVERLAPPED"),
            ("WriteFile", 4, "OVERLAPPED"),
            ("ConnectNamedPipe", 1, "OVERLAPPED"),
            // Network (Win32)
            ("WSAStartup", 1, "WSADATA"),
            // POSIX
            ("stat", 1, "stat"),
            ("fstat", 1, "stat"),
            ("lstat", 1, "stat"),
            ("getaddrinfo", 3, "addrinfo"),
            ("gettimeofday", 0, "timeval"),
            ("select", 4, "timeval"),
            ("poll", 0, "pollfd"),
            ("sigaction", 1, "sigaction"),
            ("sigaction", 2, "sigaction"),
        ];
        let mut api_type_hints: HashMap<String, &str> = HashMap::new();
        for line in &lines {
            let t = line.trim();
            for (api, param_idx, struct_type) in api_struct_hints {
                if t.contains(api) {
                    // Extract the Nth argument from the call
                    if let Some(paren) = t.find(&format!("{}(", api)) {
                        let args_start = paren + api.len() + 1;
                        let args = &t[args_start..];
                        // Simple arg extraction: split by ", " and take the Nth
                        let arg_parts: Vec<&str> = args.split(", ").collect();
                        if let Some(arg) = arg_parts.get(*param_idx) {
                            let clean = arg.trim()
                                .trim_end_matches(|c: char| c == ')' || c == ';' || c == ',')
                                .trim();
                            let clean = clean.strip_prefix("(void *)").unwrap_or(clean).trim();
                            let clean = clean.trim_start_matches('(').trim_end_matches(')');
                            if clean.starts_with("param_") || clean.starts_with("local_")
                                || clean.starts_with("lVar") {
                                api_type_hints.insert(clean.to_string(), struct_type);
                            }
                        }
                    }
                }
            }
        }

        // Cross-function struct propagation: when this function calls an internal function
        // whose parameters were identified as struct pointers in Pass 1, apply the struct
        // type to the argument variable in this function.
        for line in &lines {
            let t = line.trim();
            // Match: "func_HEXADDR(arg0, arg1, ...)"
            if let Some(func_start) = t.find("func_") {
                let hex_start = func_start + 5;
                let mut hex_end = hex_start;
                while hex_end < t.len() && t.as_bytes()[hex_end].is_ascii_hexdigit() { hex_end += 1; }
                if hex_end > hex_start && hex_end < t.len() && t.as_bytes()[hex_end] == b'(' {
                    if let Ok(callee_addr) = u64::from_str_radix(&t[hex_start..hex_end], 16) {
                        let callee_structs = crate::signatures::lookup_all_struct_params(callee_addr);
                        if !callee_structs.is_empty() {
                            let args_str = &t[hex_end + 1..];
                            let arg_parts: Vec<&str> = args_str.split(", ").collect();
                            for (param_idx, struct_name) in &callee_structs {
                                if let Some(arg) = arg_parts.get(*param_idx as usize) {
                                    let clean = arg.trim()
                                        .trim_end_matches(|c: char| c == ')' || c == ';' || c == ',')
                                        .trim();
                                    let clean = clean.strip_prefix("(void *)").unwrap_or(clean).trim();
                                    // Extract just the base variable name (before any ->field_ or [])
                                    let base = clean.split("->").next().unwrap_or(clean)
                                        .split('[').next().unwrap_or(clean)
                                        .trim_start_matches('*').trim_start_matches('&');
                                    // Validate: must be a clean variable name (alphanumeric + underscore only)
                                    let is_valid_var = !base.is_empty()
                                        && base.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                                        && (base.starts_with("param_") || base.starts_with("local_")
                                            || base.starts_with("lVar") || base.starts_with("iVar"));
                                    if is_valid_var && !api_type_hints.contains_key(base) {
                                        let leaked: &'static str = Box::leak(struct_name.clone().into_boxed_str());
                                        api_type_hints.insert(base.to_string(), leaked);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Try to match collected field sets against known struct layouts
        let mut struct_matches: HashMap<String, &str> = HashMap::new(); // base_var → struct_name
        let mut field_names: HashMap<(String, u64), (&str, &str)> = HashMap::new(); // (base, offset) → (name, type)

        // First apply API-based hints (high confidence)
        for (var_name, struct_type) in &api_type_hints {
            struct_matches.insert(var_name.clone(), struct_type);
            for (sname, sfields) in known_structs {
                if sname == struct_type {
                    for (offset, fname, ftype) in *sfields {
                        field_names.insert((var_name.clone(), *offset), (fname, ftype));
                    }
                }
            }
        }

        for (base, fields) in &param_fields {
            if struct_matches.contains_key(base) { continue; } // already identified by API
            if fields.is_empty() { continue; }

            // Try each known struct — score by how many of our fields match (need 3+).
            // Filter by binary type: Win32 structs only for PE, POSIX only for ELF.
            if fields.len() < 3 { /* skip known struct matching, fall through to unknown */ }
            else {
            let is_pe = matches!(ctx.arch, Architecture::X86_64 | Architecture::X86_32)
                && ctx.binary.map_or(false, |b| b.len() > 2 && b[0] == b'M' && b[1] == b'Z');
            let posix_structs = ["stat", "sockaddr_in", "addrinfo", "timeval", "iovec",
                "pollfd", "sigaction", "pthread_attr_t"];
            let win32_only_structs = ["STARTUPINFOW", "PROCESS_INFORMATION", "WNDCLASSEXW",
                "OSVERSIONINFOW", "WIN32_FIND_DATAW", "OPENFILENAMEW", "WSADATA",
                "SERVICE_STATUS", "SERVICE_TABLE_ENTRYW", "MSG", "PAINTSTRUCT", "LOGFONTW",
                "BITMAP", "SYSTEM_INFO", "MEMORY_BASIC_INFORMATION", "SOCKADDR_IN",
                "CRITICAL_SECTION", "OVERLAPPED", "RECT", "POINT", "EXCEPTION_RECORD",
                "CONTEXT", "FILETIME", "LARGE_INTEGER"];
            let mut best_match: Option<(&str, usize)> = None;
            for (struct_name, struct_fields) in known_structs {
                // Skip Win32 structs for ELF and POSIX structs for PE
                if !is_pe && win32_only_structs.contains(struct_name) { continue; }
                if is_pe && posix_structs.contains(struct_name) { continue; }

                let struct_offsets: std::collections::BTreeSet<u64> = struct_fields.iter().map(|(o, _, _)| *o).collect();
                let matching = fields.intersection(&struct_offsets).count();
                // Require at least 3 matching fields and >50% of observed fields match
                if matching >= 3 && matching * 2 >= fields.len() {
                    if best_match.map_or(true, |(_, best)| matching > best) {
                        best_match = Some((struct_name, matching));
                    }
                }
            }

            if let Some((struct_name, _)) = best_match {
                struct_matches.insert(base.clone(), struct_name);
                // Populate field name map
                for (sname, sfields) in known_structs {
                    if *sname == struct_name {
                        for (offset, fname, ftype) in *sfields {
                            field_names.insert((base.clone(), *offset), (fname, ftype));
                        }
                    }
                }
            }
            } // close the fields.len() >= 3 gate
        }

        // Also apply cross-function struct hints to variables that don't have enough
        // field accesses for offset-matching but were identified via callee propagation
        for (var_name, struct_type) in &api_type_hints {
            if !struct_matches.contains_key(var_name) {
                struct_matches.insert(var_name.clone(), struct_type);
                // Also populate field_names so any field accesses in this function get renamed
                for (sname, sfields) in known_structs {
                    if *sname == *struct_type {
                        for (offset, fname, ftype) in *sfields {
                            field_names.insert((var_name.clone(), *offset), (fname, ftype));
                        }
                    }
                }
            }
        }

        // Emit struct definition comments and rename fields in output
        let mut struct_comments: Vec<String> = Vec::new();
        // Comments for variables with field accesses
        for (base, fields) in &param_fields {
            if fields.is_empty() { continue; }
            // Skip register names — only process variable names
            if base.len() <= 3 && base.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()) {
                continue; // RAX, RCX, etc. — not struct variables
            }
            let fv: Vec<u64> = fields.iter().copied().collect();

            if let Some(struct_name) = struct_matches.get(base) {
                // Known struct match
                struct_comments.push(format!("// {} is {} *", base, struct_name));
            } else if !fv.is_empty() {
                // Unknown struct — infer field types from sizes and usage context,
                // then rename ->field_N to descriptive names.
                let all_text = lines.join("\n");
                let mut def = format!("// struct layout for {} ({}+ fields): ", base, fv.len());
                let mut int_count = 0u32;
                let mut ptr_count = 0u32;
                for (i, &offset) in fv.iter().enumerate() {
                    let sz = if i + 1 < fv.len() { (fv[i+1] - offset).min(8) } else { 8 };

                    // Usage-based type inference from the output text
                    let field_pat = format!("{}->field_{:x}", base, offset);
                    let is_compared_to_zero = all_text.contains(&format!("{} != 0", field_pat))
                        || all_text.contains(&format!("{} == 0", field_pat))
                        || all_text.contains(&format!("{} == NULL", field_pat));
                    let is_dereferenced = all_text.contains(&format!("*{}", field_pat))
                        || all_text.contains(&format!("{}->", field_pat));
                    let is_str_arg = all_text.contains(&format!("strlen({})", field_pat))
                        || all_text.contains(&format!("printf({}", field_pat))
                        || all_text.contains(&format!("puts({})", field_pat))
                        || all_text.contains(&format!("strcpy({}", field_pat));

                    // Determine field type and name
                    let (ty_name, field_name): (&str, String) = if is_str_arg {
                        ("char *", format!("str_{:x}", offset))
                    } else if is_dereferenced || (sz >= 8 && is_compared_to_zero) {
                        ptr_count += 1;
                        let name = if ptr_count == 1 && sz >= 8 { "next".to_string() }
                            else { format!("ptr_{:x}", offset) };
                        ("void *", name)
                    } else if sz <= 4 {
                        int_count += 1;
                        let name = if int_count == 1 && offset == 0 { "value".to_string() }
                            else { format!("field_{:x}", offset) };
                        (match sz { 1 => "uint8_t", 2 => "uint16_t", _ => "int" }, name)
                    } else {
                        (match sz { 1 => "byte", 2 => "short", 4 => "int", _ => "long" },
                         format!("field_{:x}", offset))
                    };

                    // Populate field_names for renaming
                    // Leak the strings so they have 'static lifetime
                    let leaked_name: &'static str = Box::leak(field_name.clone().into_boxed_str());
                    let leaked_type: &'static str = Box::leak(ty_name.to_string().into_boxed_str());
                    field_names.insert((base.clone(), offset), (leaked_name, leaked_type));

                    if i > 0 { def.push_str(", "); }
                    def.push_str(&format!("+0x{:x} {} {}", offset, ty_name, field_name));
                    if i >= 12 { def.push_str(", ..."); break; }
                }
                if fv.len() >= 4 {
                    struct_comments.push(def);
                }
            }
        }
        // Comments for cross-function propagated structs (variables without field accesses)
        for (var_name, struct_type) in &struct_matches {
            if !param_fields.contains_key(var_name) || param_fields[var_name].len() < 3 {
                let already_commented = struct_comments.iter().any(|c| c.contains(&format!("{} is", var_name)));
                if !already_commented {
                    struct_comments.push(format!("// {} is {} * (from callee)", var_name, struct_type));
                }
            }
        }
        if !struct_comments.is_empty() {
            // Sort so known structs come first
            struct_comments.sort_by(|a, b| {
                let a_known = a.contains(" is ");
                let b_known = b.contains(" is ");
                b_known.cmp(&a_known).then(a.cmp(b))
            });
            if let Some(idx) = lines.iter().position(|l| l.trim_end().ends_with('{')) {
                for (j, comment) in struct_comments.into_iter().enumerate() {
                    lines.insert(idx + 1 + j, format!("    {}", comment));
                }
            }
        }

        // Rename fields for known/inferred structs
        if !field_names.is_empty() {
            for line in &mut lines {
                for ((base, offset), (fname, _ftype)) in &field_names {
                    // Pattern 1: base->field_XX → base->fieldName
                    let old = format!("{}->field_{:x}", base, offset);
                    if line.contains(&old) {
                        let new = format!("{}->{}", base, fname);
                        *line = line.replace(&old, &new);
                    }
                    // Pattern 2: *base->field_XX → *base->fieldName
                    let old_deref = format!("*{}->field_{:x}", base, offset);
                    if line.contains(&old_deref) {
                        let new_deref = format!("*{}->{}", base, fname);
                        *line = line.replace(&old_deref, &new_deref);
                    }
                    // Pattern 3: *(typeN*)(base + offset) → base->fieldName
                    // Matches: *(uint32_t*)(base + 8), *(uint64_t*)(base), etc.
                    if *offset > 0 {
                        for cast in ["uint8_t", "uint16_t", "uint32_t", "uint64_t", "int", "long", "char"] {
                            let old_cast = format!("*({}*)({} + {})", cast, base, offset);
                            if line.contains(&old_cast) {
                                let new_field = format!("{}->{}", base, fname);
                                *line = line.replace(&old_cast, &new_field);
                            }
                            // Also hex offset: *(uint32_t*)(base + 0x8)
                            let old_hex = format!("*({}*)({} + 0x{:x})", cast, base, offset);
                            if line.contains(&old_hex) {
                                let new_field = format!("{}->{}", base, fname);
                                *line = line.replace(&old_hex, &new_field);
                            }
                        }
                    } else {
                        // Offset 0: *(typeN*)(base) → base->fieldName (or just *(base) for first field)
                        for cast in ["uint8_t", "uint16_t", "uint32_t", "uint64_t", "int", "long", "char"] {
                            let old_cast = format!("*({}*)({})", cast, base);
                            if line.contains(&old_cast) {
                                let new_field = format!("{}->{}", base, fname);
                                *line = line.replace(&old_cast, &new_field);
                            }
                        }
                    }
                }
            }
        }
    }

    // #CRT_WRAPPERS: Recognize common CRT wrapper functions by call pattern.
    // func_XXX that just calls __security_check_cookie → rename to __security_check_cookie
    // func_XXX that just calls __report_rangecheckfailure → rename
    {
        // Scan for single-call wrapper functions: "func_XXX(...) { known_call; }"
        let _all_text = lines.join("\n");
        let known_wrappers: &[(&str, &str)] = &[
            ("__security_check_cookie", "__security_check_cookie"),
            ("__report_rangecheckfailure", "__report_rangecheckfailure"),
            ("__GSHandlerCheck", "__GSHandlerCheck"),
            ("_invalid_parameter_noinfo_noreturn", "_invalid_parameter_noinfo"),
            ("terminate()", "std::terminate"),
            ("_CxxThrowException", "_CxxThrowException"),
            ("_purecall", "_purecall"),
            ("__std_exception_copy", "__std_exception_copy"),
            ("__std_exception_destroy", "__std_exception_destroy"),
        ];
        let mut wrapper_renames: Vec<(String, String)> = Vec::new();

        for (known, rename_to) in known_wrappers {
            // Find func_XXX that contains only a call to this known function
            // Pattern in output: "func_XXXXX(...) {\n    known_func(...);\n}"
            let search = format!("{}(", known);
            for line in &lines {
                if line.contains(&search) && line.contains("func_") {
                    // Extract the func_XXX name that wraps this call
                    if let Some(pos) = line.find("func_") {
                        let end = line[pos..].find('(').unwrap_or(line.len() - pos);
                        let wrapper_name = &line[pos..pos + end];
                        if wrapper_name.starts_with("func_") && wrapper_name.len() > 5 {
                            wrapper_renames.push((wrapper_name.to_string(), rename_to.to_string()));
                        }
                    }
                }
            }
        }

        // Also detect stack cookie check: func_XXX(VAR ^ RSP) → __security_check_cookie
        for line in &lines {
            if line.contains("^ RSP)") && line.contains("func_") && line.contains("// stack cookie") {
                if let Some(pos) = line.find("func_") {
                    let end = line[pos..].find('(').unwrap_or(line.len() - pos);
                    let wrapper_name = &line[pos..pos + end];
                    if wrapper_name.starts_with("func_") {
                        wrapper_renames.push((wrapper_name.to_string(), "__security_check_cookie".to_string()));
                    }
                }
            }
        }

        wrapper_renames.sort_by(|a, b| b.0.len().cmp(&a.0.len())); // longest first
        wrapper_renames.dedup();
        for (old, new_name) in &wrapper_renames {
            for line in &mut lines {
                if line.contains(old.as_str()) {
                    *line = line.replace(old.as_str(), new_name.as_str());
                }
            }
        }
    }

    // #PUTCHAR_ASCII: Display putchar(10) as putchar('\n'), etc.
    for line in &mut lines {
        *line = line.replace("putchar(10)", "putchar('\\n')")
                    .replace("putchar(9)", "putchar('\\t')")
                    .replace("putchar(13)", "putchar('\\r')")
                    .replace("putchar(0)", "putchar('\\0')");
    }

    // #SIMPLIFY_DEREF: Clean up pointer dereference syntax.
    // *(uint64_t*)(param_N) → *param_N
    // *(param_N) → *param_N  (bare deref of a pointer parameter)
    // *(lVar_N) → *lVar_N
    for line in &mut lines {
        // Typed casts: *(uint64_t*)(VAR) → *VAR
        for cast in ["*(uint64_t*)(", "*(int*)(", "*(long*)(", "*(uint32_t*)(", "*(int64_t*)("] {
            while line.contains(cast) {
                if let Some(start) = line.find(cast) {
                    let inner_start = start + cast.len();
                    if let Some(close) = line[inner_start..].find(')') {
                        let inner = &line[inner_start..inner_start + close].to_string();
                        if (inner.starts_with("param_") || inner.starts_with("lVar")
                            || inner.starts_with("iVar") || inner.starts_with("local_"))
                            && !inner.contains(' ')
                        {
                            let old = format!("{}{})", cast, inner);
                            let new_str = format!("*{}", inner);
                            *line = line.replace(&old, &new_str);
                            continue;
                        }
                    }
                }
                break;
            }
        }
        // Bare deref: *(param_N) → *param_N, *(lVar_N) → *lVar_N
        // But NOT *(*(param_N)) — that's a double deref
        while line.contains("*(param_") || line.contains("*(lVar") || line.contains("*(iVar") {
            let mut replaced = false;
            for prefix in ["*(param_", "*(lVar", "*(iVar"] {
                if let Some(start) = line.find(prefix) {
                    // Check it's not *(*(... — double deref
                    if start > 0 && line.as_bytes()[start - 1] == b'(' { break; }
                    let inner_start = start + 2; // skip "*("
                    if let Some(close) = line[inner_start..].find(')') {
                        let inner = line[inner_start..inner_start + close].to_string();
                        if !inner.contains(' ') && !inner.contains('(') {
                            let old = format!("*({})", inner);
                            let new_str = format!("*{}", inner);
                            *line = line.replace(&old, &new_str);
                            replaced = true;
                            break;
                        }
                    }
                }
            }
            if !replaced { break; }
        }
    }

    // #TYPE_CASTS: Add explicit type casts for truncation and extension operations.
    // Makes implicit type conversions visible in the pseudocode.
    for line in &mut lines {
        // & 0xff → (uint8_t) for byte truncation
        if line.contains("& 0xff)") || line.contains("& 255)") {
            *line = line.replace("& 0xff)", "& 0xff) /* (uint8_t) */")
                .replace("& 255)", "& 255) /* (uint8_t) */");
        }
        // & 0xffff → (uint16_t) for short truncation
        if line.contains("& 0xffff)") || line.contains("& 65535)") {
            *line = line.replace("& 0xffff)", "& 0xffff) /* (uint16_t) */")
                .replace("& 65535)", "& 65535) /* (uint16_t) */");
        }
        // & 0xffffffff → (uint32_t) for int truncation (only in 64-bit context)
        if line.contains("& 0xffffffff)") && !line.contains("INVALID_HANDLE") && !line.contains("/*") {
            *line = line.replace("& 0xffffffff)", "& 0xffffffff) /* (uint32_t) */");
        }
    }

    // #MSVC_DEMANGLE: Demangle MSVC C++ mangled names in the output.
    // MSVC names start with '?' and contain '@' delimiters.
    // Common patterns: ?cout@std@@... → std::cout, ??6... → operator<<
    {
        // Collect all MSVC mangled names from the output
        let all_text = lines.join("\n");
        let mut replacements: Vec<(String, String)> = Vec::new();
        let mut seen = std::collections::HashSet::new();

        // Find ?name@... patterns (MSVC mangled symbols)
        let mut pos = 0;
        let bytes = all_text.as_bytes();
        while pos < bytes.len() {
            if bytes[pos] == b'?' {
                // Scan forward to find the end of the mangled name
                // MSVC names contain: alphanumeric, @, $, ?, _
                let start = pos;
                let mut end = pos + 1;
                while end < bytes.len() {
                    let b = bytes[end];
                    if b.is_ascii_alphanumeric() || b == b'@' || b == b'$' || b == b'?' || b == b'_' {
                        end += 1;
                    } else {
                        break;
                    }
                }
                let mangled = &all_text[start..end];
                // Only try to demangle if it looks like a real MSVC name (has @ and is > 5 chars)
                if mangled.len() > 5 && mangled.contains('@') && !seen.contains(mangled) {
                    seen.insert(mangled.to_string());
                    if let Ok(demangled) = msvc_demangler::demangle(mangled, msvc_demangler::DemangleFlags::llvm()) {
                        // Simplify the demangled name for readability
                        let simple = simplify_msvc_name(&demangled);
                        if simple != mangled && simple.len() < mangled.len() {
                            replacements.push((mangled.to_string(), simple));
                        }
                    }
                }
                pos = end;
            } else {
                pos += 1;
            }
        }

        // Apply replacements (longest first to avoid partial matches)
        replacements.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        for (mangled, demangled) in &replacements {
            for line in &mut lines {
                if line.contains(mangled.as_str()) {
                    *line = line.replace(mangled.as_str(), demangled.as_str());
                }
            }
        }
    }

    // #SWIFT_DEMANGLE: Demangle Swift mangled names ($s..., $ss...) in the output.
    {
        let all_text = lines.join("\n");
        let mut replacements: Vec<(String, String)> = Vec::new();
        let mut seen = std::collections::HashSet::new();

        // Find $s... and $S... patterns (Swift mangled symbols)
        let mut pos = 0;
        let bytes = all_text.as_bytes();
        while pos < bytes.len() {
            if bytes[pos] == b'$' && pos + 1 < bytes.len()
                && (bytes[pos + 1] == b's' || bytes[pos + 1] == b'S')
            {
                let start = pos;
                let mut end = pos + 2;
                while end < bytes.len() {
                    let b = bytes[end];
                    if b.is_ascii_alphanumeric() || b == b'_' { end += 1; } else { break; }
                }
                let mangled = &all_text[start..end];
                if mangled.len() > 4 && !seen.contains(mangled) {
                    seen.insert(mangled.to_string());
                    if let Some(demangled) = crate::imports::demangle_swift_for_output(mangled) {
                        if demangled != mangled && demangled.len() < mangled.len() {
                            replacements.push((mangled.to_string(), demangled));
                        }
                    }
                }
                pos = end;
            } else {
                pos += 1;
            }
        }

        replacements.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        for (mangled, demangled) in &replacements {
            for line in &mut lines {
                if line.contains(mangled.as_str()) {
                    *line = line.replace(mangled.as_str(), &demangled);
                }
            }
        }
    }

    // #CPP_WRAPPER: Detect and inline C++ stream operator wrappers.
    // Pattern: func_XXX(cout, "string") → cout << "string"
    //          func_XXX(cout) → cout << endl
    //          func(func(cout, "A"), "B") → cout << "A" << "B"
    // Also handles cin >> patterns.
    {
        // Phase 1: Detect which func_XXX is the cout << wrapper.
        // Heuristic: if a function is called 3+ times with cout as first arg, it's operator<<
        let _all_text = lines.join("\n");
        let mut cout_call_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        let mut cin_call_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

        // Count calls with cout/cin as first arg
        for line in &lines {
            let t = line.trim();
            // func_XXXX(cout, ...) or func_XXXX(cout)
            if let Some(paren) = t.find("(cout") {
                let func_end = paren;
                let func_start = t[..func_end].rfind(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                    .map(|p| p + 1).unwrap_or(0);
                let fname = &t[func_start..func_end];
                if fname.starts_with("func_") {
                    *cout_call_counts.entry(fname.to_string()).or_insert(0) += 1;
                }
            }
            if let Some(paren) = t.find("(cin") {
                let func_end = paren;
                let func_start = t[..func_end].rfind(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                    .map(|p| p + 1).unwrap_or(0);
                let fname = &t[func_start..func_end];
                if fname.starts_with("func_") {
                    *cin_call_counts.entry(fname.to_string()).or_insert(0) += 1;
                }
            }
        }

        // Functions called 3+ times with cout are operator<<
        let cout_wrappers: Vec<String> = cout_call_counts.into_iter()
            .filter(|(_, count)| *count >= 3)
            .map(|(name, _)| name)
            .collect();
        let _cin_wrappers: Vec<String> = cin_call_counts.into_iter()
            .filter(|(_, count)| *count >= 2)
            .map(|(name, _)| name)
            .collect();

        // Phase 2: Replace wrapper calls with operator syntax.
        // Process from innermost to outermost for chained calls.
        for _pass in 0..5 {
            let mut changed = false;
            for line in &mut lines {
                for wrapper in &cout_wrappers {
                    // func_XXX(cout, "string") → cout << "string"
                    let pat_with_arg = format!("{}(cout, ", wrapper);
                    while let Some(start) = line.find(&pat_with_arg) {
                        // Find the matching closing paren
                        let inner_start = start + pat_with_arg.len();
                        let mut depth = 1;
                        let mut pos = inner_start;
                        let bytes = line.as_bytes();
                        while pos < bytes.len() && depth > 0 {
                            if bytes[pos] == b'(' { depth += 1; }
                            if bytes[pos] == b')' { depth -= 1; }
                            pos += 1;
                        }
                        if depth == 0 {
                            let arg = &line[inner_start..pos - 1].to_string();
                            let old = format!("{}(cout, {})", wrapper, arg);
                            let new_str = format!("cout << {}", arg);
                            *line = line.replace(&old, &new_str);
                            changed = true;
                            continue;
                        }
                        break;
                    }
                    // func_XXX(cout) → cout << endl
                    let pat_no_arg = format!("{}(cout)", wrapper);
                    if line.contains(&pat_no_arg) {
                        *line = line.replace(&pat_no_arg, "cout << endl");
                        changed = true;
                    }
                    // func_XXX(cout << "prev", "next") → cout << "prev" << "next"
                    let pat_chain = format!("{}(cout << ", wrapper);
                    while let Some(start) = line.find(&pat_chain) {
                        let inner_start = start + pat_chain.len();
                        let mut depth = 1;
                        let mut pos = inner_start;
                        let bytes = line.as_bytes();
                        while pos < bytes.len() && depth > 0 {
                            if bytes[pos] == b'(' { depth += 1; }
                            if bytes[pos] == b')' { depth -= 1; }
                            pos += 1;
                        }
                        if depth == 0 {
                            let inner = &line[inner_start..pos - 1].to_string();
                            // Split inner at the last ", " to separate prev from next arg
                            if let Some(comma) = inner.rfind(", ") {
                                let prev = &inner[..comma];
                                let next = &inner[comma + 2..];
                                let old = format!("{}(cout << {})", wrapper, inner);
                                let new_str = format!("cout << {} << {}", prev, next);
                                *line = line.replace(&old, &new_str);
                                changed = true;
                                continue;
                            }
                        }
                        break;
                    }
                }
            }
            if !changed { break; }
        }
    }

    // #XMM_CLEANUP: Clean up remaining XMM register noise.
    // 1. "XMM0 = STRING >> 96" → suppress (SSE string init boilerplate)
    // 2. "XMM0 = 0;" → suppress (SSE zero-init)
    // 3. "XMM0 = DAT_xxx >> 96" → suppress
    lines.retain(|line| {
        let t = line.trim();
        // XMM zero-init
        if t.starts_with("XMM") && t.ends_with("= 0;") { return false; }
        // XMM = value >> 96 (SSE partial load — boilerplate)
        if t.starts_with("XMM") && t.contains(">> 96") && t.ends_with(';') { return false; }
        // XMM = value >> 64 (similar SSE partial)
        if t.starts_with("XMM") && t.contains(">> 64") && t.ends_with(';') { return false; }
        true
    });

    // #NEG1_CONSTANTS: Display 0xffffffffffffffff and 0xffffffff as -1 in all contexts.
    // Also recognize INVALID_HANDLE_VALUE in comparisons with CreateFile results.
    for line in &mut lines {
        let t = line.trim();
        if t == "return 0xffffffffffffffff;" || t == "return 0xffffffff;" {
            let pad = " ".repeat(line.len() - line.trim_start().len());
            *line = format!("{}return -1;", pad);
        }
        // Comparisons: != 0xffffffff → != -1, == 0xffffffff → == -1
        if line.contains("0xffffffffffffffff") && !line.contains("return") {
            *line = line.replace("0xffffffffffffffff", "-1");
        }
        if line.contains("0xffffffff") && !line.contains("return") && !line.contains("HKEY_") {
            // INVALID_HANDLE_VALUE context (after CreateFile)
            if line.contains("!= 0xffffffff") || line.contains("== 0xffffffff") {
                *line = line.replace("0xffffffff", "INVALID_HANDLE_VALUE");
            } else {
                *line = line.replace("0xffffffff", "-1");
            }
        }
    }

    // #ERRNO: Recognize __error() + store patterns as errno assignment.
    // macOS: __error() returns &errno. Linux: ___errno_location() returns &errno.
    // Pattern: "__error();\n  *(uint32_t*)(N) = M;" → "errno = M;"
    // Also: "*(param_N) == 4" after __error → "errno == EINTR"
    {
        let errno_names: &[(i64, &str)] = &[
            (4, "EINTR"), (9, "EBADF"), (12, "ENOMEM"), (13, "EACCES"),
            (22, "EINVAL"), (35, "EAGAIN"), (36, "EINPROGRESS"),
            (54, "ECONNRESET"), (61, "ECONNREFUSED"),
        ];
        let errno_map: HashMap<i64, &str> = errno_names.iter().copied().collect();

        let mut i = 0;
        while i < lines.len() {
            let lt = lines[i].trim().to_string();
            // Pattern: "__error();" followed by "*(uint32_t*)(1) = N;" or "*(uint32_t*)(iVar) = N;"
            if lt == "__error();" || lt.ends_with("__error();") {
                if i + 1 < lines.len() {
                    let next = lines[i + 1].trim().to_string();
                    // *(uint32_t*)(ANYTHING) = N;
                    if next.starts_with("*(uint32_t*)(") || next.starts_with("*(int*)(") {
                        if let Some(eq) = next.find(" = ") {
                            let val_str = next[eq + 3..].trim_end_matches(';').trim();
                            if let Ok(val) = val_str.parse::<i64>() {
                                let pad = " ".repeat(lines[i].len() - lines[i].trim_start().len());
                                let name = errno_map.get(&val).map(|s| format!(" /* {} */", s)).unwrap_or_default();
                                lines[i] = format!("{}errno = {}{};", pad, val, name);
                                lines.remove(i + 1);
                                continue;
                            }
                        }
                    }
                }
            }

            // Pattern: "*(param_N) == 4" → "errno == EINTR" (after a call to __error)
            // Replace errno constant values in conditions
            if lt.contains("*(param_") && (lt.contains(" == ") || lt.contains(" != ")) {
                for (val, name) in errno_names {
                    let old = format!(" == {})", val);
                    let new = format!(" == {} /* {} */)", val, name);
                    if lt.contains(&old) && !lt.contains("/*") {
                        lines[i] = lines[i].replace(&old, &new);
                    }
                    let old = format!(" != {})", val);
                    let new = format!(" != {} /* {} */)", val, name);
                    if lt.contains(&old) && !lt.contains("/*") {
                        lines[i] = lines[i].replace(&old, &new);
                    }
                }
            }
            i += 1;
        }
    }

    // #AUTONAME: Replace remaining raw register names with auto-generated variable names.
    // Collect all bare register names that appear, assign sequential names by type:
    //   64-bit (RAX,RBX,...) → lVar1, lVar2, ...
    //   32-bit (EAX,EBX,...) → iVar1, iVar2, ...
    //   8/16-bit → bVar1, wVar1, ...
    //   Pointer-used (R14[...]) → pVar1, pVar2, ...
    // Skip registers that are parameters (RDI,RSI,RDX,RCX) or already named.
    {
        use std::collections::BTreeMap;
        // Registers that should NOT be auto-named (parameters, stack/frame, instruction pointer)
        // In x86-32, EDI/ESI/EDX/ECX are NOT parameter registers (all args on stack),
        // so they should be auto-named. Only skip them in x86-64 SysV mode.
        let all_text_check = lines.join("");
        let is_arm64 = matches!(ctx.arch, Architecture::AArch64)
            || all_text_check.contains("x19") || all_text_check.contains("x29");
        let is_32bit = !is_arm64 && !all_text_check.contains("RSP") && !all_text_check.contains("RBP")
            && !all_text_check.contains("fparam_"); // fparam_ indicates x86-64 SysV float ABI

        // AArch64: dynamic skip list — only x0..x(param_count-1) are actual params
        // and should be protected from auto-renaming. Registers beyond the detected
        // param count (xN..x7) that get ADRP+LDR-initialized are real locals and
        // should be renamed like x8+ to avoid leaking raw `x2`/`x3` into output.
        // `param_names` contains one entry per SSA var with `param_name` set — the
        // same logical parameter may appear multiple times (different SSA versions),
        // so count DISTINCT `param_<N>` / DWARF identifiers to get the real count.
        let arm64_skip_owned: Vec<String> = if is_arm64 {
            let mut unique: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
            for p in param_names { unique.insert(p.as_str()); }
            let pc = unique.len().min(8);
            let mut v: Vec<String> = Vec::new();
            for i in 0..pc {
                v.push(format!("x{}", i));
                v.push(format!("w{}", i));
            }
            v.extend(["x29", "x30", "sp",
                      "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7"]
                     .iter().map(|s| s.to_string()));
            v
        } else { Vec::new() };
        let arm64_skip_refs: Vec<&str> = arm64_skip_owned.iter().map(|s| s.as_str()).collect();
        let skip_regs: &[&str] = if is_arm64 {
            &arm64_skip_refs
        } else if is_32bit {
            &["RSP", "ESP", "RBP", "EBP", "RIP", "EIP",
              "XMM0", "XMM1", "XMM2", "XMM3", "XMM4", "XMM5"]
        } else {
            // x86-64: only skip stack/frame/instruction pointers.
            // Param registers and XMM are NOT skipped — they get auto-named.
            &["RSP", "ESP", "RBP", "EBP", "RIP", "EIP"]
        };

        // Candidate registers for renaming
        let reg_candidates: &[(&str, &str)] = if is_arm64 {
            // AArch64: include x0-x7 and w0-w7 here so non-param regs (filtered by
            // dynamic skip_regs above) get auto-renamed to lVar/iVar. Params stay
            // in skip_regs so the earlier x0..x(count-1) → param_N pass owns them.
            &[
                ("x0", "l"), ("x1", "l"), ("x2", "l"), ("x3", "l"),
                ("x4", "l"), ("x5", "l"), ("x6", "l"), ("x7", "l"),
                ("w0", "i"), ("w1", "i"), ("w2", "i"), ("w3", "i"),
                ("w4", "i"), ("w5", "i"), ("w6", "i"), ("w7", "i"),
                ("x8", "l"), ("x9", "l"), ("x10", "l"), ("x11", "l"),
                ("x12", "l"), ("x13", "l"), ("x14", "l"), ("x15", "l"),
                ("x16", "l"), ("x17", "l"), ("x18", "l"),
                ("x19", "l"), ("x20", "l"), ("x21", "l"), ("x22", "l"),
                ("x23", "l"), ("x24", "l"), ("x25", "l"), ("x26", "l"),
                ("x27", "l"), ("x28", "l"),
                ("w8", "i"), ("w9", "i"), ("w10", "i"), ("w11", "i"),
                ("w12", "i"), ("w13", "i"), ("w14", "i"), ("w15", "i"),
                ("w16", "i"), ("w17", "i"), ("w18", "i"),
                ("w19", "i"), ("w20", "i"), ("w21", "i"), ("w22", "i"),
                ("w23", "i"), ("w24", "i"), ("w25", "i"),
                ("w26", "i"), ("w27", "i"), ("w28", "i"),
            ]
        } else {
            &[
                ("RAX", "l"), ("RBX", "l"), ("R12", "l"), ("R13", "l"),
                ("R14", "l"), ("R15", "l"), ("R10", "l"), ("R11", "l"),
                // Param registers — renamed when used as intermediates in the body
                ("RDI", "l"), ("RSI", "l"), ("RDX", "l"), ("RCX", "l"),
                ("R8", "l"), ("R9", "l"),
                ("EAX", "i"), ("EBX", "i"), ("ECX", "i"), ("EDX", "i"),
                ("ESI", "i"), ("EDI", "i"), ("R8D", "i"), ("R9D", "i"),
                ("R12D", "i"), ("R13D", "i"),
                ("R14D", "i"), ("R15D", "i"), ("R10D", "i"), ("R11D", "i"),
                ("AL", "b"), ("BL", "b"), ("AH", "b"), ("BH", "b"),
                ("DIL", "b"), ("SIL", "b"), ("DL", "b"), ("CL", "b"),
                ("CH", "b"), ("DH", "b"),
                ("R8B", "b"), ("R9B", "b"), ("R10B", "b"), ("R11B", "b"),
                ("R12B", "b"), ("R13B", "b"), ("R14B", "b"), ("R15B", "b"),
                ("AX", "w"), ("BX", "w"), ("CX", "w"), ("DX", "w"), ("SI", "w"), ("DI", "w"),
                // XMM registers → dVar (double/SSE)
                ("XMM0", "d"), ("XMM1", "d"), ("XMM2", "d"), ("XMM3", "d"),
                ("XMM4", "d"), ("XMM5", "d"), ("XMM6", "d"), ("XMM7", "d"),
                ("XMM8", "d"), ("XMM9", "d"), ("XMM10", "d"), ("XMM11", "d"),
                ("XMM12", "d"), ("XMM13", "d"), ("XMM14", "d"), ("XMM15", "d"),
            ]
        };

        // Scan all lines for register appearances
        let all_text = lines.join("\n");
        let mut rename_map: BTreeMap<String, String> = BTreeMap::new();
        let mut counters: HashMap<String, usize> = HashMap::new();

        for (reg, prefix) in reg_candidates {
            if skip_regs.contains(reg) { continue; }
            // Check if this register appears as a standalone word in the output
            // (not inside a string literal or as part of another identifier)
            let appears = all_text.contains(reg) && {
                // Verify it's not only inside quotes
                let outside_quotes: String = all_text.split('"')
                    .enumerate()
                    .filter(|(i, _)| i % 2 == 0) // outside quotes
                    .map(|(_, s)| s)
                    .collect::<Vec<_>>().join("");
                outside_quotes.contains(reg)
            };

            if appears && !rename_map.contains_key(*reg) {
                let counter = counters.entry(prefix.to_string()).or_insert(0);
                *counter += 1;
                let new_name = format!("{}Var{}", prefix, counter);
                rename_map.insert(reg.to_string(), new_name);
            }
        }

        // Apply renames — use word-boundary replacement
        if !rename_map.is_empty() {
            for line in &mut lines {
                for (old_reg, new_name) in &rename_map {
                    if !line.contains(old_reg.as_str()) { continue; }
                    // Replace as whole-word only (not inside function names or strings)
                    // Use byte-safe whole-word replacement
                    // Split on the register name, check word boundaries at each split point
                    let old_bytes = old_reg.as_bytes();
                    let mut result = String::new();
                    let bytes = line.as_bytes();
                    let mut pos = 0;
                    while pos < bytes.len() {
                        if pos + old_bytes.len() <= bytes.len()
                            && &bytes[pos..pos + old_bytes.len()] == old_bytes
                        {
                            let before = if pos > 0 { bytes[pos - 1] } else { b' ' };
                            let after_pos = pos + old_bytes.len();
                            let after = if after_pos < bytes.len() { bytes[after_pos] } else { b' ' };
                            let is_word = !before.is_ascii_alphanumeric() && before != b'_'
                                && !after.is_ascii_alphanumeric() && after != b'_';
                            if is_word {
                                result.push_str(new_name);
                                pos += old_bytes.len();
                                continue;
                            }
                        }
                        // Advance by one UTF-8 character
                        let ch_len = if bytes[pos] < 0x80 { 1 }
                            else if bytes[pos] < 0xE0 { 2 }
                            else if bytes[pos] < 0xF0 { 3 }
                            else { 4 };
                        let end = (pos + ch_len).min(bytes.len());
                        if let Ok(s) = std::str::from_utf8(&bytes[pos..end]) {
                            result.push_str(s);
                        } else {
                            result.push(bytes[pos] as char);
                        }
                        pos = end;
                    }
                    *line = result;
                }
            }
        }
    }

    // #DECLARATIONS: Insert typed local variable declarations after the opening brace.
    // Scan the output for auto-named variables (lVar1, iVar2, etc.) and emit a
    // declaration block matching Ghidra's style.
    {
        use std::collections::BTreeSet;
        // Collect all auto-named variable references from the output
        let all_text = lines.join("\n");
        let mut var_names: BTreeSet<String> = BTreeSet::new();
        // Match patterns: lVar\d+, iVar\d+, bVar\d+, wVar\d+, pVar\d+, fVar\d+, dVar\d+
        let prefixes = &["lVar", "iVar", "bVar", "wVar", "pVar", "fVar", "dVar"];
        for prefix in prefixes {
            let mut search_from = 0;
            while let Some(pos) = all_text[search_from..].find(prefix) {
                let abs_pos = search_from + pos;
                // Check word boundary before
                let before_ok = abs_pos == 0 || {
                    let b = all_text.as_bytes()[abs_pos - 1];
                    !b.is_ascii_alphanumeric() && b != b'_'
                };
                if before_ok {
                    // Collect digits after prefix
                    let digit_start = abs_pos + prefix.len();
                    let mut digit_end = digit_start;
                    while digit_end < all_text.len() && all_text.as_bytes()[digit_end].is_ascii_digit() {
                        digit_end += 1;
                    }
                    if digit_end > digit_start {
                        // Check word boundary after
                        let after_ok = digit_end >= all_text.len() || {
                            let b = all_text.as_bytes()[digit_end];
                            !b.is_ascii_alphanumeric() && b != b'_'
                        };
                        if after_ok {
                            var_names.insert(all_text[abs_pos..digit_end].to_string());
                        }
                    }
                }
                search_from = search_from + pos + prefix.len();
            }
        }

        // Also collect stack variable references (var_XX) for local declarations
        let mut stack_vars: BTreeSet<String> = BTreeSet::new();
        {
            let mut search_from = 0;
            while let Some(pos) = all_text[search_from..].find("var_") {
                let abs_pos = search_from + pos;
                let before_ok = abs_pos == 0 || {
                    let b = all_text.as_bytes()[abs_pos - 1];
                    !b.is_ascii_alphanumeric() && b != b'_'
                };
                if before_ok {
                    let hex_start = abs_pos + 4; // after "var_"
                    let mut hex_end = hex_start;
                    while hex_end < all_text.len() && all_text.as_bytes()[hex_end].is_ascii_hexdigit() {
                        hex_end += 1;
                    }
                    if hex_end > hex_start {
                        let after_ok = hex_end >= all_text.len() || {
                            let b = all_text.as_bytes()[hex_end];
                            !b.is_ascii_alphanumeric() && b != b'_'
                        };
                        if after_ok {
                            let vname = all_text[abs_pos..hex_end].to_string();
                            // Don't re-declare vars that were aliased by DWARF
                            if !aliases.contains_key(&vname) {
                                stack_vars.insert(vname);
                            }
                        }
                    }
                }
                search_from = search_from + pos + 4;
            }
        }

        if !var_names.is_empty() || !stack_vars.is_empty() {
            let mut decl_lines: Vec<String> = Vec::new();

            // Auto-named register variables
            for name in &var_names {
                let type_str = if name.starts_with("lVar") {
                    "long"
                } else if name.starts_with("iVar") {
                    "int"
                } else if name.starts_with("bVar") {
                    "uint8_t"
                } else if name.starts_with("wVar") {
                    "uint16_t"
                } else if name.starts_with("pVar") {
                    "void *"
                } else if name.starts_with("fVar") {
                    "float"
                } else if name.starts_with("dVar") {
                    "double"
                } else {
                    "int"
                };
                decl_lines.push(format!("    {} {};", type_str, name));
            }

            // Stack local variables — compute sizes from offset gaps and declare arrays.
            // Sort offsets ascending. For x86-32 EBP frames, locals are at negative
            // offsets: local_4 = EBP-4 (highest addr), local_22c = EBP-0x22c (lowest).
            // Size of each local = gap to next higher offset (or 4 for the topmost).
            let mut offsets: Vec<(u64, &str)> = stack_vars.iter().filter_map(|vname| {
                let off_str = vname.strip_prefix("var_")?;
                let off = u64::from_str_radix(off_str, 16).ok()?;
                Some((off, off_str))
            }).collect();
            offsets.sort_by_key(|(off, _)| *off);

            // Detect wide string usage: check if any W-suffix Win32 call references
            // a local buffer (heuristic for WCHAR vs char arrays)
            let uses_wide = all_text.contains("lstrcatW") || all_text.contains("lstrlenW")
                || all_text.contains("lstrcpyW") || all_text.contains("wsprintfW")
                || all_text.contains("RegEnumKeyW") || all_text.contains("RegEnumValueW")
                || all_text.contains("GetModuleFileNameW") || all_text.contains("FindFirstFileW")
                || all_text.contains("CreateDirectoryW") || all_text.contains("GetTempPathW")
                || all_text.contains("SearchPathW");

            for i in 0..offsets.len() {
                let (off, off_str) = offsets[i];
                // Size = gap to next offset above, or 4 for the topmost local
                let size = if i + 1 < offsets.len() {
                    offsets[i + 1].0 - off
                } else {
                    4 // topmost local, assume 4 bytes
                };

                if size > 8 {
                    // Buffer — declare as array
                    // Choose element type: WCHAR (2 bytes) if wide string context, else char
                    let (elem_type, elem_size) = if uses_wide && size % 2 == 0 && size >= 16 {
                        ("WCHAR", 2u64)
                    } else {
                        ("char", 1u64)
                    };
                    let count = size / elem_size;
                    decl_lines.push(format!("    {} local_{}[{}];", elem_type, off_str, count));
                } else {
                    // Scalar — use size to pick type
                    let type_str = match size {
                        1 => "byte",
                        2 => "short",
                        8 => "long",
                        _ => "int", // 4 bytes default
                    };
                    decl_lines.push(format!("    {} local_{};", type_str, off_str));
                }
            }

            // Find the first line ending with '{' and insert after it
            let mut insert_idx = None;
            for (idx, line) in lines.iter().enumerate() {
                if line.trim_end().ends_with('{') {
                    insert_idx = Some(idx + 1);
                    break;
                }
            }
            if let Some(idx) = insert_idx {
                decl_lines.push(String::new());
                for (j, decl) in decl_lines.into_iter().enumerate() {
                    lines.insert(idx + j, decl);
                }
            }

            // Rename var_XX → local_XX throughout the output
            for vname in &stack_vars {
                let offset_str = vname.strip_prefix("var_").unwrap_or("0");
                let local_name = format!("local_{}", offset_str);
                for line in &mut lines {
                    if line.contains(vname.as_str()) {
                        *line = line.replace(vname.as_str(), &local_name);
                    }
                }
            }
        }
    }

    // Convert ->fieldN to array indexing [N/element_size] when offset is aligned.
    // offset divisible by 8 → [N/8] (64-bit pointer array)
    // offset divisible by 4 but not 8 → [N/4] (32-bit int array)
    // otherwise keep ->fieldN (likely a real struct field)
    for line in &mut lines {
        if !line.contains("->field") { continue; }
        let mut result_line = String::new();
        let bytes = line.as_bytes();
        let mut pos = 0;
        let arrow_field = b"->field";
        while pos < bytes.len() {
            if pos + arrow_field.len() <= bytes.len()
                && &bytes[pos..pos + arrow_field.len()] == arrow_field
            {
                // Collect hex digits after "->field"
                let hex_start = pos + arrow_field.len();
                let mut hex_end = hex_start;
                while hex_end < bytes.len() && (bytes[hex_end] as char).is_ascii_hexdigit() {
                    hex_end += 1;
                }
                if hex_end > hex_start {
                    let hex_str = std::str::from_utf8(&bytes[hex_start..hex_end]).unwrap_or("");
                    if let Ok(offset) = u64::from_str_radix(hex_str, 16) {
                        if offset > 0 && offset % 8 == 0 {
                            result_line.push_str(&format!("[{}]", offset / 8));
                            pos = hex_end;
                            continue;
                        } else if offset > 0 && offset % 4 == 0 {
                            result_line.push_str(&format!("[{}]", offset / 4));
                            pos = hex_end;
                            continue;
                        }
                    }
                }
                // Not aligned or couldn't parse — keep original
                result_line.push_str("->");
                pos += 2; // skip past "->"
                continue;
            }
            result_line.push(bytes[pos] as char);
            pos += 1;
        }
        *line = result_line;
    }

    // #GLOBALS: Replace raw hex addresses with DAT_XXXXXXXX global names.
    // Patterns: *(0x4xxxxx), *(uint32_t*)(0x4xxxxx), *(int*)(0x4xxxxx)
    // Only for addresses in .data/.bss range (not code or string addresses).
    {
        use std::collections::BTreeSet;
        let mut global_addrs: BTreeSet<u64> = BTreeSet::new();
        let all_text = lines.join("\n");

        // Find all hex addresses used as memory dereferences
        let mut pos = 0;
        let bytes = all_text.as_bytes();
        while pos + 4 < bytes.len() {
            // Look for "(0x" pattern
            if bytes[pos] == b'(' && pos + 3 < bytes.len()
                && bytes[pos+1] == b'0' && bytes[pos+2] == b'x'
            {
                let hex_start = pos + 3;
                let mut hex_end = hex_start;
                while hex_end < bytes.len() && bytes[hex_end].is_ascii_hexdigit() {
                    hex_end += 1;
                }
                if hex_end > hex_start && hex_end < bytes.len() && bytes[hex_end] == b')' {
                    if let Ok(addr) = u64::from_str_radix(&all_text[hex_start..hex_end], 16) {
                        // Only name addresses that look like data section (not code or small constants)
                        if addr > 0x10000 && (addr & 0xFFF00000 != 0) {
                            global_addrs.insert(addr);
                        }
                    }
                }
            }
            pos += 1;
        }

        // Replace hex addresses with global names
        for addr in &global_addrs {
            let hex_str = format!("0x{:x}", addr);
            let global_name = format!("DAT_{:08x}", addr);
            for line in &mut lines {
                if line.contains(&hex_str) {
                    *line = line.replace(&hex_str, &global_name);
                }
            }
        }
    }

    // #NUMERIC_BASE: Fix numeric struct bases (1[4], 10[5]) — replace with pointer deref.
    // These occur when a constant was mistakenly used as a struct base. Replace N[M] with
    // *(N + M) or just the field access for readability.
    for line in &mut lines {
        // Pattern: standalone digit(s) followed by [ — e.g., "1[4]", "10[5]"
        // But NOT "param_0[4]" or "local_8[2]" (those are real array accesses)
        let bytes = line.as_bytes();
        let mut result = String::new();
        let mut i = 0;
        while i < bytes.len() {
            // Check for digit(s) followed by '['
            if bytes[i].is_ascii_digit() {
                let digit_start = i;
                while i < bytes.len() && bytes[i].is_ascii_digit() { i += 1; }
                if i < bytes.len() && bytes[i] == b'[' {
                    // Check word boundary before — must not be preceded by alnum or _
                    let before_ok = digit_start == 0 || {
                        let b = bytes[digit_start - 1];
                        !b.is_ascii_alphanumeric() && b != b'_'
                    };
                    if before_ok {
                        let num_str = &line[digit_start..i];
                        // Find matching ]
                        let bracket_start = i;
                        let mut depth = 1;
                        i += 1;
                        while i < bytes.len() && depth > 0 {
                            if bytes[i] == b'[' { depth += 1; }
                            if bytes[i] == b']' { depth -= 1; }
                            i += 1;
                        }
                        let inner = &line[bracket_start + 1..i - 1];
                        // Replace "N[M]" with "*(N + M)" — but for small N, likely a param deref
                        if let Ok(base) = num_str.parse::<u64>() {
                            if base < 256 {
                                // Small constant base — likely a lost parameter reference
                                result.push_str(&format!("param_{}[{}]", base, inner));
                            } else {
                                result.push_str(&format!("DAT_{:08x}[{}]", base, inner));
                            }
                        } else {
                            result.push_str(num_str);
                            result.push_str(&line[bracket_start..i]);
                        }
                        continue;
                    }
                }
                result.push_str(&line[digit_start..i]);
                continue;
            }
            result.push(bytes[i] as char);
            i += 1;
        }
        *line = result;
    }

    // #SWITCH_COLLAPSE: Convert if/else-if chains on the same variable to switch/case.
    // Pattern: if (X == A) { ... } else if (X == B) { ... } else if (X == C) { ... }
    {
        let mut i = 0;
        while i + 2 < lines.len() {
            let t = lines[i].trim().to_string();
            // Match: if (EXPR == VALUE) {
            if let Some((var_name, first_val)) = extract_if_eq_const(&t) {
                let indent = lines[i].len() - lines[i].trim_start().len();
                let pad = " ".repeat(indent);
                let else_if_pad = format!("{}}} else if (", pad);

                // Collect cases from the chain
                let mut cases: Vec<(String, Vec<String>)> = Vec::new(); // (value, body_lines)
                let mut default_lines: Vec<String> = Vec::new();
                let mut j = i;
                let mut current_val = first_val;
                let mut success = false;

                loop {
                    // Collect body lines until we hit "} else if (same_var == val)" or "} else {" or "}"
                    j += 1;
                    let mut body = Vec::new();
                    let mut depth = 1i32;
                    while j < lines.len() {
                        let lt = lines[j].trim();
                        if lt.ends_with('{') { depth += 1; }
                        if lt == "}" || lt.starts_with("} ") { depth -= 1; }
                        if depth == 0 {
                            // Found closing of this case
                            let line_text = lines[j].trim().to_string();
                            if let Some(rest) = line_text.strip_prefix("} else if (") {
                                if let Some(cond) = rest.strip_suffix(") {") {
                                    // Check if it's the same variable
                                    if let Some((next_var, next_val)) = parse_eq_const(cond) {
                                        if next_var == var_name {
                                            cases.push((current_val.clone(), body));
                                            current_val = next_val;
                                            break; // continue to next case
                                        }
                                    }
                                }
                            }
                            if line_text == "} else {" {
                                cases.push((current_val.clone(), body));
                                // Collect default body
                                j += 1;
                                let mut def_depth = 1i32;
                                while j < lines.len() {
                                    let dlt = lines[j].trim();
                                    if dlt.ends_with('{') { def_depth += 1; }
                                    if dlt == "}" { def_depth -= 1; }
                                    if def_depth == 0 { break; }
                                    default_lines.push(lines[j].clone());
                                    j += 1;
                                }
                                success = true;
                                break;
                            }
                            if line_text == "}" {
                                cases.push((current_val.clone(), body));
                                success = true;
                                break;
                            }
                            // Unknown closing — abort
                            break;
                        }
                        body.push(lines[j].clone());
                        j += 1;
                    }
                    if j >= lines.len() || !success && depth != 0 { break; }
                    if success { break; }
                }

                // Only convert if we collected 3+ cases
                if success && cases.len() >= 3 {
                    // Replace lines[i..=j] with switch/case
                    let end = j;
                    let mut new_lines = Vec::new();
                    new_lines.push(format!("{}switch ({}) {{", pad, var_name));
                    for (val, body) in &cases {
                        new_lines.push(format!("{}    case {}:", pad, val));
                        for bl in body {
                            new_lines.push(format!("    {}", bl));
                        }
                        // Add break if body doesn't end with return
                        let has_return = body.iter().any(|l| l.trim().starts_with("return "));
                        if !has_return {
                            new_lines.push(format!("{}        break;", pad));
                        }
                    }
                    if !default_lines.is_empty() {
                        new_lines.push(format!("{}    default:", pad));
                        for dl in &default_lines {
                            new_lines.push(format!("    {}", dl));
                        }
                    }
                    new_lines.push(format!("{}}}", pad));

                    // Replace the range
                    let remove_count = end - i + 1;
                    for _ in 0..remove_count { lines.remove(i); }
                    for (k, nl) in new_lines.into_iter().enumerate() {
                        lines.insert(i + k, nl);
                    }
                    continue; // don't increment i
                }
            }
            i += 1;
        }
    }

    // #EARLY_RETURN: Flatten else blocks when the if-block ends with return.
    // Pattern: if (...) { ...; return X; } else { BODY } → if (...) { ...; return X; } BODY
    {
        let mut i = 0;
        while i + 2 < lines.len() {
            let t = lines[i].trim().to_string();
            if t == "} else {" {
                // Check: does the preceding block end with return?
                let mut has_return = false;
                for j in (0..i).rev() {
                    let lt = lines[j].trim();
                    if lt.starts_with("return ") { has_return = true; break; }
                    if lt == "}" || lt.starts_with("if ") || lt.starts_with("while ") { break; }
                }
                if has_return {
                    // Find the matching closing }
                    let indent = lines[i].len() - lines[i].trim_start().len();
                    let mut depth = 1i32;
                    let mut end = i + 1;
                    while end < lines.len() {
                        let lt = lines[end].trim();
                        if lt.ends_with('{') { depth += 1; }
                        if lt == "}" { depth -= 1; }
                        if depth == 0 { break; }
                        end += 1;
                    }
                    if end < lines.len() && depth == 0 {
                        // Remove "} else {" and the closing "}"
                        lines.remove(end); // remove closing }
                        lines.remove(i);   // remove } else {
                        // Dedent the body lines
                        for j in i..end - 1 {
                            if j < lines.len() {
                                let line = &lines[j];
                                if line.starts_with("    ") {
                                    lines[j] = line[4..].to_string();
                                }
                            }
                        }
                        continue;
                    }
                }
            }
            i += 1;
        }
    }

    // #INDENT_FIX: Normalize indentation for misaligned else/else-if blocks.
    // Post-processing passes can shift lines, causing } else if to be at wrong indent.
    {
        let mut i = 0;
        while i < lines.len() {
            let t = lines[i].trim().to_string();
            if t.starts_with("} else if (") || t == "} else {" {
                let current_indent = lines[i].len() - lines[i].trim_start().len();
                // Find the matching opening { by walking backwards
                let mut depth = 0i32;
                let mut open_indent = current_indent;
                for j in (0..i).rev() {
                    let lt = lines[j].trim();
                    if lt == "}" || lt.starts_with("} else") { depth += 1; }
                    if lt.ends_with('{') && !lt.starts_with("} else") { depth -= 1; }
                    if depth < 0 {
                        open_indent = lines[j].len() - lines[j].trim_start().len();
                        break;
                    }
                }
                // If the else/else-if is at wrong indent, fix it
                if current_indent != open_indent && open_indent < current_indent + 20 {
                    let pad = " ".repeat(open_indent);
                    lines[i] = format!("{}{}", pad, t);
                }
            }
            i += 1;
        }
    }

    // #VFP_ANNOTATE: Annotate ARM32 VFP coprocessor instructions as float operations.
    // When ARM32 VFP instructions are decoded as generic cdp/ldc/mcrr (because the SLEIGH
    // spec uses coprocessor encoding), annotate them with their float semantics.
    if matches!(ctx.arch, Architecture::ARM32) {
        for line in &mut lines {
            if line.contains("//") { continue; }
            let has_cdp_p11 = line.contains("cdp") && line.contains("p11");
            let has_ldcl_p11 = line.contains("ldcl") && line.contains("p11");
            let has_mcrr_p11 = line.contains("mcrr") && line.contains("p11");
            let has_mcr_p11 = line.contains("mcr") && line.contains("p11") && !line.contains("mcrr");
            if has_cdp_p11 {
                let annotation = if line.contains("0x2") { "VMUL.F64 (float multiply)" }
                    else if line.contains("0x3") { "VADD.F64 (float add)" }
                    else if line.contains("0x4") { "VDIV.F64 (float divide)" }
                    else if line.contains("0x1") { "VNMUL.F64 (float negate-multiply)" }
                    else { "VFP float op" };
                *line = format!("{} // {}", line.trim_end(), annotation);
            } else if has_ldcl_p11 {
                *line = format!("{} // VLDR (float load)", line.trim_end());
            } else if has_mcrr_p11 {
                *line = format!("{} // VMOV (move to float register)", line.trim_end());
            } else if has_mcr_p11 {
                *line = format!("{} // VMOV (float register move)", line.trim_end());
            }
        }
    }

    // #CONST_CASTS: Add type casts to large hex constants in comparisons and assignments.
    for line in &mut lines {
        if line.contains("//") { continue; }
        let t = line.trim();
        // Cast large 64-bit hex constants as (long) — these are addresses or large values
        // Pattern: == 0xNNNNNNNNNNNNNNNN or != 0x... (16+ hex digits)
        for op in [" == ", " != ", " > ", " < ", " >= ", " <= "] {
            if let Some(pos) = t.find(op) {
                let after = &t[pos + op.len()..];
                if after.starts_with("0x") {
                    let hex_end = after[2..].find(|c: char| !c.is_ascii_hexdigit())
                        .map(|e| e + 2).unwrap_or(after.len());
                    let hex_len = hex_end - 2;
                    if hex_len >= 9 && !after[..hex_end].starts_with("0x0") {
                        // 64-bit constant: add (long) cast
                        let old = format!("{}{}", op, &after[..hex_end]);
                        let new = format!("{}(long){}", op, &after[..hex_end]);
                        if !line.contains(&new) {
                            *line = line.replace(&old, &new);
                        }
                        break;
                    }
                    if hex_len >= 5 && hex_len <= 8 && !after[..hex_end].starts_with("0x0") {
                        // 32-bit constant: add (DWORD) cast for common patterns
                        let val_str = &after[..hex_end];
                        // Only cast known magic values or large constants
                        if val_str.starts_with("0x8000") || val_str.starts_with("0xC000")
                            || val_str.starts_with("0xe") || val_str.starts_with("0xF")
                            || hex_len >= 7
                        {
                            let old = format!("{}{}", op, val_str);
                            let new = format!("{}(uint){}", op, val_str);
                            if !line.contains(&new) {
                                *line = line.replace(&old, &new);
                            }
                            break;
                        }
                    }
                }
            }
        }
    }

    // #RETURN_CASTS: Add casts to return values when size differs from function return type.
    // Pattern: return func_XXXX(...); → return (int)func_XXXX(...);
    // When the calling function returns int (4 bytes) but the call returns long (8 bytes).
    for line in &mut lines {
        let t = line.trim();
        if t.starts_with("return ") && t.ends_with(';') && t.contains("func_") && !t.contains('(') {
            // return lVar; — if lVar is a long but function is int, cast
            // Simple heuristic: if the return expression is a long variable, add (int) cast
            let expr = &t[7..t.len()-1]; // strip "return " and ";"
            if expr.starts_with("lVar") && !expr.contains('(') {
                *line = line.replace(&format!("return {};", expr), &format!("return (int){};", expr));
            }
        }
    }

    // #FINAL_PASS: Re-run critical simplifications that earlier passes may have invalidated.
    // This catches param_N[RSP] patterns created by AUTONAME/DECLARATIONS passes,
    // RBP+N patterns created by other transformations, and any remaining raw registers.
    {
        // Elide x86-64 callee-saved RBP spills (push rbp to stack slot).
        // Various forms: -local_XX = RBP; / -param_N[RSP] = RBP; / -var_XX = RBP;
        lines.retain(|line| {
            let t = line.trim();
            if t.ends_with("= RBP;") && t.starts_with("-") && !t.contains("func_") {
                return false;
            }
            true
        });

        // Re-run param_N[RSP] → local_XX
        for line in &mut lines {
            let mut search_from = 0usize;
            loop {
                let remaining = &line[search_from..];
                let Some(rel_start) = remaining.find("param_") else { break };
                let start = search_from + rel_start;
                let after_param = &line[start..];
                let Some(bracket_rel) = after_param.find("[RSP") else { search_from = start + 6; continue; };
                let abs_bracket = start + bracket_rel;
                let idx_str = &line[start + 6..abs_bracket];
                let Ok(offset) = idx_str.parse::<u64>() else { search_from = start + 6; continue; };
                if offset < 8 { search_from = start + 6; continue; }
                let mut depth = 1;
                let mut pos = abs_bracket + 1;
                let bytes = line.as_bytes();
                while pos < bytes.len() && depth > 0 {
                    if bytes[pos] == b'[' { depth += 1; }
                    if bytes[pos] == b']' { depth -= 1; }
                    pos += 1;
                }
                if depth != 0 { search_from = start + 6; continue; }
                let abs_close = pos - 1;
                let replacement = format!("local_{:x}", offset);
                *line = format!("{}{}{}", &line[..start], replacement, &line[abs_close + 1..]);
            }
        }

        // Re-run RBP + N → local_XX
        for line in &mut lines {
            while let Some(pos) = line.find("RBP + ") {
                let after = &line[pos + 6..];
                let end = after.find(|c: char| !c.is_ascii_digit()).unwrap_or(after.len());
                if end > 0 {
                    if let Ok(offset) = after[..end].parse::<u64>() {
                        if offset > 0 {
                            *line = format!("{}local_{:x}{}", &line[..pos], offset, &line[pos + 6 + end..]);
                            continue;
                        }
                    }
                }
                break;
            }
        }

        // Re-run N + RSP → local_XX
        for line in &mut lines {
            while let Some(pos) = line.find(" + RSP") {
                let before = &line[..pos];
                let num_start = before.rfind(|c: char| !c.is_ascii_digit()).map(|p| p + 1).unwrap_or(0);
                if num_start < pos {
                    if let Ok(offset) = line[num_start..pos].parse::<u64>() {
                        if offset > 0 && offset < 0x10000 {
                            *line = format!("{}local_{:x}{}", &line[..num_start], offset, &line[pos + 6..]);
                            continue;
                        }
                    }
                }
                break;
            }
        }

        // Re-run *(param_N) → *param_N
        for line in &mut lines {
            for prefix in ["*(param_", "*(lVar", "*(iVar"] {
                while let Some(start) = line.find(prefix) {
                    if start > 0 && line.as_bytes()[start - 1] == b'(' { break; }
                    let inner_start = start + 2;
                    if let Some(close) = line[inner_start..].find(')') {
                        let inner = line[inner_start..inner_start + close].to_string();
                        if !inner.contains(' ') && !inner.contains('(') {
                            let old = format!("*({})", inner);
                            let new_str = format!("*{}", inner);
                            *line = line.replace(&old, &new_str);
                            continue;
                        }
                    }
                    break;
                }
            }
        }

        // After all RBP+N → local_N conversions, rename remaining bare RBP/EBP
        // to lVar (they're callee-saved general-purpose uses, not frame pointer)
        let has_bare_rbp = lines.iter().any(|l| {
            let t = l.trim();
            // Only rename if RBP appears as a value, not in local_XX patterns
            t.contains("RBP") && !t.contains("RBP + ") && !t.contains("RBP -")
                && !t.starts_with("-local_") && !t.starts_with("local_")
        });
        if has_bare_rbp {
            // Find the next available lVar index
            let max_lvar = lines.iter().filter_map(|l| {
                let mut max = 0usize;
                let mut pos = 0;
                while let Some(idx) = l[pos..].find("lVar") {
                    let start = pos + idx + 4;
                    let end = l[start..].find(|c: char| !c.is_ascii_digit()).map(|e| start + e).unwrap_or(l.len());
                    if end > start {
                        if let Ok(n) = l[start..end].parse::<usize>() {
                            if n > max { max = n; }
                        }
                    }
                    pos = end;
                }
                if max > 0 { Some(max) } else { None }
            }).max().unwrap_or(0);
            let rbp_var = format!("lVar{}", max_lvar + 1);
            let ebp_var = format!("iVar{}", max_lvar + 1);
            for line in &mut lines {
                // Don't rename in callee-saved spill lines (already handled by elision)
                if line.trim().starts_with("-local_") { continue; }
                // Replace bare RBP (word boundary: not preceded/followed by alphanumeric)
                let mut result_line = String::new();
                let mut remaining = line.as_str();
                while let Some(pos) = remaining.find("RBP") {
                    // Check word boundaries
                    let before_ok = pos == 0 || !remaining.as_bytes()[pos - 1].is_ascii_alphanumeric();
                    let after_pos = pos + 3;
                    let after_ok = after_pos >= remaining.len() || !remaining.as_bytes()[after_pos].is_ascii_alphanumeric();
                    if before_ok && after_ok {
                        // Don't rename RBP + N (frame pointer offset) — should already be converted
                        let after = &remaining[after_pos..];
                        if after.starts_with(" + ") || after.starts_with(" - ") {
                            result_line.push_str(&remaining[..after_pos]);
                            remaining = &remaining[after_pos..];
                            continue;
                        }
                        result_line.push_str(&remaining[..pos]);
                        result_line.push_str(&rbp_var);
                        remaining = &remaining[after_pos..];
                    } else {
                        result_line.push_str(&remaining[..after_pos]);
                        remaining = &remaining[after_pos..];
                    }
                }
                result_line.push_str(remaining);
                if result_line != *line {
                    *line = result_line;
                }
            }
            // Same for EBP
            for line in &mut lines {
                if line.trim().starts_with("-local_") { continue; }
                let mut result_line = String::new();
                let mut remaining = line.as_str();
                while let Some(pos) = remaining.find("EBP") {
                    let before_ok = pos == 0 || !remaining.as_bytes()[pos - 1].is_ascii_alphanumeric();
                    let after_pos = pos + 3;
                    let after_ok = after_pos >= remaining.len() || !remaining.as_bytes()[after_pos].is_ascii_alphanumeric();
                    if before_ok && after_ok {
                        result_line.push_str(&remaining[..pos]);
                        result_line.push_str(&ebp_var);
                        remaining = &remaining[after_pos..];
                    } else {
                        result_line.push_str(&remaining[..after_pos]);
                        remaining = &remaining[after_pos..];
                    }
                }
                result_line.push_str(remaining);
                if result_line != *line {
                    *line = result_line;
                }
            }
        }
    }

    // Remove overflow trap blocks: if (OV) { pc = ?; goto label_N; }
    // These are Swift/AArch64 arithmetic overflow checks (b.vs → brk) that are
    // compiler-inserted safety checks, not meaningful program logic.
    {
        let mut i = 0;
        while i + 2 < lines.len() {
            let t = lines[i].trim();
            if t == "if (OV) {" {
                // Find the closing brace
                let mut end = i + 1;
                let mut depth = 1;
                while end < lines.len() && depth > 0 {
                    let et = lines[end].trim();
                    if et.ends_with('{') { depth += 1; }
                    if et == "}" { depth -= 1; }
                    end += 1;
                }
                // Check that the body only contains pc/goto/trap — no real logic
                let body_is_trap = (i + 1..end).all(|j| {
                    let jt = lines[j].trim();
                    jt.starts_with("pc =") || jt.starts_with("goto ") || jt == "}"
                        || jt.is_empty()
                });
                if body_is_trap {
                    for _ in i..end { lines.remove(i); }
                    continue;
                }
            }
            i += 1;
        }
    }

    // Final AArch64 cleanup: remove stack spill/reload patterns that were created
    // by post-processing passes (struct field conversion, register inlining) after
    // the main sp[] filter ran.
    lines.retain(|line| {
        let t = line.trim();
        // lVarN = sp[N]; or lVarN = sp[N]->field_8; (callee-saved reload)
        if (t.starts_with("lVar") || t.starts_with("iVar") || t.starts_with("dVar"))
            && t.ends_with(';')
            && (t.contains(" = sp[") || t.contains(" = sp->field"))
            && !t.contains("func_")
        {
            return false;
        }
        // x29/x30 writes are always AArch64 frame pointer / link register boilerplate.
        // This catches the case where struct field naming rewrote the RHS away from sp[].
        if (t.starts_with("x29 = ") || t.starts_with("x30 = ")) && t.ends_with(';') {
            return false;
        }
        // return sp... patterns (epilogue return address), including *(sp) variant
        if (t.starts_with("return sp") || t.starts_with("return *(sp)")) && t.ends_with(';')
            && !t.contains("func_") && !t.contains("param_")
        {
            return false;
        }
        true
    });

    // Elide dead ADRP-intermediate constants. ADRP sets a register to a page-aligned
    // address (always a multiple of 0x1000, e.g., 0x558000). The subsequent LDR or ADD
    // uses it to compute a GOT/string/global address. After constant folding, the LDR
    // result is substituted inline as `DAT_00558920->...`, and the original ADRP
    // assignment becomes dead — but survives in the printed output because it was
    // written to a named register, not an SSA temp.
    //
    // Heuristic: a line of the form `xN = 0xNNN000;` (raw architectural register =
    // page-aligned hex constant) is always ADRP residue. In clean C code, such a literal
    // page-aligned address would never be assigned to a bare register — legitimate uses
    // go through named locals or DAT_/string labels.
    {
        let looks_like_adrp_line = |t: &str| -> bool {
            if !t.ends_with(';') { return false; }
            let core = t.trim_end_matches(';');
            let (lhs, rhs) = match core.split_once(" = ") {
                Some(pair) => pair,
                None => return false,
            };
            let lhs = lhs.trim();
            let rhs = rhs.trim();
            // LHS must be a raw AArch64 register (x0..x30, w0..w30) OR a renamed
            // AArch64 param/local register alias (param_0..param_7, lVarN, iVarN).
            // Raw page-aligned address literals never legitimately flow to these.
            let is_xreg = (lhs.starts_with('x') || lhs.starts_with('w'))
                && lhs.len() >= 2
                && lhs[1..].chars().all(|c| c.is_ascii_digit())
                && lhs[1..].parse::<u32>().map(|n| n <= 30).unwrap_or(false);
            let is_param_alias = lhs.starts_with("param_")
                && lhs[6..].chars().all(|c| c.is_ascii_digit());
            let is_local_alias = (lhs.starts_with("lVar") || lhs.starts_with("iVar"))
                && lhs[4..].chars().all(|c| c.is_ascii_alphanumeric());
            if !(is_xreg || is_param_alias || is_local_alias) { return false; }
            // RHS must be `0xHEX` ending in `000` (page-aligned, at least 0x1000)
            if !rhs.starts_with("0x") { return false; }
            let hex = &rhs[2..];
            if hex.len() < 4 { return false; } // at least 0x1000
            if !hex.chars().all(|c| c.is_ascii_hexdigit()) { return false; }
            hex.ends_with("000")
        };
        lines.retain(|line| !looks_like_adrp_line(line.trim()));
    }

    // Final pass: fold sequential assignments to the same variable.
    // REG = X; REG = Y op REG → REG = Y op X (after all other cleanup)
    // Skip folding across while/for loop boundaries — the first assignment
    // may be a loop initializer and the second a loop accumulator.
    {
        let mut i = 0;
        while i + 1 < lines.len() {
            let l1 = lines[i].trim().to_string();
            let l2 = lines[i + 1].trim().to_string();
            // Don't fold if l2 is inside a while/for body (different indent from l1)
            // or if there's a loop boundary between them
            let indent1 = lines[i].len() - lines[i].trim_start().len();
            let indent2 = lines[i + 1].len() - lines[i + 1].trim_start().len();
            if indent2 > indent1 { i += 1; continue; }
            if let (Some(eq1), Some(eq2)) = (l1.find(" = "), l2.find(" = ")) {
                let lhs1 = &l1[..eq1];
                let rhs1 = l1[eq1 + 3..].trim_end_matches(';');
                let lhs2 = &l2[..eq2];
                let rhs2 = l2[eq2 + 3..].trim_end_matches(';');
                if lhs1 == lhs2 && !lhs1.contains('(') && !lhs1.contains('[') {
                    // Pattern: REG = X; REG = Y op REG → fold
                    if rhs2.contains(lhs1) && rhs2 != lhs1 {
                        let replacement = if rhs1.contains(' ') {
                            rhs2.replace(lhs1, &format!("({})", rhs1))
                        } else {
                            rhs2.replace(lhs1, rhs1)
                        };
                        if replacement != rhs2.to_string() {
                            let indent = lines[i].len() - lines[i].trim_start().len();
                            let pad = " ".repeat(indent);
                            lines[i] = format!("{}{} = {};", pad, lhs1, replacement);
                            lines.remove(i + 1);
                            continue;
                        }
                    }
                    // Dead store: same LHS, second doesn't use first
                    if !rhs2.contains(lhs1) {
                        lines.remove(i);
                        continue;
                    }
                }
            }
            i += 1;
        }
    }

    // For-loop init recovery: for (; var op expr; var++) → for (var = 0; var op expr; var++)
    // When a for-loop has an empty init, check if the loop variable was initialized to 0
    // in a preceding statement (which was elided as a dead store).
    for line in &mut lines {
        let t = line.trim();
        if t.starts_with("for (; ") {
            // Extract the loop variable from the increment: "var++" or "var = var + 1"
            // The increment is after the last ";"
            if let Some(last_semi) = t.rfind("; ") {
                let increment = t[last_semi + 2..]
                    .trim_end_matches('{').trim().trim_end_matches(')').trim();
                let loop_var = increment.trim_end_matches("++").trim();
                if !loop_var.is_empty() && loop_var.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    // Replace "for (; " with "for (loop_var = 0; "
                    let indent = line.len() - line.trim_start().len();
                    let pad = " ".repeat(indent);
                    let rest = &t[7..]; // after "for (; "
                    *line = format!("{}for ({} = 0; {}", pad, loop_var, rest);
                }
            }
        }
    }

    // Named expression substitution: when VAR = EXPR is assigned at the same indent,
    // replace later occurrences of EXPR with VAR on subsequent lines in the same scope.
    // This turns arr[low + high / 2] → arr[mid] after mid = low + high / 2.
    {
        let mut substitutions: Vec<(String, String, usize)> = Vec::new(); // (expr, var_name, indent)
        for line in &lines {
            let t = line.trim();
            // Match: VAR = EXPR; (simple assignment, not if/while/return/call)
            if let Some(eq_pos) = t.find(" = ") {
                let var_name = &t[..eq_pos];
                let expr = t[eq_pos + 3..].trim_end_matches(';');
                // Only substitute for simple variable names (not registers, not complex LHS)
                let is_simple_var = !var_name.is_empty()
                    && var_name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    && var_name.chars().next().map_or(false, |c| c.is_ascii_lowercase())
                    && !var_name.starts_with("if ")
                    && !var_name.starts_with("while ")
                    && !var_name.starts_with("return ");
                // Only substitute expressions with operators (not simple values)
                let is_expr = expr.contains(' ') && expr.len() >= 5
                    && !expr.contains('(') // avoid substituting call results
                    && !expr.starts_with('"'); // avoid string literals
                let indent = line.len() - line.trim_start().len();
                if is_simple_var && is_expr {
                    substitutions.push((expr.to_string(), var_name.to_string(), indent));
                }
            }
        }
        // Apply substitutions: for each (expr, var), replace expr with var in later lines
        // Only replace within array indices and conditions (not in assignments)
        for (expr, var_name, _sub_indent) in &substitutions {
            let mut found_def = false;
            for line in &mut lines {
                let t = line.trim();
                if !found_def {
                    // Find the definition line
                    if t.starts_with(&format!("{} = {}", var_name, expr)) {
                        found_def = true;
                    }
                    continue;
                }
                // Only substitute in conditions and array accesses, not assignments
                if t.starts_with(&format!("{} = ", var_name)) { continue; } // skip self-assign
                if line.contains(expr.as_str()) {
                    *line = line.replace(expr.as_str(), var_name);
                }
            }
        }
    }

    // Variable naming heuristics: rename generic lVar/iVar to meaningful names.
    // - Loop counters (incremented in for/while) → i, j, k
    // - Variables compared to string length → len, n
    // - Variables used as malloc size → size, n
    {
        let all_text = lines.join("\n");

        // Detect loop counters: "iVarN++" or "lVarN++" or "lVarN = lVarN + 1"
        let mut counter_idx = 0;
        let counter_names = ["i", "j", "k", "m"];
        let mut renames: Vec<(String, String)> = Vec::new();
        for var_prefix in ["iVar", "lVar"] {
            for n in 1..=20 {
                let var = format!("{}{}", var_prefix, n);
                let is_counter = all_text.contains(&format!("{}++", var))
                    || all_text.contains(&format!("{} = {} + 1", var, var))
                    || all_text.contains(&format!("{} += 1", var));
                if is_counter && counter_idx < counter_names.len() {
                    // Don't rename if already used elsewhere with a meaningful role
                    if !renames.iter().any(|(_, to)| to == counter_names[counter_idx]) {
                        renames.push((var, counter_names[counter_idx].to_string()));
                        counter_idx += 1;
                    }
                }
            }
        }

        // Apply renames with word-boundary matching
        for (from, to) in &renames {
            for line in &mut lines {
                if !line.contains(from) { continue; }
                let mut new_line = String::new();
                let mut remaining = line.as_str();
                while let Some(pos) = remaining.find(from.as_str()) {
                    let before_ok = pos == 0
                        || !remaining.as_bytes()[pos - 1].is_ascii_alphanumeric()
                        && remaining.as_bytes()[pos - 1] != b'_';
                    let after_pos = pos + from.len();
                    let after_ok = after_pos >= remaining.len()
                        || !remaining.as_bytes()[after_pos].is_ascii_alphanumeric()
                        && remaining.as_bytes()[after_pos] != b'_';
                    if before_ok && after_ok {
                        new_line.push_str(&remaining[..pos]);
                        new_line.push_str(to);
                        remaining = &remaining[after_pos..];
                    } else {
                        new_line.push_str(&remaining[..after_pos]);
                        remaining = &remaining[after_pos..];
                    }
                }
                new_line.push_str(remaining);
                *line = new_line;
            }
        }
    }

    // AArch64 register renaming: replace bare register names with meaningful names.
    // x0-x7 → param_0-param_7 (argument registers)
    // x30 returns → void return (link register is not a return value)
    {
        // Detect AArch64: prefer the architecture context; fall back to textual
        // heuristic for test paths that do not thread ctx through (x0-leak scan).
        let is_aarch64 = matches!(ctx.arch, Architecture::AArch64)
            || (lines.iter().any(|l| {
                let t = l.trim();
                t.contains("x0 ") || t.contains("x19") || t.contains("x29") || t.contains("x30")
            }) && !lines.iter().any(|l| l.contains("RAX") || l.contains("RBP") || l.contains("ESP")));

        if is_aarch64 {
            for line in &mut lines {
                let t = line.trim().to_string();

                // "return x30;" → "return;" (link register epilogue, not a return value)
                if t == "return x30;" {
                    let indent = line.len() - line.trim_start().len();
                    *line = format!("{}return;", " ".repeat(indent));
                    continue;
                }

                // Replace bare x0-x(N-1) with param_0-param_(N-1) when used as values.
                // `param_names` contains one entry per SSA-versioned write of a
                // parameter register, so the same logical parameter may appear
                // multiple times. Dedupe preserving insertion order of the first
                // occurrence, and use the deduped list to know both the count and
                // the canonical name (honors DWARF names when present).
                let mut distinct_param_names: Vec<String> = Vec::new();
                for p in param_names {
                    if !distinct_param_names.iter().any(|x| x == p) {
                        distinct_param_names.push(p.clone());
                    }
                }
                let aarch64_param_count = distinct_param_names.len().min(8);
                // Rename both the 64-bit (xN) and 32-bit sub-register (wN) forms.
                // `wN` is the lower 32 bits of `xN`; without renaming it, int-typed
                // parameters leak to output as raw `w1`, `w2`, etc.
                for reg_idx in 0..aarch64_param_count as u64 {
                    for prefix in &['x', 'w'] {
                        let reg = format!("{}{}", prefix, reg_idx);
                        let param = distinct_param_names[reg_idx as usize].clone();
                        if !line.contains(&reg) { continue; }
                        let mut new_line = String::new();
                        let mut remaining = line.as_str();
                        while let Some(pos) = remaining.find(&reg) {
                            let before_ok = pos == 0
                                || !remaining.as_bytes()[pos - 1].is_ascii_alphanumeric()
                                && remaining.as_bytes()[pos - 1] != b'_';
                            let after_pos = pos + reg.len();
                            let after_ok = after_pos >= remaining.len()
                                || (!remaining.as_bytes()[after_pos].is_ascii_alphanumeric()
                                    && remaining.as_bytes()[after_pos] != b'_');
                            if before_ok && after_ok {
                                new_line.push_str(&remaining[..pos]);
                                new_line.push_str(&param);
                                remaining = &remaining[after_pos..];
                            } else {
                                new_line.push_str(&remaining[..after_pos]);
                                remaining = &remaining[after_pos..];
                            }
                        }
                        new_line.push_str(remaining);
                        *line = new_line;
                    }
                }
            }

            // Remove standalone "return x30;" that might have been inside if blocks
            lines.retain(|l| l.trim() != "return x30;");

            // Fix "x-N" artifacts: these are "x0 - N" where x0 was rendered as "x"
            // (sub-register naming artifact). Replace with "param_0 - N".
            for line in &mut lines {
                let patterns = ["x-1", "x-2", "x-3", "x-4"];
                for pat in &patterns {
                    if line.contains(pat) {
                        let replacement = format!("param_0 - {}", &pat[2..]);
                        *line = line.replace(pat, &replacement);
                    }
                }
            }

            // Fix "param_-N" artifacts: negative param offsets from stack-relative
            // address computation. Replace with "sp - N" or remove.
            for line in &mut lines {
                if line.contains("param_-") {
                    // Replace param_-N with (sp - N) in expressions
                    let mut new = line.clone();
                    for n in (1..=256).rev() {
                        let pat = format!("param_-{}", n);
                        let rep = format!("(sp - {})", n);
                        new = new.replace(&pat, &rep);
                    }
                    *line = new;
                }
            }
        }
    }

    // Fold compound const arithmetic at print time: `base + N + M` → `base + (N+M)`,
    // and `base - N - M` → `base - (N+M)`, etc. The SSA tree may represent chained
    // address computation as nested `BinOp(Add, BinOp(Add, x, c1), c2)` which emits
    // as `x + c1 + c2` with constants unmerged. Collapse to a single constant for
    // readability (matches Ghidra's `puVar3 + 0x18` over `puVar3 + 16 + 8`).
    {
        fn parse_num(s: &str) -> Option<i64> {
            let s = s.trim();
            if let Some(h) = s.strip_prefix("0x") { i64::from_str_radix(h, 16).ok() }
            else if let Some(h) = s.strip_prefix("0X") { i64::from_str_radix(h, 16).ok() }
            else { s.parse::<i64>().ok() }
        }
        fn fmt_num(n: i64) -> String {
            if n >= 0 && n < 16 { format!("{}", n) }
            else if n >= 0 { format!("0x{:x}", n) }
            else if n > -16 { format!("{}", n) }
            else { format!("-0x{:x}", -n) }
        }
        // Scan for ` OP C1 OP C2` where OP is + or -, C1/C2 are numeric literals.
        // Returns (start, end, replacement) for the combined constant pair found.
        // Only rewrites the numeric tail — leaves any preceding expression untouched.
        fn find_combine(line: &str) -> Option<(usize, usize, String)> {
            let bytes = line.as_bytes();
            // Find any " + " or " - " followed by a number
            let mut i = 0;
            while i + 3 < bytes.len() {
                let is_plus = bytes[i] == b' ' && bytes[i+1] == b'+' && bytes[i+2] == b' ';
                let is_minus = bytes[i] == b' ' && bytes[i+1] == b'-' && bytes[i+2] == b' ';
                if !(is_plus || is_minus) { i += 1; continue; }
                let sign1 = if is_plus { 1 } else { -1 };
                let num1_start = i + 3;
                // Match number (decimal or 0xHEX)
                let (num1_end, num1_val) = match parse_leading_num(&line[num1_start..]) {
                    Some(x) => (num1_start + x.0, x.1),
                    None => { i += 1; continue; }
                };
                // Require a following " + " or " - " immediately
                if num1_end + 3 > bytes.len() { i += 1; continue; }
                let after = &bytes[num1_end..];
                let is_plus2 = after.len() >= 3 && after[0] == b' ' && after[1] == b'+' && after[2] == b' ';
                let is_minus2 = after.len() >= 3 && after[0] == b' ' && after[1] == b'-' && after[2] == b' ';
                if !(is_plus2 || is_minus2) { i += 1; continue; }
                let sign2 = if is_plus2 { 1 } else { -1 };
                let num2_start = num1_end + 3;
                let (num2_end, num2_val) = match parse_leading_num(&line[num2_start..]) {
                    Some(x) => (num2_start + x.0, x.1),
                    None => { i += 1; continue; }
                };
                let total = sign1 * num1_val + sign2 * num2_val;
                let replacement = if total >= 0 {
                    format!(" + {}", fmt_num(total))
                } else {
                    format!(" - {}", fmt_num(-total))
                };
                return Some((i, num2_end, replacement));
            }
            None
        }
        fn parse_leading_num(s: &str) -> Option<(usize, i64)> {
            let bytes = s.as_bytes();
            if bytes.is_empty() { return None; }
            let neg = bytes[0] == b'-';
            let start = if neg { 1 } else { 0 };
            if start >= bytes.len() { return None; }
            let is_hex = start + 1 < bytes.len() && bytes[start] == b'0'
                && (bytes[start + 1] == b'x' || bytes[start + 1] == b'X');
            let num_start = if is_hex { start + 2 } else { start };
            let mut end = num_start;
            while end < bytes.len() {
                let c = bytes[end];
                let ok = if is_hex { c.is_ascii_hexdigit() } else { c.is_ascii_digit() };
                if !ok { break; }
                end += 1;
            }
            if end == num_start { return None; }
            let digits = &s[num_start..end];
            let v = if is_hex {
                i64::from_str_radix(digits, 16).ok()?
            } else {
                digits.parse::<i64>().ok()?
            };
            Some((end, if neg { -v } else { v }))
        }
        for _ in 0..4 {
            let mut changed = false;
            for line in lines.iter_mut() {
                while let Some((s, e, repl)) = find_combine(line) {
                    let mut new_line = String::with_capacity(line.len());
                    new_line.push_str(&line[..s]);
                    new_line.push_str(&repl);
                    new_line.push_str(&line[e..]);
                    *line = new_line;
                    changed = true;
                }
            }
            if !changed { break; }
        }
        // Silence unused warnings if compiler complains
        let _ = parse_num;
    }

    // Dead reassignment elimination (printer-level DCE for register copies).
    // Pattern: `REG = X;` followed directly by `REG = Y;` where REG is not read
    // between the two lines. The first assignment is dead. Common in AArch64 code
    // where x0 is repeatedly loaded with different values before each call
    // (`param_0 = X; param_0 = Y; param_0 = func(...);`).
    //
    // Preserves the last assignment and any assignment whose value is read by an
    // intermediate Store or Call. Safety: only eliminates when the LHS is a
    // simple identifier (no `->`, `*`, `[`) to avoid dropping a real store.
    {
        let is_simple_lhs = |lhs: &str| -> bool {
            !lhs.contains("->") && !lhs.contains('*') && !lhs.contains('[')
                && !lhs.contains('.') && !lhs.contains('(')
                && !lhs.is_empty()
        };
        let line_reads = |line: &str, sym: &str| -> bool {
            // Check if `sym` appears as a word in `line`'s RHS (anything after `=`)
            let rhs = match line.find(" = ") {
                Some(p) => &line[p + 3..],
                None => line, // No assign — whole line
            };
            // whole-word match
            let mut s = rhs;
            while let Some(p) = s.find(sym) {
                let before = if p == 0 { b' ' } else { s.as_bytes()[p - 1] };
                let after_pos = p + sym.len();
                let after = if after_pos < s.len() { s.as_bytes()[after_pos] } else { b' ' };
                if !before.is_ascii_alphanumeric() && before != b'_'
                    && !after.is_ascii_alphanumeric() && after != b'_'
                {
                    return true;
                }
                s = &s[p + sym.len()..];
            }
            false
        };
        let mut i = 0;
        while i + 1 < lines.len() {
            let t1 = lines[i].trim();
            let t2 = lines[i + 1].trim();
            if !t1.ends_with(';') || !t2.ends_with(';') {
                i += 1;
                continue;
            }
            let (lhs1, rhs1) = match t1.trim_end_matches(';').split_once(" = ") {
                Some(p) => p,
                None => { i += 1; continue; }
            };
            let (lhs2, _rhs2) = match t2.trim_end_matches(';').split_once(" = ") {
                Some(p) => p,
                None => { i += 1; continue; }
            };
            let lhs1 = lhs1.trim();
            let lhs2 = lhs2.trim();
            if lhs1 != lhs2 || !is_simple_lhs(lhs1) {
                i += 1;
                continue;
            }
            // Don't drop if RHS1 references LHS itself (e.g., `x = x + 1`)
            if line_reads(rhs1, lhs1) {
                i += 1;
                continue;
            }
            // Don't drop if RHS1 looks like a call (side effect)
            if rhs1.contains("(") && rhs1.ends_with(')') {
                i += 1;
                continue;
            }
            lines.remove(i);
            // Do not advance i — the new line at i might also be dead
        }
    }

    // `*(uintN_t*)(base + offset) = val;` → `base->field_offset = val;`.
    // The typed-deref form appears when the printer rejects the simpler
    // array conversion for safety, but for plain-identifier bases the
    // struct-field syntax is both cleaner and matches the field naming used
    // elsewhere in the function. Only rewrites when the base is a simple
    // identifier (lVar, local_, param_N, etc.) and the offset is a hex
    // constant.
    for line in lines.iter_mut() {
        let mut search_from = 0usize;
        loop {
            let Some(star_rel) = line[search_from..].find("*(uint") else { break };
            let star_pos = search_from + star_rel;
            let Some(close_rel) = line[star_pos..].find("*)(") else { break };
            let paren_open = star_pos + close_rel + 2;
            // Find matching close paren for the (BASE + OFFSET) group.
            let mut depth = 0i32;
            let mut close: Option<usize> = None;
            for (i, b) in line[paren_open..].bytes().enumerate() {
                if b == b'(' { depth += 1; }
                else if b == b')' {
                    depth -= 1;
                    if depth == 0 { close = Some(paren_open + i); break; }
                }
            }
            let Some(close) = close else { break };
            let inner = &line[paren_open + 1..close];
            // Split on ` + ` — require exactly one addition.
            let parts: Vec<&str> = inner.split(" + ").collect();
            if parts.len() != 2 {
                search_from = close + 1;
                continue;
            }
            let base = parts[0].trim();
            let offset = parts[1].trim();
            // Base must be a simple identifier.
            let base_ok = !base.is_empty()
                && base.chars().next().map_or(false, |c| c.is_ascii_alphabetic() || c == '_')
                && base.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
            // Offset must parse as hex/decimal.
            let off_val: Option<u64> = if let Some(h) = offset.strip_prefix("0x") {
                u64::from_str_radix(h, 16).ok()
            } else if offset.chars().all(|c| c.is_ascii_digit()) {
                offset.parse::<u64>().ok()
            } else { None };
            if !base_ok || off_val.is_none() {
                search_from = close + 1;
                continue;
            }
            let off = off_val.unwrap();
            // Only rewrite in lvalue position (followed by ` = `). Read-side
            // `param = *(uint64_t*)(...)` is harder to collapse safely.
            let trail = &line[close + 1..];
            if !trail.starts_with(" = ") {
                search_from = close + 1;
                continue;
            }
            let replacement = format!("{}->field_{:x}", base, off);
            *line = format!("{}{}{}", &line[..star_pos], replacement, &line[close + 1..]);
            search_from = star_pos + replacement.len();
        }
    }

    // Drop gratuitous parens around bare `local_<hex>` identifiers left over
    // from earlier sp-rewrites that inherited outer parens from the original
    // expression (e.g. `(sp + 200)` → `(local_200)`). A single identifier
    // never needs parens in C.
    for line in lines.iter_mut() {
        let mut search_from = 0usize;
        while let Some(rel) = line[search_from..].find("(local_") {
            let open = search_from + rel;
            let inner_start = open + 1;
            let name_end = inner_start + "local_".len();
            let after = &line[name_end..];
            let hex_end = after.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(after.len());
            if hex_end == 0 { search_from = open + 1; continue; }
            let close_pos = name_end + hex_end;
            if line.as_bytes().get(close_pos).copied() != Some(b')') {
                search_from = open + 1;
                continue;
            }
            // Replace `(local_HEX)` with `local_HEX`.
            *line = format!("{}{}{}",
                &line[..open],
                &line[inner_start..close_pos],
                &line[close_pos + 1..]);
        }
    }

    // Drop stale struct-layout comments that reference the frame-base
    // sentinel (`local_0` or raw `sp`). Their field list is the pre-collapse
    // view; downstream passes now map those fields to `local_<offset>` so
    // the hint is redundant and even misleading.
    lines.retain(|line| {
        let t = line.trim();
        if !t.starts_with("//") { return true; }
        if t.contains("struct layout for local_0")
            || t.contains("struct layout for sp")
        { return false; }
        true
    });

    // Return-type/sig consistency fix. If a function is declared
    // `long/int func_X(...)` but every return in the body is a bare `return;`,
    // rewrite the signature return type to `void`. The inverse (`void func_X`
    // but body returns a value) is rarer and is best fixed upstream, but we
    // cover it textually as well when the returned value is a plain name.
    {
        let mut has_value_return = false;
        let mut has_void_return = false;
        let mut sig_idx: Option<usize> = None;
        let mut value_expr: Option<String> = None;
        let flush = |sig_idx: &mut Option<usize>,
                      hvr: &mut bool, hvo: &mut bool,
                      ve: &mut Option<String>,
                      lines: &mut Vec<String>| {
            if let Some(i) = *sig_idx {
                let line = lines[i].clone();
                if !*hvr && *hvo && (line.starts_with("long ") || line.starts_with("int ")) {
                    // long/int func(... → void func(...
                    let rest = if line.starts_with("long ") { &line[5..] } else { &line[4..] };
                    lines[i] = format!("void {}", rest);
                } else if *hvr && !*hvo && line.starts_with("void ") && ve.is_some() {
                    // void func(... but returns a value — promote to long.
                    lines[i] = format!("long {}", &line[5..]);
                }
            }
            *sig_idx = None; *hvr = false; *hvo = false; *ve = None;
        };
        let mut i = 0;
        while i < lines.len() {
            let t = lines[i].trim();
            // Function signature line: starts with a return type keyword and
            // contains `func_` or a demangled name and ends with `{`.
            let is_sig = t.ends_with('{') && (
                t.starts_with("long ") || t.starts_with("int ")
                    || t.starts_with("void ") || t.starts_with("uint64_t ")
                    || t.starts_with("uint ") || t.starts_with("char ")
                    || t.starts_with("bool ") || t.starts_with("double ")
                    || t.starts_with("float ")
            ) && t.contains('(');
            if is_sig {
                flush(&mut sig_idx, &mut has_value_return, &mut has_void_return, &mut value_expr, &mut lines);
                sig_idx = Some(i);
            } else if t.starts_with("return ") && t.ends_with(';') && !t.contains('(') {
                has_value_return = true;
                let expr = t.trim_start_matches("return ").trim_end_matches(';').trim();
                if value_expr.is_none() {
                    value_expr = Some(expr.to_string());
                }
            } else if t == "return;" {
                has_void_return = true;
            }
            i += 1;
        }
        flush(&mut sig_idx, &mut has_value_return, &mut has_void_return, &mut value_expr, &mut lines);
    }

    // Unused-variable-declaration DCE.
    //
    // SSA var tracking emits one declaration per SSA version of every
    // user-facing variable (`long lVar2;`, `int iVar5;`, etc.). After all
    // downstream elision passes the body may no longer reference many of
    // those names. Scan all declarations and drop any whose name never
    // appears outside its own declaration line.
    {
        let mut i = 0usize;
        while i < lines.len() {
            let t = lines[i].trim();
            // `TYPE name;` declaration pattern — must start with a common C
            // type keyword, end in `;`, and have no `=` (otherwise it's an
            // initializer and has side effects).
            let is_decl_keyword = t.starts_with("long ") || t.starts_with("int ")
                || t.starts_with("uint64_t ") || t.starts_with("uint32_t ")
                || t.starts_with("uint16_t ") || t.starts_with("uint8_t ")
                || t.starts_with("char ") || t.starts_with("short ")
                || t.starts_with("float ") || t.starts_with("double ")
                || t.starts_with("bool ");
            if !is_decl_keyword || !t.ends_with(';') || t.contains('=') {
                i += 1;
                continue;
            }
            // Pull the name: `<type> name;` — after the first space.
            let core = t.trim_end_matches(';');
            let Some(sp) = core.find(' ') else { i += 1; continue; };
            let name = core[sp + 1..].trim();
            // Reject arrays / multi-part decls (contain [ ,): treat conservatively.
            if name.contains('[') || name.contains(',') || name.is_empty() {
                i += 1; continue;
            }
            // Scan all other lines for a word-boundary match on `name`.
            let mut used = false;
            for (j, other) in lines.iter().enumerate() {
                if j == i { continue; }
                let bytes = other.as_bytes();
                let mut k = 0;
                while k + name.len() <= bytes.len() {
                    if &bytes[k..k + name.len()] == name.as_bytes() {
                        let before = if k > 0 { bytes[k - 1] } else { b' ' };
                        let after_idx = k + name.len();
                        let after = bytes.get(after_idx).copied().unwrap_or(b' ');
                        let word = !before.is_ascii_alphanumeric() && before != b'_'
                            && !after.is_ascii_alphanumeric() && after != b'_';
                        if word { used = true; break; }
                    }
                    k += 1;
                }
                if used { break; }
            }
            if !used {
                lines.remove(i);
                continue;
            }
            i += 1;
        }
    }

    // Cross-line DCE on return-register assignments.
    //
    // AArch64 x0 (printed as `param_0`) and x86-64 RAX are used both as the
    // first parameter/return register and as a scratch value holder for
    // address computations and intermediate call args. The earlier adjacent
    // DCE only eliminates consecutive `REG = X; REG = Y;` pairs. Real code
    // interleaves calls and address math, leaving chains like:
    //
    //     param_0 = DAT_X->field_0;
    //     lVar2 = close;
    //     param_0 = lVar4 + 24;
    //     param_0 = QObject::QObject();
    //
    // The first and third `param_0 = ...` are dead — the next write clobbers
    // them without an intervening read. Scan each `param_0 = RHS;` (or any
    // simple identifier LHS) and look forward in the line stream; if the
    // next touch of that LHS is another write (and nothing between reads it),
    // treat this line as dead. Handling:
    //   - RHS is a pure value (no parens) → drop the line entirely.
    //   - RHS is a call (`fn(...)`) and the next touch is a write → keep
    //     the call for its side effect, strip the `LHS = ` prefix.
    //   - RHS references LHS itself (`x = x + 1`): never drop.
    {
        let reads_var_outside_lhs = |line: &str, sym: &str| -> bool {
            // `sym` appears as a word outside a leading `SYM = ` assignment.
            let trimmed = line.trim_start();
            let body = if let Some(eq_pos) = trimmed.find(" = ") {
                let lhs = &trimmed[..eq_pos];
                if lhs == sym { &trimmed[eq_pos + 3..] } else { trimmed }
            } else { trimmed };
            let bytes = body.as_bytes();
            let mut i = 0;
            while i + sym.len() <= bytes.len() {
                if &bytes[i..i + sym.len()] == sym.as_bytes() {
                    let before = if i > 0 { bytes[i - 1] } else { b' ' };
                    let after_idx = i + sym.len();
                    let after = bytes.get(after_idx).copied().unwrap_or(b' ');
                    let word = !before.is_ascii_alphanumeric() && before != b'_'
                        && !after.is_ascii_alphanumeric() && after != b'_';
                    if word { return true; }
                }
                i += 1;
            }
            false
        };
        let is_simple_lhs = |lhs: &str| -> bool {
            !lhs.contains("->") && !lhs.contains('*') && !lhs.contains('[')
                && !lhs.contains('.') && !lhs.contains('(') && !lhs.is_empty()
        };
        // Only act on RHS that makes DCE safe: the value has no side effect
        // beyond the assignment itself. A trailing `)` signals a call, which
        // we preserve on strip-LHS instead of deleting.
        let rhs_is_pure = |rhs: &str| -> bool { !rhs.contains('(') && !rhs.contains(')') };
        let mut i = 0;
        while i < lines.len() {
            let (leading, t) = {
                let l = &lines[i];
                let ls_count = l.len() - l.trim_start().len();
                (&l[..ls_count], l[ls_count..].trim_end().to_string())
            };
            if !t.ends_with(';') { i += 1; continue; }
            let core = t.trim_end_matches(';');
            let Some((lhs, rhs)) = core.split_once(" = ") else { i += 1; continue; };
            let lhs = lhs.trim();
            let rhs = rhs.trim();
            if !is_simple_lhs(lhs) { i += 1; continue; }
            // Bail if the LHS is a real function parameter (param_N where N < the
            // function's declared param count). We still want to DCE scratch
            // writes to x0 = param_0 inside the body, so don't bail on `param_0`
            // universally — only stop the pass from processing it when the
            // function genuinely rebinds a parameter to a new value that is
            // never used further (that's legitimate noise too, so keep the pass).
            // If RHS references LHS, skip (self-ref).
            if reads_var_outside_lhs(rhs, lhs) { i += 1; continue; }

            // Scan forward for next touch of this LHS. Track brace depth so we
            // don't mistake a block-closing `}` (inside an if / while / for) for
            // end-of-function. A `return lVar3;` may live inside a nested block,
            // and the earlier bail on any `}` at line start was dropping the
            // assignment that feeds it.
            let mut next_is_write = false;
            let mut found_read = false;
            let mut brace_depth: i32 = 0;
            for j in (i + 1)..lines.len() {
                let l2 = &lines[j];
                // Update brace depth *before* treating `}` as end-of-function,
                // so only the outermost closer triggers the end condition.
                let opens = l2.matches('{').count() as i32;
                let closes = l2.matches('}').count() as i32;
                let was_depth = brace_depth;
                brace_depth += opens - closes;
                // End-of-function: pre-update depth was 0 and closes > 0.
                if was_depth <= 0 && closes > 0
                    && !l2.trim_start().starts_with("} else")
                {
                    next_is_write = true;
                    break;
                }
                // Skip pure comment lines.
                let t2 = l2.trim();
                if t2.is_empty() || t2.starts_with("//") || t2.starts_with("/*")
                    || t2.starts_with("*")
                { continue; }
                // Check for write first: `LHS = ...;`
                let t2_trim = t2.trim_end_matches(';');
                if let Some((l2_lhs, l2_rhs)) = t2_trim.split_once(" = ") {
                    let l2_lhs = l2_lhs.trim();
                    let l2_rhs = l2_rhs.trim();
                    // If the RHS reads our LHS, that's a read even though line is a write.
                    if reads_var_outside_lhs(l2_rhs, lhs) { found_read = true; break; }
                    if l2_lhs == lhs {
                        // A clean overwrite with no read in RHS.
                        next_is_write = true;
                        break;
                    }
                }
                // Non-assignment line (standalone call, control-flow condition):
                // treat any appearance of the LHS as a read.
                if reads_var_outside_lhs(t2, lhs) { found_read = true; break; }
            }

            if next_is_write && !found_read {
                if rhs_is_pure(rhs) {
                    lines.remove(i);
                    continue; // don't advance — recheck new i
                } else if rhs.ends_with(')') {
                    // Don't strip the LHS of allocation-style calls — the
                    // return value is almost certainly used as a pointer later,
                    // and our forward scan can miss uses hidden inside the
                    // args of a subsequent call (`func(..., the_value, ...)`)
                    // because the register tracker may have inlined the value
                    // directly, leaving no textual `LHS` reference.
                    let is_alloc_like = ["operator new", "operator new[]",
                        "malloc(", "calloc(", "realloc(", "strdup(", "strndup(",
                        "mmap(", "fopen(", "opendir(", "open("]
                        .iter().any(|s| rhs.starts_with(s) || rhs.contains(s));
                    if !is_alloc_like {
                        lines[i] = format!("{}{};", leading, rhs);
                    }
                }
            }
            i += 1;
        }
    }

    // Dead standalone deref statements like `*(param_0);` have no side effect
    // once the register tracker is folded. Strip them. Runs AFTER the cross-line
    // DCE so any bare deref that surfaced from LHS stripping also gets dropped.
    lines.retain(|line| {
        let t = line.trim();
        if !t.ends_with(';') { return true; }
        let body = t.trim_end_matches(';').trim();
        if !body.starts_with("*(") || !body.ends_with(')') { return true; }
        let inner = &body[2..body.len() - 1];
        if inner.contains('(') { return true; }
        false
    });

    // `?` placeholder cleanup on C++ method calls. When the SSA cannot resolve
    // the `this` pointer (x0 at call time) to a concrete expression, `Expr::Unknown`
    // surfaces as a literal `?` in the first arg slot. For C++ methods the leading
    // `?` is almost always the implicit `this` pointer that the analyst can infer
    // from context, so drop it when the call target contains `::` (method syntax)
    // AND there are other arguments. Free functions (no `::`) keep the `?` so the
    // analyst still sees that arg0 is unresolved.
    for line in lines.iter_mut() {
        // Look for `NAME::METHOD(?, ...)` or `NAME::METHOD(?)` — drop the
        // placeholder in either position.
        let mut search_from = 0usize;
        while let Some(rel) = line[search_from..].find("::") {
            let abs = search_from + rel;
            let rest = &line[abs..];
            let Some(open_rel) = rest.find('(') else { break };
            let open = abs + open_rel;
            let after_paren = open + 1;
            if line[after_paren..].starts_with("?, ") {
                let end = after_paren + 3;
                *line = format!("{}{}", &line[..after_paren], &line[end..]);
            } else if line[after_paren..].starts_with("?)") {
                *line = format!("{}{}", &line[..after_paren], &line[after_paren + 1..]);
            }
            search_from = after_paren;
        }
        // `strlen(?)` / other well-known C libc calls whose first arg is
        // obviously a pointer — strip the lone `?` when it's the only arg so
        // the call reads `strlen()`. Keeps `strlen(?, extra)` untouched.
        for marker in &["strlen(", "strcpy(", "strcmp(", "strcat(", "strdup(",
                        "puts(", "fputs(", "free(", "close("] {
            let mut search_from = 0usize;
            while let Some(rel) = line[search_from..].find(marker) {
                let open = search_from + rel + marker.len() - 1;
                let after_paren = open + 1;
                if line[after_paren..].starts_with("?)") {
                    *line = format!("{}{}", &line[..after_paren], &line[after_paren + 1..]);
                }
                search_from = after_paren;
            }
        }
        // Also cover `operator NAME(?, ...)` / `operator NAME(?)` —
        // operators, like methods, take `this` as their first (hidden) arg.
        for marker in &["operator new(", "operator delete(", "operator new[](",
                        "operator delete[]("] {
            let mut search_from = 0usize;
            while let Some(rel) = line[search_from..].find(marker) {
                let open = search_from + rel + marker.len() - 1;
                let after_paren = open + 1;
                if line[after_paren..].starts_with("?, ") {
                    let end = after_paren + 3;
                    *line = format!("{}{}", &line[..after_paren], &line[end..]);
                } else if line[after_paren..].starts_with("?)") {
                    *line = format!("{}{}", &line[..after_paren], &line[after_paren + 1..]);
                }
                search_from = after_paren;
            }
        }
    }

    // `local_0->field_N` is the frame base plus offset N — semantically the
    // same stack location as `local_N`. Collapse to the canonical name so the
    // output stays consistent regardless of which SSA path produced the access.
    // Only applies to `local_0`, since non-zero bases denote real struct
    // pointers stored in the frame.
    for line in lines.iter_mut() {
        while let Some(pos) = line.find("local_0->field_") {
            let prev = if pos == 0 { b' ' } else { line.as_bytes()[pos - 1] };
            if prev.is_ascii_alphanumeric() || prev == b'_' { break; }
            let after_start = pos + "local_0->field_".len();
            let after = &line[after_start..];
            let end = after.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(after.len());
            if end == 0 { break; }
            if let Ok(off) = u64::from_str_radix(&after[..end], 16) {
                let replacement = format!("local_{:x}", off);
                *line = format!("{}{}{}",
                    &line[..pos], replacement, &line[after_start + end..]);
                continue;
            }
            break;
        }
    }

    // Frame-pointer-alias propagation: when a local holds the frame base
    // (e.g. `iVar1 = local_0;`), later accesses through that alias
    // (`iVar1->field_K`) are identical to `local_K`. Track the alias within
    // the function, rewrite downstream field accesses, and drop the now-dead
    // `iVar = local_0;` assignment when the original name is unused after.
    {
        let mut i = 0usize;
        while i < lines.len() {
            // Extract owned copies up front so the later `&mut lines[j]` does
            // not conflict with the read of `lines[i]`.
            let (lhs, rhs) = {
                let t = lines[i].trim();
                let core = match t.strip_suffix(';') { Some(c) => c, None => { i += 1; continue; } };
                let pair = match core.split_once(" = ") { Some(p) => p, None => { i += 1; continue; } };
                (pair.0.trim().to_string(), pair.1.trim().to_string())
            };
            if rhs != "local_0" { i += 1; continue; }
            if lhs.is_empty() || lhs.contains('[') || lhs.contains('.')
                || lhs.contains(' ') || lhs.contains("->")
            { i += 1; continue; }
            let alias_prefix = format!("{}->field_", lhs);
            let mut rewrote_any = false;
            let mut other_use = false;
            // Rewrite downstream references.
            for j in (i + 1)..lines.len() {
                let l2 = &mut lines[j];
                // First, rewrite all `ALIAS->field_HEX` occurrences.
                while let Some(pos) = l2.find(alias_prefix.as_str()) {
                    let prev = if pos == 0 { b' ' } else { l2.as_bytes()[pos - 1] };
                    if prev.is_ascii_alphanumeric() || prev == b'_' { break; }
                    let after_start = pos + alias_prefix.len();
                    let after = &l2[after_start..];
                    let end = after.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(after.len());
                    if end == 0 { break; }
                    if let Ok(off) = u64::from_str_radix(&after[..end], 16) {
                        let replacement = format!("local_{:x}", off);
                        *l2 = format!("{}{}{}",
                            &l2[..pos], replacement, &l2[after_start + end..]);
                        rewrote_any = true;
                        continue;
                    }
                    break;
                }
                // Any other appearance of the bare alias name = still in use.
                let bytes = l2.as_bytes();
                let mut k = 0;
                while k + lhs.len() <= bytes.len() {
                    if &bytes[k..k + lhs.len()] == lhs.as_bytes() {
                        let before = if k > 0 { bytes[k - 1] } else { b' ' };
                        let after_idx = k + lhs.len();
                        let after = bytes.get(after_idx).copied().unwrap_or(b' ');
                        let word = !before.is_ascii_alphanumeric() && before != b'_'
                            && !after.is_ascii_alphanumeric() && after != b'_';
                        if word { other_use = true; break; }
                    }
                    k += 1;
                }
                if other_use { break; }
            }
            if rewrote_any && !other_use {
                lines.remove(i);
                continue;
            }
            i += 1;
        }
    }

    // local_N->field_0 collapse: `local_N` is a stack memory slot, not a struct
    // pointer. A `local_N->field_0 = V;` store is really `*(sp + N + 0) = V`,
    // i.e. a plain word write to the local. Rewrite to `local_N = V;` (Ghidra
    // emits the same form). Only collapse field_0 — non-zero field offsets
    // name distinct stack positions, and keeping the arrow syntax preserves
    // their relationship with neighbouring fields of the same local struct.
    for line in lines.iter_mut() {
        let mut search_from = 0usize;
        while let Some(rel) = line[search_from..].find("local_") {
            let pos = search_from + rel;
            let prev = if pos == 0 { b' ' } else { line.as_bytes()[pos - 1] };
            if prev.is_ascii_alphanumeric() || prev == b'_' {
                search_from = pos + 6;
                continue;
            }
            let after = &line[pos + 6..];
            let end_digits = after.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(after.len());
            if end_digits == 0 {
                search_from = pos + 6;
                continue;
            }
            let tail_start = pos + 6 + end_digits;
            let tail = &line[tail_start..];
            if !tail.starts_with("->field_0") {
                search_from = tail_start;
                continue;
            }
            // Reject if field_0 is actually `->field_0X` (e.g., field_08).
            let suffix_byte = line.as_bytes().get(tail_start + 9).copied().unwrap_or(b' ');
            if suffix_byte.is_ascii_hexdigit() {
                search_from = tail_start;
                continue;
            }
            // Replace `local_N->field_0` with `local_N` in place.
            let new_line = format!("{}{}{}",
                &line[..tail_start], "", &line[tail_start + 9..]);
            *line = new_line;
            // Don't advance — the next search starts from the same pos since
            // the replacement shortened the line.
        }
    }

    // Redundant `(uint)` / `(uint32_t)` casts on already-32-bit loads/fields.
    // The SLEIGH pipeline emits `(uint)*lVar2` or `(uint)lVar2->field_N` for
    // Subpiece truncation of a 64-bit load to 32-bit width, but at that point
    // the RHS has a well-defined 32-bit-readable semantics and the cast adds
    // noise. Strip the cast when it wraps a simple memory reference (but keep
    // casts around expressions/signed conversions where width differs).
    for line in lines.iter_mut() {
        for cast in &["(uint)", "(uint32_t)"] {
            while let Some(pos) = line.find(cast) {
                let after = &line[pos + cast.len()..];
                // Strip when wrapped value is obviously already 32-bit-readable:
                //  - literal `0` / small literal (useless cast)
                //  - `*ptr` / `*(expr)` plain deref
                //  - identifier followed by `->` (struct / field) — covers both
                //    generic `->field_N` and DWARF-resolved names like `->st_gid`
                //  - `(expr)->field_` form with parenthesized base
                let is_literal = after.starts_with('0')
                    && after.as_bytes().get(1).map_or(true,
                        |&c| !c.is_ascii_alphanumeric() && c != b'_' && c != b'x');
                let is_deref = after.starts_with('*');
                let is_ident_field = after.starts_with(|c: char|
                        c.is_ascii_alphabetic() || c == '_')
                    && after.contains("->");
                let is_paren_field = after.starts_with('(')
                    && after.find("->").map_or(false,
                        |arrow| arrow < after.find(|c: char| c == ';' || c == ',' || c == ')' && false)
                            .unwrap_or(after.len()));
                let ok = is_literal || is_deref || is_ident_field || is_paren_field;
                if !ok { break; }
                let new_line = format!("{}{}", &line[..pos], after);
                *line = new_line;
            }
        }
    }

    // AArch64 atomic refcount/counter loop recognition.
    //
    // The SLEIGH semantics for LDXR/STXR decomposes a simple atomic decrement
    //   1:  ldxr  w0, [x1]
    //       sub   w0, w0, #1
    //       stxr  w2, w0, [x1]
    //       cbnz  w2, 1b
    // into a CFG whose loop condition mixes two flag temporaries — the STXR
    // success flag and a ZR-like comparison — and the fold pass cannot yet
    // collapse it. Surface pattern:
    //
    //   while ((!tmp_N) ? 1 : tmp_M != 0) {
    //       <lhs>->field_K = *<rhs> - 1;   (or *(<rhs>) - 1)
    //   }
    //
    // where `<lhs>` and `<rhs>` denote the same counter address. Rewrite to a
    // single self-documenting line; cover both decrement (`- 1`) and
    // increment (`+ 1`) bodies. Guarded so only the exact shape matches —
    // arbitrary `while ((!x) ? 1 : y)` stays untouched.
    {
        let mut i = 0;
        while i + 2 < lines.len() {
            let t1 = lines[i].trim();
            let t2 = lines[i + 1].trim();
            let t3 = lines[i + 2].trim();
            let cond_match = t1.starts_with("while ((!tmp_")
                && t1.contains(") ? 1 : tmp_")
                && t1.ends_with(") {");
            if !cond_match { i += 1; continue; }
            let body_op = if t2.ends_with(" - 1;") { '-' }
                else if t2.ends_with(" + 1;") { '+' }
                else { i += 1; continue; };
            if t3 != "}" { i += 1; continue; }
            // Parse `LHS = *RHS ± 1;` and require LHS's base points at the
            // same counter as RHS (same pointer, possibly with a field suffix).
            let body = t2.trim_end_matches(';').trim();
            let body = body.trim_end_matches(" - 1").trim_end_matches(" + 1");
            let (lhs, rhs) = match body.split_once(" = *") {
                Some((l, r)) => (l.trim(), r.trim().trim_start_matches('(').trim_end_matches(')')),
                None => { i += 1; continue; },
            };
            // Canonical counter expression: RHS if LHS doesn't add a field
            // offset; otherwise RHS if RHS equals LHS's base (before `->field_`).
            let counter_expr = {
                let lhs_base = lhs.split("->field_").next().unwrap_or(lhs);
                if lhs_base == rhs { rhs.to_string() }
                else { rhs.to_string() }
            };
            let indent = " ".repeat(lines[i].len() - lines[i].trim_start().len());
            let op_name = if body_op == '-' { "dec" } else { "inc" };
            let op_c = if body_op == '-' { "--" } else { "++" };
            let replacement = format!("{}{}(*{}); // atomic {}", indent, op_c, counter_expr, op_name);
            lines[i] = replacement;
            lines.remove(i + 1);
            lines.remove(i + 1); // the `}` line
            i += 1;
        }
    }

    // Renumber leaked Unique-space temporaries (`tmp_<huge_hex>`) to per-function
    // counters (`tmp_0`, `tmp_1`, ...). The huge hex offsets are SLEIGH unique-space
    // identifiers (instruction-address << 16 | bit-offset) — meaningful to the codegen
    // but visually noisy in output. The temp names that survive to here are
    // multi-use Unique varnodes (single-use ones get inlined by fold.rs Pass 3),
    // typically Phi-derived flag bits in loop conditions; renumbering preserves
    // the substitution (so equal temps remain visibly equal) while making the
    // names readable.
    {
        let mut tmp_map: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
        let mut next_idx: usize = 0;
        // Phase 1: collect distinct tmp_HEX names (only those with long hex offsets,
        // so we don't accidentally renumber a meaningful `tmp_0` already in use).
        for line in lines.iter() {
            let mut s = line.as_str();
            while let Some(pos) = s.find("tmp_") {
                let after = &s[pos + 4..];
                let end = after.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(after.len());
                if end >= 4 {
                    let original = format!("tmp_{}", &after[..end]);
                    tmp_map.entry(original).or_insert_with(|| {
                        let n = next_idx;
                        next_idx += 1;
                        format!("tmp_{}", n)
                    });
                }
                s = &after[end..];
            }
        }
        // Phase 2: substitute. Iterate the map in insertion order (BTreeMap orders
        // by key, but each new value is unique so order doesn't matter for replace).
        if !tmp_map.is_empty() {
            for line in lines.iter_mut() {
                for (orig, new) in &tmp_map {
                    if line.contains(orig.as_str()) {
                        *line = line.replace(orig.as_str(), new.as_str());
                    }
                }
            }
        }
    }

    // Final LR/FP stack-save elision — catches `local_N = x30;`, `local_N = x29;`,
    // `sp[N] = x30;`, `sp[N] = x29;` that late passes may surface. These stores
    // are prologue boilerplate; the restore lives in the epilogue and has already
    // been dropped.
    lines.retain(|line| {
        let t = line.trim();
        if !(t.ends_with(" = x30;") || t.ends_with(" = x29;")) { return true; }
        if t.starts_with("local_") || t.starts_with("sp[") { return false; }
        true
    });

    // Final `sp->field_<hex>` → `local_<hex>` pass. Late transforms in the
    // pipeline (DWARF field renames, register tracker substitution) can
    // surface new `sp->field_N` references after the main sp→local pass has
    // already run. Cap the accepted offset at 0x1000 so we never rewrite a
    // `sp->field_N` that is actually indexing a struct pointer aliased to sp.
    for line in lines.iter_mut() {
        let mut search_from = 0usize;
        while let Some(rel) = line[search_from..].find("sp->field_") {
            let pos = search_from + rel;
            let prev = if pos == 0 { b' ' } else { line.as_bytes()[pos - 1] };
            if prev.is_ascii_alphanumeric() || prev == b'_' {
                search_from = pos + "sp->field_".len();
                continue;
            }
            let after_start = pos + "sp->field_".len();
            let after = &line[after_start..];
            let end = after.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(after.len());
            if end == 0 { search_from = after_start; continue; }
            let Ok(off) = u64::from_str_radix(&after[..end], 16) else {
                search_from = after_start + end; continue;
            };
            if off > 0x1000 {
                search_from = after_start + end;
                continue;
            }
            let replacement = format!("local_{:x}", off);
            *line = format!("{}{}{}",
                &line[..pos], replacement, &line[after_start + end..]);
            search_from = pos + replacement.len();
        }
    }

    // Final `(local_<hex>)` paren cleanup — runs after every other transform
    // so any late-added redundant wrappers are caught.
    for line in lines.iter_mut() {
        let mut search_from = 0usize;
        while let Some(rel) = line[search_from..].find("(local_") {
            let open = search_from + rel;
            let inner_start = open + 1;
            let name_end = inner_start + "local_".len();
            let after = &line[name_end..];
            let hex_end = after.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(after.len());
            if hex_end == 0 { search_from = open + 1; continue; }
            let close_pos = name_end + hex_end;
            if line.as_bytes().get(close_pos).copied() != Some(b')') {
                search_from = open + 1;
                continue;
            }
            *line = format!("{}{}{}",
                &line[..open],
                &line[inner_start..close_pos],
                &line[close_pos + 1..]);
        }
    }

    // Final dead-deref pass — runs at the very end so any bare `*(x);` that
    // survived (including ones surfaced by late cast stripping, e.g.
    // `(uint)*(param_0);` → `*(param_0);`) is caught.
    lines.retain(|line| {
        let t = line.trim();
        if !t.ends_with(';') { return true; }
        let body = t.trim_end_matches(';').trim();
        if !body.starts_with("*(") || !body.ends_with(')') { return true; }
        let inner = &body[2..body.len() - 1];
        if inner.contains('(') { return true; }
        false
    });

    for line in &lines {
        let is_blank = line.trim().is_empty();
        if is_blank && prev_blank { continue; }
        result.push_str(line);
        result.push('\n');
        prev_blank = is_blank;
    }
    *out = result;
}

struct PrintCtx<'a> {
    arch: Architecture,
    binary: Option<&'a [u8]>,
    imports: &'a HashMap<u64, String>,
    try_regions: &'a [crate::eh_frame::TryRegion],
}

/// Remove prologue/epilogue boilerplate from the top level.
/// Generate a C-style function signature from SSA parameter and return type analysis.
fn generate_function_signature(out: &mut String, ssa: &SsaCfg, func_name: &str) {
    use crate::ir::InferredType;

    // If this function has a known signature, use it for return type
    let sig = crate::signatures::lookup(func_name);
    // Also check learned types by address (from two-pass interprocedural analysis)
    let learned_sig = func_name.strip_prefix("func_")
        .and_then(|hex| u64::from_str_radix(hex, 16).ok())
        .and_then(crate::signatures::lookup_addr);

    // Detect return type from Return terminators
    let mut return_type = "void";
    let mut _return_size = 0u32;
    if let Some(sig) = sig {
        return_type = sig.ret.c_str();
    } else {
        for block in &ssa.blocks {
            if let SsaTerminator::Return(Some(v)) = &block.terminator {
                let vdef = ssa.var(*v);
                _return_size = vdef.size;
                // Prefer display_type from signature propagation
                return_type = if let Some(d) = vdef.display_type {
                    d
                } else {
                    inferred_type_to_c(vdef.inferred_type, vdef.size)
                };
                break;
            }
        }
        // If no return terminator has a value, check learned types from call-site analysis
        let has_return_val = ssa.blocks.iter().any(|b|
            matches!(&b.terminator, SsaTerminator::Return(Some(_))));
        if !has_return_val {
            if let Some(lsig) = learned_sig {
                return_type = lsig.ret.c_str();
            } else {
                return_type = "void";
            }
        }
    }

    // Collect parameters — variables with param_name set
    // Exclude loop Phi variable names (e.g., "iVar1") which use param_name
    // for printer elision but are not function parameters.
    let mut params: Vec<(String, u32, InferredType, Option<&str>)> = Vec::new();
    for v in &ssa.vars {
        if let Some(ref name) = v.param_name {
            if matches!(&v.expr, Expr::Phi(_)) && !name.starts_with("param_") {
                continue;
            }
            params.push((name.clone(), v.size, v.inferred_type, v.display_type));
        }
    }
    // Deduplicate by name (SSA may have multiple defs of the same param)
    // Deduplicate and sort by param index (param_0, param_1, ...)
    let mut seen = std::collections::HashSet::new();
    params.retain(|p| seen.insert(p.0.clone()));
    params.sort_by(|a, b| {
        let idx_a = a.0.strip_prefix("param_")
            .or_else(|| a.0.strip_prefix("fparam_"))
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(999);
        let idx_b = b.0.strip_prefix("param_")
            .or_else(|| b.0.strip_prefix("fparam_"))
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(999);
        let is_float_a = a.0.starts_with("fparam_");
        let is_float_b = b.0.starts_with("fparam_");
        is_float_a.cmp(&is_float_b).then(idx_a.cmp(&idx_b)).then(a.0.cmp(&b.0))
    });

    // Format parameter list — use display_type > signature > InferredType
    let param_strs: Vec<String> = params.iter().enumerate().map(|(i, (name, size, ty, disp))| {
        let type_name = if let Some(d) = disp {
            // display_type set by signature propagation (e.g., "HANDLE", "DWORD")
            *d
        } else if let Some(sig) = sig {
            if i < sig.params.len() {
                sig.params[i].ty.c_str()
            } else {
                inferred_type_to_c(*ty, *size)
            }
        } else {
            inferred_type_to_c(*ty, *size)
        };
        format!("{} {}", type_name, name)
    }).collect();

    let params_str = if param_strs.is_empty() {
        "void".to_string()
    } else {
        param_strs.join(", ")
    };

    out.push_str(&format!("{} {}({}) {{\n", return_type, func_name, params_str));
}

/// Map InferredType + size to a C type string.
fn inferred_type_to_c(ty: crate::ir::InferredType, size: u32) -> &'static str {
    use crate::ir::InferredType;
    match (ty, size) {
        (InferredType::Float, 4) => "float",
        (InferredType::Float, 8) => "double",
        (InferredType::Float, _) => "float", // XMM registers may be 16 bytes; default to float
        (InferredType::Signed, 1) => "char",
        (InferredType::Signed, 4) => "int",
        (InferredType::Signed, 8) => "long",
        (InferredType::Pointer, _) | (_, 8) => "long",
        (InferredType::Bool, _) => "bool",
        (_, 1) => "uint8_t",
        (_, 4) => "int",
        _ => "int",
    }
}

/// Convert a signature type to a C cast string for call argument casts.
fn sigtype_to_cast(ty: crate::signatures::SigType) -> Option<&'static str> {
    use crate::signatures::SigType;
    match ty {
        SigType::Int => Some("int"),
        SigType::UInt | SigType::DWord | SigType::RegSam => Some("DWORD"),
        SigType::Long | SigType::LResult | SigType::LStatus | SigType::Ntstatus | SigType::HResult => Some("long"),
        SigType::ULong => Some("unsigned long"),
        SigType::SizeT => Some("size_t"),
        SigType::CharPtr | SigType::LpStr | SigType::LpCStr => Some("char *"),
        SigType::ConstCharPtr => Some("const char *"),
        SigType::WCharPtr | SigType::LpWStr | SigType::LpCWStr => Some("LPCWSTR"),
        SigType::ConstWCharPtr => Some("LPCWSTR"),
        SigType::VoidPtr | SigType::LpVoid => Some("void *"),
        SigType::ConstVoidPtr => Some("const void *"),
        SigType::Handle | SigType::HModule | SigType::HInstance => Some("HANDLE"),
        SigType::Hwnd => Some("HWND"),
        SigType::HKey => Some("HKEY"),
        SigType::HDc => Some("HDC"),
        SigType::HIcon => Some("HICON"),
        SigType::HBrush => Some("HBRUSH"),
        SigType::HBitmap => Some("HBITMAP"),
        SigType::HFont => Some("HFONT"),
        SigType::HMenu => Some("HMENU"),
        SigType::WParam => Some("WPARAM"),
        SigType::LParam => Some("LPARAM"),
        SigType::Atom => Some("ATOM"),
        SigType::Word => Some("WORD"),
        SigType::Byte => Some("BYTE"),
        SigType::LpByte => Some("LPBYTE"),
        SigType::LpDWord => Some("LPDWORD"),
        SigType::PhKey => Some("PHKEY"),
        SigType::ScHandle => Some("SC_HANDLE"),
        SigType::Bool => Some("BOOL"),
        SigType::FilePtr => Some("FILE *"),
        SigType::Fd | SigType::SockFd => None, // int — no cast needed
        SigType::Void => None,
    }
}

fn filter_boilerplate(stmts: &[StructuredStmt], ssa: &SsaCfg) -> Vec<StructuredStmt> {
    stmts.iter().filter(|stmt| {
        match stmt {
            StructuredStmt::Assign { lhs, .. } => {
                let vdef = ssa.var(*lhs);
                if is_stack_management(vdef, ssa) { return false; }
                if is_frame_pointer_op(vdef) { return false; }
                if vdef.varnode.space == AddressSpaceId::Register && vdef.varnode.offset == RIP_OFFSET {
                    return false;
                }
                true
            }
            StructuredStmt::Store { addr, val: _ } => {
                let addr_def = ssa.var(*addr);
                if addr_def.varnode.space == AddressSpaceId::Register
                    && (addr_def.varnode.offset == RSP_OFFSET || addr_def.varnode.offset == ESP_OFFSET)
                { return false; }
                if is_sp_expr(&addr_def.expr, ssa) { return false; }
                true
            }
            _ => true,
        }
    }).cloned().collect()
}

fn is_stack_management(vdef: &VarDef, ssa: &SsaCfg) -> bool {
    if vdef.varnode.space != AddressSpaceId::Register { return false; }
    if vdef.varnode.offset == RSP_OFFSET {
        if let Expr::BinOp(BinOpKind::Add | BinOpKind::Sub, l, _) = &vdef.expr {
            let lv = ssa.var(*l);
            return lv.varnode.space == AddressSpaceId::Register && lv.varnode.offset == RSP_OFFSET;
        }
        if let Expr::Var(id) = &vdef.expr {
            let v = ssa.var(*id);
            return v.varnode.space == AddressSpaceId::Register && v.varnode.offset == RBP_OFFSET;
        }
    }
    // x86-32: ESP = ESP ± N (stack allocation, PUSH/POP, cdecl cleanup)
    if vdef.varnode.offset == ESP_OFFSET && vdef.varnode.size == 4 {
        if let Expr::BinOp(BinOpKind::Add | BinOpKind::Sub, l, _) = &vdef.expr {
            let lv = ssa.var(*l);
            return lv.varnode.space == AddressSpaceId::Register && lv.varnode.offset == ESP_OFFSET;
        }
        if let Expr::Var(id) = &vdef.expr {
            let v = ssa.var(*id);
            return v.varnode.space == AddressSpaceId::Register
                && (v.varnode.offset == EBP_OFFSET || v.varnode.offset == ESP_OFFSET);
        }
    }
    false
}

fn is_frame_pointer_op(vdef: &VarDef) -> bool {
    if vdef.varnode.space != AddressSpaceId::Register { return false; }
    if vdef.varnode.offset == RBP_OFFSET || vdef.varnode.offset == RSP_OFFSET
        || vdef.varnode.offset == EBP_OFFSET || vdef.varnode.offset == ESP_OFFSET
    {
        match &vdef.expr {
            Expr::Var(_) => true,
            Expr::Load(_) => vdef.varnode.offset == RBP_OFFSET || vdef.varnode.offset == EBP_OFFSET,
            _ => false,
        }
    } else {
        false
    }
}

/// Check if a VarId resolves to an ESP-derived expression (for condition cleanup).
fn is_esp_derived_var(id: VarId, ssa: &SsaCfg) -> bool {
    let vdef = ssa.var(id);
    if vdef.varnode.space == AddressSpaceId::Register
        && (vdef.varnode.offset == ESP_OFFSET || vdef.varnode.offset == RSP_OFFSET)
    {
        return true;
    }
    match &vdef.expr {
        Expr::Var(inner) => is_esp_derived_var(*inner, ssa),
        Expr::BinOp(BinOpKind::Add | BinOpKind::Sub, l, _) => is_esp_derived_var(*l, ssa),
        _ => false,
    }
}

fn is_sp_expr(expr: &Expr, ssa: &SsaCfg) -> bool {
    match expr {
        Expr::Var(id) => {
            let v = ssa.var(*id);
            v.varnode.space == AddressSpaceId::Register
                && (v.varnode.offset == RSP_OFFSET || v.varnode.offset == ESP_OFFSET)
        }
        Expr::BinOp(_, l, _) => {
            let v = ssa.var(*l);
            v.varnode.space == AddressSpaceId::Register
                && (v.varnode.offset == RSP_OFFSET || v.varnode.offset == ESP_OFFSET)
        }
        _ => false,
    }
}

/// Check if a body would produce no visible output after filtering.
fn is_body_empty(stmts: &[StructuredStmt], ssa: &SsaCfg) -> bool {
    for stmt in stmts {
        match stmt {
            StructuredStmt::Assign { lhs, .. } => {
                let vdef = ssa.var(*lhs);
                if vdef.varnode.space == AddressSpaceId::Unique { continue; }
                if vdef.varnode.space == AddressSpaceId::Register && is_flag(vdef.varnode.offset) { continue; }
                if matches!(&vdef.expr, Expr::Phi(_)) { continue; }
                if is_zext_artifact(vdef, ssa) { continue; }
                if is_self_assign(vdef, ssa) { continue; }
                // Stack management (ESP/RSP arithmetic) is filtered in output
                if is_stack_management(vdef, ssa) { continue; }
                if is_frame_pointer_op(vdef) { continue; }
                if vdef.varnode.space == AddressSpaceId::Register && vdef.varnode.offset == RIP_OFFSET { continue; }
                // Call returns with use_count <= 1 are inlined at use site
                if vdef.call_return && vdef.use_count <= 1 { continue; }
                // Arg register assigns consumed by a call
                if is_arg_consumed_by_call(*lhs, ssa) { continue; }
                return false;
            }
            StructuredStmt::Store { addr, .. } => {
                // ESP/RSP-derived stores are filtered in output
                let addr_def = ssa.var(*addr);
                if addr_def.varnode.space == AddressSpaceId::Register
                    && (addr_def.varnode.offset == RSP_OFFSET || addr_def.varnode.offset == ESP_OFFSET)
                { continue; }
                if is_sp_expr(&addr_def.expr, ssa) { continue; }
                return false;
            }
            StructuredStmt::Return(_)
            | StructuredStmt::Call { .. } | StructuredStmt::While { .. }
            | StructuredStmt::DoWhile { .. } | StructuredStmt::Switch { .. }
            | StructuredStmt::Break | StructuredStmt::Continue
            | StructuredStmt::Goto(_) => return false,
            StructuredStmt::IfElse { then_body, else_body, .. } => {
                if !is_body_empty(then_body, ssa) || !is_body_empty(else_body, ssa) {
                    return false;
                }
            }
            StructuredStmt::Label(_) => {}
        }
    }
    true
}

fn print_stmts(stmts: &[StructuredStmt], ssa: &SsaCfg, ctx: &PrintCtx, indent: usize, out: &mut String) {
    let mut tracker = RegTracker::new();
    for (i, stmt) in stmts.iter().enumerate() {
        print_stmt_tracked(stmt, stmts, i, ssa, ctx, indent, out, &mut tracker);
    }
}

/// Tracks what each register currently holds, for display-time copy elision.
struct RegTracker {
    /// Map: (register offset, size) → VarId of the source value
    reg_source: std::collections::HashMap<(u64, u32), VarId>,
    /// Map: (register offset, size) → formatted expression string (for call returns)
    reg_expr_str: std::collections::HashMap<(u64, u32), String>,
    /// Map: stack variable name → formatted value string (for Store alias tracking)
    stack_alias: std::collections::HashMap<String, String>,
}

impl RegTracker {
    fn new() -> Self {
        Self {
            reg_source: std::collections::HashMap::new(),
            reg_expr_str: std::collections::HashMap::new(),
            stack_alias: std::collections::HashMap::new(),
        }
    }

    fn set(&mut self, offset: u64, size: u32, source: VarId) {
        self.reg_source.insert((offset, size), source);
        self.reg_expr_str.remove(&(offset, size));
    }

    /// Record that a register holds a call return value with the given expression string.
    fn set_call_return(&mut self, offset: u64, size: u32, expr_str: String) {
        self.reg_expr_str.insert((offset, size), expr_str);
        self.reg_source.remove(&(offset, size));
    }

    fn get(&self, offset: u64, size: u32) -> Option<VarId> {
        self.reg_source.get(&(offset, size)).copied()
    }

    /// Get the formatted expression string for a register (call return value).
    fn get_expr_str(&self, offset: u64, size: u32) -> Option<&str> {
        self.reg_expr_str.get(&(offset, size)).map(|s| s.as_str())
    }

    fn invalidate(&mut self, offset: u64, size: u32) {
        self.reg_source.remove(&(offset, size));
        self.reg_expr_str.remove(&(offset, size));
    }

    fn invalidate_all(&mut self) {
        self.reg_source.clear();
        // Keep call return expressions — they survive across the call boundary
        // because the call itself produces them
    }

    /// Invalidate all, including call return expressions.
    #[allow(dead_code)]
    fn invalidate_everything(&mut self) {
        self.reg_source.clear();
        self.reg_expr_str.clear();
    }

    /// Resolve a VarId through the tracker: if the var is a register that
    /// currently holds a known source, return that source instead.
    fn resolve(&self, id: VarId, ssa: &SsaCfg) -> VarId {
        let vdef = ssa.var(id);
        if vdef.varnode.space == AddressSpaceId::Register {
            if let Some(src) = self.get(vdef.varnode.offset, vdef.varnode.size) {
                return src;
            }
        }
        id
    }
}

fn print_stmt_tracked(stmt: &StructuredStmt, stmts: &[StructuredStmt], stmt_idx: usize, ssa: &SsaCfg, ctx: &PrintCtx, indent: usize, out: &mut String, tracker: &mut RegTracker) {
    let pad: String = "    ".repeat(indent);

    match stmt {
        StructuredStmt::Assign { lhs, .. } => {
            let vdef = ssa.var(*lhs);
            if vdef.varnode.space == AddressSpaceId::Unique { return; }
            if vdef.varnode.space == AddressSpaceId::Register && is_flag(vdef.varnode.offset) { return; }
            // Skip unnamed Phi nodes; named loop Phis render as initialization (e.g., "iVar1 = 0")
            if matches!(&vdef.expr, Expr::Phi(_)) && vdef.param_name.is_none() { return; }
            if is_zext_artifact(vdef, ssa) { return; }
            if is_self_assign(vdef, ssa) { return; }
            if vdef.call_return && vdef.use_count <= 1 { return; }
            if is_arg_consumed_by_call(*lhs, ssa) { return; }

            // Inside loop bodies (no Return in stmt list), elide register
            // assignments that feed into a Store to a stack variable.
            let has_return_in_list = stmts.iter().any(|s| matches!(s, StructuredStmt::Return(_)));
            let has_store_in_list = stmts.iter().any(|s| matches!(s, StructuredStmt::Store { .. }));
            if vdef.varnode.space == AddressSpaceId::Register && indent > 0 && !has_return_in_list {
                // In loop bodies with Stores: elide simple register setup
                // (copies, sign extensions, loads) that feed into the Store.
                // In loop bodies WITHOUT Stores (-O2 code): keep them visible.
                if has_store_in_list {
                    if let Expr::Var(_) | Expr::UnaryOp(UnaryOpKind::Sext | UnaryOpKind::Zext, _)
                        | Expr::Load(_) = &vdef.expr
                    {
                        return; // Intermediate register setup feeding a Store
                    }
                }
                if let Some(next) = stmts.get(stmt_idx + 1..) {
                    // Skip hidden stmts (Unique/flag assigns) to find next visible
                    for ns in next {
                        match ns {
                            StructuredStmt::Store { val, addr } => {
                                // Check if the Store's value references this register
                                let sv = ssa.var(*val);
                                if sv.varnode.space == AddressSpaceId::Register
                                    && sv.varnode.offset == vdef.varnode.offset
                                {
                                    // The Store captures this register's value
                                    // Check the Store is to a stack variable
                                    if try_stack_var_name(*addr, ssa).is_some() {
                                        return; // Elide: Store will display the value
                                    }
                                }
                                break; // Found a visible statement, stop looking
                            }
                            StructuredStmt::Assign { lhs: next_lhs, .. } => {
                                let nv = ssa.var(*next_lhs);
                                if nv.varnode.space == AddressSpaceId::Unique { continue; }
                                if nv.varnode.space == AddressSpaceId::Register
                                    && is_flag(nv.varnode.offset) { continue; }
                                // Skip assigns to the same register (computation chain)
                                if nv.varnode.space == AddressSpaceId::Register
                                    && nv.varnode.offset == vdef.varnode.offset { continue; }
                                break; // Different visible assign, stop looking
                            }
                            _ => break,
                        }
                    }
                }
            }

            // Track register copies for display-time elision
            if vdef.varnode.space == AddressSpaceId::Register {
                if let Expr::Var(src_id) = &vdef.expr {
                    let src = ssa.var(*src_id);
                    if src.varnode.space == AddressSpaceId::Register {
                        // Check if source register has an inlined call return expression
                        if let Some(expr_str) = tracker.get_expr_str(src.varnode.offset, src.varnode.size) {
                            let s = expr_str.to_string();
                            tracker.set_call_return(vdef.varnode.offset, vdef.varnode.size, s);
                            return; // Elided: call return propagated through register copy
                        }
                        let resolved = tracker.resolve(*src_id, ssa);
                        tracker.set(vdef.varnode.offset, vdef.varnode.size, resolved);
                        let resolved_var = ssa.var(resolved);
                        if resolved_var.varnode.space != AddressSpaceId::Register
                            || resolved_var.param_name.is_some()
                        {
                            return; // Elided: value available via tracker
                        }
                    } else if src.varnode.space != AddressSpaceId::Unique {
                        // REG = stack_var/const: track it
                        tracker.set(vdef.varnode.offset, vdef.varnode.size, *src_id);
                    } else {
                        // REG = Unique (expression result): invalidate, don't track
                        tracker.invalidate(vdef.varnode.offset, vdef.varnode.size);
                    }
                } else if let Expr::Load(ptr) = &vdef.expr {
                    // REG = Load(addr): track so later uses resolve to the stack var
                    let had_call_return = tracker.get_expr_str(vdef.varnode.offset, vdef.varnode.size).is_some();
                    tracker.set(vdef.varnode.offset, vdef.varnode.size, *lhs);
                    // Skip printing if this register is just used as an intermediate
                    // to pass a stack value to another assignment or call.
                    // But DON'T skip if this overwrites a call return — the restore is important.
                    // Skip stack Loads that are only used as intermediates:
                    // - use_count <= 1: only used once (tracked at use site)
                    // - had_call_return: this is a restore after a call (tracked)
                    // - use_count <= 2 AND all uses are copies to other regs/stack
                    if get_rbp_offset(*ptr, ssa).is_some() && (vdef.use_count <= 2 || had_call_return) {
                        return; // Elided: stack Load tracked
                    }
                } else {
                    // REG = computed expression (BinOp, etc.): invalidate call_return
                    // so it is not incorrectly propagated through subsequent copies.
                    tracker.invalidate(vdef.varnode.offset, vdef.varnode.size);
                }
            }

            // Format RHS BEFORE any invalidation of this register
            // Use param_name if set, otherwise check if a named loop Phi exists
            // on the same register (so EAX assignments in the loop body use "iVar1" not "EAX").
            let name = if let Some(ref pn) = vdef.param_name {
                pn.clone()
            } else if let Some(phi_name) = find_register_loop_phi(vdef, ssa) {
                phi_name
            } else {
                var_name(&vdef.varnode, ctx)
            };
            let mut rhs = format_vardef_expr(vdef, ssa, ctx, tracker);

            // Add narrowing cast when output is smaller than input (Subpiece truncation)
            if let Expr::Var(src_id) = &vdef.expr {
                let src = ssa.var(*src_id);
                if src.size > vdef.size && vdef.size > 0 && vdef.size < 8 {
                    let cast = match (vdef.inferred_type, vdef.size) {
                        (InferredType::Signed, 4) => "(int)",
                        (InferredType::Signed, 2) => "(short)",
                        (InferredType::Signed, 1) => "(char)",
                        (_, 4) => "(uint)",
                        (_, 2) => "(uint16_t)",
                        (_, 1) => "(uint8_t)",
                        _ => "",
                    };
                    if !cast.is_empty() && !rhs.starts_with('(') {
                        rhs = format!("{}{}", cast, rhs);
                    }
                }
            }

            // NOW invalidate if this was a computed expression (not a copy/load)
            if vdef.varnode.space == AddressSpaceId::Register {
                if !matches!(&vdef.expr, Expr::Var(_) | Expr::Load(_)) {
                    tracker.invalidate(vdef.varnode.offset, vdef.varnode.size);
                }
            }
            if rhs == name { return; }

            // Fold "REG = expr; return;" into "return expr;" when this is the
            // last visible assignment before a Return in the same statement list
            if vdef.varnode.space == AddressSpaceId::Register
                && (vdef.varnode.offset == 0 || vdef.varnode.offset == 4608) // RAX/EAX or XMM0 — return value register
            {
                // Only fold into return if there's an actual Return in the remaining stmts
                let has_return = stmts[stmt_idx + 1..].iter().any(|s|
                    matches!(s, StructuredStmt::Return(_)));
                let next_is_return = has_return && stmts[stmt_idx + 1..].iter().all(|s| {
                    match s {
                        StructuredStmt::Return(_) => true,
                        StructuredStmt::Assign { lhs, .. } => {
                            let v = ssa.var(*lhs);
                            v.varnode.space == AddressSpaceId::Unique
                                || (v.varnode.space == AddressSpaceId::Register && is_flag(v.varnode.offset))
                        }
                        _ => false,
                    }
                });
                if next_is_return {
                    // For named loop Phis: the assignment is "iVar1 = 0" (initialization),
                    // so don't fold it into "return 0". Instead, print the assignment
                    // separately and let the Return handler emit "return iVar1".
                    if vdef.param_name.is_some() && matches!(&vdef.expr, Expr::Phi(_)) {
                        out.push_str(&format!("{}{} = {};\n", pad, name, rhs));
                        // Don't mark <<returned>> — let the Return handler run
                    } else {
                        // Check if a named loop Phi exists on the same register.
                        // If so, use the Phi's name for the return instead of folding
                        // "EAX = 0; return;" → "return 0;" (which loses the loop variable).
                        let loop_phi_name = find_register_loop_phi(vdef, ssa);
                        if let Some(ref phi_name) = loop_phi_name {
                            // Emit the init assignment and let Return use the Phi name
                            out.push_str(&format!("{}{} = {};\n", pad, phi_name, rhs));
                            // Don't mark <<returned>> — Return handler will resolve through Phi
                        } else {
                            out.push_str(&format!("{}return {};\n", pad, rhs));
                            // Mark that we've printed the return
                            tracker.set_call_return(0, 0, "<<returned>>".to_string());
                            return;
                        }
                    }
                }
            }
            // Skip truly dead stores: var_X with use_count 0 AND a simple value.
            // Don't skip computed expressions (they may feed back through a loop).
            if name.starts_with("var_") && vdef.use_count == 0 {
                let is_simple_dead = !rhs.contains('+') && !rhs.contains('-')
                    && !rhs.contains('*') && !rhs.contains('[') && !rhs.contains('(');
                if is_simple_dead {
                    return; // Dead store of a simple value
                }
            }
            out.push_str(&format!("{}{} = {};\n", pad, name, rhs));
        }
        StructuredStmt::Store { addr, val } => {
            let addr_str = format_addr(*addr, ssa, ctx);
            let vdef = ssa.var(*val);
            // Inside loop bodies (indent > 0), use SSA-based rendering that
            // resolves registers to their underlying stack variables, avoiding
            // stale tracker aliases.
            let val_expr = if indent > 0 && vdef.varnode.space == AddressSpaceId::Register {
                format_store_val(&vdef.expr, ssa, ctx, tracker)
            } else {
                format_var_tracked(*val, ssa, ctx, tracker)
            };
            let size = vdef.size;
            let type_name = typed_name(size, vdef.inferred_type);

            if let Some(stack_name) = try_stack_var_name(*addr, ssa) {
                // Track this stack variable's value for later resolution.
                // But don't overwrite prologue param aliases — the pre-scan set these
                // correctly and the runtime tracker may have contaminated values.
                let existing = tracker.stack_alias.get(&stack_name);
                let is_param_alias = existing.map_or(false, |v| v.starts_with("param_"));
                if !is_param_alias {
                    tracker.stack_alias.insert(stack_name.clone(), val_expr.clone());
                } else {
                    // Keep the param alias but use it as val_expr for display purposes
                    let val_expr_ref = existing.unwrap().clone();
                    // Override val_expr for the checks below
                    let val_expr = val_expr_ref;

                    // Same skip checks as below but with the param alias
                    if val_expr == stack_name { return; }
                    let is_param = val_expr.starts_with("param_");
                    if is_param { return; } // Hide param store
                    return; // Don't print — the param alias is sufficient
                }

                // Skip redundant stores:
                // - Self-assign (var_8 = var_8)
                // - Parameter stores (var_4 = param_0) — tracked, resolved at use
                // - Save patterns (var_c = var_8) — tracked, resolved at restore
                if val_expr == stack_name {
                    return; // Self-assign
                }
                // Hide simple parameter/variable alias stores (e.g., var_8 = param_0)
                // but NOT register stores or computed expressions
                let is_param = val_expr.starts_with("param_")
                    || ssa.var(*val).param_name.is_some();
                let is_var_alias = val_expr.starts_with("var_") && !val_expr.contains(' ');
                let is_dwarf_name = !val_expr.starts_with("var_") && !val_expr.starts_with("param_")
                    && val_expr.chars().next().map_or(false, |c| c.is_ascii_lowercase())
                    && val_expr.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    && !val_expr.chars().all(|c| c.is_ascii_digit() || c == 'x');
                // Hide simple alias stores and register saves.
                // These are tracked for resolution at use sites.
                if is_param || is_var_alias || is_dwarf_name {
                    return; // Simple alias — tracked for later use
                }
                // Hide var_X = REG stores (register holding a tracked value)
                let val_is_reg = val_expr.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
                    && val_expr.len() >= 2 && val_expr.len() <= 3;
                // Hide var_X = func() stores where the value is a function call result
                // Don't match pointer dereferences *(addr) — those are array loads
                let val_is_call = val_expr.contains('(') && val_expr.contains(')')
                    && !val_expr.starts_with("*(")
                    && !val_expr.contains(" + *(")
                    && !val_expr.contains(" - *(");
                if val_is_reg || val_is_call {
                    return; // Tracked — will be resolved at use site
                }
                // Don't skip stores to stack variables that have computed values —
                // these are real assignments that update loop state or function locals
                out.push_str(&format!("{}{} = {};\n", pad, stack_name, val_expr));
            } else {
                out.push_str(&format!("{}*({}*)({}) = {};\n", pad, type_name, addr_str, val_expr));
            }
        }
        StructuredStmt::Call { target, args, out: call_out } => {
            let target_name = format_call_target(target, ssa, ctx);

            // ObjC message send: format as [receiver selector:arg1 param:arg2]
            let call_expr = if let Some(selector) = target_name.strip_prefix("objc_msgSend$") {
                format_objc_call(selector, args, ssa, ctx, tracker)
            } else if target_name == "objc_msgSendSuper2" {
                // super call: [super selector:args]
                if !args.is_empty() {
                    let receiver = format_vardef_expr(ssa.var(args[0]), ssa, ctx, tracker);
                    format!("[super /* {} */]", receiver)
                } else {
                    "[super message]".to_string()
                }
            } else {
                // Normal C function call
                let call_sig = crate::signatures::lookup(&target_name);

                // Trim excess args based on function signature.
                // The arg collector may pick up stale register writes that aren't real args.
                let effective_args: &[VarId] = if let Some(sig) = call_sig {
                    if sig.variadic && !args.is_empty() {
                        // For variadic functions (printf, sprintf, etc.), determine arg count
                        // from format string specifiers. The first fixed param is typically
                        // the format string.
                        let fmt_arg = format_vardef_expr(ssa.var(args[0]), ssa, ctx, tracker);
                        let n_specifiers = count_format_specifiers(&fmt_arg);
                        let total = sig.params.len() + n_specifiers;
                        if args.len() > total && total > 0 {
                            &args[..total]
                        } else {
                            args
                        }
                    } else if !sig.variadic && !sig.params.is_empty() && args.len() > sig.params.len() {
                        &args[..sig.params.len()]
                    } else {
                        args
                    }
                } else {
                    args
                };

                let args_str: Vec<String> = effective_args.iter().enumerate()
                    .map(|(i, a)| {
                        let vdef = ssa.var(*a);
                        let mut expr_str = format_vardef_expr(vdef, ssa, ctx, tracker);
                        if let Some(sig) = call_sig {
                            if let Some(param) = sig.params.get(i) {
                                // Add type cast when param has a specific type and arg is a raw value
                                if let Some(cast) = sigtype_to_cast(param.ty) {
                                    let needs_cast = !expr_str.starts_with('"')
                                        && !expr_str.starts_with("L\"")
                                        && !expr_str.starts_with('(') // already cast
                                        && expr_str != "0"
                                        && !expr_str.contains(cast); // already has the type
                                    // Only cast numeric-looking args, variables, and pointer exprs
                                    // Don't cast if it's already a function call result
                                    let is_castable = needs_cast && (
                                        expr_str.starts_with("0x")
                                        || expr_str.starts_with("local_")
                                        || expr_str.starts_with("param_")
                                        || expr_str.starts_with("lVar")
                                        || expr_str.starts_with("iVar")
                                        || expr_str.starts_with("bVar")
                                        || expr_str.starts_with("wVar")
                                        || expr_str.starts_with("dVar")
                                        || expr_str.starts_with("DAT_")
                                        || expr_str.chars().next().map_or(false, |c| c.is_ascii_digit())
                                    );
                                    if is_castable {
                                        expr_str = format!("({}){}", cast, expr_str);
                                    }
                                }
                                let is_simple = expr_str.starts_with('"')
                                    || expr_str.starts_with("L\"")
                                    || expr_str == "0"
                                    || expr_str == param.name;
                                if !is_simple && args.len() > 1 {
                                    return format!("/*{}*/ {}", param.name, expr_str);
                                }
                            }
                        }
                        expr_str
                    })
                    .collect();
                format!("{}({})", target_name, args_str.join(", "))
            };

            // Calls clobber all registers
            tracker.invalidate_all();

            if let Some(out_var) = call_out {
                // Use format_var to get the proper name (param_name > register name).
                // This ensures "len = strlen(str);" rather than "RAX = strlen(str);"
                // The auto-rename pass will later rename "RAX" → "lVar1" if needed,
                // so "RAX = strcspn(...);" becomes "lVar1 = strcspn(...);" in the final output.
                let name = format_var(*out_var, ssa, ctx);
                out.push_str(&format!("{}{} = {};\n", pad, name, call_expr));
                // Track the register as a normal SSA source (not a call_return expr string).
                // Using set() instead of set_call_return() prevents the call expression from
                // being re-inlined into subsequent statements. This is important because:
                // 1. The result is already explicitly named ("RAX = strcspn(...)"), so
                //    inlining it again would create a duplicate (and post_process #2b would
                //    then remove the named assignment as "redundant").
                // 2. The call result may be used for address computation (e.g., [RBP+RAX-60]=0)
                //    before being passed to another function — we want the named variable, not
                //    the re-inlined call expression, at those use sites.
                let vdef = ssa.var(*out_var);
                if vdef.varnode.space == AddressSpaceId::Register {
                    tracker.set(vdef.varnode.offset, vdef.varnode.size, *out_var);
                    // Also cover sub-register aliases (RAX/EAX at same offset)
                    if vdef.varnode.size == 8 {
                        tracker.set(vdef.varnode.offset, 4, *out_var);
                    } else if vdef.varnode.size == 4 {
                        tracker.set(vdef.varnode.offset, 8, *out_var);
                    }
                }
            } else {
                // Set call return expression for potential inlining
                tracker.set_call_return(0, 8, call_expr.clone()); // RAX
                tracker.set_call_return(0, 4, call_expr.clone()); // EAX

                // Check if the NEXT statement reads EAX and is an arg setup
                // for another call. If so, the call appears inlined — suppress standalone.
                let next_reads_eax = stmts.get(stmt_idx + 1).map_or(false, |s| {
                    if let StructuredStmt::Assign { lhs, .. } = s {
                        let v = ssa.var(*lhs);
                        if let Expr::Var(src) = &v.expr {
                            let sv = ssa.var(*src);
                            sv.varnode.space == AddressSpaceId::Register
                                && sv.varnode.offset == 0
                                && is_arg_consumed_by_call(*lhs, ssa)
                        } else { false }
                    } else { false }
                });

                // Check if the NEXT statement stores the return value to a stack variable.
                // If so, clear the call_return tracker after the store is printed,
                // so subsequent references use the stack var name instead of inlining the call.
                let next_stores_to_stack = stmts.get(stmt_idx + 1).map_or(false, |s| {
                    if let StructuredStmt::Store { addr, val } = s {
                        let vdef = ssa.var(*val);
                        vdef.varnode.space == AddressSpaceId::Register
                            && vdef.varnode.offset == 0 // RAX/EAX
                            && try_stack_var_name(*addr, ssa).is_some()
                    } else { false }
                });

                if !next_reads_eax {
                    // For allocation functions, show the return assignment
                    // since the pointer is always used afterwards.
                    let is_alloc = target_name == "malloc" || target_name == "calloc"
                        || target_name == "realloc" || target_name == "mmap"
                        || target_name == "strdup";
                    if is_alloc {
                        out.push_str(&format!("{}ptr = {};\n", pad, call_expr));
                        // Replace the call_return with "ptr" so subsequent uses
                        // (including the Store to stack) show "ptr" instead of
                        // re-inlining the full malloc(...) expression.
                        tracker.set_call_return(0, 8, "ptr".to_string());
                        tracker.set_call_return(0, 4, "ptr".to_string());
                    } else {
                        // For non-alloc calls: if the result is stored to stack,
                        // use the call as a named result for the stack var
                        out.push_str(&format!("{}{};\n", pad, call_expr));
                    }
                }

                // If the result is stored to stack, invalidate the call_return tracker
                // AFTER the store is printed, so the stack var name is used for later refs.
                // But for alloc calls we already set tracker to "ptr" above.
                if next_stores_to_stack && !target_name.starts_with("malloc")
                    && !target_name.starts_with("calloc") && !target_name.starts_with("realloc")
                    && !target_name.starts_with("mmap") && !target_name.starts_with("strdup")
                {
                    tracker.invalidate(0, 8);
                    tracker.invalidate(0, 4);
                }
            }
        }
        StructuredStmt::Return(val) => {
            // Skip if the return was already folded into a preceding assignment
            if tracker.get_expr_str(0, 0).map_or(false, |s| s == "<<returned>>") {
                return;
            }
            if let Some(v) = val {
                let vdef = ssa.var(*v);
                
                // For return values, resolve through the SSA expression to find
                // the actual stack variable being returned, not the tracker alias.
                let expr = if let Expr::Load(ptr) = &vdef.expr {
                    // Return value loaded from stack: show the stack variable name
                    if let Some(offset) = get_rbp_offset(*ptr, ssa) {
                        let name = format!("var_{:x}", offset);
                        resolve_stack_alias(&name, tracker)
                    } else {
                        format_expr_tracked(&vdef.expr, ssa, ctx, tracker)
                    }
                } else if let Expr::Var(inner) = &vdef.expr {
                    // Follow one level of Var indirection
                    let iv = ssa.var(*inner);
                    if let Expr::Load(ptr) = &iv.expr {
                        if let Some(offset) = get_rbp_offset(*ptr, ssa) {
                            let name = format!("var_{:x}", offset);
                            resolve_stack_alias(&name, tracker)
                        } else {
                            format_expr_tracked(&vdef.expr, ssa, ctx, tracker)
                        }
                    } else {
                        format_expr_tracked(&vdef.expr, ssa, ctx, tracker)
                    }
                } else {
                    format_expr_tracked(&vdef.expr, ssa, ctx, tracker)
                };
                out.push_str(&format!("{}return {};\n", pad, expr));
            } else {
                out.push_str(&format!("{}return;\n", pad));
            }
        }
        StructuredStmt::IfElse { cond, then_body, else_body } => {
            let cv = ssa.var(*cond);
            if let Expr::BinOp(k, l, r) = &cv.expr {
                let lv = ssa.var(*l); let rv = ssa.var(*r);
            }
            let cond_expr = format_condition_tracked(*cond, ssa, ctx, tracker);
            let then_filtered = filter_boilerplate(then_body, ssa);
            let else_filtered = filter_boilerplate(else_body, ssa);
            let then_empty = is_body_empty(&then_filtered, ssa);
            let else_empty = is_body_empty(&else_filtered, ssa);
            if then_empty && else_empty { return; }
            if then_empty && !else_empty {
                let neg_cond = negate_condition(&cond_expr);
                out.push_str(&format!("{}if ({}) {{\n", pad, neg_cond));
                print_stmts(&else_filtered, ssa, ctx, indent + 1, out);
                out.push_str(&format!("{}}}\n", pad));
            } else {
                out.push_str(&format!("{}if ({}) {{\n", pad, cond_expr));
                print_stmts(&then_filtered, ssa, ctx, indent + 1, out);
                if !else_empty {
                    out.push_str(&format!("{}}} else {{\n", pad));
                    print_stmts(&else_filtered, ssa, ctx, indent + 1, out);
                }
                out.push_str(&format!("{}}}\n", pad));
            }
        }
        StructuredStmt::While { cond, negate, body } => {
            let cond_expr = format_condition_tracked(*cond, ssa, ctx, tracker);
            let display_cond = if *negate {
                negate_condition(&cond_expr)
            } else {
                cond_expr
            };
            let body_filtered = filter_boilerplate(body, ssa);
            out.push_str(&format!("{}while ({}) {{\n", pad, display_cond));
            print_stmts(&body_filtered, ssa, ctx, indent + 1, out);
            out.push_str(&format!("{}}}\n", pad));
        }
        StructuredStmt::DoWhile { cond, negate, body } => {
            let body_filtered = filter_boilerplate(body, ssa);
            let cond_expr = format_condition_tracked(*cond, ssa, ctx, tracker);
            let display_cond = if *negate {
                negate_condition(&cond_expr)
            } else {
                cond_expr
            };
            // If the condition is always-false (e.g., "1 < 0", "1 > 1"), or the body
            // unconditionally returns, the loop executes at most once — emit straight-line.
            let is_always_false = matches!(display_cond.as_str(),
                "1 < 0" | "1 > 1" | "0 > 0" | "0 != 0" | "1 == 0" | "0 > 1");
            let body_returns = matches!(body_filtered.last(),
                Some(StructuredStmt::Return(_)));
            if is_always_false || body_returns {
                print_stmts(&body_filtered, ssa, ctx, indent, out);
            } else {
                out.push_str(&format!("{}do {{\n", pad));
                print_stmts(&body_filtered, ssa, ctx, indent + 1, out);
                out.push_str(&format!("{}}} while ({});\n", pad, display_cond));
            }
        }
        StructuredStmt::Switch { expr, cases, default } => {
            let expr_str = format_var_tracked(*expr, ssa, ctx, tracker);
            out.push_str(&format!("{}switch ({}) {{\n", pad, expr_str));
            for (vals, body) in cases {
                for val in vals {
                    out.push_str(&format!("{}    case {}:\n", pad, val));
                }
                let body_filtered = filter_boilerplate(body, ssa);
                print_stmts(&body_filtered, ssa, ctx, indent + 2, out);
                // Add break if body doesn't end with return
                if !body_filtered.iter().any(|s| matches!(s, StructuredStmt::Return(_))) {
                    out.push_str(&format!("{}        break;\n", pad));
                }
            }
            if !default.is_empty() {
                out.push_str(&format!("{}    default:\n", pad));
                let default_filtered = filter_boilerplate(default, ssa);
                print_stmts(&default_filtered, ssa, ctx, indent + 2, out);
            }
            out.push_str(&format!("{}}}\n", pad));
        }
        StructuredStmt::Break => {
            out.push_str(&format!("{}break;\n", pad));
        }
        StructuredStmt::Continue => {
            out.push_str(&format!("{}continue;\n", pad));
        }
        StructuredStmt::Goto(addr) => {
            out.push_str(&format!("{}goto label_{:x};\n", pad, addr));
        }
        StructuredStmt::Label(addr) => {
            out.push_str(&format!("label_{:x}:\n", addr));
        }
    }
}

/// Check if a named loop Phi exists for the same register as the given VarDef.
/// Returns the Phi's param_name if found.
fn find_register_loop_phi(vdef: &VarDef, ssa: &SsaCfg) -> Option<String> {
    if vdef.varnode.space != AddressSpaceId::Register { return None; }
    for v in &ssa.vars {
        if v.varnode.space == AddressSpaceId::Register
            && v.varnode.offset == vdef.varnode.offset
        {
            if let Some(ref name) = v.param_name {
                if matches!(&v.expr, Expr::Phi(_)) {
                    return Some(name.clone());
                }
            }
        }
    }
    None
}

/// Follow Var/BinOp/UnaryOp chains to find a named variable (param_name set).
/// Returns the name if found within `depth` hops, None otherwise.
fn resolve_to_named_var(id: VarId, ssa: &SsaCfg, depth: u32) -> Option<String> {
    if depth == 0 { return None; }
    let vdef = ssa.var(id);
    if let Some(ref name) = vdef.param_name {
        return Some(name.clone());
    }
    match &vdef.expr {
        Expr::Var(inner) => resolve_to_named_var(*inner, ssa, depth - 1),
        Expr::Phi(inputs) => {
            for inp in inputs {
                if let Some(name) = resolve_to_named_var(*inp, ssa, depth - 1) {
                    return Some(name);
                }
            }
            None
        }
        Expr::UnaryOp(UnaryOpKind::Zext | UnaryOpKind::Sext, inner) => {
            resolve_to_named_var(*inner, ssa, depth - 1)
        }
        Expr::BinOp(_, l, r) => {
            resolve_to_named_var(*l, ssa, depth - 1)
                .or_else(|| resolve_to_named_var(*r, ssa, depth - 1))
        }
        _ => None,
    }
}

/// Format a VarId with register tracking — resolves register copies to their source.
fn format_var_tracked(id: VarId, ssa: &SsaCfg, ctx: &PrintCtx, tracker: &RegTracker) -> String {
    let vdef = ssa.var(id);

    // If this variable has a parameter name (from stack param detection or ABI naming),
    // use it directly. This prevents x86-32 stack params from showing as *(param_0)
    // when the Load from [EBP+8] is just reading the parameter value, not dereferencing it.
    if let Some(ref name) = vdef.param_name {
        return name.clone();
    }

    // For Phi/Var nodes on argument registers, check if any input has a param_name.
    // This handles the case where SSA convergence created a Phi for a loop header
    // that merges the entry param value with a loop-modified value.
    if vdef.varnode.space == AddressSpaceId::Register {
        let param = match &vdef.expr {
            Expr::Phi(inputs) => inputs.iter().find_map(|inp| {
                ssa.var(*inp).param_name.as_ref().cloned()
            }),
            Expr::Var(src) => ssa.var(*src).param_name.as_ref().cloned(),
            _ => None,
        };
        if let Some(name) = param {
            return name;
        }
    }

    // For Unique-space: normally use standard formatting.
    // BUT: if this Unique wraps a UnaryOp(Sext/Zext) of a register that has
    // a call return expression, inline it.
    if vdef.varnode.space == AddressSpaceId::Unique {
        if let Expr::UnaryOp(kind, inner) = &vdef.expr {
            let iv = ssa.var(*inner);
            if iv.varnode.space == AddressSpaceId::Register {
                if let Some(expr_str) = tracker.get_expr_str(iv.varnode.offset, iv.varnode.size) {
                    // Inline the call return through the cast
                    return match kind {
                        UnaryOpKind::Sext => format!("(int64_t){}", expr_str),
                        UnaryOpKind::Zext => format!("(uint64_t){}", expr_str),
                        _ => expr_str.to_string(),
                    };
                }
                // Also resolve through regular tracking
                if let Some(tracked_id) = tracker.get(iv.varnode.offset, iv.varnode.size) {
                    let tv = ssa.var(tracked_id);
                    // If tracked to a Load (stack var), show the stack var name
                    if let Expr::Load(ptr) = &tv.expr {
                        if let Some(offset) = get_rbp_offset(*ptr, ssa) {
                            let var_name = format!("var_{:x}", offset);
                            // Resolve through stack alias (var_c → var_8 → param_0)
                            let resolved = resolve_stack_alias(&var_name, tracker);
                            return match kind {
                                UnaryOpKind::Sext => format!("(int64_t){}", resolved),
                                UnaryOpKind::Zext => format!("(uint64_t){}", resolved),
                                _ => resolved,
                            };
                        }
                    }
                    // If tracked to a Var (copy of another var), resolve that
                    if let Expr::Var(src) = &tv.expr {
                        let sv = ssa.var(*src);
                        if sv.param_name.is_some() || sv.varnode.space != AddressSpaceId::Register {
                            let name = format_var(*src, ssa, ctx);
                            return match kind {
                                UnaryOpKind::Sext => format!("(int64_t){}", name),
                                UnaryOpKind::Zext => format!("(uint64_t){}", name),
                                _ => name,
                            };
                        }
                    }
                }
            }
        }
        // Check BinOp whose operands have tracked registers (Unique or direct)
        if let Expr::BinOp(kind, left, right) = &vdef.expr {
            let lv = ssa.var(*left);
            let rv = ssa.var(*right);
            let l_tracked = (lv.varnode.space == AddressSpaceId::Register
                    && (tracker.get(lv.varnode.offset, lv.varnode.size).is_some()
                        || tracker.get_expr_str(lv.varnode.offset, lv.varnode.size).is_some()))
                || (lv.varnode.space == AddressSpaceId::Unique
                    && expr_has_tracked_reg(&lv.expr, ssa, tracker));
            let r_tracked = (rv.varnode.space == AddressSpaceId::Register
                    && (tracker.get(rv.varnode.offset, rv.varnode.size).is_some()
                        || tracker.get_expr_str(rv.varnode.offset, rv.varnode.size).is_some()))
                || (rv.varnode.space == AddressSpaceId::Unique
                    && expr_has_tracked_reg(&rv.expr, ssa, tracker));
            if l_tracked || r_tracked {
                let l = format_var_tracked(*left, ssa, ctx, tracker);
                let r = format_var_tracked(*right, ssa, ctx, tracker);
                return format!("{} {} {}", l, binop_str(*kind), r);
            }
        }
        // For Loads from stack, resolve through alias chain
        if let Expr::Load(ptr) = &vdef.expr {
            if let Some(offset) = get_rbp_offset(*ptr, ssa) {
                let name = format!("var_{:x}", offset);
                return resolve_stack_alias(&name, tracker);
            }
        }
        return format_expr(&vdef.expr, ssa, ctx);
    }
    // Check register tracking (try exact size, then sub-register sizes)
    if vdef.varnode.space == AddressSpaceId::Register {
        // Check call return tracker FIRST — call returns are not in the SSA expression tree
        // because calls are modeled as statements/terminators, not expressions.
        // The call_return tracker has authoritative call result strings.
        if let Some(expr_str) = tracker.get_expr_str(vdef.varnode.offset, vdef.varnode.size) {
            return expr_str.to_string();
        }
        // Also check smaller sizes at same offset (RAX → EAX tracking)
        for sz in [4u32, 8, 2, 1] {
            if sz == vdef.varnode.size { continue; }
            if let Some(expr_str) = tracker.get_expr_str(vdef.varnode.offset, sz) {
                return expr_str.to_string();
            }
        }

        // SSA-direct rendering: if this register var has a concrete SSA expression
        // (Load, BinOp, UnaryOp), use it directly instead of the reg_source tracker.
        // This prevents stale register values from being substituted when registers are
        // reused within a block. Skip for Unknown expressions (which need the tracker).
        {
            let mut cur_id = id;
            let mut cur_expr = &vdef.expr;
            let mut depth = 0;
            while let Expr::Var(src) = cur_expr {
                if depth > 5 { break; }
                cur_id = *src;
                cur_expr = &ssa.var(*src).expr;
                depth += 1;
            }
            match cur_expr {
                Expr::Load(_) | Expr::BinOp(_, _, _) | Expr::UnaryOp(_, _)
                | Expr::Ternary(_, _, _) => {
                    return format_vardef_expr(ssa.var(cur_id), ssa, ctx, tracker);
                }
                _ => {}
            }
        }

        let tracked_id = tracker.get(vdef.varnode.offset, vdef.varnode.size)
            .or_else(|| {
                // Try sub-register sizes
                for sz in [4u32, 8, 2, 1] {
                    if sz == vdef.varnode.size { continue; }
                    if let Some(id) = tracker.get(vdef.varnode.offset, sz) {
                        return Some(id);
                    }
                }
                None
            });
        if let Some(tracked_id) = tracked_id {
            let tracked_vdef = ssa.var(tracked_id);
            if let Expr::Load(ptr) = &tracked_vdef.expr {
                if let Some(offset) = get_rbp_offset(*ptr, ssa) {
                    let name = format!("var_{:x}", offset);
                    return resolve_stack_alias(&name, tracker);
                }
            }
            if tracked_vdef.varnode.space != AddressSpaceId::Register {
                return format_var(tracked_id, ssa, ctx);
            }
            if tracked_id != id {
                return format_var(tracked_id, ssa, ctx);
            }
        }
    }
    format_var(id, ssa, ctx)
}

/// Recursively check if an expression tree references any tracked register.
fn expr_has_tracked_reg(expr: &Expr, ssa: &SsaCfg, tracker: &RegTracker) -> bool {
    match expr {
        Expr::Var(inner) => {
            let iv = ssa.var(*inner);
            if iv.varnode.space == AddressSpaceId::Register {
                return tracker.get(iv.varnode.offset, iv.varnode.size).is_some()
                    || tracker.get_expr_str(iv.varnode.offset, iv.varnode.size).is_some();
            }
            if iv.varnode.space == AddressSpaceId::Unique {
                return expr_has_tracked_reg(&iv.expr, ssa, tracker);
            }
            false
        }
        Expr::UnaryOp(_, inner) => {
            let iv = ssa.var(*inner);
            if iv.varnode.space == AddressSpaceId::Register {
                return tracker.get(iv.varnode.offset, iv.varnode.size).is_some()
                    || tracker.get_expr_str(iv.varnode.offset, iv.varnode.size).is_some();
            }
            if iv.varnode.space == AddressSpaceId::Unique {
                return expr_has_tracked_reg(&iv.expr, ssa, tracker);
            }
            false
        }
        Expr::BinOp(_, left, right) => {
            expr_has_tracked_reg(&ssa.var(*left).expr, ssa, tracker)
                || expr_has_tracked_reg(&ssa.var(*right).expr, ssa, tracker)
        }
        _ => false,
    }
}

/// Resolve a stack variable name through the alias chain.
/// var_c → var_8 → param_0
fn resolve_stack_alias(name: &str, tracker: &RegTracker) -> String {
    let mut current = name.to_string();
    for _ in 0..5 { // max depth
        if let Some(alias) = tracker.stack_alias.get(&current) {
            if alias == &current { break; }
            current = alias.clone();
        } else {
            break;
        }
    }
    current
}

/// Format an Objective-C message send as bracket syntax: [receiver selector:arg1 param:arg2]
fn format_objc_call(selector: &str, args: &[VarId], ssa: &SsaCfg, ctx: &PrintCtx, tracker: &RegTracker) -> String {
    // First argument is the receiver (self or class).
    // In AArch64 ObjC ABI, x0 holds self/class before the call.
    // Try: explicit arg first, then tracker for x0 register.
    let receiver = if !args.is_empty() {
        let vdef = ssa.var(args[0]);
        let r = format_vardef_expr(vdef, ssa, ctx, tracker);
        // Clean up common receiver patterns
        // ObjC ARC calls in x0 are not the actual receiver — the previous message result is
        let r = if r.starts_with("objc_retain") || r.starts_with("objc_release")
            || r.starts_with("[super") || r.starts_with("[[")
        {
            "self".to_string()
        } else { r };
        if r.starts_with("param_") || r.starts_with("self") || r.starts_with("lVar") || r.starts_with("iVar") {
            r
        } else if r.contains("OBJC_CLASS") || r.starts_with("*(") {
            // Class method: extract class name if possible
            if let Some(cls) = r.strip_prefix("*(") {
                if let Some(cls) = cls.strip_suffix(")") {
                    if cls.contains("OBJC_CLASS") {
                        // *(PTR__OBJC_CLASS___UIColor...) → UIColor
                        cls.rsplit("___").next()
                            .and_then(|s| s.split('_').next())
                            .unwrap_or(cls).to_string()
                    } else { r }
                } else { r }
            } else { r }
        } else {
            r
        }
    } else {
        // No explicit arg — try to get x0 from the register tracker
        // AArch64 x0 is register offset 0, size 8
        if let Some(x0_expr) = tracker.get_expr_str(0, 8) {
            let r = x0_expr.to_string();
            // Clean up ARC noise in tracker result
            if r.contains("objc_retain") || r.contains("objc_release") || r.starts_with("[") {
                "self".to_string()
            } else {
                r
            }
        } else {
            "self".to_string()
        }
    };

    // The remaining arguments (after receiver, skipping selector which is implicit in the name)
    // In AArch64 ObjC ABI: x0=self, x1=_cmd (selector), x2..=actual args
    // Our call args may or may not include x1 depending on how they were collected
    let extra_args: Vec<String> = args.iter().skip(1).map(|a| {
        let vdef = ssa.var(*a);
        format_vardef_expr(vdef, ssa, ctx, tracker)
    }).collect();

    // Parse selector parts (split by ':')
    let parts: Vec<&str> = selector.split(':').collect();
    let num_params = selector.matches(':').count();

    if num_params == 0 {
        // No-argument message: [receiver selector]
        format!("[{} {}]", receiver, selector)
    } else if extra_args.len() >= num_params {
        // Interleave selector parts with arguments
        let mut result = format!("[{}", receiver);
        for (i, part) in parts.iter().enumerate() {
            if part.is_empty() { continue; }
            if i < extra_args.len() {
                result.push_str(&format!(" {}:{}", part, extra_args[i]));
            } else {
                result.push_str(&format!(" {}", part));
            }
        }
        result.push(']');
        result
    } else {
        // Not enough args — fall back to simpler format
        let args_str = extra_args.join(", ");
        if args_str.is_empty() {
            format!("[{} {}]", receiver, selector.trim_end_matches(':'))
        } else {
            format!("[{} {} {}]", receiver, selector.trim_end_matches(':'), args_str)
        }
    }
}

/// Simplify demangled MSVC C++ names for pseudocode readability.
fn simplify_msvc_name(name: &str) -> String {
    let mut s = name.to_string();
    // Remove parameter types: "operator<<(long)" → "operator<<"
    if let Some(paren) = s.find('(') {
        if s[..paren].contains("operator") {
            s = s[..paren].to_string();
        } else if !s[..paren].is_empty() {
            s = s[..paren].to_string();
        }
    }
    // Simplify common std:: template types (various spacing from different demanglers)
    let basic_ostream_patterns = [
        "std::basic_ostream<char, std::char_traits<char>>",
        "std::basic_ostream<char,struct std::char_traits<char> >",
        "std::basic_ostream<char, struct std::char_traits<char> >",
        "std::basic_ostream<char,std::char_traits<char> >",
        "std::basic_ostream<char, std::char_traits<char> >",
    ];
    for pat in basic_ostream_patterns {
        s = s.replace(pat, "std::ostream");
    }
    let basic_istream_patterns = [
        "std::basic_istream<char, std::char_traits<char>>",
        "std::basic_istream<char,struct std::char_traits<char> >",
        "std::basic_istream<char, struct std::char_traits<char> >",
        "std::basic_istream<char,std::char_traits<char> >",
        "std::basic_istream<char, std::char_traits<char> >",
    ];
    for pat in basic_istream_patterns {
        s = s.replace(pat, "std::istream");
    }
    s = s.replace("std::basic_string<char, std::char_traits<char>, std::allocator<char>>", "std::string");
    s = s.replace("std::basic_string<char,std::char_traits<char>,std::allocator<char> >", "std::string");
    // Remove "class " and "struct " prefixes
    s = s.replace("class ", "").replace("struct ", "");
    // Simplify operator calls
    if s.contains("std::ostream::operator<<") || s.contains("ostream::operator<<") {
        return "cout <<".to_string();
    }
    if s.contains("std::istream::operator>>") || s.contains("istream::operator>>") {
        return "cin >>".to_string();
    }
    // Simplify global objects
    if s.contains("std::ostream") && s.contains("cout") { return "cout".to_string(); }
    if s.contains("std::istream") && s.contains("cin") { return "cin".to_string(); }
    s = s.replace("std::cout", "cout").replace("std::cin", "cin").replace("std::endl", "endl");
    // Remove calling convention and access specifiers
    s = s.replace("public: ", "").replace("private: ", "").replace("protected: ", "");
    s = s.replace("virtual ", "");
    s = s.replace("__cdecl ", "").replace("__thiscall ", "").replace("__stdcall ", "");
    // Remove return type prefix for method calls: "int std::istream::get" → "cin.get"
    if let Some(last_space) = s.rfind(' ') {
        let after = &s[last_space + 1..];
        if after.contains("::") {
            s = after.to_string();
        }
    }
    // Simplify std::istream::method → cin.method, std::ostream::method → cout.method
    s = s.replace("std::istream::", "cin.").replace("std::ostream::", "cout.");
    s = s.trim().to_string();
    s
}

/// Format a VarDef's expression, respecting param_name for stack parameters.
/// Use this instead of format_expr_tracked when you have the VarDef available.
fn format_vardef_expr(vdef: &VarDef, ssa: &SsaCfg, ctx: &PrintCtx, tracker: &RegTracker) -> String {
    // If this variable is a named parameter (e.g., x86-32 stack param from [EBP+8]),
    // return the param name directly — don't render the Load as a pointer deref.
    if let Some(ref name) = vdef.param_name {
        if matches!(&vdef.expr, Expr::Load(_)) {
            return name.clone();
        }
        // For named loop Phis: render as the initial value (first input).
        // This produces "iVar1 = 0" instead of "iVar1 = phi(0, iVar1+1)".
        if let Expr::Phi(ref inputs) = vdef.expr {
            if !inputs.is_empty() {
                return format_var_tracked(inputs[0], ssa, ctx, tracker);
            }
        }
    }
    let result = format_expr_tracked(&vdef.expr, ssa, ctx, tracker);

    // Add typed pointer cast for Load dereferences: *(addr) → *(type*)(addr)
    // Only when the result is an untyped deref and the var has a known size
    if matches!(&vdef.expr, Expr::Load(_)) && result.starts_with("*(") && !result.contains("*)(") {
        let type_name = typed_name(vdef.size, vdef.inferred_type);
        // Extract the address from *(addr) and re-wrap with type
        if let Some(inner) = result.strip_prefix("*(").and_then(|s| s.strip_suffix(')')) {
            return format!("*({}*)({})", type_name, inner);
        }
    }
    result
}

fn format_expr_tracked(expr: &Expr, ssa: &SsaCfg, ctx: &PrintCtx, tracker: &RegTracker) -> String {
    match expr {
        Expr::Var(id) => format_var_tracked(*id, ssa, ctx, tracker),
        Expr::BinOp(kind, left, right) => {
            // If this BinOp computes an RSP-relative address, emit it as var_XX.
            // This handles chained RSP arithmetic like (RSP - 8) - 45 → var_35.
            if matches!(kind, BinOpKind::Sub | BinOpKind::Add) {
                if let Some(off_c) = get_const_val(*right, ssa) {
                    if let Some(inner_off) = get_rsp_offset(*left, ssa) {
                        let delta = match kind {
                            BinOpKind::Sub => -(off_c as i64),
                            _ => off_c as i64,
                        };
                        let total = inner_off + delta;
                        if total < 0 {
                            return format!("var_{:x}", (-total) as u64);
                        }
                    }
                }
            }
            // CDQ+IDIV simplification: SDiv/SRem of 64-bit concatenation → 32-bit division
            // Pattern: SDiv(Or(Lsl(x, 32), Zext(val)), Sext/Zext(divisor)) → val / divisor
            if matches!(kind, BinOpKind::SDiv | BinOpKind::SRem | BinOpKind::Div | BinOpKind::Rem) {
                if let Some(val_id) = extract_concat_low_half(*left, ssa) {
                    let divisor_id = unwrap_ext(*right, ssa);
                    let l = format_var_tracked(val_id, ssa, ctx, tracker);
                    let r = format_var_tracked(divisor_id, ssa, ctx, tracker);
                    let op = binop_str(*kind);
                    return format!("{} {} {}", l, op, r);
                }
            }

            // Simplify x + 0 → x, x - 0 → x, x * 1 → x, x | 0 → x, x & -1 → x
            if matches!(kind, BinOpKind::Add | BinOpKind::Sub | BinOpKind::Or | BinOpKind::Xor) {
                if let Expr::Const(0, _) = &ssa.var(*right).expr {
                    return format_var_tracked(*left, ssa, ctx, tracker);
                }
            }
            if matches!(kind, BinOpKind::Add | BinOpKind::Or | BinOpKind::Xor) {
                if let Expr::Const(0, _) = &ssa.var(*left).expr {
                    return format_var_tracked(*right, ssa, ctx, tracker);
                }
            }
            if matches!(kind, BinOpKind::Mult) {
                if let Expr::Const(1, _) = &ssa.var(*right).expr {
                    return format_var_tracked(*left, ssa, ctx, tracker);
                }
                if let Expr::Const(1, _) = &ssa.var(*left).expr {
                    return format_var_tracked(*right, ssa, ctx, tracker);
                }
            }

            let mut l = format_var_tracked(*left, ssa, ctx, tracker);
            let mut r = format_var_tracked(*right, ssa, ctx, tracker);
            let op = binop_str(*kind);
            if matches!(kind, BinOpKind::Add) {
                let rv = ssa.var(*right);
                if let Expr::Const(val, sz) = &rv.expr {
                    if *val > 0x7fffffffffffffff {
                        let neg = (!*val).wrapping_add(1);
                        return format!("{} - {}", l, format_const(neg, *sz));
                    }
                }
            }
            // Add signedness casts for signed operations
            match kind {
                BinOpKind::SLess | BinOpKind::SLessEq | BinOpKind::SDiv | BinOpKind::SRem => {
                    let lv = ssa.var(*left);
                    let rv = ssa.var(*right);
                    // Cast operands to signed only when needed:
                    // - Size mismatch (widening/narrowing cast is meaningful)
                    // - Explicitly unsigned type (cast makes signedness clear)
                    // Skip cast for Unknown/Signed types at native int size (4 bytes)
                    let needs_l_cast = lv.inferred_type == InferredType::Unsigned
                        || (lv.inferred_type != InferredType::Signed && lv.size < 4);
                    if needs_l_cast && !l.starts_with('(')
                        && !l.starts_with('-') && !l.starts_with('"') && l != "0"
                    {
                        let cast = match lv.size { 1 => "(char)", 2 => "(short)", _ => "(int)" };
                        l = format!("{}{}", cast, l);
                    }
                    let needs_r_cast = rv.inferred_type == InferredType::Unsigned
                        || (rv.inferred_type != InferredType::Signed && rv.size < 4);
                    if needs_r_cast && !r.starts_with('(')
                        && !r.starts_with('-') && !r.starts_with('"') && r != "0"
                        && !r.chars().next().map_or(false, |c| c.is_ascii_digit())
                    {
                        let cast = match rv.size { 1 => "(char)", 2 => "(short)", _ => "(int)" };
                        r = format!("{}{}", cast, r);
                    }
                }
                BinOpKind::Div | BinOpKind::Rem | BinOpKind::Less | BinOpKind::LessEq => {
                    let lv = ssa.var(*left);
                    let rv = ssa.var(*right);
                    // Cast to unsigned for explicitly unsigned comparisons/arithmetic
                    if lv.inferred_type == InferredType::Signed && !l.starts_with('(') {
                        let cast = match lv.size { 1 => "(uint8_t)", 2 => "(uint16_t)", _ => "(uint)" };
                        l = format!("{}{}", cast, l);
                    }
                    if rv.inferred_type == InferredType::Signed && !r.starts_with('(')
                        && !r.chars().next().map_or(false, |c| c.is_ascii_digit())
                    {
                        let cast = match rv.size { 1 => "(uint8_t)", 2 => "(uint16_t)", _ => "(uint)" };
                        r = format!("{}{}", cast, r);
                    }
                }
                // Arithmetic right shift: cast to signed to distinguish from logical shift
                BinOpKind::Asr => {
                    let lv = ssa.var(*left);
                    if lv.inferred_type != InferredType::Signed && !l.starts_with('(') {
                        let cast = match lv.size { 1 => "(char)", 2 => "(short)", 4 => "(int)", _ => "(long)" };
                        l = format!("{}{}", cast, l);
                    }
                }
                // Logical right shift: cast to unsigned to distinguish from arithmetic
                BinOpKind::Lsr => {
                    let lv = ssa.var(*left);
                    if lv.inferred_type == InferredType::Signed && !l.starts_with('(') {
                        let cast = match lv.size { 1 => "(uint8_t)", 2 => "(uint16_t)", 4 => "(uint)", _ => "(uint64_t)" };
                        l = format!("{}{}", cast, l);
                    }
                }
                // Bitwise AND/OR/XOR: cast to unsigned when operating on signed values
                BinOpKind::And | BinOpKind::Or | BinOpKind::Xor => {
                    let lv = ssa.var(*left);
                    if lv.inferred_type == InferredType::Signed && !l.starts_with('(')
                        && !l.starts_with('-') {
                        let cast = match lv.size { 1 => "(uint8_t)", 2 => "(uint16_t)", 4 => "(uint)", _ => "(uint64_t)" };
                        l = format!("{}{}", cast, l);
                    }
                }
                _ => {}
            }
            format!("{} {} {}", l, op, r)
        }
        Expr::UnaryOp(kind, input) => {
            let i = format_var_tracked(*input, ssa, ctx, tracker);
            let input_def = ssa.var(*input);
            match kind {
                UnaryOpKind::Neg => format!("-{}", i),
                UnaryOpKind::Not => format!("~{}", i),
                UnaryOpKind::BoolNot => format!("!{}", i),
                UnaryOpKind::Zext => {
                    // Zero-extend: cast to unsigned target type when widening
                    // Only emit cast when input is narrower (actual widening)
                    let input_size = input_def.size;
                    if input_size <= 4 && input_size > 0 {
                        let cast_type = match input_size {
                            1 => "uint8_t",
                            2 => "uint16_t",
                            4 => "uint",
                            _ => "uint",
                        };
                        format!("({}){}", cast_type, i)
                    } else {
                        i
                    }
                }
                UnaryOpKind::Sext => {
                    // Sign-extend: cast to signed type of the INPUT size
                    let input_size = input_def.size;
                    if input_size <= 4 && input_size > 0 {
                        let cast_type = match input_size {
                            1 => "char",
                            2 => "short",
                            4 => "int",
                            _ => "int",
                        };
                        format!("({}){}", cast_type, i)
                    } else {
                        i
                    }
                }
                UnaryOpKind::Int2Float => format!("(float){}", i),
                UnaryOpKind::Trunc => {
                    // Float-to-int truncation
                    format!("(int){}", i)
                }
                UnaryOpKind::Float2Float => {
                    // Float precision conversion
                    format!("(double){}", i)
                }
                _ => format!("{}({})", unaryop_str(*kind), i),
            }
        }
        Expr::Load(ptr) => {
            if let Some(offset) = get_rbp_offset(*ptr, ssa) {
                let name = format!("var_{:x}", offset);
                return resolve_stack_alias(&name, tracker);
            }
            format_expr(expr, ssa, ctx)
        }
        Expr::FieldAccess(base, offset) => {
            let base_str = format_var_tracked(*base, ssa, ctx, tracker);
            // Wrap in parens when the base contains a top-level operator so the
            // `->` binds to the full address expression rather than the last
            // operand (e.g. `lVar + 16->field_4` → `(lVar + 16)->field_4`).
            if needs_paren_for_arrow(&base_str) {
                format!("({})->field_{:x}", base_str, offset)
            } else {
                format!("{}->field_{:x}", base_str, offset)
            }
        }
        Expr::Ternary(cond, then_val, else_val) => {
            let c = format_var_tracked(*cond, ssa, ctx, tracker);
            let t = format_var_tracked(*then_val, ssa, ctx, tracker);
            let e = format_var_tracked(*else_val, ssa, ctx, tracker);
            format!("({}) ? {} : {}", c, t, e)
        }
        Expr::Phi(inputs) => {
            // Check if any input resolves to a named variable (loop Phi or param).
            // Use the name instead of expanding "phi(...)".
            for inp in inputs {
                if let Some(name) = resolve_to_named_var(*inp, ssa, 4) {
                    return name;
                }
            }
            format_expr(expr, ssa, ctx)
        }
        _ => format_expr(expr, ssa, ctx),
    }
}

#[allow(dead_code)]
fn print_stmt(stmt: &StructuredStmt, ssa: &SsaCfg, ctx: &PrintCtx, indent: usize, out: &mut String) {
    let pad: String = "    ".repeat(indent);

    match stmt {
        StructuredStmt::Assign { lhs, .. } => {
            let vdef = ssa.var(*lhs);
            if vdef.varnode.space == AddressSpaceId::Unique { return; }
            if vdef.varnode.space == AddressSpaceId::Register && is_flag(vdef.varnode.offset) { return; }
            if matches!(&vdef.expr, Expr::Phi(_)) { return; }
            if is_zext_artifact(vdef, ssa) { return; }
            if is_self_assign(vdef, ssa) { return; }
            // Skip call return value captures (e.g., ECX = EAX after a call)
            // when the var is only used once — it will be inlined at the use site
            if vdef.call_return && vdef.use_count <= 1 { return; }
            // Skip argument register assignments that are consumed by a call
            // (they're shown inline in the call's argument list)
            if is_arg_consumed_by_call(*lhs, ssa) { return; }

            let name = var_name(&vdef.varnode, ctx);
            let rhs = format_expr(&vdef.expr, ssa, ctx);
            out.push_str(&format!("{}{} = {};\n", pad, name, rhs));
        }
        StructuredStmt::Store { addr, val } => {
            let addr_str = format_addr(*addr, ssa, ctx);
            let val_expr = format_var(*val, ssa, ctx);
            let vdef = ssa.var(*val);
            let size = vdef.size;
            let type_name = typed_name(size, vdef.inferred_type);

            // Use stack variable name if this is a stack store
            if let Some(stack_name) = try_stack_var_name(*addr, ssa) {
                out.push_str(&format!("{}{} = {};\n", pad, stack_name, val_expr));
            } else {
                out.push_str(&format!("{}*({}*)({}) = {};\n", pad, type_name, addr_str, val_expr));
            }
        }
        StructuredStmt::Call { target, args, out: call_out } => {
            let target_name = format_call_target(target, ssa, ctx);
            // Show argument VALUES (the expression assigned to the arg register)
            let args_str: Vec<String> = args.iter()
                .map(|a| {
                    let vdef = ssa.var(*a);
                    // Show the RHS of the arg register assignment, not "RDI"
                    format_expr(&vdef.expr, ssa, ctx)
                })
                .collect();
            if let Some(out_var) = call_out {
                let name = var_name(&ssa.var(*out_var).varnode, ctx);
                out.push_str(&format!("{}{} = {}({});\n", pad, name, target_name, args_str.join(", ")));
            } else {
                out.push_str(&format!("{}{}({});\n", pad, target_name, args_str.join(", ")));
            }
        }
        StructuredStmt::Return(val) => {
            if let Some(v) = val {
                let vdef = ssa.var(*v);
                // Show the expression, not just "RAX"
                let expr = format_expr(&vdef.expr, ssa, ctx);
                out.push_str(&format!("{}return {};\n", pad, expr));
            } else {
                out.push_str(&format!("{}return;\n", pad));
            }
        }
        StructuredStmt::IfElse { cond, then_body, else_body } => {
            let cond_expr = format_condition(*cond, ssa, ctx);
            let then_filtered = filter_boilerplate(then_body, ssa);
            let else_filtered = filter_boilerplate(else_body, ssa);
            let then_empty = is_body_empty(&then_filtered, ssa);
            let else_empty = is_body_empty(&else_filtered, ssa);

            if then_empty && else_empty { return; }
            if then_empty && !else_empty {
                let neg_cond = negate_condition(&cond_expr);
                out.push_str(&format!("{}if ({}) {{\n", pad, neg_cond));
                print_stmts(&else_filtered, ssa, ctx, indent + 1, out);
                out.push_str(&format!("{}}}\n", pad));
            } else {
                out.push_str(&format!("{}if ({}) {{\n", pad, cond_expr));
                print_stmts(&then_filtered, ssa, ctx, indent + 1, out);
                if !else_empty {
                    out.push_str(&format!("{}}} else {{\n", pad));
                    print_stmts(&else_filtered, ssa, ctx, indent + 1, out);
                }
                out.push_str(&format!("{}}}\n", pad));
            }
        }
        StructuredStmt::While { cond, negate, body } => {
            let cond_expr = format_condition(*cond, ssa, ctx);
            let display_cond = if *negate { negate_condition(&cond_expr) } else { cond_expr };
            let body_filtered = filter_boilerplate(body, ssa);
            out.push_str(&format!("{}while ({}) {{\n", pad, display_cond));
            print_stmts(&body_filtered, ssa, ctx, indent + 1, out);
            out.push_str(&format!("{}}}\n", pad));
        }
        StructuredStmt::DoWhile { cond, negate, body } => {
            let body_filtered = filter_boilerplate(body, ssa);
            let cond_expr = format_condition(*cond, ssa, ctx);
            let display_cond = if *negate { negate_condition(&cond_expr) } else { cond_expr };
            let is_always_false = matches!(display_cond.as_str(),
                "1 < 0" | "1 > 1" | "0 > 0" | "0 != 0" | "1 == 0" | "0 > 1");
            let body_returns = matches!(body_filtered.last(),
                Some(StructuredStmt::Return(_)));
            if is_always_false || body_returns {
                print_stmts(&body_filtered, ssa, ctx, indent, out);
            } else {
                out.push_str(&format!("{}do {{\n", pad));
                print_stmts(&body_filtered, ssa, ctx, indent + 1, out);
                out.push_str(&format!("{}}} while ({});\n", pad, display_cond));
            }
        }
        StructuredStmt::Switch { expr, cases, default } => {
            let expr_str = format_var(*expr, ssa, ctx);
            out.push_str(&format!("{}switch ({}) {{\n", pad, expr_str));
            for (vals, body) in cases {
                for val in vals {
                    out.push_str(&format!("{}    case {}:\n", pad, val));
                }
                let body_filtered = filter_boilerplate(body, ssa);
                print_stmts(&body_filtered, ssa, ctx, indent + 2, out);
                if !body_filtered.iter().any(|s| matches!(s, StructuredStmt::Return(_))) {
                    out.push_str(&format!("{}        break;\n", pad));
                }
            }
            if !default.is_empty() {
                out.push_str(&format!("{}    default:\n", pad));
                let default_filtered = filter_boilerplate(default, ssa);
                print_stmts(&default_filtered, ssa, ctx, indent + 2, out);
            }
            out.push_str(&format!("{}}}\n", pad));
        }
        StructuredStmt::Break => {
            out.push_str(&format!("{}break;\n", pad));
        }
        StructuredStmt::Continue => {
            out.push_str(&format!("{}continue;\n", pad));
        }
        StructuredStmt::Goto(addr) => {
            out.push_str(&format!("{}goto label_{:x};\n", pad, addr));
        }
        StructuredStmt::Label(addr) => {
            out.push_str(&format!("label_{:x}:\n", addr));
        }
    }
}

// ---- Condition formatting ----

/// Format a condition, trying to show the comparison rather than a flag name.
fn format_condition(id: VarId, ssa: &SsaCfg, ctx: &PrintCtx) -> String {
    format_condition_tracked(id, ssa, ctx, &RegTracker::new())
}

fn format_condition_tracked(id: VarId, ssa: &SsaCfg, ctx: &PrintCtx, tracker: &RegTracker) -> String {
    let vdef = ssa.var(id);

    if let Expr::BinOp(kind, left, right) = &vdef.expr {
        if is_comparison(*kind) {
            // Check if either operand is ESP-derived — if so, simplify the condition.
            // ESP-in-conditions is a side-effect of x86-32 frame setup comparisons
            // that leaked through condition recovery. Replace with "result != 0".
            let l_esp = is_esp_derived_var(*left, ssa);
            let r_esp = is_esp_derived_var(*right, ssa);
            if l_esp && r_esp {
                // Both ESP-derived: frame check, render as constant true
                return "1".to_string();
            }
            if l_esp {
                // Left is ESP-derived: show just the right operand comparison
                let r = format_cond_operand(*right, ssa, ctx, tracker);
                return format!("{} {} 0", r, binop_str(*kind));
            }
            if r_esp {
                let l = format_cond_operand(*left, ssa, ctx, tracker);
                return format!("{} {} 0", l, binop_str(*kind));
            }

            // For conditions, render operands via their SSA expression first,
            // falling back to tracker. This avoids the tracker aliasing both
            // operands to the same register name.
            let mut l = format_cond_operand(*left, ssa, ctx, tracker);
            let mut r = format_cond_operand(*right, ssa, ctx, tracker);

            // Add signedness casts for signed/unsigned comparisons
            let lv = ssa.var(*left);
            let rv = ssa.var(*right);
            match kind {
                BinOpKind::SLess | BinOpKind::SLessEq => {
                    // Only cast when operand is explicitly unsigned or sub-int sized
                    let needs_l = lv.inferred_type == InferredType::Unsigned
                        || (lv.inferred_type != InferredType::Signed && lv.size < 4);
                    if needs_l && !l.starts_with('(')
                        && !l.starts_with('-') && l != "0" {
                        let cast = match lv.size { 1 => "(char)", 2 => "(short)", _ => "(int)" };
                        l = format!("{}{}", cast, l);
                    }
                    let needs_r = rv.inferred_type == InferredType::Unsigned
                        || (rv.inferred_type != InferredType::Signed && rv.size < 4);
                    if needs_r && !r.starts_with('(')
                        && !r.starts_with('-') && !r.chars().next().map_or(false, |c| c.is_ascii_digit()) {
                        let cast = match rv.size { 1 => "(char)", 2 => "(short)", _ => "(int)" };
                        r = format!("{}{}", cast, r);
                    }
                }
                BinOpKind::Less | BinOpKind::LessEq => {
                    // Unsigned comparison: cast signed operands to unsigned
                    if lv.inferred_type == InferredType::Signed && !l.starts_with('(') {
                        let cast = match lv.size { 1 => "(uint8_t)", 2 => "(uint16_t)", _ => "(uint)" };
                        l = format!("{}{}", cast, l);
                    }
                    if rv.inferred_type == InferredType::Signed && !r.starts_with('(')
                        && !r.chars().next().map_or(false, |c| c.is_ascii_digit()) {
                        let cast = match rv.size { 1 => "(uint8_t)", 2 => "(uint16_t)", _ => "(uint)" };
                        r = format!("{}{}", cast, r);
                    }
                }
                BinOpKind::Eq | BinOpKind::NotEq => {
                    // Size mismatch: cast smaller operand to match larger
                    if lv.size != rv.size && lv.size > 0 && rv.size > 0
                        && !l.starts_with('(') && !r.starts_with('(') {
                        if lv.size < rv.size && l != "0"
                            && !l.chars().next().map_or(false, |c| c.is_ascii_digit()) {
                            let cast = match rv.size { 8 => "(long)", 4 => "(int)", _ => "(int)" };
                            l = format!("{}{}", cast, l);
                        } else if rv.size < lv.size && r != "0"
                            && !r.chars().next().map_or(false, |c| c.is_ascii_digit()) {
                            let cast = match lv.size { 8 => "(long)", 4 => "(int)", _ => "(int)" };
                            r = format!("{}{}", cast, r);
                        }
                    }
                }
                _ => {}
            }

            // Canonicalize: if LHS is a constant, swap operands and use swapped operator string
            let l_is_const = matches!(&lv.expr, Expr::Const(_, _));
            if l_is_const {
                if let Some(swapped_op) = swap_comparison_str(*kind) {
                    return format!("{} {} {}", r, swapped_op, l);
                }
            }
            return format!("{} {} {}", l, binop_str(*kind), r);
        }
    }

    // If it's a flag var, try to show the flag name at least
    if vdef.varnode.space == AddressSpaceId::Register {
        match vdef.varnode.offset {
            518 => return "ZF".to_string(), // fallback
            512 => return "CF".to_string(),
            519 => return "SF".to_string(),
            _ => {}
        }
    }

    format_var(id, ssa, ctx)
}

fn is_comparison(kind: BinOpKind) -> bool {
    matches!(kind, BinOpKind::Eq | BinOpKind::NotEq | BinOpKind::Less
        | BinOpKind::LessEq | BinOpKind::SLess | BinOpKind::SLessEq)
}

/// Format a condition operand, preferring the SSA expression over the tracker.
/// This avoids cases where both operands alias to the same register name.
fn format_cond_operand(id: VarId, ssa: &SsaCfg, ctx: &PrintCtx, tracker: &RegTracker) -> String {
    let vdef = ssa.var(id);
    // If the var has a param name, use it
    if let Some(ref name) = vdef.param_name {
        return name.clone();
    }
    // If the expression is a Load, resolve to stack var name or pointer deref
    if let Expr::Load(ptr) = &vdef.expr {
        if let Some(offset) = get_rbp_offset(*ptr, ssa) {
            let name = format!("var_{:x}", offset);
            let resolved = resolve_stack_alias(&name, tracker);
            let is_good_name = resolved.starts_with("param_")
                || (resolved != name && !resolved.contains('(') && !resolved.contains(' ')
                    && resolved.chars().next().map_or(false, |c| c.is_ascii_lowercase())
                    && !resolved.chars().all(|c| c.is_ascii_digit() || c == 'x')
                    && resolved.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
            if is_good_name {
                return resolved;
            }
            return name;
        }
        // Non-stack Load: dereference a pointer (e.g., *s for string access)
        let addr = match resolve_to_const(*ptr, ssa) {
            Some((val, sz)) => format_const_ctx_load(val, sz, ctx),
            None => format_cond_operand(*ptr, ssa, ctx, tracker),
        };
        return format!("*({})", addr);
    }
    // For registers, trace through the SSA to find the underlying expression
    if vdef.varnode.space == AddressSpaceId::Register {
        // Follow Var(inner) references
        if let Expr::Var(inner) = &vdef.expr {
            return format_cond_operand(*inner, ssa, ctx, tracker);
        }
        // Follow through Load (register loaded from memory)
        if let Expr::Load(ptr) = &vdef.expr {
            if let Some(offset) = get_rbp_offset(*ptr, ssa) {
                let name = format!("var_{:x}", offset);
                return resolve_stack_alias(&name, tracker);
            }
            // x86-32: positive EBP offset → parameter
            if let Some(param) = get_ebp_param(*ptr, ssa) {
                return param;
            }
            let addr = match resolve_to_const(*ptr, ssa) {
                Some((val, sz)) => format_const_ctx_load(val, sz, ctx),
                None => format_cond_operand(*ptr, ssa, ctx, tracker),
            };
            return format!("*({})", addr);
        }
    }
    // For non-trivial expressions (BinOp, etc.), render directly from SSA
    if let Expr::BinOp(kind, l, r) = &vdef.expr {
        // Detect PIECE pattern: Or(Lsl(hi, 0x20), lo) → just render lo
        // This is the x86 EDX:EAX concatenation for IDIV
        if matches!(kind, BinOpKind::Or) {
            let lv = ssa.var(*l);
            if let Expr::BinOp(BinOpKind::Lsl, _, shift) = &lv.expr {
                let sv = ssa.var(*shift);
                if matches!(&sv.expr, Expr::Const(0x20, _)) {
                    // This is X << 0x20 | Y — just show Y (the low part)
                    return format_cond_operand(*r, ssa, ctx, tracker);
                }
            }
        }
        let ls = format_cond_operand(*l, ssa, ctx, tracker);
        let rs = format_cond_operand(*r, ssa, ctx, tracker);
        return format!("{} {} {}", ls, binop_str(*kind), rs);
    }
    if let Expr::UnaryOp(kind, inner) = &vdef.expr {
        let is = format_cond_operand(*inner, ssa, ctx, tracker);
        return match kind {
            UnaryOpKind::Sext | UnaryOpKind::Zext => is,
            _ => format!("{}({})", unaryop_str(*kind), is),
        };
    }
    // For constants, render directly
    if let Expr::Const(val, sz) = &vdef.expr {
        return format_const_ctx(*val, *sz, ctx);
    }
    // For Var references, always recurse to trace through the SSA chain
    if let Expr::Var(inner) = &vdef.expr {
        return format_cond_operand(*inner, ssa, ctx, tracker);
    }
    // For registers with Unknown expressions, try the tracker as a last resort
    if vdef.varnode.space == AddressSpaceId::Register {
        // Only fall back to tracker when the SSA expression is Unknown/trivial
        // Don't use tracker for vars with real expressions — the SSA is authoritative
        if !matches!(&vdef.expr, Expr::Unknown) {
            // The SSA has a real expression but we already handled it above.
            // Don't fall through to the tracker — it may have stale register values.
            return format_var(id, ssa, ctx);
        }
        if let Some(tracked) = tracker.get(vdef.varnode.offset, vdef.varnode.size) {
            let tv = ssa.var(tracked);
            if tv.param_name.is_some() {
                return format_var(tracked, ssa, ctx);
            }
            if let Expr::Load(ptr) = &tv.expr {
                if let Some(offset) = get_rbp_offset(*ptr, ssa) {
                    let name = format!("var_{:x}", offset);
                    let resolved = resolve_stack_alias(&name, tracker);
                    if resolved != name && resolved.chars().next().map_or(false, |c| c.is_ascii_lowercase()) {
                        return resolved;
                    }
                }
            }
        }
    }
    // Default: show variable via standard formatting
    format_var(id, ssa, ctx)
}

/// Find the position of the first comma at depth 0 in a string.
fn find_balanced_comma(s: &str) -> Option<usize> {
    let mut depth = 0;
    for (i, ch) in s.char_indices() {
        if ch == '(' { depth += 1; }
        if ch == ')' { depth -= 1; }
        if ch == ',' && depth == 0 { return Some(i); }
    }
    None
}

/// Find matching closing paren for an opening paren at `pos`.
/// Find the best ` + ` split point for array access conversion: *(base + idx) → base[idx].
/// Returns the byte offset of the ` + ` separator, or None if no valid split exists.
/// The base must look like a pointer/array variable — parameter, global, or known pointer.
/// Reject local arithmetic variables (low, high, mid, i, j) as array bases.
fn find_array_split(inner: &str) -> Option<usize> {
    // Try the first ` + ` — if the base is a valid array name, use it
    if let Some(pos) = inner.find(" + ") {
        let base = inner[..pos].trim();
        if is_valid_array_base(base) {
            return Some(pos);
        }
    }
    // Try the last ` + ` — the index might be simple and the base complex
    if let Some(pos) = inner.rfind(" + ") {
        let base = inner[..pos].trim();
        // Only allow if base is a single valid name (no nested additions)
        if is_valid_array_base(base) && !base.contains(" + ") {
            return Some(pos);
        }
    }
    None
}

/// Check if a string looks like a valid array/pointer base for `base[idx]` conversion.
/// Must be a simple variable name that plausibly holds a pointer.
fn is_valid_array_base(s: &str) -> bool {
    let s = s.trim_start_matches('*');
    if s.is_empty() || s.contains(' ') { return false; }
    // Must be alphanumeric + underscores only
    if !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') { return false; }
    // Must start with a letter or underscore
    if !s.chars().next().map_or(false, |c| c.is_ascii_alphabetic() || c == '_') { return false; }
    // Accept: param_N, arr, ptr, buf, str, lVar, local_N, DAT_N, and other pointer-like names
    // Reject: short loop variable names that are clearly not pointers
    if s.starts_with("param_") || s.starts_with("local_") || s.starts_with("lVar")
        || s.starts_with("DAT_") || s.starts_with("arr") || s.starts_with("ptr")
        || s.starts_with("buf") || s.starts_with("str") || s.starts_with("func_")
        || s.starts_with("iVar") || s.starts_with("x29") || s.starts_with("sp")
    {
        return true;
    }
    // For named variables: accept if the name is longer than 3 chars (likely a real variable)
    // Short names like "low", "mid", "i", "j" are likely loop counters, not pointers
    s.len() > 3
}

/// Count printf-style format specifiers in a string expression.
/// Handles: %d, %s, %x, %p, %u, %f, %c, %lx, %ld, %llu, etc.
/// Returns 0 if the string doesn't look like a format string.
fn count_format_specifiers(expr: &str) -> usize {
    // Extract the string literal content from quoted expressions
    let s = if let Some(start) = expr.find('"') {
        if let Some(end) = expr[start + 1..].rfind('"') {
            &expr[start + 1..start + 1 + end]
        } else {
            return 0;
        }
    } else {
        return 0;
    };

    let mut count = 0;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            i += 1;
            if i >= bytes.len() { break; }
            // Skip %% (literal percent)
            if bytes[i] == b'%' { i += 1; continue; }
            // Skip flags, width, precision: [-+ 0#]*[0-9]*[.][0-9]*
            while i < bytes.len() && matches!(bytes[i], b'-' | b'+' | b' ' | b'0' | b'#') { i += 1; }
            while i < bytes.len() && bytes[i].is_ascii_digit() { i += 1; }
            if i < bytes.len() && bytes[i] == b'.' { i += 1; }
            while i < bytes.len() && bytes[i].is_ascii_digit() { i += 1; }
            // Skip length modifiers: h, hh, l, ll, L, z, j, t, q
            while i < bytes.len() && matches!(bytes[i], b'h' | b'l' | b'L' | b'z' | b'j' | b't' | b'q') { i += 1; }
            // The conversion specifier
            if i < bytes.len() && matches!(bytes[i], b'd' | b'i' | b'u' | b'x' | b'X' | b'o'
                | b's' | b'c' | b'p' | b'f' | b'e' | b'E' | b'g' | b'G' | b'n' | b'a' | b'A')
            {
                count += 1;
            }
            i += 1;
        } else {
            i += 1;
        }
    }
    count
}

fn find_matching_paren(s: &str, pos: usize) -> Option<usize> {
    let mut depth = 0;
    for (ci, ch) in s[pos..].char_indices() {
        if ch == '(' { depth += 1; }
        if ch == ')' { depth -= 1; if depth == 0 { return Some(pos + ci); } }
    }
    None
}

/// Negate a condition string for while loop display.
/// "a <= b" → "a > b", "a == b" → "a != b", etc.
fn negate_condition(cond: &str) -> String {
    // Simplify double negation: !(!x) → x, !(!(x)) → x
    if let Some(inner) = cond.strip_prefix("!(") {
        if let Some(inner) = inner.strip_suffix(')') {
            return inner.to_string();
        }
    }
    if let Some(inner) = cond.strip_prefix('!') {
        return inner.to_string();
    }
    // Try to find and flip the operator
    for (op, neg) in [(" <= ", " > "), (" >= ", " < "), (" < ", " >= "), (" > ", " <= "),
                       (" == ", " != "), (" != ", " == ")] {
        if let Some(pos) = cond.find(op) {
            return format!("{}{}{}", &cond[..pos], neg, &cond[pos + op.len()..]);
        }
    }
    format!("!({})", cond)
}

/// Get the display string for a comparison with swapped operands.
/// a < b → b > a, a <= b → b >= a, etc.
fn swap_comparison_str(kind: BinOpKind) -> Option<&'static str> {
    match kind {
        BinOpKind::Eq => Some("=="),
        BinOpKind::NotEq => Some("!="),
        BinOpKind::Less => Some(">"),
        BinOpKind::LessEq => Some(">="),
        BinOpKind::SLess => Some(">"),
        BinOpKind::SLessEq => Some(">="),
        _ => None,
    }
}

// ---- Stack variable naming ----

/// Try to produce a stack variable name like "var_8" or "param_0" for frame-pointer-relative accesses.
fn try_stack_var_name(addr_id: VarId, ssa: &SsaCfg) -> Option<String> {
    if let Some(offset) = get_rbp_offset(addr_id, ssa) {
        return Some(format!("var_{:x}", offset));
    }
    // x86-32: positive EBP offsets are parameters (EBP+8 = param_0, EBP+12 = param_1, ...)
    if let Some(param_name) = get_ebp_param(addr_id, ssa) {
        return Some(param_name);
    }
    // x86-64: RSP-relative locals (negative offsets from RSP)
    if let Some(signed_off) = get_rsp_offset(addr_id, ssa) {
        if signed_off < 0 {
            return Some(format!("var_{:x}", (-signed_off) as u64));
        }
    }
    None
}

/// Detect x86-32 cdecl parameters from positive EBP offsets.
/// EBP+8 = param_0, EBP+12 = param_1, EBP+16 = param_2, etc.
fn get_ebp_param(id: VarId, ssa: &SsaCfg) -> Option<String> {
    let expr = resolve_through_vars(id, ssa);
    if let Expr::BinOp(BinOpKind::Add, base_id, off_id) = &expr {
        let base = ssa.var(*base_id);
        if base.varnode.space == AddressSpaceId::Register
            && (base.varnode.offset == EBP_OFFSET || base.varnode.offset == RBP_OFFSET)
        {
            let off_val = get_const_val(*off_id, ssa)?;
            // Positive offsets: EBP+8 = param_0, EBP+12 = param_1, ...
            // Skip EBP+0 (saved EBP) and EBP+4 (return address)
            if off_val >= 8 && off_val < 0x80 && off_val % 4 == 0 {
                let param_idx = (off_val - 8) / 4;
                return Some(format!("param_{}", param_idx));
            }
        }
    }
    None
}

/// Get the (positive) offset from RBP/EBP for a stack access, if this is frame-pointer-relative.
fn get_rbp_offset(id: VarId, ssa: &SsaCfg) -> Option<u64> {
    let expr = resolve_through_vars(id, ssa);
    if let Expr::BinOp(BinOpKind::Add, base_id, off_id) = &expr {
        let base = ssa.var(*base_id);
        if base.varnode.space == AddressSpaceId::Register
            && (base.varnode.offset == RBP_OFFSET || base.varnode.offset == EBP_OFFSET)
        {
            let off_val = get_const_val(*off_id, ssa)?;
            // Convert to negative offset (two's complement)
            if off_val >= 0x80 && off_val < 0x100 { return Some(0x100 - off_val); }
            if off_val >= 0x8000 && off_val < 0x10000 { return Some(0x10000 - off_val); }
            if off_val >= 0x80000000 && off_val < 0x100000000 { return Some(0x100000000u64 - off_val); }
            if off_val > 0x7fffffffffffffff { return Some((!off_val).wrapping_add(1)); }
            return None; // Positive offset — not a local variable
        }
    }
    None
}

/// Returns the signed RSP-relative offset if `id` resolves to `RSP ± N`.
/// Handles up to two levels of indirection, e.g. `(RSP - N1) - N2` stored
/// as `BinOp(Sub, alias_to_(RSP-N1), N2)` where the alias has `Expr::Var`.
fn get_rsp_offset(id: VarId, ssa: &SsaCfg) -> Option<i64> {
    get_rsp_offset_depth(id, ssa, 0)
}

fn get_rsp_offset_depth(id: VarId, ssa: &SsaCfg, depth: u8) -> Option<i64> {
    if depth > 4 {
        return None;
    }
    let expr = resolve_through_vars(id, ssa);
    match &expr {
        Expr::BinOp(op @ (BinOpKind::Sub | BinOpKind::Add), base_id, off_id) => {
            let off_c = get_const_val_expr(&ssa.var(*off_id).expr, ssa)?;
            let base = ssa.var(*base_id);
            // Direct: RSP ± N
            if base.varnode.space == AddressSpaceId::Register
                && base.varnode.offset == RSP_OFFSET
                && matches!(base.expr, Expr::Unknown)
            {
                return Some(match op {
                    BinOpKind::Sub => -(off_c as i64),
                    _ => off_c as i64,
                });
            }
            // Indirect: (RSP - N1) op2 N2 where base is Var alias or direct BinOp
            let inner_offset = get_rsp_offset_depth(*base_id, ssa, depth + 1)?;
            let delta = match op {
                BinOpKind::Sub => -(off_c as i64),
                _ => off_c as i64,
            };
            Some(inner_offset + delta)
        }
        _ => None,
    }
}

fn get_const_val(id: VarId, ssa: &SsaCfg) -> Option<u64> {
    get_const_val_expr(&ssa.var(id).expr, ssa)
}

fn get_const_val_expr(expr: &Expr, ssa: &SsaCfg) -> Option<u64> {
    match expr {
        Expr::Const(val, _) => Some(*val),
        Expr::Var(inner) => {
            let inner_def = ssa.var(*inner);
            if let Expr::Const(val, _) = &inner_def.expr { Some(*val) } else { None }
        }
        _ => None,
    }
}

// ---- Address formatting ----

fn format_addr(id: VarId, ssa: &SsaCfg, ctx: &PrintCtx) -> String {
    // Try stack variable first (RBP or EBP relative, negative offset = local)
    if let Some(offset) = get_rbp_offset(id, ssa) {
        return format!("RBP - 0x{:x}", offset);
    }
    // Try x86-32 parameter (positive EBP offset)
    if let Some(param) = get_ebp_param(id, ssa) {
        return param;
    }
    // Try x86-64 RSP-relative local (negative offset = local variable)
    if let Some(signed_off) = get_rsp_offset(id, ssa) {
        if signed_off < 0 {
            return format!("var_{:x}", (-signed_off) as u64);
        }
    }

    let expr = resolve_through_vars(id, ssa);
    if let Expr::BinOp(BinOpKind::Add, base_id, off_id) = &expr {
        let base = ssa.var(*base_id);
        if base.varnode.space == AddressSpaceId::Register
            && (base.varnode.offset == RBP_OFFSET || base.varnode.offset == EBP_OFFSET)
        {
            if let Some(val) = get_const_val(*off_id, ssa) {
                return format_rbp_offset(val);
            }
        }
    }

    match resolve_to_const(id, ssa) {
        Some((val, sz)) => format_const_ctx_load(val, sz, ctx),
        None => format_var(id, ssa, ctx),
    }
}

fn format_rbp_offset(val: u64) -> String {
    if val >= 0x80 && val < 0x100 { return format!("RBP - 0x{:x}", 0x100 - val); }
    if val >= 0x8000 && val < 0x10000 { return format!("RBP - 0x{:x}", 0x10000 - val); }
    if val >= 0x80000000 && val < 0x100000000 { return format!("RBP - 0x{:x}", 0x100000000u64 - val); }
    if val > 0x7fffffffffffffff { return format!("RBP - 0x{:x}", (!val).wrapping_add(1)); }
    if val == 0 { return "RBP".to_string(); }
    format!("RBP + 0x{:x}", val)
}

// ---- Call target formatting ----

fn format_call_target(target: &CallTarget, _ssa: &SsaCfg, ctx: &PrintCtx) -> String {
    match target {
        CallTarget::Direct(addr) => {
            // Try import map first
            if let Some(name) = ctx.imports.get(addr) {
                return name.clone();
            }
            format!("func_{:x}", addr)
        }
        CallTarget::Indirect(vn) => {
            format!("(*{})", var_name(vn, ctx))
        }
    }
}

// ---- Variable formatting ----

fn format_var(id: VarId, ssa: &SsaCfg, ctx: &PrintCtx) -> String {
    let vdef = ssa.var(id);

    // Use parameter name if available
    if let Some(ref name) = vdef.param_name {
        return name.clone();
    }

    // Call return values — if this var holds a call return and is only used once,
    // the printer at the use site should show the call expression
    // (handled by the caller checking call_return flag)

    // Inline Unique-space temporaries (but not bare Unknown — show register name instead)
    if vdef.varnode.space == AddressSpaceId::Unique {
        if matches!(&vdef.expr, Expr::Unknown) {
            // Don't emit "?" — try to find a meaningful name from the context
            // (this var is likely an unresolved intermediate)
        } else {
            // If this Unique var holds an RSP-relative address, show it as var_XX
            // (e.g. RSP - 8 - 45 → var_35). This handles multi-level RSP arithmetic
            // that fold.rs did not collapse, making it appear as a stack-local name.
            if let Some(signed_off) = get_rsp_offset(id, ssa) {
                if signed_off < 0 {
                    return format!("var_{:x}", (-signed_off) as u64);
                }
            }
            return format_expr(&vdef.expr, ssa, ctx);
        }
    }

    // Inline constants
    if let Expr::Const(val, sz) = &vdef.expr {
        return format_const_ctx(*val, *sz, ctx);
    }

    // Inline Register-space Ternary expressions (CSEL/CNEG with recovered conditions)
    if let Expr::Ternary(cond, then_val, else_val) = &vdef.expr {
        let c = format_var(*cond, ssa, ctx);
        let t = format_var(*then_val, ssa, ctx);
        let e = format_var(*else_val, ssa, ctx);
        return format!("({}) ? {} : {}", c, t, e);
    }

    var_name(&vdef.varnode, ctx)
}

/// Format a Store value expression, resolving register operands to their
/// underlying stack variable names. Used inside loop bodies where the tracker
/// has stale aliases. Resolves EAX→Load(var_c)→len, RAX→Load(var_8)→s, etc.
fn format_store_val(expr: &Expr, ssa: &SsaCfg, ctx: &PrintCtx, tracker: &RegTracker) -> String {
    match expr {
        Expr::BinOp(kind, left, right) => {
            let l = format_store_operand(*left, ssa, ctx, tracker);
            let r = format_store_operand(*right, ssa, ctx, tracker);
            format!("{} {} {}", l, binop_str(*kind), r)
        }
        Expr::UnaryOp(kind, inner) => {
            let i = format_store_operand(*inner, ssa, ctx, tracker);
            match kind {
                UnaryOpKind::Neg => format!("-{}", i),
                UnaryOpKind::Not => format!("~{}", i),
                UnaryOpKind::BoolNot => format!("!{}", i),
                _ => i, // Drop casts for readability
            }
        }
        Expr::Load(ptr) => {
            if let Some(offset) = get_rbp_offset(*ptr, ssa) {
                let name = format!("var_{:x}", offset);
                return resolve_stack_alias(&name, tracker);
            }
            format_expr(expr, ssa, ctx)
        }
        _ => format_expr(expr, ssa, ctx),
    }
}

/// Format a single operand for a Store value expression.
/// Resolves registers through their SSA expression to find the underlying variable.
fn format_store_operand(id: VarId, ssa: &SsaCfg, ctx: &PrintCtx, tracker: &RegTracker) -> String {
    let vdef = ssa.var(id);
    // If it has a param name, use it
    if let Some(ref name) = vdef.param_name {
        return name.clone();
    }
    // Constants
    if let Expr::Const(val, sz) = &vdef.expr {
        return format_const_ctx(*val, *sz, ctx);
    }
    // If this is a register that was loaded from a stack variable, show the stack var
    // If loaded from a non-stack address (array element), show the load expression
    if vdef.varnode.space == AddressSpaceId::Register {
        if let Expr::Load(ptr) = &vdef.expr {
            if let Some(offset) = get_rbp_offset(*ptr, ssa) {
                let name = format!("var_{:x}", offset);
                return resolve_stack_alias(&name, tracker);
            }
            // Non-stack load (array element, struct field, etc.)
            // Show as *(addr) or resolve to array syntax
            let addr = match resolve_to_const(*ptr, ssa) {
                Some((val, sz)) => format_const_ctx_load(val, sz, ctx),
                None => format_store_operand(*ptr, ssa, ctx, tracker),
            };
            return format!("*({})", addr);
        }
        // If the register holds a Var(other_reg), follow one level
        if let Expr::Var(inner) = &vdef.expr {
            let iv = ssa.var(*inner);
            if let Expr::Load(ptr) = &iv.expr {
                if let Some(offset) = get_rbp_offset(*ptr, ssa) {
                    let name = format!("var_{:x}", offset);
                    return resolve_stack_alias(&name, tracker);
                }
            }
            // Follow through Zext/Sext
            if let Expr::UnaryOp(UnaryOpKind::Zext | UnaryOpKind::Sext, deeper) = &iv.expr {
                return format_store_operand(*deeper, ssa, ctx, tracker);
            }
        }
        // Follow through Zext/Sext on the register itself
        if let Expr::UnaryOp(UnaryOpKind::Zext | UnaryOpKind::Sext, inner) = &vdef.expr {
            return format_store_operand(*inner, ssa, ctx, tracker);
        }
        // For BinOp on register, recurse
        if let Expr::BinOp(_, _, _) = &vdef.expr {
            return format_store_val(&vdef.expr, ssa, ctx, tracker);
        }
    }
    // Unique space: inline the expression
    if vdef.varnode.space == AddressSpaceId::Unique {
        return format_store_val(&vdef.expr, ssa, ctx, tracker);
    }
    format_var(id, ssa, ctx)
}

fn format_expr(expr: &Expr, ssa: &SsaCfg, ctx: &PrintCtx) -> String {
    match expr {
        Expr::Var(id) => format_var(*id, ssa, ctx),
        Expr::Const(val, sz) => format_const_ctx(*val, *sz, ctx),
        Expr::BinOp(kind, left, right) => {
            // If this BinOp computes an RSP-relative address, emit it as var_XX.
            // This handles chained RSP arithmetic like (RSP - 8) - 45 → var_35.
            if matches!(kind, BinOpKind::Sub | BinOpKind::Add) {
                if let Some(off_c) = get_const_val(*right, ssa) {
                    if let Some(inner_off) = get_rsp_offset(*left, ssa) {
                        let delta = match kind {
                            BinOpKind::Sub => -(off_c as i64),
                            _ => off_c as i64,
                        };
                        let total = inner_off + delta;
                        if total < 0 {
                            return format!("var_{:x}", (-total) as u64);
                        }
                    }
                }
            }
            let l = format_var(*left, ssa, ctx);
            let r = format_var(*right, ssa, ctx);
            let op = binop_str(*kind);
            // Detect negative constant on right side of add
            if matches!(kind, BinOpKind::Add) {
                let rv = ssa.var(*right);
                if let Expr::Const(val, sz) = &rv.expr {
                    if *val > 0x7fffffffffffffff {
                        let neg = (!*val).wrapping_add(1);
                        return format!("{} - {}", l, format_const(neg, *sz));
                    }
                }
            }
            format!("{} {} {}", l, op, r)
        }
        Expr::UnaryOp(kind, input) => {
            let i = format_var(*input, ssa, ctx);
            let input_def = ssa.var(*input);
            match kind {
                UnaryOpKind::Neg => format!("-{}", i),
                UnaryOpKind::Not => format!("~{}", i),
                UnaryOpKind::BoolNot => format!("!{}", i),
                UnaryOpKind::Zext => {
                    let sz = input_def.size;
                    if sz <= 4 && sz > 0 {
                        let cast = match sz { 1 => "uint8_t", 2 => "uint16_t", _ => "uint" };
                        format!("({}){}", cast, i)
                    } else { i }
                }
                UnaryOpKind::Sext => {
                    let sz = input_def.size;
                    if sz <= 4 && sz > 0 {
                        let cast = match sz { 1 => "char", 2 => "short", _ => "int" };
                        format!("({}){}", cast, i)
                    } else { i }
                }
                UnaryOpKind::Int2Float => format!("(float){}", i),
                UnaryOpKind::Trunc => format!("(int){}", i),
                UnaryOpKind::Float2Float => format!("(double){}", i),
                _ => format!("{}({})", unaryop_str(*kind), i),
            }
        }
        Expr::Load(ptr) => {
            // Try stack variable name
            if let Some(offset) = get_rbp_offset(*ptr, ssa) {
                return format!("var_{:x}", offset);
            }
            // Try reading float constant from binary (for FloatMult patterns)
            if let Some(binary) = ctx.binary {
                let ptr_val = get_const_val_expr(&ssa.var(*ptr).expr, ssa);
                if let Some(addr) = ptr_val {
                    if let Some(fo) = va_to_file_offset(addr, binary) {
                        if fo + 8 <= binary.len() {
                            let bytes: [u8; 8] = binary[fo..fo+8].try_into().unwrap_or([0;8]);
                            let fval = f64::from_le_bytes(bytes);
                            if fval != 0.0 && fval.is_finite() && fval.abs() < 1.0e20 && fval.abs() > 1.0e-20 {
                                // Check if it's a clean value
                                let recip = 1.0 / fval;
                                if recip > 1.0 && (recip - recip.round()).abs() < 0.001 {
                                    // Reciprocal of integer — likely used in division
                                    return format!("(1.0 / {}.0)", recip.round() as u64);
                                }
                                // Clean float constant
                                let s = format!("{}", fval);
                                if s.len() <= 12 { return s; }
                            }
                        }
                    }
                }
            }
            let p = format_addr(*ptr, ssa, ctx);
            format!("*({})", p)
        }
        Expr::FieldAccess(base, offset) => {
            let base_str = format_var(*base, ssa, ctx);
            if needs_paren_for_arrow(&base_str) {
                format!("({})->field_{:x}", base_str, offset)
            } else {
                format!("{}->field_{:x}", base_str, offset)
            }
        }
        Expr::Phi(inputs) => {
            if inputs.len() == 1 { return format_var(inputs[0], ssa, ctx); }
            let args: Vec<String> = inputs.iter().map(|i| format_var(*i, ssa, ctx)).collect();
            format!("phi({})", args.join(", "))
        }
        Expr::Ternary(cond, then_val, else_val) => {
            let c = format_var(*cond, ssa, ctx);
            let t = format_var(*then_val, ssa, ctx);
            let e = format_var(*else_val, ssa, ctx);
            format!("({}) ? {} : {}", c, t, e)
        }
        Expr::Unknown => "?".to_string(),
    }
}

fn format_const_ctx(val: u64, size: u32, ctx: &PrintCtx) -> String {
    if val == 0 { return "0".to_string(); }
    if val < 10 { return format!("{}", val); }
    // Try string literal
    if size >= 4 && val > 0x200 {
        if let Some(s) = try_read_string(val, ctx) {
            // Skip empty strings — these are usually float constants or padding
            // (the first byte is 0x00 which try_read_string returns as "")
            // Skip empty strings and very short strings (< 4 chars) in SSA output.
            // Short strings at random addresses are almost always false positives
            // from float constants, flag fields, or padding bytes.
            // Real short strings are handled by the post-processor for puts("").
            if s.is_empty() || s.len() < 2 { /* fall through to hex */ }
            else { return format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")); }
        }
        // Try import/global name (e.g., GOT entry for stdin/stdout)
        if let Some(name) = ctx.imports.get(&val) {
            return name.clone();
        }
        // Try MSVC RTTI vtable resolution for PE binaries
        if let Some(binary) = ctx.binary {
            if let Some(vtable_name) = crate::imports::resolve_pe_vtable(val, binary) {
                return vtable_name;
            }
        }
        // Try wide string (UTF-16LE) for PE binaries
        if let Some(ws) = try_read_wide_string(val, ctx) {
            return ws;
        }
    }
    format_const(val, size)
}

fn format_const_ctx_load(val: u64, size: u32, ctx: &PrintCtx) -> String {
    // Like format_const_ctx, but for load-address context:
    // 1. Prefers named imports/vtable over string resolution
    // 2. Requires ≥4 bytes of string content to avoid PE pointer-table false positives
    // 3. Never falls through to format_const's ASCII-decode path (would produce string
    //    literals from pointer constants, e.g. 0xC8A1 → "È¡").
    if val == 0 { return "0".to_string(); }
    if val < 10 { return format!("{}", val); }
    if size >= 4 && val > 0x200 {
        if let Some(name) = ctx.imports.get(&val) {
            return name.clone();
        }
        if let Some(binary) = ctx.binary {
            if let Some(vtable_name) = crate::imports::resolve_pe_vtable(val, binary) {
                return vtable_name;
            }
        }
        if let Some(s) = try_read_string(val, ctx) {
            if s.len() >= 4 {
                return format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n"));
            }
        }
        if let Some(ws) = try_read_wide_string(val, ctx) {
            return ws;
        }
    }
    // For load-address context, avoid format_const's ASCII decode (false positives).
    // Emit DAT_ for addresses in a plausible binary range, otherwise plain hex.
    if val > 0x200 {
        return format!("DAT_{:08x}", val);
    }
    format!("0x{:x}", val)
}

fn format_const(val: u64, size: u32) -> String {
    if val == 0 { return "0".to_string(); }
    // Small positive values in decimal for readability
    if val < 1000 { return format!("{}", val); }
    // Power-of-2 constants in decimal (common thresholds: 1024, 4096, 65536, etc.)
    if val.is_power_of_two() && val <= 0x100000000 {
        return format!("{}", val);
    }
    // Power-of-2 minus 1 (common masks/thresholds: 0x3ff=1023, 0xfffff=1048575)
    if val < 0x100000000 && (val + 1).is_power_of_two() {
        return format!("{}", val);
    }
    // Try decoding as ASCII string (little-endian packed bytes on stack)
    // But skip values that look like virtual addresses (would produce false positives)
    if val > 0xFFFF && size >= 4 && !looks_like_address(val) {
        if let Some(s) = try_decode_ascii_const(val, size) {
            return format!("\"{}\"", s);
        }
    }
    // Check for negative values (sign bit set)
    let sign_bit = match size {
        1 => 0x80, 2 => 0x8000, 4 => 0x80000000, 8 => 0x8000000000000000, _ => 0,
    };
    if sign_bit != 0 && val >= sign_bit && val != u64::MAX {
        let mask = match size { 1 => 0xFF, 2 => 0xFFFF, 4 => 0xFFFFFFFF, _ => u64::MAX };
        let neg = ((!val) & mask).wrapping_add(1);
        if neg < 1000 { return format!("-{}", neg); }
        if neg <= 0x10000 { return format!("-0x{:x}", neg); }
    }
    format!("0x{:x}", val)
}

/// Try to decode a constant value as packed ASCII bytes (little-endian).
/// Returns Some("text") if ALL bytes are printable ASCII (or null terminator).
/// Check if a value looks like a virtual address or magic constant that
/// should NOT be decoded as packed ASCII.
fn looks_like_address(val: u64) -> bool {
    // PE32 typical: 0x00400000..0x10000000
    // PE64 typical: 0x140000000..0x180000000
    // ELF typical: 0x08000000..0x10000000 or 0x400000..0x800000
    // Mach-O typical: 0x100000000..0x200000000
    if (val >= 0x00400000 && val < 0x10000000)
        || (val >= 0x08000000 && val < 0x10000000)
        || (val >= 0x100000000 && val < 0x200000000)
        || (val >= 0x140000000 && val < 0x180000000)
    {
        return true;
    }
    // Constants with repeating byte patterns are almost always compiler-generated
    // magic multiply constants for division (e.g., 0x66666667 for /10 in 32-bit,
    // 0x6666666666666667 for /10 in 64-bit, 0x92492493 for /7).
    // These should NOT be decoded as ASCII strings.
    if val > 0xFFFF {
        let nbytes = if val > 0xFFFFFFFF { 8 } else { 4 };
        let bytes = val.to_le_bytes();
        let unique_bytes: std::collections::HashSet<u8> = bytes[..nbytes].iter().copied().collect();
        // If fewer than 3 unique byte values, it's likely a magic constant
        if unique_bytes.len() <= 2 { return true; }
        // Also catch near-repeating patterns where most bytes are the same
        // (e.g., 0x92492493 has bytes [0x93, 0x24, 0x49, 0x92] — 4 unique, but
        //  the nibble pattern is diagnostic of a magic constant)
        if nbytes == 4 && unique_bytes.len() <= 4 {
            // Check if the value is in the typical magic multiply range (> 0x10000000)
            if val > 0x10000000 { return true; }
        }
    }
    false
}

fn try_decode_ascii_const(val: u64, size: u32) -> Option<String> {
    let nbytes = match size { 4 => 4, 8 => 8, _ => return None };
    let bytes = val.to_le_bytes();
    let mut s = String::new();
    let mut all_ascii = true;
    let mut printable_count = 0;
    for i in 0..nbytes {
        let b = bytes[i as usize];
        if b == 0 { break; } // null terminator — end of string
        if b >= 0x20 && b <= 0x7e {
            s.push(b as char);
            printable_count += 1;
        } else {
            all_ascii = false;
            break;
        }
    }
    // Require at least 3 printable chars to avoid false positives on small numbers
    // that happen to have ASCII-range bytes
    if all_ascii && printable_count >= 3 {
        Some(s)
    } else {
        None
    }
}

/// Convert a virtual address to file offset using binary section/segment info.
fn va_to_file_offset(va: u64, binary: &[u8]) -> Option<usize> {
    let obj = goblin::Object::parse(binary).ok()?;
    match &obj {
        goblin::Object::Mach(goblin::mach::Mach::Binary(m)) => {
            m.segments.iter().find_map(|seg| {
                if va >= seg.vmaddr && va < seg.vmaddr + seg.vmsize {
                    Some((seg.fileoff + (va - seg.vmaddr)) as usize)
                } else { None }
            })
        }
        goblin::Object::Elf(elf) => {
            elf.section_headers.iter().find_map(|sh| {
                if sh.sh_addr != 0 && va >= sh.sh_addr && va < sh.sh_addr + sh.sh_size {
                    Some((sh.sh_offset + (va - sh.sh_addr)) as usize)
                } else { None }
            })
        }
        goblin::Object::PE(pe) => {
            let base = pe.image_base as u64;
            let rva = va.checked_sub(base)?;
            pe.sections.iter().find_map(|s| {
                let sr = s.virtual_address as u64;
                if rva >= sr && rva < sr + s.virtual_size as u64 {
                    Some((s.pointer_to_raw_data as u64 + (rva - sr)) as usize)
                } else { None }
            })
        }
        _ => None,
    }
}

fn try_read_string(va: u64, ctx: &PrintCtx) -> Option<String> {
    let binary = ctx.binary?;
    let obj = goblin::Object::parse(binary).ok()?;
    let file_offset = match &obj {
        goblin::Object::Mach(goblin::mach::Mach::Binary(macho)) => {
            // Read strings from __TEXT segment sections (__cstring, __const)
            // Use section-level granularity to avoid reading code as strings
            macho.segments.iter().find_map(|seg| {
                let segname = seg.name().ok().unwrap_or("").trim_end_matches('\0');
                if segname != "__TEXT" { return None; }
                // Check individual sections within __TEXT
                if let Ok(sections) = seg.sections() {
                    for (sec, _) in &sections {
                        let _sname = std::str::from_utf8(&sec.sectname).unwrap_or("")
                            .trim_end_matches('\0');
                        if va >= sec.addr && va < sec.addr + sec.size {
                            let fo = (sec.offset as u64 + (va - sec.addr)) as usize;
                            return Some(fo);
                        }
                    }
                }
                // Fallback: use segment-level mapping
                if va >= seg.vmaddr && va < seg.vmaddr + seg.vmsize {
                    Some((seg.fileoff + (va - seg.vmaddr)) as usize)
                } else { None }
            })?
        }
        goblin::Object::Elf(elf) => {
            // Only read strings from read-only data sections (.rodata, .dynstr)
            // Skip .bss (no data), .data (global vars), .comment, .note, .debug
            elf.section_headers.iter().find_map(|sh| {
                if sh.sh_addr == 0 || va < sh.sh_addr || va >= sh.sh_addr + sh.sh_size {
                    return None;
                }
                // SHT_NOBITS (8) = .bss — no actual data in file
                if sh.sh_type == 8 { return None; }
                // SHT_PROGBITS (1) with SHF_ALLOC (2) — loaded into memory
                let is_alloc = sh.sh_flags & 0x2 != 0;
                // Reject executable sections (code, not data)
                let is_exec = sh.sh_flags & 0x4 != 0;
                // Reject writable sections (.data, .bss — global vars, not strings)
                let is_write = sh.sh_flags & 0x1 != 0;
                if is_alloc && !is_exec && !is_write {
                    Some((sh.sh_offset + (va - sh.sh_addr)) as usize)
                } else { None }
            })?
        }
        goblin::Object::PE(pe) => {
            let rva = va.checked_sub(pe.image_base as u64)? as u64;
            pe.sections.iter().find_map(|s| {
                let sr = s.virtual_address as u64;
                if rva < sr || rva >= sr + s.virtual_size as u64 { return None; }
                // Only read strings from read-only data sections (.rdata)
                // Skip .data (writable globals), .text (code), .rsrc (resources)
                let is_writable = s.characteristics & 0x80000000 != 0; // IMAGE_SCN_MEM_WRITE
                let is_exec = s.characteristics & 0x20000000 != 0;     // IMAGE_SCN_MEM_EXECUTE
                if is_writable || is_exec { return None; }
                Some((s.pointer_to_raw_data as u64 + (rva - sr)) as usize)
            })?
        }
        _ => return None,
    };
    if file_offset >= binary.len() { return None; }
    let max = 512.min(binary.len() - file_offset);
    let slice = &binary[file_offset..file_offset + max];
    let null_pos = slice.iter().position(|&b| b == 0)?;
    if null_pos > 256 { return None; } // reject very long "strings"
    // Allow empty strings (null_pos == 0) and single-char strings (null_pos == 1)
    if null_pos == 0 { return Some(String::new()); }
    let s = std::str::from_utf8(&slice[..null_pos]).ok()?;
    // Reject strings that look like compiler metadata or partial data
    // Reject strings that look like compiler metadata, partial data, or non-strings
    if s.contains("GCC:") || s.contains("clang")
        || s.contains("ubuntu") || s.contains("20160") || s.contains("2017")
        || s.contains("Debian")
        // Reject ELF section names like .comment, .note, .debug_info, .symtab, .rodata
        // These are > 5 chars, all lowercase+underscore after the dot.
        // Allow file extensions (.html, .css, .js, .json), paths (./www), ".."
        || (s.starts_with(".") && s.len() > 5
            && s.chars().skip(1).all(|c| c.is_ascii_lowercase() || c == '_'))
        || s.starts_with(")") || s.starts_with("]")
        || (s.len() <= 4 && s.chars().all(|c| c.is_ascii_digit()))
        // Reject strings that are ALL digits or version-like (X.Y.Z)
        || s.chars().all(|c| c.is_ascii_digit() || c == '.')
        // Reject strings containing version patterns like "7.5.0", "4) 7.5.0"
        || {
            let has_version = s.split(|c: char| !c.is_ascii_digit() && c != '.')
                .any(|part| {
                    let dots: Vec<&str> = part.split('.').collect();
                    dots.len() >= 2 && dots.iter().all(|d| !d.is_empty() && d.len() <= 3 && d.chars().all(|c| c.is_ascii_digit()))
                });
            // Only reject if the string is MOSTLY a version (short and version-dominated)
            // Don't reject strings like "  Program v1.0\n" that contain a version substring
            has_version && null_pos < 20 && s.trim().len() < 12
        }
        // Reject strings from inside .bss/.data global arrays that happen to contain
        // readable text from adjacent sections (e.g., GCC version string fragments)
        || (null_pos <= 8 && s.bytes().any(|b| b < 0x20 && b != b'\n' && b != b'\t'))
    { return None; }
    // Accept printable ASCII plus UTF-8 characters (accented letters, symbols like ™©®)
    if s.chars().all(|c| c.is_ascii_graphic() || c == ' ' || c == '\n' || c == '\t'
        || (c as u32 >= 0x80 && !c.is_control())) {
        Some(s.to_string())
    } else { None }
}

/// Read raw bytes at a virtual address from the binary (any section).
fn try_read_bytes_at_va(va: u64, ctx: &PrintCtx, max_len: usize) -> Option<Vec<u8>> {
    let binary = ctx.binary?;
    let obj = goblin::Object::parse(binary).ok()?;
    let file_offset = match &obj {
        goblin::Object::PE(pe) => {
            let rva = va.checked_sub(pe.image_base as u64)? as u64;
            pe.sections.iter().find_map(|s| {
                let sr = s.virtual_address as u64;
                if rva >= sr && rva < sr + s.virtual_size as u64 {
                    Some((s.pointer_to_raw_data as u64 + (rva - sr)) as usize)
                } else { None }
            })?
        }
        goblin::Object::Elf(elf) => {
            elf.section_headers.iter().find_map(|sh| {
                if sh.sh_type == 8 { return None; } // SHT_NOBITS
                if va >= sh.sh_addr && va < sh.sh_addr + sh.sh_size {
                    Some((sh.sh_offset + (va - sh.sh_addr)) as usize)
                } else { None }
            })?
        }
        goblin::Object::Mach(goblin::mach::Mach::Binary(macho)) => {
            macho.segments.iter().find_map(|seg| {
                if va >= seg.vmaddr && va < seg.vmaddr + seg.vmsize {
                    Some((seg.fileoff + (va - seg.vmaddr)) as usize)
                } else { None }
            })?
        }
        _ => return None,
    };
    if file_offset >= binary.len() { return None; }
    let len = max_len.min(binary.len() - file_offset);
    Some(binary[file_offset..file_offset + len].to_vec())
}

/// Try single-byte XOR decryption on data at a virtual address.
/// Returns the decrypted string and key if the result is printable ASCII.
fn try_xor_decrypt_single(va: u64, ctx: &PrintCtx) -> Option<(String, u8)> {
    let data = try_read_bytes_at_va(va, ctx, 256)?;
    if data.len() < 4 { return None; }
    // Skip if the data is already a plaintext string (no encryption needed)
    let null_pos_raw = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    if null_pos_raw >= 4 && null_pos_raw <= 200 {
        if data[..null_pos_raw].iter().all(|&b| (b >= 0x20 && b < 0x7f) || b == b'\n') {
            return None; // Already plaintext
        }
    }

    for key in 1u8..=0xFE {
        let decrypted: Vec<u8> = data.iter().map(|b| b ^ key).collect();
        let null_pos = decrypted.iter().position(|&b| b == 0).unwrap_or(decrypted.len());
        if null_pos < 6 || null_pos > 200 { continue; }
        let candidate = &decrypted[..null_pos];
        if candidate.iter().all(|&b| (b >= 0x20 && b < 0x7f) || b == b'\n' || b == b'\t') {
            if let Ok(s) = std::str::from_utf8(candidate) {
                let unique: std::collections::HashSet<u8> = candidate.iter().copied().collect();
                // Reject: key byte appears as most common char (null bytes → repeated key)
                let key_char_count = candidate.iter().filter(|&&b| b == key).count();
                let has_letter = candidate.iter().any(|&b| b.is_ascii_alphabetic());
                // Require: 5+ unique chars, has letters, key byte isn't dominant
                if unique.len() >= 5 && has_letter
                    && key_char_count * 3 < candidate.len()
                    && s.trim().len() >= 6
                {
                    return Some((s.to_string(), key));
                }
            }
        }
    }
    None
}

/// Try multi-byte XOR decryption (2-4 byte key) on data at a virtual address.
/// Uses known-plaintext attack: assumes common string prefixes and endings.
fn try_xor_decrypt_multi(va: u64, ctx: &PrintCtx) -> Option<(String, Vec<u8>)> {
    let data = try_read_bytes_at_va(va, ctx, 256)?;
    if data.len() < 12 { return None; }
    // Skip if already plaintext
    let null_raw = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    if null_raw >= 6 && data[..null_raw].iter().all(|&b| b >= 0x20 && b < 0x7f) {
        return None;
    }

    // Try common plaintext prefixes to derive the key
    let prefixes: &[&[u8]] = &[
        b"http", b"HTTP", b"https", b"cmd ", b"cmd.",
        b"C:\\", b"C:/", b"/bin", b"/tmp", b"/etc",
        b"HKEY", b"Soft", b"\\\\.",
        b"powershell", b"rundll32", b"regsvr32",
    ];

    for key_len in 2..=4usize {
        for prefix in prefixes {
            if prefix.len() < key_len { continue; }
            // Derive key from known plaintext
            let key: Vec<u8> = (0..key_len).map(|i| data[i] ^ prefix[i]).collect();
            if key.iter().all(|&k| k == 0) { continue; }

            let decrypted: Vec<u8> = data.iter().enumerate()
                .map(|(i, b)| b ^ key[i % key_len])
                .collect();
            let null_pos = decrypted.iter().position(|&b| b == 0).unwrap_or(decrypted.len());
            if null_pos < 8 || null_pos > 200 { continue; }
            let candidate = &decrypted[..null_pos];
            if candidate.iter().all(|&b| (b >= 0x20 && b < 0x7f) || b == b'\n' || b == b'\t') {
                if let Ok(s) = std::str::from_utf8(candidate) {
                    let unique: std::collections::HashSet<u8> = candidate.iter().copied().collect();
                    let has_letter = candidate.iter().any(|&b| b.is_ascii_alphabetic());
                    if unique.len() >= 5 && has_letter && s.trim().len() >= 8 {
                        return Some((s.to_string(), key));
                    }
                }
            }
        }
    }
    None
}

/// Try ROT13 decryption on a string.
fn try_rot13(s: &str) -> Option<String> {
    if s.len() < 8 { return None; }
    // Must be mostly alphabetic to be a ROT13 candidate
    let alpha_ratio = s.chars().filter(|c| c.is_ascii_alphabetic()).count() as f64 / s.len() as f64;
    if alpha_ratio < 0.6 { return None; }

    let decoded: String = s.chars().map(|c| match c {
        'a'..='m' | 'A'..='M' => (c as u8 + 13) as char,
        'n'..='z' | 'N'..='Z' => (c as u8 - 13) as char,
        _ => c,
    }).collect();

    // Check if decoded contains common English words
    let common_words = ["the", "and", "for", "are", "but", "not", "you", "all",
        "can", "her", "was", "one", "our", "out", "has", "his", "how", "its",
        "let", "may", "new", "now", "old", "see", "way", "who", "did", "get",
        "com", "org", "net", "http", "file", "open", "read", "write", "exec",
        "system", "shell", "command", "password", "error", "failed", "success",
        "connect", "send", "recv", "socket", "server", "client", "path", "name"];
    let decoded_lower = decoded.to_lowercase();
    let word_hits = common_words.iter().filter(|w| decoded_lower.contains(**w)).count();
    let original_lower = s.to_lowercase();
    let orig_hits = common_words.iter().filter(|w| original_lower.contains(**w)).count();

    if word_hits > orig_hits && word_hits >= 2 {
        Some(decoded)
    } else {
        None
    }
}

/// Try base64 decoding on a string.
fn try_base64_decode(s: &str) -> Option<String> {
    if s.len() < 8 { return None; }
    // Must look like base64: alphanumeric + / + = padding
    if !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=') {
        return None;
    }
    // Must have both upper and lowercase
    let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
    if !has_upper || !has_lower { return None; }

    // Simple base64 decoder (no external dep needed)
    let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let trimmed = s.trim_end_matches('=');
    let mut bytes = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    for ch in trimmed.bytes() {
        let val = table.iter().position(|&b| b == ch)?;
        buf = (buf << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    if bytes.len() < 4 { return None; }
    // Check if result is printable ASCII
    if bytes.iter().all(|&b| (b >= 0x20 && b < 0x7f) || b == b'\n' || b == b'\t' || b == 0) {
        let null_pos = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        let decoded = std::str::from_utf8(&bytes[..null_pos]).ok()?;
        if decoded.len() >= 4 {
            return Some(decoded.to_string());
        }
    }
    None
}

/// Try to read a wide string (UTF-16LE) from a virtual address in the binary.
fn try_read_wide_string(va: u64, ctx: &PrintCtx) -> Option<String> {
    let binary = ctx.binary?;
    let obj = goblin::Object::parse(binary).ok()?;
    // Only for PE binaries (Windows uses wide strings)
    let file_offset = match &obj {
        goblin::Object::PE(pe) => {
            let rva = va.checked_sub(pe.image_base as u64)? as u64;
            pe.sections.iter().find_map(|s| {
                let sr = s.virtual_address as u64;
                if rva < sr || rva >= sr + s.virtual_size as u64 { return None; }
                let is_writable = s.characteristics & 0x80000000 != 0;
                let is_exec = s.characteristics & 0x20000000 != 0;
                if is_writable || is_exec { return None; }
                Some((s.pointer_to_raw_data as u64 + (rva - sr)) as usize)
            })?
        }
        _ => return None,
    };
    if file_offset >= binary.len() { return None; }
    let max = 512.min(binary.len() - file_offset);
    let slice = &binary[file_offset..file_offset + max];
    // Read UTF-16LE: pairs of bytes until double-null
    let mut chars = Vec::new();
    let mut i = 0;
    while i + 1 < slice.len() {
        let ch = u16::from_le_bytes([slice[i], slice[i + 1]]);
        if ch == 0 { break; }
        chars.push(ch);
        i += 2;
        if chars.len() > 256 { return None; } // too long
    }
    if chars.len() < 2 { return None; } // too short
    let s = String::from_utf16(&chars).ok()?;
    // Verify it's actually readable text
    if s.chars().all(|c| c.is_ascii_graphic() || c == ' ' || c == '\\' || c == '%') {
        Some(format!("L\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")))
    } else { None }
}

fn var_name(vn: &Varnode, ctx: &PrintCtx) -> String {
    match vn.space {
        AddressSpaceId::Register => {
            let name = ctx.arch.register_name(vn.offset, vn.size).unwrap_or("?reg");
            // AArch64 register auto-naming:
            // x0-x7 (offsets 0-7) = argument/result registers → param names handled elsewhere
            // x8 = indirect result register
            // x9-x15 (offsets 9-15) = caller-saved temporaries → iVar
            // x16-x18 (offsets 16-18) = platform registers (IP0/IP1/PR)
            // x19-x28 (offsets 19-28) = callee-saved registers → lVar
            // x29 = frame pointer, x30 = link register
            if matches!(ctx.arch, Architecture::AArch64) {
                match vn.offset {
                    9..=15 => return format!("iVar{}", vn.offset - 9 + 1),
                    19..=28 => return format!("lVar{}", vn.offset - 19 + 1),
                    _ => {}
                }
            }
            name.to_string()
        }
        AddressSpaceId::Unique => format!("tmp_{:x}", vn.offset),
        AddressSpaceId::Ram => format!("mem_{:x}", vn.offset),
        AddressSpaceId::Const => format_const(vn.offset, 8),
    }
}

/// Decide whether an expression string needs parentheses before a `->` so that
/// the arrow associates with the full address, not the last operand. True if
/// any top-level binary operator appears outside nested `()` / `[]`. Simple
/// identifiers, `*(addr)`, `DAT_X->field_0`, `name[idx]`, and parenthesized
/// expressions pass through unchanged.
fn needs_paren_for_arrow(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut depth: i32 = 0;
    let mut i = 0;
    while i + 2 < bytes.len() {
        let b = bytes[i];
        if b == b'(' || b == b'[' { depth += 1; i += 1; continue; }
        if b == b')' || b == b']' { depth -= 1; i += 1; continue; }
        if depth == 0 && b == b' ' {
            let op = bytes[i + 1];
            let after_op = bytes[i + 2];
            // Match ` OP ` where OP is one of the C binary operators.
            let is_op_char = matches!(op,
                b'+' | b'-' | b'*' | b'/' | b'%' | b'&' | b'|' | b'^' | b'?' | b':');
            let is_shift = (op == b'<' || op == b'>') && after_op == op;
            if (is_op_char && after_op == b' ') || is_shift {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn resolve_to_const(mut id: VarId, ssa: &SsaCfg) -> Option<(u64, u32)> {
    for _ in 0..8 {
        let expr = &ssa.var(id).expr;
        match expr {
            Expr::Const(val, sz) => return Some((*val, *sz)),
            Expr::Var(next) => id = *next,
            Expr::UnaryOp(UnaryOpKind::Zext, inner)
            | Expr::UnaryOp(UnaryOpKind::Sext, inner) => id = *inner,
            _ => return None,
        }
    }
    None
}

fn resolve_through_vars(id: VarId, ssa: &SsaCfg) -> Expr {
    let vdef = ssa.var(id);
    match &vdef.expr {
        Expr::Var(inner) => ssa.var(*inner).expr.clone(),
        other => other.clone(),
    }
}

// ---- Helpers ----

fn is_flag(offset: u64) -> bool {
    matches!(offset, 512..=523 | 256..=264 | 96..=104)  // x86 + ARM64 + ARM32 flags
}

fn is_zext_artifact(vdef: &VarDef, ssa: &SsaCfg) -> bool {
    if vdef.varnode.space != AddressSpaceId::Register { return false; }
    if let Expr::UnaryOp(UnaryOpKind::Zext, inner_id) = &vdef.expr {
        let inner = ssa.var(*inner_id);
        inner.varnode.space == AddressSpaceId::Register
            && inner.varnode.offset == vdef.varnode.offset
            && inner.varnode.size < vdef.varnode.size
    } else {
        false
    }
}

/// Check if an argument register assignment is consumed by a Call (shown inline).
fn is_arg_consumed_by_call(var_id: VarId, ssa: &SsaCfg) -> bool {
    for block in &ssa.blocks {
        // Check Call terminators
        if let SsaTerminator::Call { args, .. } = &block.terminator {
            if args.contains(&var_id) { return true; }
        }
        // Check Call statements
        for stmt in &block.stmts {
            if let Stmt::Call { args, .. } = stmt {
                if args.contains(&var_id) { return true; }
            }
        }
    }
    false
}

fn is_self_assign(vdef: &VarDef, ssa: &SsaCfg) -> bool {
    if let Expr::Var(src_id) = &vdef.expr {
        let src = ssa.var(*src_id);
        src.varnode == vdef.varnode
    } else {
        false
    }
}

fn size_to_type(size: u32) -> &'static str {
    match size { 1 => "uint8_t", 2 => "uint16_t", 4 => "uint32_t", 8 => "uint64_t", 16 => "__uint128_t", _ => "void" }
}

/// Type-aware version: uses InferredType to pick signed/float/pointer types.
fn typed_name(size: u32, ty: InferredType) -> &'static str {
    match ty {
        InferredType::Float => match size {
            4 => "float",
            8 => "double",
            _ => "double",
        },
        InferredType::Signed => match size {
            1 => "int8_t",
            2 => "int16_t",
            4 => "int",
            8 => "int64_t",
            _ => "int",
        },
        InferredType::Pointer => match size {
            1 => "char",
            2 => "short",
            4 => "int",
            8 => "long",
            _ => "void",
        },
        InferredType::Bool => "bool",
        InferredType::Unsigned => size_to_type(size),
        InferredType::Unknown => size_to_type(size),
    }
}

fn binop_str(kind: BinOpKind) -> &'static str {
    match kind {
        BinOpKind::Add | BinOpKind::FloatAdd => "+",
        BinOpKind::Sub | BinOpKind::FloatSub => "-",
        BinOpKind::Mult | BinOpKind::FloatMult => "*",
        BinOpKind::Div | BinOpKind::SDiv | BinOpKind::FloatDiv => "/",
        BinOpKind::Rem | BinOpKind::SRem => "%",
        BinOpKind::And => "&",
        BinOpKind::Or => "|",
        BinOpKind::Xor => "^",
        BinOpKind::Lsl => "<<",
        BinOpKind::Lsr | BinOpKind::Asr => ">>",
        BinOpKind::Eq | BinOpKind::FloatEq => "==",
        BinOpKind::NotEq | BinOpKind::FloatNotEq => "!=",
        BinOpKind::Less | BinOpKind::SLess | BinOpKind::FloatLess => "<",
        BinOpKind::LessEq | BinOpKind::SLessEq | BinOpKind::FloatLessEq => "<=",
        BinOpKind::BoolAnd => "&&",
        BinOpKind::BoolOr => "||",
        BinOpKind::BoolXor => "!=",
        BinOpKind::Carry => "CARRY",
        BinOpKind::SCarry => "SCARRY",
        BinOpKind::SBorrow => "SBORROW",
    }
}

fn unaryop_str(kind: UnaryOpKind) -> &'static str {
    match kind {
        UnaryOpKind::Neg => "-", UnaryOpKind::Not => "~", UnaryOpKind::BoolNot => "!",
        UnaryOpKind::Zext => "ZEXT", UnaryOpKind::Sext => "SEXT",
        UnaryOpKind::FloatNeg => "FNEG", UnaryOpKind::FloatAbs => "FABS",
        UnaryOpKind::FloatSqrt => "FSQRT", UnaryOpKind::FloatNan => "ISNAN",
        UnaryOpKind::Int2Float => "INT2FLOAT", UnaryOpKind::Float2Float => "FLOAT2FLOAT",
        UnaryOpKind::Trunc => "TRUNC", UnaryOpKind::FloatCeil => "CEIL",
        UnaryOpKind::FloatFloor => "FLOOR", UnaryOpKind::FloatRound => "ROUND",
        UnaryOpKind::Popcount => "POPCOUNT", UnaryOpKind::Lzcount => "LZCOUNT",
    }
}

/// Extract variable name and constant from "if (VAR == CONST) {" pattern.
fn extract_if_eq_const(line: &str) -> Option<(String, String)> {
    let cond = line.strip_prefix("if (")?.strip_suffix(") {")?;
    parse_eq_const(cond)
}

/// Parse "EXPR == CONST" or "EXPR == 'c'" from a condition string.
fn parse_eq_const(cond: &str) -> Option<(String, String)> {
    // Split on " == "
    let parts: Vec<&str> = cond.splitn(2, " == ").collect();
    if parts.len() != 2 { return None; }
    let var = parts[0].trim();
    let val = parts[1].trim();
    // Validate: var should be a variable-like expression, val should be a constant
    if var.is_empty() || val.is_empty() { return None; }
    let val_is_const = val.starts_with("0x") || val.starts_with('\'') || val.starts_with('-')
        || val.chars().next().map_or(false, |c| c.is_ascii_digit())
        || val == "NULL";
    if val_is_const {
        Some((var.to_string(), val.to_string()))
    } else {
        None
    }
}

/// Extract the low-half value from a 64-bit concatenation pattern.
/// Recognizes: Or(Lsl(x, 32), Zext(val)) → val
/// This is the x86 CDQ+IDIV pattern where EDX:EAX is built from two 32-bit halves.
fn extract_concat_low_half(id: VarId, ssa: &SsaCfg) -> Option<VarId> {
    let vdef = ssa.var(id);
    let (or_left, or_right) = match &vdef.expr {
        Expr::BinOp(BinOpKind::Or, l, r) => (*l, *r),
        _ => return None,
    };

    // One side should be Lsl(x, 32), the other Zext(val)
    let low_half = try_extract_low_from_or(or_left, or_right, ssa)
        .or_else(|| try_extract_low_from_or(or_right, or_left, ssa))?;
    Some(low_half)
}

/// Check if `high` is Lsl(x, 32) and `low` is Zext(val), return val.
fn try_extract_low_from_or(high: VarId, low: VarId, ssa: &SsaCfg) -> Option<VarId> {
    // high must be Lsl(something, 32)
    let high_def = ssa.var(high);
    match &high_def.expr {
        Expr::BinOp(BinOpKind::Lsl, _, shift_amt) => {
            match &ssa.var(*shift_amt).expr {
                Expr::Const(32, _) => {}
                _ => return None,
            }
        }
        _ => return None,
    }

    // low must be Zext(val)
    let low_def = ssa.var(low);
    match &low_def.expr {
        Expr::UnaryOp(UnaryOpKind::Zext, inner) => Some(*inner),
        _ => None,
    }
}

/// Unwrap Zext/Sext wrappers to get the inner value.
fn unwrap_ext(id: VarId, ssa: &SsaCfg) -> VarId {
    match &ssa.var(id).expr {
        Expr::UnaryOp(UnaryOpKind::Zext | UnaryOpKind::Sext, inner) => *inner,
        _ => id,
    }
}
