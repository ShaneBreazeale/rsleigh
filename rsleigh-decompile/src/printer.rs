use std::collections::HashMap;
use pcode_ir::{Varnode, AddressSpaceId};
use rsleigh_api::Architecture;
use crate::ir::*;

const RBP_OFFSET: u64 = 40;
const RSP_OFFSET: u64 = 32;
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
) -> String {
    let mut out = String::new();
    let ctx = PrintCtx { arch, binary, imports };
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
        .filter_map(|v| v.param_name.as_ref().cloned())
        .collect();
    post_process(&mut out, &all_aliases, &param_names, struct_fields, &ctx);
    out
}

fn collect_store_aliases(stmts: &[StructuredStmt], ssa: &SsaCfg, ctx: &PrintCtx, tracker: &mut RegTracker) {
    for stmt in stmts {
        if let StructuredStmt::Store { addr, val } = stmt {
            if let Some(stack_name) = try_stack_var_name(*addr, ssa) {
                let val_expr = format_var_tracked(*val, ssa, ctx, tracker);
                tracker.stack_alias.insert(stack_name, val_expr);
            }
        }
        // Also check Assigns that write to arg registers
        if let StructuredStmt::Assign { lhs, .. } = stmt {
            let vdef = ssa.var(*lhs);
            if vdef.varnode.space == AddressSpaceId::Register {
                if let Expr::Var(_) | Expr::Load(_) = &vdef.expr {
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
                    } else {
                        // Dead store
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
    for line in &mut lines {
        // Pattern 1: *(uintN_t*)(X + Y)
        while let Some(star_pos) = line.find("*(uint") {
            if let Some(type_end) = line[star_pos..].find("*)(") {
                let abs_paren = star_pos + type_end + 2;
                if let Some(close) = find_matching_paren(line, abs_paren) {
                    let inner = &line[abs_paren + 1..close];
                    if let Some(plus) = inner.find(" + ") {
                        let base = &inner[..plus];
                        let idx = &inner[plus + 3..];
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
                if let Some(plus) = inner.find(" + ") {
                    let base = &inner[..plus];
                    let idx = &inner[plus + 3..];
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
    if !param_names.is_empty() {
        for line in &mut lines {
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
                let num_start = line.find(&minus_pat).unwrap() + minus_pat.len();
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
                let hex_start = line.find(&minus_hex_pat).unwrap() + minus_hex_pat.len();
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
                let hex_start = line.find(&plus_hex_pat).unwrap() + plus_hex_pat.len();
                let hex_end = line[hex_start..].find(|c: char| !c.is_ascii_hexdigit())
                    .map(|e| hex_start + e).unwrap_or(line.len());
                let hex_str = line[hex_start..hex_end].to_string();
                if let Ok(val) = u64::from_str_radix(&hex_str, 16) {
                    // Large values are actually negative offsets (e.g., 0xfffffffc = -4)
                    let neg_off = if val >= 0xffffff00 {
                        0x100000000u64 - val // 32-bit sign extension
                    } else if val >= 0x80 && val < 0x100 {
                        0x100 - val // 8-bit sign extension
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
                    if (is_return_bare || is_return_var) && !expr.is_empty() {
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
                    // Search forward for "return var_name;" at top level
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
                    let indent = lines[i].len() - lines[i].trim_start().len();
                    let pad = " ".repeat(indent);
                    let _var_name = lt.split(' ').next().unwrap_or("buf");
                    for idx in (i + 1..=end).rev() { lines.remove(idx); }
                    lines[i] = format!("{}// stack string: \"{}\"", pad, merged);
                    // Keep the first var assignment for reference
                    // Actually just show the merged string as a comment
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

    // #DEDUP: Remove duplicate call lines within the same scope.
    // The nested-call unwinding can create the same call line multiple times.
    // Remove non-consecutive duplicates of function calls at the same indent level.
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
                let mut j = i + 1;
                while j < lines.len() {
                    let jt = lines[j].trim();
                    let j_indent = lines[j].len() - lines[j].trim_start().len();
                    if j_indent == indent && jt == lt {
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
                                                // Replace the table load line with switch/case comment
                                                let case_str = cases.join(", ");
                                                lines[i] = format!("{}// switch table: {}", pad, case_str);
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
                && !lt.starts_with("//") && !lt.starts_with("var_")
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
            // But only in conditions (after if/while), not in general expressions
            if line.contains(&format!("== {})", val)) || line.contains(&format!("!= {})", val))
                || line.contains(&format!("> {})", val)) || line.contains(&format!("< {})", val))
                || line.contains(&format!(">= {})", val)) || line.contains(&format!("<= {})", val))
                || line.contains(&format!("- {} ==", val))
            {
                if !line.contains("\"") || line.contains("if (") || line.contains("while (") {
                    *line = line.replace(&format!("== {})", val), &format!("== {})", ch));
                    *line = line.replace(&format!("!= {})", val), &format!("!= {})", ch));
                    *line = line.replace(&format!("> {})", val), &format!("> {})", ch));
                    *line = line.replace(&format!("< {})", val), &format!("< {})", ch));
                    *line = line.replace(&format!(">= {})", val), &format!(">= {})", ch));
                    *line = line.replace(&format!("<= {})", val), &format!("<= {})", ch));
                    *line = line.replace(&format!("- {} ==", val), &format!("== {}  //", ch));
                }
            }
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
                && !lt.starts_with("return ") && !lt.starts_with("//")
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
}

/// Remove prologue/epilogue boilerplate from the top level.
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
                    && addr_def.varnode.offset == RSP_OFFSET
                { return false; }
                if is_rsp_expr(&addr_def.expr, ssa) { return false; }
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
    false
}

fn is_frame_pointer_op(vdef: &VarDef) -> bool {
    if vdef.varnode.space != AddressSpaceId::Register { return false; }
    if vdef.varnode.offset == RBP_OFFSET || vdef.varnode.offset == RSP_OFFSET {
        match &vdef.expr {
            Expr::Var(_) => true,
            Expr::Load(_) => vdef.varnode.offset == RBP_OFFSET,
            _ => false,
        }
    } else {
        false
    }
}

fn is_rsp_expr(expr: &Expr, ssa: &SsaCfg) -> bool {
    match expr {
        Expr::Var(id) => {
            let v = ssa.var(*id);
            v.varnode.space == AddressSpaceId::Register && v.varnode.offset == RSP_OFFSET
        }
        Expr::BinOp(_, l, _) => {
            let v = ssa.var(*l);
            v.varnode.space == AddressSpaceId::Register && v.varnode.offset == RSP_OFFSET
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
                return false;
            }
            StructuredStmt::Return(_) | StructuredStmt::Store { .. }
            | StructuredStmt::Call { .. } | StructuredStmt::While { .. }
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
            if matches!(&vdef.expr, Expr::Phi(_)) { return; }
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
                    // Format BEFORE invalidating so the expression can resolve
                    // the old register values through the tracker
                }
            }

            // Format RHS BEFORE any invalidation of this register
            let name = var_name(&vdef.varnode, ctx);
            let rhs = format_expr_tracked(&vdef.expr, ssa, ctx, tracker);

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
                && vdef.varnode.offset == 0 // RAX/EAX — return value register
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
                    out.push_str(&format!("{}return {};\n", pad, rhs));
                    // Mark that we've printed the return
                    tracker.set_call_return(0, 0, "<<returned>>".to_string());
                    return;
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
                // Track this stack variable's value for later resolution
                tracker.stack_alias.insert(stack_name.clone(), val_expr.clone());

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
            let args_str: Vec<String> = args.iter()
                .map(|a| {
                    let vdef = ssa.var(*a);
                    format_expr_tracked(&vdef.expr, ssa, ctx, tracker)
                })
                .collect();
            let call_expr = format!("{}({})", target_name, args_str.join(", "));

            // Calls clobber all registers
            tracker.invalidate_all();

            if let Some(out_var) = call_out {
                let name = var_name(&ssa.var(*out_var).varnode, ctx);
                out.push_str(&format!("{}{} = {};\n", pad, name, call_expr));
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

                if !next_reads_eax {
                    // For allocation functions, show the return assignment
                    // since the pointer is always used afterwards.
                    let is_alloc = target_name == "malloc" || target_name == "calloc"
                        || target_name == "realloc" || target_name == "mmap"
                        || target_name == "strdup";
                    if is_alloc {
                        out.push_str(&format!("{}ptr = {};\n", pad, call_expr));
                    } else {
                        out.push_str(&format!("{}{};\n", pad, call_expr));
                    }
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
        StructuredStmt::Goto(addr) => {
            out.push_str(&format!("{}goto label_{:x};\n", pad, addr));
        }
        StructuredStmt::Label(addr) => {
            out.push_str(&format!("label_{:x}:\n", addr));
        }
    }
}

/// Format a VarId with register tracking — resolves register copies to their source.
fn format_var_tracked(id: VarId, ssa: &SsaCfg, ctx: &PrintCtx, tracker: &RegTracker) -> String {
    let vdef = ssa.var(id);
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
        if let Some(expr_str) = tracker.get_expr_str(vdef.varnode.offset, vdef.varnode.size) {
            return expr_str.to_string();
        }
        // Also check smaller sizes at same offset (RAX → EAX tracking)
        if tracker.get_expr_str(vdef.varnode.offset, vdef.varnode.size).is_none() {
            for sz in [4u32, 8, 2, 1] {
                if sz == vdef.varnode.size { continue; }
                if let Some(expr_str) = tracker.get_expr_str(vdef.varnode.offset, sz) {
                    return expr_str.to_string();
                }
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

fn format_expr_tracked(expr: &Expr, ssa: &SsaCfg, ctx: &PrintCtx, tracker: &RegTracker) -> String {
    match expr {
        Expr::Var(id) => format_var_tracked(*id, ssa, ctx, tracker),
        Expr::BinOp(kind, left, right) => {
            let l = format_var_tracked(*left, ssa, ctx, tracker);
            let r = format_var_tracked(*right, ssa, ctx, tracker);
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
            format!("{} {} {}", l, op, r)
        }
        Expr::UnaryOp(kind, input) => {
            let i = format_var_tracked(*input, ssa, ctx, tracker);
            match kind {
                UnaryOpKind::Neg => format!("-{}", i),
                UnaryOpKind::Not => format!("~{}", i),
                UnaryOpKind::BoolNot => format!("!{}", i),
                UnaryOpKind::Zext => i, // zero-extend is implicit in C
                UnaryOpKind::Sext => format!("(int){}", i),
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
            // For conditions, render operands via their SSA expression first,
            // falling back to tracker. This avoids the tracker aliasing both
            // operands to the same register name.
            let l = format_cond_operand(*left, ssa, ctx, tracker);
            let r = format_cond_operand(*right, ssa, ctx, tracker);
            // Canonicalize: if LHS is a constant, swap operands and use swapped operator string
            let lv = ssa.var(*left);
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
        let addr = format_cond_operand(*ptr, ssa, ctx, tracker);
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
            let addr = format_cond_operand(*ptr, ssa, ctx, tracker);
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
    // For registers, also try the tracker for param names
    if vdef.varnode.space == AddressSpaceId::Register {
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

/// Try to produce a stack variable name like "var_8" for RBP-relative accesses.
fn try_stack_var_name(addr_id: VarId, ssa: &SsaCfg) -> Option<String> {
    let offset = get_rbp_offset(addr_id, ssa)?;
    Some(format!("var_{:x}", offset))
}

/// Get the (positive) offset from RBP for a stack access, if this is RBP-relative.
fn get_rbp_offset(id: VarId, ssa: &SsaCfg) -> Option<u64> {
    let expr = resolve_through_vars(id, ssa);
    if let Expr::BinOp(BinOpKind::Add, base_id, off_id) = &expr {
        let base = ssa.var(*base_id);
        if base.varnode.space == AddressSpaceId::Register && base.varnode.offset == RBP_OFFSET {
            let off_val = get_const_val(*off_id, ssa)?;
            // Convert to negative offset
            if off_val >= 0x80 && off_val < 0x100 { return Some(0x100 - off_val); }
            if off_val >= 0x8000 && off_val < 0x10000 { return Some(0x10000 - off_val); }
            if off_val > 0x7fffffffffffffff { return Some((!off_val).wrapping_add(1)); }
            return None; // Positive offset — not a local variable
        }
    }
    None
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
    // Try stack variable first
    if let Some(offset) = get_rbp_offset(id, ssa) {
        return format!("RBP - 0x{:x}", offset);
    }

    let expr = resolve_through_vars(id, ssa);
    if let Expr::BinOp(BinOpKind::Add, base_id, off_id) = &expr {
        let base = ssa.var(*base_id);
        if base.varnode.space == AddressSpaceId::Register && base.varnode.offset == RBP_OFFSET {
            if let Some(val) = get_const_val(*off_id, ssa) {
                return format_rbp_offset(val);
            }
        }
    }

    format_var(id, ssa, ctx)
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

    // Inline Unique-space temporaries
    if vdef.varnode.space == AddressSpaceId::Unique {
        return format_expr(&vdef.expr, ssa, ctx);
    }

    // Inline constants
    if let Expr::Const(val, sz) = &vdef.expr {
        return format_const_ctx(*val, *sz, ctx);
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
            let addr = format_store_operand(*ptr, ssa, ctx, tracker);
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
            match kind {
                UnaryOpKind::Neg => format!("-{}", i),
                UnaryOpKind::Not => format!("~{}", i),
                UnaryOpKind::BoolNot => format!("!{}", i),
                UnaryOpKind::Zext => i, // zero-extend is implicit in C
                UnaryOpKind::Sext => format!("(int){}", i),
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
        Expr::Phi(inputs) => {
            if inputs.len() == 1 { return format_var(inputs[0], ssa, ctx); }
            let args: Vec<String> = inputs.iter().map(|i| format_var(*i, ssa, ctx)).collect();
            format!("phi({})", args.join(", "))
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
    }
    format_const(val, size)
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
/// Check if a value looks like a virtual address (common image base ranges).
/// Used to avoid false-positive ASCII string decoding of address constants.
fn looks_like_address(val: u64) -> bool {
    // PE32 typical: 0x00400000..0x10000000
    // PE64 typical: 0x140000000..0x180000000
    // ELF typical: 0x08000000..0x10000000 or 0x400000..0x800000
    // Mach-O typical: 0x100000000..0x200000000
    (val >= 0x00400000 && val < 0x10000000)
        || (val >= 0x08000000 && val < 0x10000000)
        || (val >= 0x100000000 && val < 0x200000000)
        || (val >= 0x140000000 && val < 0x180000000)
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
            // Only read strings from __TEXT segment (read-only, contains __cstring)
            // Skip __DATA/__DATA_CONST (global vars, GOT pointers)
            macho.segments.iter().find_map(|seg| {
                let segname = seg.name().ok().unwrap_or("").trim_end_matches('\0');
                if segname != "__TEXT" { return None; }
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
    let max = 200.min(binary.len() - file_offset);
    let slice = &binary[file_offset..file_offset + max];
    let null_pos = slice.iter().position(|&b| b == 0)?;
    if null_pos > 120 { return None; } // reject very long "strings"
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
            has_version && null_pos < 20
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

fn var_name(vn: &Varnode, ctx: &PrintCtx) -> String {
    match vn.space {
        AddressSpaceId::Register => {
            ctx.arch.register_name(vn.offset, vn.size).unwrap_or("?reg").to_string()
        }
        AddressSpaceId::Unique => format!("tmp_{:x}", vn.offset),
        AddressSpaceId::Ram => format!("mem_{:x}", vn.offset),
        AddressSpaceId::Const => format_const(vn.offset, 8),
    }
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
    matches!(offset, 512..=523 | 256..=264)  // x86 flags + ARM64 flags
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
