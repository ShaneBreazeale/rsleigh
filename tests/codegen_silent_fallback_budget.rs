//! Budget test for silent fallbacks in the codegen template.
//!
//! Audit P2 #3 (lighter wedge). The full audit recommendation is to
//! emit diagnostic events from generated lift code so silent zeros
//! become observable at runtime. That requires regenerating every
//! generated crate (~30) which is out of scope for a single commit.
//!
//! Instead this test pins the static count of `quote! { 0u64 }` /
//! `quote! { 0i128 }` / `=> 0u64` / `=> 0i128` literals in
//! `src/codegen/builder/disassembler/constructor/execution.rs`. If
//! new fallback sites appear, the test fails — author must either
//! eliminate them, document them in this file's MOTIVATIONS map, or
//! bump the budget with a justification.
//!
//! Existing sites (snapshot at commit time):
//!
//!   line 59  : `context_field_i128` default for unwired context — covered by
//!              ConstructorStruct.context_fields wiring (audit Patch 3).
//!   line 144 : `dynamic_value_expr` token-field branch fallback — fires when
//!              the requested field is not populated; rare, audited path.
//!   line 202 : attach-table miss — table lookup default; legitimate when the
//!              attach lookup is partial.
//!   line 456 : disassembly read-scope context default.
//!   line 461 : disassembly read-scope token default.
//!
//! Five sites. Bumps require updating both this list and the budget.

use std::path::Path;

const EXECUTION_RS: &str = "src/codegen/builder/disassembler/constructor/execution.rs";
const SILENT_FALLBACK_BUDGET: usize = 5;

#[test]
fn codegen_silent_fallback_count_within_budget() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(EXECUTION_RS);
    let src =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));

    let count = src
        .lines()
        .filter(|line| {
            line.contains("quote! { 0u64 }")
                || line.contains("quote! { 0i128 }")
                || line.contains("=> 0u64")
                || line.contains("=> 0i128")
        })
        .count();

    assert_eq!(
        count, SILENT_FALLBACK_BUDGET,
        "silent-fallback budget violated: counted {} occurrences in {}, \
         expected exactly {}. Either remove the new fallback or update \
         SILENT_FALLBACK_BUDGET + the MOTIVATIONS list in this test.",
        count, EXECUTION_RS, SILENT_FALLBACK_BUDGET
    );
}
