#[allow(
    non_camel_case_types,
    non_snake_case,
    unused_variables,
    unused_mut,
    unused_parens,
    clippy::all
)]
mod x86_64 {
    include!(concat!(env!("OUT_DIR"), "/x86_64/root.rs"));
}

use x86_64::*;

fn context_x86_64() -> ContextMemory {
    let mut ctx = ContextMemory::default();
    ctx.write_longMode(1);
    ctx.write_addrsize(2);
    ctx.write_opsize(1);
    ctx
}

fn main() {
    let mut context = context_x86_64();
    let mut global_set = GlobalSet::new(context_x86_64());

    let tests: &[(&[u8], &str)] = &[
        (&[0x48, 0x89, 0xc7], "MOV rdi, rax"),
        (&[0x48, 0x01, 0xc7], "ADD rdi, rax"),
        (&[0x50], "PUSH rax"),
        (&[0x58], "POP rax"),
        (&[0xc3], "RET"),
        (&[0x74, 0x05], "JE rel8"),
        (&[0xeb, 0x0a], "JMP rel8"),
        (&[0xff, 0xd0], "CALL rax"),
        (&[0x48, 0x8b, 0x07], "MOV rax,[rdi]"),
        (&[0x48, 0x39, 0xc7], "CMP rdi, rax"),
    ];

    for (bytes, name) in tests {
        context = context_x86_64();
        if let Some((inst_next, display, mut pcode)) =
            parse_instruction(bytes, &mut context, 0x1000, &mut global_set)
        {
            pcode_ir::optimize(&mut pcode);
            println!("{name}:");
            let disasm: Vec<String> = display.iter().map(|d| format!("{}", d)).collect();
            println!("  decoded: {}", disasm.join(""));
            println!("  len={}, pcode_ops={}", inst_next - 0x1000, pcode.len());
            for op in &pcode {
                println!("    {:?}", op);
            }
        } else {
            eprintln!("  FAILED to decode {name}");
        }
        println!();
    }
}
