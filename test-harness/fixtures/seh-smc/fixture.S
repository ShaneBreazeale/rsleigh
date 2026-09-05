// Original, synthetic PE64 SEH-SMC regression fixture; repository license.
// Assemble with Clang's Windows COFF target. No CRT or SDK dependencies.
.intel_syntax noprefix
.text
.globl entry, protected_fault, smc_handler

.seh_proc entry
entry:
    sub rsp, 40
    .seh_stackalloc 40
    .seh_endprologue
    call protected_fault
    add rsp, 40
    ret
.seh_endproc

.seh_proc protected_fault
protected_fault:
    push rbx
    .seh_pushreg rbx
    sub rsp, 32
    .seh_stackalloc 32
    .seh_handler smc_handler, @except
    .seh_endprologue
    ud2                             // STATUS_ILLEGAL_INSTRUCTION
    // Serialize instruction fetch after the handler's code write.
    xor eax, eax
    cpuid                           // RBX is preserved by this function
    call payload
    add rsp, 32
    pop rbx
    ret
.seh_endproc

smc_handler:
    cmp dword ptr [rcx], 0xc000001d
    jne .Lsearch
    test dword ptr [rcx + 4], 7      // noncontinuable / unwinding flags
    jne .Lsearch
#if INDIRECT
    lea rax, [rip + .Lpatch]
    jmp rax                         // must follow this to recover the write
    ret                             // prevents accidental linear fallthrough
#endif
.Lpatch:
    mov byte ptr [rip + payload + 1], 42
    add qword ptr [r8 + 0xf8], 2    // CONTEXT.Rip: skip the two-byte UD2
    xor eax, eax                    // ExceptionContinueExecution = 0
    ret
.Lsearch:
    mov eax, 1                      // ExceptionContinueSearch = 1
    ret

// Deliberately writable executable code: isolates patch recovery from APIs.
.section .smc,"xw"
.globl payload
payload:
    .byte 0xb8, 0, 0, 0, 0, 0xc3   // mov eax, 0; ret -> mov eax, 42; ret
