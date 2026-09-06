; Original fixture source, repository license. x86-32 cdecl, PE base 0x400000.
; seed.rs deterministically encodes this source and its minimal PE container.
; Bytes are checked by the native decoder in the evaluation workflow.
; No assembler, JVM, solver, or model service is required.

; 0x401000
mov eax, 7
ret                         ; 0x401005: return 7

; 0x401020
push 22                     ; argument 1 is pushed first
push 11                     ; argument 0 is closest to the return address
call helper                 ; 0x401024: helper(11, 22)
add esp, 8
push 44
push 33
call helper                 ; 0x401030: helper(33, 44)
add esp, 8
ret

; 0x401040
test eax, eax               ; incoming eax is unknown
jnz second_return           ; 0x401042
mov eax, 1
ret                         ; 0x401049
second_return:              ; 0x40104a
mov eax, 2
ret                         ; 0x40104f

; 0x401060
mov eax, [ecx]              ; no known store: memory remains unresolved
ret                         ; 0x401062

; 0x401080
helper:
mov eax, 9
ret
