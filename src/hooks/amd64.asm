        ;; Test file for AMD64 inline hooks.
[BITS 64]
default rel

%macro HookTestCase 2
        db '---', 10
        db 'arch: AMD64', 10
        db 'name: '           ; The name of the test case.
        db %2, 10
        db '...', 10
        db '<bin>'
test%1:
%endmacro

%macro EndHookTestCase 0
        nop
        nop
        nop
        nop
        db '</bin>', 10
        nop
        nop
        nop
        nop
%endmacro


section .text:
start:
        ;; The Start of the .text section is mapped at offset 0.
        ;; We mark it so it can be easily found by the profile
        ;; generation script.
        ;; Pad here by exactly 0x100 chars to ensure that __target__ is at
        ;; offset 0x100.
        db '__start__                                                       '
        db '                                                                '
        db '                                                                '
        db '                                                                '

target:
        db '__target__'
        ;; The target for all the jumps.
        ret

temp:   dq 0

        ;; Following are test cases for hooks.
        HookTestCase ImmediateJump, "ImmediateJump"
        jmp target
        EndHookTestCase

        HookTestCase IndirectJump, "IndirectJump"
        lea rax, [rel target]
        jmp rax
        EndHookTestCase

        HookTestCase IndirectJump2, "IndirectJump2"
        lea rax, [target]
        mov [temp], rax
        mov rbx, [temp]
        jmp rbx
        EndHookTestCase

        HookTestCase IndirectJump3, "IndirectJump3"
        lea rbx, [target]
        jmp rbx
        EndHookTestCase

        HookTestCase IndirectJump4, "IndirectJump4"
        lea rcx, [target]
        jmp rcx
        EndHookTestCase

        HookTestCase IndirectJump5, "IndirectJump5"
        lea rcx, [target]
        mov [start], rcx
        jmp [start]
        EndHookTestCase

        HookTestCase PushRet, "PushRet"
        lea rax, [target]
        push rax
        ret
        EndHookTestCase

        HookTestCase PushRet2, "PushRet2"
        lea rax, [target]
        mov [start], rax
        push qword [start]
        ret
        EndHookTestCase

        HookTestCase BranchJump, "BranchJump"
        xor rax, rax
        jz target
        EndHookTestCase

        HookTestCase Combination, "Combination"
        LEA RAX, [start]
        NOP
        NOP
        ADD RAX, 0x00100
        CALL RAX
        EndHookTestCase

        ;; Ref: http://www.ragestorm.net/blogs/?p=101
        ;; Absolute jmp are not allowed in 64 bit so this hook uses push/ret.
        HookTestCase AbsoluteJump, "AbsoluteJump"
        push qword 0x100
        ret
        EndHookTestCase

        ;; http://www.ragestorm.net/blogs/?p=107
        HookTestCase AbsoluteJump2, "AbsoluteJump2"
        jmp [address]
address:
        dq 0x100
        EndHookTestCase

        HookTestCase AbsoluteJump3, "AbsoluteJump3"
        MOV RAX, [address2]
        JMP RAX

address2:
        dq 0x100
        EndHookTestCase