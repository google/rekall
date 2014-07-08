        ;; Test file for I386 inline hooks.
[BITS 32]
default rel

%macro HookTestCase 2
%1:
        db '---', 10
        db 'arch: I386', 10
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

        HookTestCase ImmediateCall, "ImmediateCall"
        call target
        EndHookTestCase

        HookTestCase RelativeJump, "RelativeJump"
        lea eax, [target]
        mov [temp], eax
        jmp [rel temp]
        EndHookTestCase

        HookTestCase IndirectJump, "IndirectJump"
        lea eax, [target]
        jmp eax
        EndHookTestCase

        HookTestCase IndirectJump2, "IndirectJump2"
        lea eax, [target]
        mov [temp], eax
        mov ebx, [temp]
        jmp ebx
        EndHookTestCase

        HookTestCase IndirectJump3, "IndirectJump3"
        lea ebx, [target]
        jmp ebx
        EndHookTestCase

        HookTestCase IndirectJump4, "IndirectJump4"
        lea ecx, [target]
        jmp ecx
        EndHookTestCase

        HookTestCase PushRet, "PushRet"
        lea eax, [target]
        push eax
        ret
        EndHookTestCase

        HookTestCase BranchJump, "BranchJump"
        xor eax, eax
        jz target
        EndHookTestCase

        HookTestCase Combination, "Combination"
        LEA EAX, [start]
        NOP
        NOP
        ADD EAX, 0x00100
        CALL EAX
        EndHookTestCase

        ;; Ref: http://www.ragestorm.net/blogs/?p=101
        HookTestCase AbsoluteJump, "AbsoluteJump"
        push dword 0x100
        ret
        EndHookTestCase

        ;; http://www.ragestorm.net/blogs/?p=107
        HookTestCase AbsoluteJump2, "AbsoluteJump2"
        jmp [address]
address:
        dd 0x100
        EndHookTestCase