---
abstract: Disassemble the given offset.
args: {address_space: 'The address space to use. (type: AddressSpace)

    ', branch: 'If set we follow all branches to cover all code. (type: Boolean)



    * Default: False', canonical: 'If set emit canonical instructions. These can be
    used to develop signatures. (type: Boolean)



    * Default: False', end: 'The end address to disassemble up to. (type: IntParser)

    ', length: 'The number of instructions (lines) to disassemble. (type: IntParser)

    ', mode: "Disassemble Mode (AMD64 or I386). Defaults to 'auto'. (type: Choices)\n\
    \n\n* Valid Choices:\n    - I386\n    - AMD64\n    - MIPS\n", offset: 'An offset
    to disassemble. This can also be the name of a symbol with an optional offset.
    For example: tcpip!TcpCovetNetBufferList. (type: SymbolAddress)

    ', verbosity: 'An integer reflecting the amount of desired output: 0 = quiet,
    10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: Disassemble
epydoc: rekall.plugins.tools.disassembler.Disassemble-class.html
layout: plugin
module: rekall.plugins.tools.disassembler
title: dis
---

This plugin is used to disassemble memory regions. The offset to disassemble may be given as:

* An address in the current default address space (See the
  [cc](SetProcessContext.html) plugin for an explaination of the default address
  space).

* The name of a kernel module with an optional symbol name. The symbol may be an
  experted symbol, or non-exported symbol as defined in the pdb file for that
  kernel module.

### Notes

1. When using the interactive console you can complete symbol names by double
   tapping the [tab] key. For example **dis "nt!KiSetTi[tab][tab]**.

2. Rekall attempts to resolve addresses in the disassembly back to known symbol
   names. Additionally, for indirect operations, Rekall also prints the current
   value of the memory location. This feature is especially useful for
   understanding where indirect jumps are going - without needing to consider PE
   import tables etc. This works since the IAT is already patched into memory,
   hence Rekall can completely ignore IAT resoltion (unlike a standalone PE
   analyser like IDA).

### Sample output

Here we disassemble the kernel function **KiSetTimerEx** to observe the DPC
pointer obfuscation that Patch Guard uses on 64 bit Windows 7. We can see the
names of the symbols used and their current values, as well as the name of
internally called functions.

```
win7.elf 23:48:14> dis "nt!KiSetTimerEx"
-----------------> dis("nt!KiSetTimerEx")
   Address      Rel Op Codes             Instruction                    Comment
-------------- ---- -------------------- ------------------------------ -------
------ nt!KiSetTimerEx ------
0xf8000269d4f0    0 48895c2408           MOV [RSP+0x8], RBX
0xf8000269d4f5    5 4889542410           MOV [RSP+0x10], RDX
0xf8000269d4fa    A 55                   PUSH RBP
0xf8000269d4fb    B 56                   PUSH RSI
0xf8000269d4fc    C 57                   PUSH RDI
0xf8000269d4fd    D 4154                 PUSH R12
0xf8000269d4ff    F 4155                 PUSH R13
0xf8000269d501   11 4156                 PUSH R14
0xf8000269d503   13 4157                 PUSH R15
0xf8000269d505   15 4883ec50             SUB RSP, 0x50
0xf8000269d509   19 488b05f09b2200       MOV RAX, [RIP+0x229bf0]        0x6D7CFFA404933FBB nt!KiWaitNever
0xf8000269d510   20 488b1dc19c2200       MOV RBX, [RIP+0x229cc1]        0x933DD660CFFF8004 nt!KiWaitAlways
0xf8000269d517   27 4c8bb424b0000000     MOV R14, [RSP+0xb0]
0xf8000269d51f   2F 4933de               XOR RBX, R14
0xf8000269d522   32 488bf1               MOV RSI, RCX
0xf8000269d525   35 450fb6f9             MOVZX R15D, R9B
0xf8000269d529   39 480fcb               BSWAP RBX
0xf8000269d52c   3C 418bf8               MOV EDI, R8D
0xf8000269d52f   3F 4833d9               XOR RBX, RCX
0xf8000269d532   42 8bc8                 MOV ECX, EAX
0xf8000269d534   44 48d3cb               ROR RBX, CL
0xf8000269d537   47 4833d8               XOR RBX, RAX
0xf8000269d53a   4A 450f20c4             MOV R12, CR8
0xf8000269d53e   4E b802000000           MOV EAX, 0x2
0xf8000269d543   53 440f22c0             MOV CR8, RAX
0xf8000269d547   57 65488b2c2520000000   MOV RBP, [GS:0x20]
0xf8000269d550   60 33d2                 XOR EDX, EDX
0xf8000269d552   62 488bce               MOV RCX, RSI
0xf8000269d555   65 e8f6b0ffff           CALL 0xf80002698650            nt!KiCancelTimer
0xf8000269d55a   6A 48895e30             MOV [RSI+0x30], RBX
```
