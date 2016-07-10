---
abstract: Find hidden and injected code
args: {dump_dir: 'Path suitable for dumping files. (type: String)

    ', eprocess: 'Kernel addresses of eprocess structs. (type: ArrayIntParser)



    * Default: ', method: "Method to list processes. (type: ChoiceArray)\n\n\n* Valid\
    \ Choices:\n    - PsActiveProcessHead\n    - CSRSS\n    - PspCidTable\n    - Sessions\n\
    \    - Handles\n\n\n* Default: PsActiveProcessHead, CSRSS, PspCidTable, Sessions,\
    \ Handles", pids: 'One or more pids of processes to select. (type: ArrayIntParser)



    * Default: ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    '}
class_name: Malfind
epydoc: rekall.plugins.windows.malware.malfind.Malfind-class.html
layout: plugin
module: rekall.plugins.windows.malware.malfind
title: malfind
---

The malfind command helps find hidden or injected code/DLLs in user mode memory,
based on characteristics such as VAD tag and page permissions.

Note: malfind does not detect DLLs injected into a process using
**CreateRemoteThread->LoadLibrary**. DLLs injected with this technique are not
hidden and thus you can view them with dlllist. The purpose of malfind is to
locate DLLs that standard methods/tools do not see.

Here is an example of using it to detect the presence of Zeus. The first memory
segment (starting at 0x2aa0000) was detected because it is executable, marked as
private (not shared between processes) and has a VadS tag... which means there
is no memory mapped file already occupying the space. Based on a disassembly of
the data found at this address, it seems to contain some API hook trampoline
stubs.

The second memory segment (starting at 0x3080000) was detected because it contained an executable that isn't listed in the PEB's module lists.

If you want to save extracted copies of the memory segments identified by
malfind, just supply an output directory with the *dump_dir* parameter. In this
case, an unpacked copy of the Zeus binary that was injected into explorer.exe
would be written to disk.

```
zeus2x4.vmem 22:53:43> malfind proc_regex="explorer"
---------------------> malfind(proc_regex="explorer")
**************************************************f pid 1752
Process: explorer.exe Pid: 1752 Address: 0x2aa0000
Vad Tag: VadS Protection: EXECUTE_READWRITE
Flags: CommitCharge: 1, MemCommit: 1, PrivateMemory: 1, Protection: 6

 0x2aa0000 b8 35 00 00 00 e9 a9 d1 e6 79 68 6c 02 00 00 e9  .5.......yhl....
 0x2aa0010 b4 63 e7 79 8b ff 55 8b ec e9 7c 11 d7 79 8b ff  .c.y..U...|..y..
 0x2aa0020 55 8b ec e9 01 32 77 74 8b ff 55 8b ec e9 7c 60  U....2wt..U...|`
 0x2aa0030 72 74 8b ff 55 8b ec e9 ca e9 72 74 8b ff 55 8b  rt..U.....rt..U.

0x02aa0000      b835000000           MOV EAX, 0x35
0x02aa0005      e9a9d1e679           JMP 0x7c90d1b3
0x02aa000a      686c020000           PUSH DWORD 0x26c
0x02aa000f      e9b463e779           JMP 0x7c9163c8
0x02aa0014      8bff                 MOV EDI, EDI
0x02aa0016      55                   PUSH EBP
0x02aa0017      8bec                 MOV EBP, ESP
0x02aa0019      e97c11d779           JMP 0x7c81119a
0x02aa001e      8bff                 MOV EDI, EDI
0x02aa0020      55                   PUSH EBP
0x02aa0021      8bec                 MOV EBP, ESP
0x02aa0023      e901327774           JMP 0x77213229
0x02aa0028      8bff                 MOV EDI, EDI
0x02aa002a      55                   PUSH EBP
0x02aa002b      8bec                 MOV EBP, ESP
0x02aa002d      e97c607274           JMP 0x771c60ae
0x02aa0032      8bff                 MOV EDI, EDI
0x02aa0034      55                   PUSH EBP
0x02aa0035      8bec                 MOV EBP, ESP
0x02aa0037      e9cae97274           JMP 0x771cea06
0x02aa003c      8bff                 MOV EDI, EDI
0x02aa003e      55                   PUSH EBP
0x02aa003f      8bec                 MOV EBP, ESP
0x02aa0041      e9e8327774           JMP 0x7721332e
0x02aa0046      8bff                 MOV EDI, EDI
0x02aa0048      55                   PUSH EBP
0x02aa0049      8bec                 MOV EBP, ESP
0x02aa004b      e9494d7274           JMP 0x771c4d99
0x02aa0050      8bff                 MOV EDI, EDI
0x02aa0052      55                   PUSH EBP
0x02aa0053      8bec                 MOV EBP, ESP
0x02aa0055      e99d827274           JMP 0x771c82f7
0x02aa005a      8bff                 MOV EDI, EDI
0x02aa005c      55                   PUSH EBP
0x02aa005d      8bec                 MOV EBP, ESP
0x02aa005f      e9ef927574           JMP 0x771f9353
0x02aa0064      8bff                 MOV EDI, EDI
0x02aa0066      55                   PUSH EBP
0x02aa0067      8bec                 MOV EBP, ESP
0x02aa0069      e9fe897374           JMP 0x771d8a6c
0x02aa006e      6a2c                 PUSH 0x2c
0x02aa0070      68187b1c77           PUSH DWORD 0x771c7b18
0x02aa0075      e957797274           JMP 0x771c79d1
0x02aa007a      8bff                 MOV EDI, EDI
0x02aa007c      55                   PUSH EBP
0x02aa007d      8bec                 MOV EBP, ESP
0x02aa007f      e9ac3d016f           JMP 0x71ab3e30
0x02aa0084      8bff                 MOV EDI, EDI
0x02aa0086      55                   PUSH EBP
0x02aa0087      8bec                 MOV EBP, ESP
0x02aa0089      e99e4b016f           JMP 0x71ab4c2c
0x02aa008e      8bff                 MOV EDI, EDI
0x02aa0090      55                   PUSH EBP
0x02aa0091      8bec                 MOV EBP, ESP
0x02aa0093      e96768016f           JMP 0x71ab68ff
0x02aa0098      8bff                 MOV EDI, EDI
0x02aa009a      55                   PUSH EBP
0x02aa009b      8bec                 MOV EBP, ESP
0x02aa009d      e9598b977b           JMP 0x7e418bfb
0x02aa00a2      8bff                 MOV EDI, EDI
0x02aa00a4      55                   PUSH EBP
0x02aa00a5      8bec                 MOV EBP, ESP
0x02aa00a7      e9130d997b           JMP 0x7e430dbf
0x02aa00ac      8bff                 MOV EDI, EDI
0x02aa00ae      55                   PUSH EBP
**************************************************
Process: explorer.exe Pid: 1752 Address: 0x3080000
Vad Tag: VadS Protection: EXECUTE_READWRITE
Flags: CommitCharge: 52, MemCommit: 1, PrivateMemory: 1, Protection: 6

 0x3080000 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00  MZ..............
 0x3080010 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00  ........@.......
 0x3080020 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
 0x3080030 00 00 00 00 00 00 00 00 00 00 00 00 c0 00 00 00  ................

0x03080000      4d                   DEC EBP
0x03080001      5a                   POP EDX
0x03080002      90                   NOP
0x03080003      0003                 ADD [EBX], AL
0x03080005      0000                 ADD [EAX], AL
0x03080007      000400               ADD [EAX+EAX], AL
0x0308000a      0000                 ADD [EAX], AL
0x0308000c      ff                   DB 0xff
0x0308000d      ff00                 INC DWORD [EAX]
0x0308000f      00b800000000         ADD [EAX+0x0], BH
0x03080015      0000                 ADD [EAX], AL
0x03080017      004000               ADD [EAX+0x0], AL
0x0308001a      0000                 ADD [EAX], AL
0x0308001c      0000                 ADD [EAX], AL
0x0308001e      0000                 ADD [EAX], AL
```