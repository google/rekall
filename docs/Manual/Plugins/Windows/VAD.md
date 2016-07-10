---
abstract: "Concise dump of the VAD.\n\n    Similar to windbg's !vad.\n    "
args: {eprocess: 'Kernel addresses of eprocess structs. (type: ArrayIntParser)



    * Default: ', method: "Method to list processes. (type: ChoiceArray)\n\n\n* Valid\
    \ Choices:\n    - PsActiveProcessHead\n    - CSRSS\n    - PspCidTable\n    - Sessions\n\
    \    - Handles\n\n\n* Default: PsActiveProcessHead, CSRSS, PspCidTable, Sessions,\
    \ Handles", offset: 'Only print the vad corresponding to this offset. (type: IntParser)

    ', pids: 'One or more pids of processes to select. (type: ArrayIntParser)



    * Default: ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    ', regex: 'A regular expression to filter VAD filenames. (type: RegEx)

    '}
class_name: VAD
epydoc: rekall.plugins.windows.vadinfo.VAD-class.html
layout: plugin
module: rekall.plugins.windows.vadinfo
title: vad
---

The windows kernel manages process memory using the Virtual Address Descriptor
tree. The VAD is a tree of mapped memory regions into the process address
space. The VAD regions are used to manage the process address space (i.e. its
page tables).

The **vad** plugin displays all the vad regions in the process and their
properties.

### Notes

1. The `start` and `end` columns refer to the page number of the region. To
   convert from an address to page number simply multiply (or divide) by 0x1000.

2. If a memory region is mapped from a file (e.g. via the **mmap** call) the
   filename will be shown.

3. Most executables (e.g. dlls) are mapped with the EXECUTE_WRITECOPY
   permission. This is so that the executable pages are shared between all
   processes. As soon as a process attempts to write to that region the binary
   will be mapped EXECUTE_READWRITE.

4. When a dll is mapped into the vad, the PE header is placed at the vad's start
   address. This means that you can dump the dll by simply passing the vad's
   start address to [pedump](PEDump.html) as the image base.

### Sample output

```
win7_trial_64bit.dmp.E01 23:10:34> vad 1232
**************************************************
Pid: 1232 grrservice.exe
     VAD       lev     start           end        com -       -      Protect              Filename
-------------- --- -------------- -------------- ---- ------- ------ -------------------- --------
0xfa80020877a0 1         0x73660        0x736bb    6 Mapped  Exe    EXECUTE_WRITECOPY    \Windows\System32\wow64win.dll
0xfa8002083a50 2           0x400          0x427    8 Mapped  Exe    EXECUTE_WRITECOPY    \Python27\grrservice.exe
0xfa800207fd80 3           0x290          0x293    0 Mapped         READONLY             Pagefile-backed section
0xfa800205a6d0 4            0x50           0x8f    7 Private        READWRITE
0xfa80020848f0 5            0x40           0x40    0 Mapped  Exe    EXECUTE_WRITECOPY    \Windows\System32\apisetschema.dll
0xfa800208b590 6            0x10           0x1f    0 Mapped         READWRITE            Pagefile-backed section
0xfa8002066300 5            0x90          0x28f    3 Private        READWRITE
0xfa800208acd0 4           0x2b0          0x316    0 Mapped         READONLY             \Windows\System32\locale.nls
0xfa8002082470 5           0x2a0          0x2a0    1 Private        READWRITE
0xfa80020aaad0 5           0x360          0x39f    7 Private        READWRITE
0xfa80020a0170 6           0x3a0          0x3df    7 Private        READWRITE
0xfa800207e180 3           0x830          0x92f   28 Private        READWRITE
0xfa800208aa30 4           0x580          0x58f    3 Private        READWRITE
0xfa800209f6d0 5           0x430          0x4af    1 Private        READWRITE
0xfa80020590f0 5           0x5f0          0x66f    6 Private        READWRITE
0xfa8001fea860 4         0x735d0        0x7361a    4 Mapped  Exe    EXECUTE_WRITECOPY    \Windows\SysWOW64\apphelp.dll
0xfa80020a01c0 5           0xb30          0xd2f    3 Private        READWRITE
0xfa800209f680 6           0xd30          0xf2f    3 Private        READWRITE
0xfa8002087f00 5         0x73650        0x73657    2 Mapped  Exe    EXECUTE_WRITECOPY    \Windows\System32\wow64cpu.dll
0xfa80020838a0 2         0x7efb0        0x7efd2    0 Mapped         READONLY             Pagefile-backed section
0xfa8002087c00 3         0x760a0        0x7619f    3 Mapped  Exe    EXECUTE_WRITECOPY    \Windows\SysWOW64\kernel32.dll
0xfa800208af80 4         0x74b50        0x74b95    3 Mapped  Exe    EXECUTE_WRITECOPY    \Windows\SysWOW64\KernelBase.dll
0xfa8002087cb0 5         0x74a70        0x74a7b    2 Mapped  Exe    EXECUTE_WRITECOPY    \Windows\SysWOW64\cryptbase.dll
0xfa8002085e30 6         0x736c0        0x736fe    3 Mapped  Exe    EXECUTE_WRITECOPY    \Windows\System32\wow64.dll
0xfa800208a900 6         0x74a80        0x74adf    2 Mapped  Exe    EXECUTE_WRITECOPY    \Windows\SysWOW64\sspicli.dll
0xfa800208b900 5         0x76000        0x7609f    5 Mapped  Exe    EXECUTE_WRITECOPY    \Windows\SysWOW64\advapi32.dll
0xfa8002086430 4         0x76ce0        0x76dfe    0 Private Exe    EXECUTE_READWRITE
0xfa80020874f0 5         0x767b0        0x7685b    8 Mapped  Exe    EXECUTE_WRITECOPY    \Windows\SysWOW64\msvcrt.dll
0xfa800208aaf0 6         0x763b0        0x7649f    2 Mapped  Exe    EXECUTE_WRITECOPY    \Windows\SysWOW64\rpcrt4.dll
0xfa800208b1d0 6         0x76860        0x76878    4 Mapped  Exe    EXECUTE_WRITECOPY    \Windows\SysWOW64\sechost.dll
0xfa80020839c0 5         0x771b0        0x7735b   12 Mapped  Exe    EXECUTE_WRITECOPY    \Windows\System32\ntdll.dll
0xfa8001d47490 6         0x76f50        0x77049    0 Private Exe    EXECUTE_READWRITE
0xfa8002083930 6         0x77390        0x7750f    9 Mapped  Exe    EXECUTE_WRITECOPY    \Windows\SysWOW64\ntdll.dll
0xfa800209f5e0 7         0x7efad        0x7efaf    3 Private        READWRITE
0xfa800204f6b0 3         0x7f0e0        0x7ffdf    0 Private        READONLY
0xfa8002084980 4         0x7efde        0x7efde    1 Private        READWRITE
0xfa8002084350 5         0x7efdb        0x7efdd    3 Private        READWRITE
0xfa800209f9b0 6         0x7efd5        0x7efd7    3 Private        READWRITE
0xfa8002083800 5         0x7efdf        0x7efdf    1 Private        READWRITE
0xfa800208b260 6         0x7efe0        0x7f0df    0 Mapped         READONLY             Pagefile-backed section
0xfa800207c840 4         0x7ffe0        0x7ffef   -1 Private        READONLY
0xfa80020810b0 5         0x7fff0     0x7fffffef   -1 Private        READONLY
```