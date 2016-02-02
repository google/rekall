---
abstract: Detect unlinked DLLs
args: {eprocess: 'Kernel addresses of eprocess structs. (type: ArrayIntParser)

    ', method: "Method to list processes. (type: ChoiceArray)\n\n\n* Valid Choices:\n\
    \    - PsActiveProcessHead\n    - CSRSS\n    - PspCidTable\n    - Sessions\n \
    \   - Handles\n\n\n* Default: PsActiveProcessHead, CSRSS, PspCidTable, Sessions,\
    \ Handles", phys_eprocess: 'Physical addresses of eprocess structs. (type: ArrayIntParser)

    ', pid: 'One or more pids of processes to select. (type: ArrayIntParser)

    ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    ', verbosity: 'An integer reflecting the amount of desired output: 0 = quiet,
    10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: LdrModules
epydoc: rekall.plugins.windows.malware.malfind.LdrModules-class.html
layout: plugin
module: rekall.plugins.windows.malware.malfind
title: ldrmodules
---

There are many ways to hide a DLL. One of the ways involves unlinking the DLL
from one (or all) of the linked lists in the PEB. However, when this is done,
there is still information contained within the VAD (Virtual Address Descriptor)
which identifies the base address of the DLL and its full path on disk. To
cross-reference this information (known as memory mapped files) with the 3 PEB
lists, use the ldrmodules command.

For each memory mapped PE file, the ldrmodules command prints True or False if
the PE exists in the PEB lists.

```
win8.1.raw 22:17:36> ldrmodules proc_regex="winpmem"
-------------------> ldrmodules(proc_regex="winpmem")
Pid      Process                   Base      InLoad InInit InMem MappedPath
-------- -------------------- -------------- ------ ------ ----- ----------
2628     winpmem_1.5.2.       0x0000753b0000 False False False \Windows\SysWOW64\KernelBase.dll
2628     winpmem_1.5.2.       0x000000020000 True  False True  \temp\winpmem_1.5.2.exe
2628     winpmem_1.5.2.       0x000076c30000 False False False \Windows\SysWOW64\kernel32.dll
2628     winpmem_1.5.2.       0x000074a40000 False False False \Windows\SysWOW64\cryptbase.dll
2628     winpmem_1.5.2.       0x000074a50000 False False False \Windows\SysWOW64\sspicli.dll
2628     winpmem_1.5.2.       0x000077010000 True  True  True  \Windows\System32\wow64cpu.dll
2628     winpmem_1.5.2.       0x000076f50000 True  True  True  \Windows\System32\wow64.dll
2628     winpmem_1.5.2.       0x000076fa0000 True  True  True  \Windows\System32\wow64win.dll
2628     winpmem_1.5.2.       0x000075250000 False False False \Windows\SysWOW64\rpcrt4.dll
2628     winpmem_1.5.2.       0x7ff87f320000 True  True  True  \Windows\System32\ntdll.dll
2628     winpmem_1.5.2.       0x000077020000 False False False \Windows\SysWOW64\ntdll.dll
2628     winpmem_1.5.2.       0x0000749e0000 False False False \Windows\SysWOW64\bcryptprimitives.dll
2628     winpmem_1.5.2.       0x000074ff0000 False False False \Windows\SysWOW64\advapi32.dll
2628     winpmem_1.5.2.       0x000076f10000 False False False \Windows\SysWOW64\sechost.dll
2628     winpmem_1.5.2.       0x000074d80000 False False False \Windows\SysWOW64\msvcrt.dll
```

Since the PEB and the DLL lists that it contains all exist in user mode, its
also possible for malware to hide (or obscure) a DLL by simply overwriting the
path. Tools that only look for unlinked entries may miss the fact that malware
could overwrite *C:\bad.dll* to show *C:\windows\system32\kernel32.dll*. So you
can also pass the *verbosity=10* parameter to ldrmodules to see the full path of
all entries.

For concrete examples, see [ZeroAccess Misleads Memory-File
Link](http://blogs.mcafee.com/mcafee-labs/zeroaccess-misleads-memory-file-link)
and [QuickPost: Flame &
Volatility](http://mnin.blogspot.com/2012/06/quickpost-flame-volatility.html).

```
win8.1.raw 22:17:41> ldrmodules proc_regex="winpmem", verbosity=10
-------------------> ldrmodules(proc_regex="winpmem", verbosity=10)
Pid      Process                   Base      InLoad InInit InMem MappedPath
-------- -------------------- -------------- ------ ------ ----- ----------
2628     winpmem_1.5.2.       0x0000753b0000 False False False \Windows\SysWOW64\KernelBase.dll
2628     winpmem_1.5.2.       0x000000020000 True  False True  \temp\winpmem_1.5.2.exe
  Load Path: C:\temp\winpmem_1.5.2.exe : winpmem_1.5.2.exe
  Mem Path: C:\temp\winpmem_1.5.2.exe : winpmem_1.5.2.exe
2628     winpmem_1.5.2.       0x000076c30000 False False False \Windows\SysWOW64\kernel32.dll
2628     winpmem_1.5.2.       0x000074a40000 False False False \Windows\SysWOW64\cryptbase.dll
2628     winpmem_1.5.2.       0x000074a50000 False False False \Windows\SysWOW64\sspicli.dll
2628     winpmem_1.5.2.       0x000077010000 True  True  True  \Windows\System32\wow64cpu.dll
  Load Path: C:\Windows\system32\wow64cpu.dll : wow64cpu.dll
  Init Path: C:\Windows\system32\wow64cpu.dll : wow64cpu.dll
  Mem Path: C:\Windows\system32\wow64cpu.dll : wow64cpu.dll
2628     winpmem_1.5.2.       0x000076f50000 True  True  True  \Windows\System32\wow64.dll
  Load Path: C:\Windows\SYSTEM32\wow64.dll : wow64.dll
  Init Path: C:\Windows\SYSTEM32\wow64.dll : wow64.dll
  Mem Path: C:\Windows\SYSTEM32\wow64.dll : wow64.dll
2628     winpmem_1.5.2.       0x000076fa0000 True  True  True  \Windows\System32\wow64win.dll
  Load Path: C:\Windows\system32\wow64win.dll : wow64win.dll
  Init Path: C:\Windows\system32\wow64win.dll : wow64win.dll
  Mem Path: C:\Windows\system32\wow64win.dll : wow64win.dll
2628     winpmem_1.5.2.       0x000075250000 False False False \Windows\SysWOW64\rpcrt4.dll
2628     winpmem_1.5.2.       0x7ff87f320000 True  True  True  \Windows\System32\ntdll.dll
  Load Path: C:\Windows\SYSTEM32\ntdll.dll : ntdll.dll
  Init Path: C:\Windows\SYSTEM32\ntdll.dll : ntdll.dll
  Mem Path: C:\Windows\SYSTEM32\ntdll.dll : ntdll.dll
2628     winpmem_1.5.2.       0x000077020000 False False False \Windows\SysWOW64\ntdll.dll
2628     winpmem_1.5.2.       0x0000749e0000 False False False \Windows\SysWOW64\bcryptprimitives.dll
2628     winpmem_1.5.2.       0x000074ff0000 False False False \Windows\SysWOW64\advapi32.dll
2628     winpmem_1.5.2.       0x000076f10000 False False False \Windows\SysWOW64\sechost.dll
2628     winpmem_1.5.2.       0x000074d80000 False False False \Windows\SysWOW64\msvcrt.dll
```

### Notes

1. Wow64 processes (i.e. 32 bit processes on 64 bit windows) will not show any
   32 bit DLLs in any of the loader lists. This is normal (and you will see the
   Dlls loaded from the \Windows\Wow64 directory.
