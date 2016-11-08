---
abstract: Prints a list of dll modules mapped into each process.
args: {eprocess: 'Kernel addresses of eprocess structs. (type: ArrayIntParser)



    * Default: ', method: "Method to list processes. (type: ChoiceArray)\n\n\n* Valid\
    \ Choices:\n    - PsActiveProcessHead\n    - CSRSS\n    - PspCidTable\n    - Sessions\n\
    \    - Handles\n\n\n* Default: PsActiveProcessHead, CSRSS, PspCidTable, Sessions,\
    \ Handles", pids: 'One or more pids of processes to select. (type: ArrayIntParser)



    * Default: ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    ', verbosity: 'An integer reflecting the amount of desired output: 0 = quiet,
    10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: WinDllList
epydoc: rekall.plugins.windows.taskmods.WinDllList-class.html
layout: plugin
module: rekall.plugins.windows.taskmods
title: dlllist
---

Lists dll modules loaded into a process by following the doubly linked list of
**LDR_DATA_TABLE_ENTRY** stored in in
**_EPROCESS.Peb.Ldr.InLoadOrderModuleList**. DLLs are automatically added to
this list when a process calls *LoadLibrary* (or some derivative such as
*LdrLoadDll*) and they aren't removed until *FreeLibrary* is called and the
reference count reaches zero.

All the usual process selectors are supported.

### Note

1. Wow64 processes (i.e. 32 bit binaries running on 64 bit windows) load dlls
   through a different mechanism.

2. Since the **InLoadOrderModuleList** is maintained in the process address
   space, it is simple to manipulate from Ring 3 (without kernel access). This
   means that this plugin may not show all the linked in DLLs.

3. A better plugin to use is the [ldrmodules](LdrModules.html) plugin, which
   uses the VAD to enumerate dlls. The VAD is maintained in kernel memory and
   therefore can only be accessed through Ring 0 access.

### Sample output

Below we see winpmem used to acquire the image of this Windows 8.1 system. Since
winpmem is a 32 bit application, we see the wow64.dll dynamically loaded. Note
that in this case, the 32 bit dlls will not show in the
**InLoadOrderModuleList**. Using the [ldrmodules](LdrModules.html) plugin
reveals all the 32 bit dlls loaded.

```
win8.1.raw 15:35:10> dlllist proc_regex="winpmem"
-------------------> dlllist(proc_regex="winpmem")
winpmem_1.5.2. pid: 2628
Command line : winpmem_1.5.2.exe  -2 win8.1.raw
Note: use ldrmodules for listing DLLs in Wow64 processes


     Base           Size      Load Reason/Count              Path
-------------- -------------- ------------------------------ ----
0x000000020000        0x2d000 LoadReasonStaticDependency     C:\temp\winpmem_1.5.2.exe
0x7ff87f320000       0x1a9000 LoadReasonStaticDependency     C:\Windows\SYSTEM32\ntdll.dll
0x000076f50000        0x49000 LoadReasonDynamicLoad          C:\Windows\SYSTEM32\wow64.dll
0x000076fa0000        0x68000 LoadReasonStaticDependency     C:\Windows\system32\wow64win.dll
0x000077010000         0x9000 LoadReasonStaticDependency     C:\Windows\system32\wow64cpu.dll
win8.1.raw 15:35:51> ldrmodules proc_regex="winpmem"
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
2628     winpmem_1.5.2.       0x0ff87f320000 False False False \Windows\System32\ntdll.dll
2628     winpmem_1.5.2.       0x000077020000 False False False \Windows\SysWOW64\ntdll.dll
2628     winpmem_1.5.2.       0x0000749e0000 False False False \Windows\SysWOW64\bcryptprimitives.dll
2628     winpmem_1.5.2.       0x000074ff0000 False False False \Windows\SysWOW64\advapi32.dll
2628     winpmem_1.5.2.       0x000076f10000 False False False \Windows\SysWOW64\sechost.dll
2628     winpmem_1.5.2.       0x000074d80000 False False False \Windows\SysWOW64\msvcrt.dll
```