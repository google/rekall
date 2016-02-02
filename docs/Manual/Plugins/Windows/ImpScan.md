---
abstract: Scan for calls to imported functions.
args: {base: 'Base address in process memory if --pid is supplied, otherwise an address
    in kernel space (type: IntParser)

    ', eprocess: 'Kernel addresses of eprocess structs. (type: ArrayIntParser)

    ', kernel: 'Scan in kernel space. (type: Boolean)

    ', method: "Method to list processes. (type: ChoiceArray)\n\n\n* Valid Choices:\n\
    \    - PsActiveProcessHead\n    - CSRSS\n    - PspCidTable\n    - Sessions\n \
    \   - Handles\n\n\n* Default: PsActiveProcessHead, CSRSS, PspCidTable, Sessions,\
    \ Handles", phys_eprocess: 'Physical addresses of eprocess structs. (type: ArrayIntParser)

    ', pid: 'One or more pids of processes to select. (type: ArrayIntParser)

    ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    ', size: 'Size of memory to scan (type: IntParser)

    '}
class_name: ImpScan
epydoc: rekall.plugins.windows.malware.impscan.ImpScan-class.html
layout: plugin
module: rekall.plugins.windows.malware.impscan
title: impscan
---


### Sample output

```
win8.1.raw 18:30:34> impscan proc_regex="dwm.exe"
-------------------> impscan(proc_regex="dwm.exe")
**************************************************
Process dwm.exe PID 692
     IAT            Call      Module               Function
-------------- -------------- -------------------- --------
0x7ff7474f4000 0x7ff87f2c369c sechost.dll          ConvertStringSecurityDescriptorToSecurityDescriptorW
0x7ff7474f4030 0x7ff87b48beb0 uxtheme.dll          CloseThemeData
0x7ff7474f4038 0x7ff87b4bfc80 uxtheme.dll          OpenThemeData
0x7ff7474fa020 0x7ff87e4b5d34 msvcrt.dll           382
0x7ff7474fa030 0x7ff87e4b5f18 msvcrt.dll           410
0x7ff7474fa050 0x7ff87e4b9948 msvcrt.dll           144
0x7ff7474fa058 0x7ff87e4babc0 msvcrt.dll           129
0x7ff7474fa0e0 0x7ff87e4b468c msvcrt.dll           35
0x7ff7474fa0e8 0x7ff87e4b1cd4 msvcrt.dll           36
0x7ff7474fa120 0x7ff87f38f85c ntdll.dll            1252
0x7ff7474fa128 0x7ff87f36e384 ntdll.dll            1229
0x7ff7474fa130 0x7ff87c9a3dec KERNELBASE.dll       170
0x7ff7474fa138 0x7ff87f33c31c ntdll.dll            815
0x7ff7474fa148 0x7ff87f383270 ntdll.dll            RtlInitializeCriticalSection
0x7ff7474fa158 0x7ff87f36d100 ntdll.dll            RtlAcquireSRWLockShared
0x7ff7474fa168 0x7ff87f36b810 ntdll.dll            RtlLeaveCriticalSection
0x7ff7474fa170 0x7ff87c9a24f4 KERNELBASE.dll       157
0x7ff7474fa180 0x7ff87f36e50c ntdll.dll            1228
0x7ff7474fa188 0x7ff87f35db60 ntdll.dll            RtlAcquireSRWLockExclusive
0x7ff7474fa190 0x7ff87f36b550 ntdll.dll            867
0x7ff7474fa1a0 0x7ff87c9a14a0 KERNELBASE.dll       635
0x7ff7474fa1c8 0x7ff87c9a1440 KERNELBASE.dll       481
0x7ff7474fa1e8 0x7ff87f37c7c0 ntdll.dll            RtlSetLastWin32Error
0x7ff7474fa1f8 0x7ff87f366b90 ntdll.dll            928
0x7ff7474fa200 0x7ff87f3620d0 ntdll.dll            RtlAllocateHeap
0x7ff7474fa208 0x7ff87c9ac960 KERNELBASE.dll       684
0x7ff7474fa218 0x7ff87c9a14e0 KERNELBASE.dll       554
0x7ff7474fa230 0x7ff87edd3184 KERNEL32.DLL         GetStartupInfoW
0x7ff7474fa238 0x7ff87edd3074 KERNEL32.DLL         SetPriorityClass
```