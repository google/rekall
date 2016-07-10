---
abstract: Dump detailed information about a running process.
args: {eprocess: 'Kernel addresses of eprocess structs. (type: ArrayIntParser)



    * Default: ', method: "Method to list processes. (type: ChoiceArray)\n\n\n* Valid\
    \ Choices:\n    - PsActiveProcessHead\n    - CSRSS\n    - PspCidTable\n    - Sessions\n\
    \    - Handles\n\n\n* Default: PsActiveProcessHead, CSRSS, PspCidTable, Sessions,\
    \ Handles", pids: 'One or more pids of processes to select. (type: ArrayIntParser)



    * Default: ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    '}
class_name: ProcInfo
epydoc: rekall.plugins.windows.procinfo.ProcInfo-class.html
layout: plugin
module: rekall.plugins.windows.procinfo
title: procinfo
---

The **procinfo** plugin displays basic information about a process. It takes all
the usual process selectors (e.g. pid, name etc) and prints information about
the PE file (using **peinfo**) as well as the process environment strings.

### Sample output

```
win7.elf 14:43:15> procinfo proc_regex="csrss"
**************************************************
Pid: 348 csrss.exe

Process Environment
   ComSpec=C:\Windows\system32\cmd.exe
   FP_NO_HOST_CHECK=NO
   NUMBER_OF_PROCESSORS=1
   OS=Windows_NT
   Path=C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\
   PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
   PROCESSOR_ARCHITECTURE=AMD64
   PROCESSOR_IDENTIFIER=Intel64 Family 6 Model 37 Stepping 2, GenuineIntel
   PROCESSOR_LEVEL=6
   PROCESSOR_REVISION=2502
   PSModulePath=C:\Windows\system32\WindowsPowerShell\v1.0\Modules\
   SystemDrive=C:
   SystemRoot=C:\Windows
   TEMP=C:\Windows\TEMP
   TMP=C:\Windows\TEMP
   USERNAME=SYSTEM
   windir=C:\Windows

PE Infomation
Attribute            Value
-------------------- -----
Machine              IMAGE_FILE_MACHINE_AMD64
TimeDateStamp        2009-07-13 23:19:49+0000
Characteristics      IMAGE_FILE_EXECUTABLE_IMAGE, IMAGE_FILE_LARGE_ADDRESS_AWARE
GUID/Age             E8979C26A0EE47A69575E54FA6C7F6BE1
PDB                  csrss.pdb
MajorOperatingSystemVersion 6
MinorOperatingSystemVersion 1
MajorImageVersion    6
MinorImageVersion    1
MajorSubsystemVersion 6
MinorSubsystemVersion 1

Sections (Relative to 0x497B0000):
Perm Name          VMA            Size
---- -------- -------------- --------------
xr-  .text    0x000000001000 0x000000000c00
-rw  .data    0x000000002000 0x000000000200
-r-  .pdata   0x000000003000 0x000000000200
-r-  .rsrc    0x000000004000 0x000000000800
-r-  .reloc   0x000000005000 0x000000000200

Data Directories:
-                                             VMA            Size
---------------------------------------- -------------- --------------
IMAGE_DIRECTORY_ENTRY_EXPORT             0x000000000000 0x000000000000
IMAGE_DIRECTORY_ENTRY_IMPORT             0x0000497b17c4 0x00000000003c
IMAGE_DIRECTORY_ENTRY_RESOURCE           0x0000497b4000 0x0000000007f8
IMAGE_DIRECTORY_ENTRY_EXCEPTION          0x0000497b3000 0x00000000003c
IMAGE_DIRECTORY_ENTRY_SECURITY           0x000000000000 0x000000000000
IMAGE_DIRECTORY_ENTRY_BASERELOC          0x0000497b5000 0x00000000000c
IMAGE_DIRECTORY_ENTRY_DEBUG              0x0000497b10a0 0x00000000001c
IMAGE_DIRECTORY_ENTRY_COPYRIGHT          0x000000000000 0x000000000000
IMAGE_DIRECTORY_ENTRY_GLOBALPTR          0x000000000000 0x000000000000
IMAGE_DIRECTORY_ENTRY_TLS                0x000000000000 0x000000000000
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG        0x000000000000 0x000000000000
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT       0x0000497b02b0 0x000000000030
IMAGE_DIRECTORY_ENTRY_IAT                0x0000497b1000 0x000000000098
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT       0x000000000000 0x000000000000
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR     0x000000000000 0x000000000000
IMAGE_DIRECTORY_ENTRY_RESERVED           0x000000000000 0x000000000000

Import Directory (Original):
Name                                               Ord
-------------------------------------------------- -----
ntdll.dll!NtSetInformationProcess                  498
ntdll.dll!RtlSetHeapInformation                    1158
ntdll.dll!RtlSetUnhandledExceptionFilter           1179
ntdll.dll!NtTerminateProcess                       535
ntdll.dll!RtlVirtualUnwind                         1264
ntdll.dll!RtlLookupFunctionEntry                   1025
ntdll.dll!RtlCaptureContext                        635
ntdll.dll!NtTerminateThread                        536
ntdll.dll!RtlUnhandledExceptionFilter              1219
ntdll.dll!RtlSetProcessIsCritical                  1166
ntdll.dll!isspace                                  1900
ntdll.dll!RtlUnicodeStringToAnsiString             1222
ntdll.dll!RtlAllocateHeap                          613
ntdll.dll!RtlFreeAnsiString                        840
ntdll.dll!RtlNormalizeProcessParams                1041
CSRSRV.dll!CsrServerInitialization                 22
CSRSRV.dll!CsrUnhandledExceptionFilter             26

Export Directory:
    Entry      Stat Ord   Name
-------------- ---- ----- --------------------------------------------------
Version Information:
key                  value
-------------------- -----
CompanyName          Microsoft Corporation
FileDescription      Client Server Runtime Process
FileVersion          6.1.7600.16385 (win7_rtm.090713-1255)
InternalName         CSRSS.Exe
LegalCopyright       Microsoft Corporation. All rights reserved.
OriginalFilename     CSRSS.Exe
ProductName          Microsoft Windows Operating System
ProductVersion       6.1.7600.16385
```