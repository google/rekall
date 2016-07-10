---
abstract: Dumps out the vad sections to a file
args: {dump_dir: 'Path suitable for dumping files. (type: String)

    ', eprocess: 'Kernel addresses of eprocess structs. (type: ArrayIntParser)



    * Default: ', max_size: 'Maximum file size to dump. (type: IntParser)



    * Default: 104857600', method: "Method to list processes. (type: ChoiceArray)\n\
    \n\n* Valid Choices:\n    - PsActiveProcessHead\n    - CSRSS\n    - PspCidTable\n\
    \    - Sessions\n    - Handles\n\n\n* Default: PsActiveProcessHead, CSRSS, PspCidTable,\
    \ Sessions, Handles", offset: 'Only print the vad corresponding to this offset.
    (type: IntParser)

    ', pids: 'One or more pids of processes to select. (type: ArrayIntParser)



    * Default: ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    ', regex: 'A regular expression to filter VAD filenames. (type: RegEx)

    '}
class_name: VADDump
epydoc: rekall.plugins.windows.vadinfo.VADDump-class.html
layout: plugin
module: rekall.plugins.windows.vadinfo
title: vaddump
---

Although you can dump a process executable using the [procdump](ProcDump.html)
plugin, this only dumps the main executable. For further analysis of a process
it is useful to dump its entire address space. Since the address space is
discontiguous it is best to dump it out one vad segment at a time.

### Sample output

```
win7_trial_64bit.dmp.E01 23:45:01> vaddump pid=1232, dump_dir="/tmp"
************* grrservice.exe (1232) *************
    Start           End           Length     Filename                                                     Comment
-------------- -------------- -------------- ------------------------------------------------------------ -------
0x000073660000 0x0000736bbfff        0x5bfff grrservice.exe.2f684a70.73660000-736bbfff.dmp                \Windows\System32\wow64win.dll
0x000000400000 0x000000427fff        0x27fff grrservice.exe.2f684a70.00400000-00427fff.dmp                \Python27\grrservice.exe
0x000000290000 0x000000293fff         0x3fff grrservice.exe.2f684a70.00290000-00293fff.dmp                Pagefile-backed section
0x000000050000 0x00000008ffff        0x3ffff grrservice.exe.2f684a70.00050000-0008ffff.dmp
0x000000040000 0x000000040fff          0xfff grrservice.exe.2f684a70.00040000-00040fff.dmp                \Windows\System32\apisetschema.dll
0x000000010000 0x00000001ffff         0xffff grrservice.exe.2f684a70.00010000-0001ffff.dmp                Pagefile-backed section
0x000000090000 0x00000028ffff       0x1fffff grrservice.exe.2f684a70.00090000-0028ffff.dmp
0x0000002b0000 0x000000316fff        0x66fff grrservice.exe.2f684a70.002b0000-00316fff.dmp                \Windows\System32\locale.nls
0x0000002a0000 0x0000002a0fff          0xfff grrservice.exe.2f684a70.002a0000-002a0fff.dmp
0x000000360000 0x00000039ffff        0x3ffff grrservice.exe.2f684a70.00360000-0039ffff.dmp
0x0000003a0000 0x0000003dffff        0x3ffff grrservice.exe.2f684a70.003a0000-003dffff.dmp
0x000000830000 0x00000092ffff        0xfffff grrservice.exe.2f684a70.00830000-0092ffff.dmp
0x000000580000 0x00000058ffff         0xffff grrservice.exe.2f684a70.00580000-0058ffff.dmp
0x000000430000 0x0000004affff        0x7ffff grrservice.exe.2f684a70.00430000-004affff.dmp
0x0000005f0000 0x00000066ffff        0x7ffff grrservice.exe.2f684a70.005f0000-0066ffff.dmp
0x0000735d0000 0x00007361afff        0x4afff grrservice.exe.2f684a70.735d0000-7361afff.dmp                \Windows\SysWOW64\apphelp.dll
0x000000b30000 0x000000d2ffff       0x1fffff grrservice.exe.2f684a70.00b30000-00d2ffff.dmp
0x000000d30000 0x000000f2ffff       0x1fffff grrservice.exe.2f684a70.00d30000-00f2ffff.dmp
0x000073650000 0x000073657fff         0x7fff grrservice.exe.2f684a70.73650000-73657fff.dmp                \Windows\System32\wow64cpu.dll
0x00007efb0000 0x00007efd2fff        0x22fff grrservice.exe.2f684a70.7efb0000-7efd2fff.dmp                Pagefile-backed section
0x0000760a0000 0x00007619ffff        0xfffff grrservice.exe.2f684a70.760a0000-7619ffff.dmp                \Windows\SysWOW64\kernel32.dll
0x000074b50000 0x000074b95fff        0x45fff grrservice.exe.2f684a70.74b50000-74b95fff.dmp                \Windows\SysWOW64\KernelBase.dll
0x000074a70000 0x000074a7bfff         0xbfff grrservice.exe.2f684a70.74a70000-74a7bfff.dmp                \Windows\SysWOW64\cryptbase.dll
0x0000736c0000 0x0000736fefff        0x3efff grrservice.exe.2f684a70.736c0000-736fefff.dmp                \Windows\System32\wow64.dll
0x000074a80000 0x000074adffff        0x5ffff grrservice.exe.2f684a70.74a80000-74adffff.dmp                \Windows\SysWOW64\sspicli.dll
0x000076000000 0x00007609ffff        0x9ffff grrservice.exe.2f684a70.76000000-7609ffff.dmp                \Windows\SysWOW64\advapi32.dll
0x000076ce0000 0x000076dfefff       0x11efff grrservice.exe.2f684a70.76ce0000-76dfefff.dmp
0x0000767b0000 0x00007685bfff        0xabfff grrservice.exe.2f684a70.767b0000-7685bfff.dmp                \Windows\SysWOW64\msvcrt.dll
0x0000763b0000 0x00007649ffff        0xeffff grrservice.exe.2f684a70.763b0000-7649ffff.dmp                \Windows\SysWOW64\rpcrt4.dll
0x000076860000 0x000076878fff        0x18fff grrservice.exe.2f684a70.76860000-76878fff.dmp                \Windows\SysWOW64\sechost.dll
0x0000771b0000 0x00007735bfff       0x1abfff grrservice.exe.2f684a70.771b0000-7735bfff.dmp                \Windows\System32\ntdll.dll
0x000076f50000 0x000077049fff        0xf9fff grrservice.exe.2f684a70.76f50000-77049fff.dmp
0x000077390000 0x00007750ffff       0x17ffff grrservice.exe.2f684a70.77390000-7750ffff.dmp                \Windows\SysWOW64\ntdll.dll
0x00007efad000 0x00007efaffff         0x2fff grrservice.exe.2f684a70.7efad000-7efaffff.dmp
0x00007f0e0000 0x00007ffdffff       0xefffff grrservice.exe.2f684a70.7f0e0000-7ffdffff.dmp
0x00007efde000 0x00007efdefff          0xfff grrservice.exe.2f684a70.7efde000-7efdefff.dmp
0x00007efdb000 0x00007efddfff         0x2fff grrservice.exe.2f684a70.7efdb000-7efddfff.dmp
0x00007efd5000 0x00007efd7fff         0x2fff grrservice.exe.2f684a70.7efd5000-7efd7fff.dmp
0x00007efdf000 0x00007efdffff          0xfff grrservice.exe.2f684a70.7efdf000-7efdffff.dmp
0x00007efe0000 0x00007f0dffff        0xfffff grrservice.exe.2f684a70.7efe0000-7f0dffff.dmp                Pagefile-backed section
0x00007ffe0000 0x00007ffeffff         0xffff grrservice.exe.2f684a70.7ffe0000-7ffeffff.dmp
0x00007fff0000 0x07fffffeffff  0x7ff7fffffff grrservice.exe.2f684a70.7fff0000-7fffffeffff.dmp
...
win7_trial_64bit.dmp.E01 23:45:13> peinfo executable="/tmp/grrservice.exe.2f684a70.760a0000-7619ffff.dmp"
Attribute            Value
-------------------- -----
Machine              IMAGE_FILE_MACHINE_I386
TimeDateStamp        2011-07-16 04:33:08+0000
Characteristics      IMAGE_FILE_32BIT_MACHINE, IMAGE_FILE_DLL,
                     IMAGE_FILE_EXECUTABLE_IMAGE
GUID/Age             0EB73428EC4E430FB8EDD94C5946855B2
PDB                  wkernel32.pdb
MajorOperatingSystemVersion 6
MinorOperatingSystemVersion 1
MajorImageVersion    6
MinorImageVersion    1
MajorSubsystemVersion 6
MinorSubsystemVersion 1

Sections (Relative to 0x760A0000):
Perm Name          VMA            Size
---- -------- -------------- --------------
xr-  .text    0x000000010000 0x0000000c0000
-rw  .data    0x0000000d0000 0x000000010000
-r-  .rsrc    0x0000000e0000 0x000000010000
-r-  .reloc   0x0000000f0000 0x000000010000

Data Directories:
-                                             VMA            Size
---------------------------------------- -------------- --------------
IMAGE_DIRECTORY_ENTRY_EXPORT             0x00007615f728 0x00000000aa1a
IMAGE_DIRECTORY_ENTRY_IMPORT             0x00007616a144 0x0000000001f4
IMAGE_DIRECTORY_ENTRY_RESOURCE           0x000076180000 0x000000000520
IMAGE_DIRECTORY_ENTRY_EXCEPTION          0x000000000000 0x000000000000
IMAGE_DIRECTORY_ENTRY_SECURITY           0x000000000000 0x000000000000
IMAGE_DIRECTORY_ENTRY_BASERELOC          0x000076190000 0x00000000ad3c
IMAGE_DIRECTORY_ENTRY_DEBUG              0x00007616feb8 0x000000000038
IMAGE_DIRECTORY_ENTRY_COPYRIGHT          0x000000000000 0x000000000000
IMAGE_DIRECTORY_ENTRY_GLOBALPTR          0x000000000000 0x000000000000
IMAGE_DIRECTORY_ENTRY_TLS                0x000000000000 0x000000000000
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG        0x000076123330 0x000000000040
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT       0x000000000000 0x000000000000
IMAGE_DIRECTORY_ENTRY_IAT                0x0000760b0000 0x000000000ddc
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT       0x000000000000 0x000000000000
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR     0x000000000000 0x000000000000
IMAGE_DIRECTORY_ENTRY_RESERVED           0x000000000000 0x000000000000

Import Directory (Original):
Name                                               Ord
-------------------------------------------------- -----
API-MS-Win-Core-RtlSupport-L1-1-0.dll!RtlUnwind    3
API-MS-Win-Core-RtlSupport-L1-1-0.dll!RtlCaptureContext 0
API-MS-Win-Core-RtlSupport-L1-1-0.dll!RtlCaptureStackBackTrace 1
ntdll.dll!NtCreateEvent                            227
ntdll.dll!NtDuplicateObject                        275
ntdll.dll!RtlConvertSidToUnicodeString             686
ntdll.dll!NtNotifyChangeKey                        337
ntdll.dll!RtlRunOnceInitialize                     1151
```