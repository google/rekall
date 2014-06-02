---
layout: plugin
title: dlldump
abstract: |
  Dump DLLs from a process address space

epydoc: rekall.plugins.windows.procdump.DLLDump-class.html
args:
  regex: 'A Regular expression for selecting the dlls to dump.'
  out_fd: 'A file like object to write the output.'
  dump_dir: 'Path suitable for dumping files. (Optional)'
  pid: 'One or more pids of processes to select.'
  eprocess: 'Kernel addresses of eprocess structs.'
  phys_eprocess: 'Physical addresses of eprocess structs.'
  proc_regex: 'A regex to select a process by name.'
  method: 'Method to list processes (Default uses all methods).'

---

To extract a DLL from a process's memory space and dump it to disk for analysis,
use the dlldump command. All the usual process selectors are
supported. Additionally a regular expression can be specified for the DLL name
to dump.

### Note

1. In order to dump any PE file from memory we need the PE header to be memory
   resident. Often this is not the case, and the header is flushed out of
   virtual memory. In this case it is still possible to dump parts of the PE
   image using the [vaddump](VADDump.html) plugin.

2. When dumping any binary from memory, it is not usually a perfect binary
   (i.e. you can not just run it). This is because the Import Address Table
   (IAT) reflects the patched version in memory and some pages may be
   missing. The resultant binary is probably only useful to analyses using a
   tool like IDA pro.


### Sample output

```
win8.1.raw 14:51:37> dlldump proc_regex="winpmem", dump_dir="/tmp/"
-------------------> dlldump(proc_regex="winpmem", dump_dir="/tmp/")
  _EPROCESS    Name                  Base      Module               Dump File
-------------- ---------------- -------------- -------------------- ---------
0xe0000204a900 winpmem_1.5.2.   0x000000020000 winpmem_1.5.2.exe    module.2628.3d04a900.20000.winpmem_1.5.2.exe
0xe0000204a900 winpmem_1.5.2.   0x7ff87f320000 ntdll.dll            module.2628.3d04a900.7ff87f320000.ntdll.dll
0xe0000204a900 winpmem_1.5.2.   0x000076f50000 wow64.dll            module.2628.3d04a900.76f50000.wow64.dll
0xe0000204a900 winpmem_1.5.2.   0x000076fa0000 wow64win.dll         module.2628.3d04a900.76fa0000.wow64win.dll
0xe0000204a900 winpmem_1.5.2.   0x000077010000 wow64cpu.dll         module.2628.3d04a900.77010000.wow64cpu.dll
```