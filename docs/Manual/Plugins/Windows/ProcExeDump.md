---
layout: plugin
title: procdump
abstract: |
  Dump a process to an executable file sample

epydoc: rekall.plugins.windows.procdump.ProcExeDump-class.html
args:
  out_fd: ''
  dump_dir: 'Path suitable for dumping files. (Optional)'
  pid: 'One or more pids of processes to select.'
  eprocess: 'Kernel addresses of eprocess structs.'
  phys_eprocess: 'Physical addresses of eprocess structs.'
  proc_regex: 'A regex to select a process by name.'
  method: 'Method to list processes (Default uses all methods).'

---

This plugin dumps the mapped PE files associated with a windows process. It is
equivalent to calling **pedump** with an image base corresponding to the VAD
section of the main process executable.

The **procdump** plugin is a thin wrapper around the **pedump** plugin.

### Sample output

```
win7.elf 14:42:55> procdump proc_regex="csrss", dump_dir="/tmp/"
**************************************************
Dumping csrss.exe, pid: 348    output: executable.csrss_exe_348.exe
**************************************************
Dumping csrss.exe, pid: 396    output: executable.csrss_exe_396.exe
```