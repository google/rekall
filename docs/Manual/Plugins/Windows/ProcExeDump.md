---
abstract: Dump a process to an executable file sample
args: {dump_dir: 'Path suitable for dumping files. (type: String)

    ', eprocess: 'Kernel addresses of eprocess structs. (type: ArrayIntParser)



    * Default: ', method: "Method to list processes. (type: ChoiceArray)\n\n\n* Valid\
    \ Choices:\n    - PsActiveProcessHead\n    - CSRSS\n    - PspCidTable\n    - Sessions\n\
    \    - Handles\n\n\n* Default: PsActiveProcessHead, CSRSS, PspCidTable, Sessions,\
    \ Handles", out_fd: 'A file like object to write the output. (type: String)

    ', pids: 'One or more pids of processes to select. (type: ArrayIntParser)



    * Default: ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    '}
class_name: ProcExeDump
epydoc: rekall.plugins.windows.procdump.ProcExeDump-class.html
layout: plugin
module: rekall.plugins.windows.procdump
title: procdump
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