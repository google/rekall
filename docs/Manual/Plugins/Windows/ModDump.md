---
abstract: Dump kernel drivers from kernel space.
args: {dump_dir: 'Path suitable for dumping files. (type: String)

    ', eprocess: 'Kernel addresses of eprocess structs. (type: ArrayIntParser)



    * Default: ', method: "Method to list processes. (type: ChoiceArray)\n\n\n* Valid\
    \ Choices:\n    - PsActiveProcessHead\n    - CSRSS\n    - PspCidTable\n    - Sessions\n\
    \    - Handles\n\n\n* Default: PsActiveProcessHead, CSRSS, PspCidTable, Sessions,\
    \ Handles", out_fd: 'A file like object to write the output. (type: String)

    ', pids: 'One or more pids of processes to select. (type: ArrayIntParser)



    * Default: ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    ', regex: 'A Regular expression for selecting the dlls to dump. (type: RegEx)



    * Default: .', verbosity: 'An integer reflecting the amount of desired output:
    0 = quiet, 10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: ModDump
epydoc: rekall.plugins.windows.procdump.ModDump-class.html
layout: plugin
module: rekall.plugins.windows.procdump
title: moddump
---

To extract a kernel module from memory and dump it to disk for analysis, use the
moddump command. A regular expression can be specified for the module name to
dump.

### Note

1. In order to dump any PE file from memory we need the PE header to be memory
   resident. Often this is not the case, and the header is flushed out of
   virtual memory.

2. When dumping any binary from memory, it is not usually a perfect binary
   (i.e. you can not just run it). This is because the Import Address Table
   (IAT) reflects the patched version in memory and some pages may be
   missing. The resultant binary is probably only useful to analyses using a
   tool like IDA pro.


### Sample output

In this example we dump the winpmem driver to disk. The winpmem driver loads
from a temporary file name (You can see it using the [modules](Modules.html)
plugin.

```
win8.1.raw 23:27:12> moddump regex="tmp", dump_dir="/tmp"
-------------------> moddump(regex="tmp", dump_dir="/tmp")
Dumping pmeA86F.tmp, Base: f800025ca000 output: driver.f800025ca000.sys
```