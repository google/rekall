---
abstract: Dump windows processes.
args: {all: 'Use the entire range of address space. (type: Boolean)



    * Default: False', coalesce: 'Merge contiguous pages into larger ranges. (type:
    Boolean)



    * Default: False', dump_dir: 'Path suitable for dumping files. (type: String)

    ', eprocess: 'Kernel addresses of eprocess structs. (type: ArrayIntParser)



    * Default: ', method: "Method to list processes. (type: ChoiceArray)\n\n\n* Valid\
    \ Choices:\n    - PsActiveProcessHead\n    - CSRSS\n    - PspCidTable\n    - Sessions\n\
    \    - Handles\n\n\n* Default: PsActiveProcessHead, CSRSS, PspCidTable, Sessions,\
    \ Handles", pids: 'One or more pids of processes to select. (type: ArrayIntParser)



    * Default: ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    '}
class_name: WinMemDump
epydoc: rekall.plugins.windows.taskmods.WinMemDump-class.html
layout: plugin
module: rekall.plugins.windows.taskmods
title: memdump
---

To dump all addressable memory in a process, use the memdump plugin. This plugin
enumerates the process page tables and writes them out into an external file. An
index file is also created which can be used to find the virtual address of each
byte in the output file.

You would typically use this output file in order to scan for e.g. virus
signatures or other patterns in tools which do not understand virtual memory
mappings.

The plugin accepts all the usual process filtering commands (e.g. by pid,
proc_regex etc). Additionally if no filtering command is specified the plugin
dumps the kernel's address space. (You can dump all processes by providing a
**proc_regex** of '.').

### Notes

1. This plugin is very similar to the vaddump plugin, except that it dumps the
   page table, and not only the VAD tree. This plugin actually contains all
   memory currently accessible to the process (despite any possible manipulation
   of the VAD tree).

2. The process's virtual address space is typically fragmented and had large,
   unmapped gaps in it. Therefore this plugin does not just zero fill these
   gaps, rather it writes all addressable memory directly to the output
   file. This means that contiguous memory in the output file is not necessarily
   contiguous in memory.

3. To find out where a particular byte in the output file maps in the process
   virtual memory, check the index file (Example below).

4. Note that processes typically alway map the kernel in the upper memory region
   (i.e. above the symbol `MmHighestUserAddress`. This plugin does not dump the
   kernel portion of the address space, unless the **--all** parameter is
   specified.


### Sample output

```
win7.elf 00:30:52> memdump pid=2912, dump_dir="/tmp/"
-----------------> memdump(pid=2912, dump_dir="/tmp/")
**************************************************
Writing vol.exe 0xfa8002193060 to vol.exe_2912.dmp
win7.elf 00:30:55> ls -l /tmp/vol.exe_2912.dmp -h
-rw-r----- 1 scudette staff 2.2M Jun 18 00:30 /tmp/vol.exe_2912.dmp
win7.elf 00:30:59> less /tmp/vol.exe_2912.dmp.idx
 File Address      Length      Virtual Addr
-------------- -------------- --------------
0x000000000000 0x000000001000 0x000000010000
0x000000001000 0x000000001000 0x000000020000
0x000000002000 0x000000001000 0x000000021000
0x000000003000 0x000000001000 0x00000002f000
0x000000004000 0x000000001000 0x000000040000
0x000000005000 0x000000001000 0x000000050000
0x000000006000 0x000000001000 0x000000051000
```