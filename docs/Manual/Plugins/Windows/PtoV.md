---
abstract: Converts a physical address to a virtual address.
args: {eprocess: 'Kernel addresses of eprocess structs. (type: ArrayIntParser)



    * Default: ', method: "Method to list processes. (type: ChoiceArray)\n\n\n* Valid\
    \ Choices:\n    - PsActiveProcessHead\n    - CSRSS\n    - PspCidTable\n    - Sessions\n\
    \    - Handles\n\n\n* Default: PsActiveProcessHead, CSRSS, PspCidTable, Sessions,\
    \ Handles", physical_address: 'The Virtual Address to examine. (type: IntParser)

    ', pids: 'One or more pids of processes to select. (type: ArrayIntParser)



    * Default: ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    '}
class_name: PtoV
epydoc: rekall.plugins.windows.pfn.PtoV-class.html
layout: plugin
module: rekall.plugins.windows.pfn
title: ptov
---

This plugin uses the **PFN Database** to convert a physical page to its virtual
address. It is similar to the **pas2vas** plugin in this regard, but does not
need to enumerate all address spaces prior to running (so it is a bit faster).

### Notes

1. The plugin currently only works for kernel addresses and for 4k pages. So for
   example this will not work reliably for pool memory (since Pool is allocated
   in 2mb pages).

2. If this plugin does not work for a certain address, try to use the
   **pas2vas** plugin.


### Sample output

```
win7.elf 15:22:57> vtop 0xfa8002635810
-----------------> vtop(0xfa8002635810)
Virtual 0xfa8002635810 Page Directory 0x271ec000
pml4e@ 0x271ecfa8 = 0x4000863
pdpte@ 0x4000000 = 0x4001863
pde@ 0x4001098 = 0x2ac009e3
Large page mapped 0x2ae35810
Physical Address 0x2ac35810
win7.elf 15:23:05> ptov 0x2ac35810
-----------------> ptov(0x2ac35810)
Physical Address 0x2ac35810 => Virtual Address 0xf6fd40035810
DTB @ 0x187000
PML4E @ 0x187f68
PDPTE @ 0x187fa8
PDE @ 0x4000000
PTE @ 0x40011a8
```