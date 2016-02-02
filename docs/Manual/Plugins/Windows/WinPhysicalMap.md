---
abstract: Prints the boot physical memory map.
args: {}
class_name: WinPhysicalMap
epydoc: rekall.plugins.windows.misc.WinPhysicalMap-class.html
layout: plugin
module: rekall.plugins.windows.misc
title: phys_map
---

This plugin will simply print the kernels idea of the physical memory layout on
a machine. Typically the physical address space is not contiguous (i.e. does not
have RAM chip mapping all address ranges between 0 and the maximum number). This
is because the BIOS needs to leave gaps for DMA devices to be mapped.

The BIOS sets up an initial mapping and communicates the mapping to the kernel
through a BIOS service call (Or EFI call) which can be done while the kernel
still boots (In real mode). The kernel then keeps this information and returns
it through the **MmGetPhysicalMemoryRanges()** function.

### Notes

1. It is rather easy to manupulate this information to subvert acquisition. Most
   acquisition tools use this information to determine where it is safe to read
   and to avoid reading from DMA mapped memory.

### Sample output

```
win8.1.raw 15:19:26> phys_map
-------------------> phys_map()
  Phys Start      Phys End    Number of Pages
-------------- -------------- ---------------
0x000000001000 0x00000009f000 158
0x000000100000 0x000000102000 2
0x000000103000 0x00003fff0000 261869
```
