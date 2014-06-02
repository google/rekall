---
layout: plugin
title: virt_map
abstract: |
  Prints the Windows Kernel Virtual Address Map.
  
  On 32 bit windows, the kernel virtual address space can be managed
  dynamically. This plugin shows each region and what it is used for.
  
  Note that on 64 bit windows the address space is large enough to not worry
  about it. In that case, the offsets and regions are hard coded.
  
  http://www.woodmann.com/forum/entry.php?219-Using-nt!_MiSystemVaType-to-navigate-dynamic-kernel-address-space-in-Windows7

epydoc: rekall.plugins.windows.misc.WinVirtualMap-class.html
args:

---

