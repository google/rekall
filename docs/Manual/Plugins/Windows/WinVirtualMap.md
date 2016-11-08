---
abstract: "Prints the Windows Kernel Virtual Address Map.\n\n    On 32 bit windows,\
  \ the kernel virtual address space can be managed\n    dynamically. This plugin\
  \ shows each region and what it is used for.\n\n    Note that on 64 bit windows\
  \ the address space is large enough to not worry\n    about it. In that case, the\
  \ offsets and regions are hard coded.\n\n    http://www.woodmann.com/forum/entry.php?219-Using-nt!_MiSystemVaType-to-navigate-dynamic-kernel-address-space-in-Windows7\n\
  \    "
args: {verbosity: 'An integer reflecting the amount of desired output: 0 = quiet,
    10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: WinVirtualMap
epydoc: rekall.plugins.windows.misc.WinVirtualMap-class.html
layout: plugin
module: rekall.plugins.windows.misc
title: virt_map
---

