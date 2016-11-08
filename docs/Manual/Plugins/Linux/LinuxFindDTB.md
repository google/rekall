---
abstract: "A scanner for DTB values. Handles both 32 and 64 bits.\n\n    The plugin\
  \ also autodetects when the guest is running as a XEN\n    ParaVirtualized guest\
  \ and returns a compatible address space.\n    "
args: {verbosity: 'An integer reflecting the amount of desired output: 0 = quiet,
    10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: LinuxFindDTB
epydoc: rekall.plugins.linux.common.LinuxFindDTB-class.html
layout: plugin
module: rekall.plugins.linux.common
title: find_dtb
---
