---
layout: plugin
title: psscan
abstract: |
  Scan Physical memory for _EPROCESS pool allocations.
  
  Status flags:
    E: A known _EPROCESS address from pslist.
    P: A known pid from pslist.

epydoc: rekall.plugins.windows.filescan.PSScan-class.html
args:
  address_space: ''
  scan_in_kernel: 'Scan in the kernel address space'

---

