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

Pool scanning is a technique for discovering kernel data structures based on
signatures. It is essentially the memory forensic equivalent of carving. The
**psscan** plugin carves for **_EPROCESS** structures in memory.

By default the plugin scans in the physical address space. Any hits are resolved
into the virtual address space by following the lists. If **scan_in_kernel** is
specified, the scanning occurs in kernel space.

### Notes

1. Like other pool scanning plugins, this plugin may produce false positives
   since it essentially carves **_EPROCESS** structures out of memory. On the
   other hand, this plugin may reveal files which have been closed or freed.

2. The plugin displays the physical address of the **_EPROCESS** found. It
   may be possible to derive their virtual address using the [ptov](PtoV.html)
   plugin. Alternatively, specify the *scan_in_kernel* option, to ensure
   scanning occurs in the kernel address space.
