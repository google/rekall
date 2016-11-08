---
abstract: "Scan Physical memory for _EPROCESS pool allocations.\n\n    Status flags:\n\
  \      E: A known _EPROCESS address from pslist.\n      P: A known pid from pslist.\n\
  \    "
args: {eprocess: 'Kernel addresses of eprocess structs. (type: ArrayIntParser)



    * Default: ', limit: 'The length of data to search in each selected region. (type:
    IntParser)



    * Default: 18446744073709551616', method: "Method to list processes. (type: ChoiceArray)\n\
    \n\n* Valid Choices:\n    - PsActiveProcessHead\n    - CSRSS\n    - PspCidTable\n\
    \    - Sessions\n    - Handles\n\n\n* Default: PsActiveProcessHead, CSRSS, PspCidTable,\
    \ Sessions, Handles", pids: 'One or more pids of processes to select. (type: ArrayIntParser)



    * Default: ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    ', scan_kernel: 'Scan the entire kernel address space. (type: Boolean)



    * Default: False', scan_kernel_code: 'Scan the kernel image and loaded drivers.
    (type: Boolean)



    * Default: False', scan_kernel_nonpaged_pool: 'Scan the kernel non-paged pool.
    (type: Boolean)



    * Default: False', scan_kernel_paged_pool: 'Scan the kernel paged pool. (type:
    Boolean)



    * Default: False', scan_kernel_session_pools: 'Scan session pools for all processes.
    (type: Boolean)



    * Default: False', scan_physical: 'Scan the physical address space only. (type:
    Boolean)



    * Default: False', scan_process_memory: 'Scan all of process memory. Uses process
    selectors to narrow down selections. (type: Boolean)



    * Default: False', verbosity: 'An integer reflecting the amount of desired output:
    0 = quiet, 10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: PSScan
epydoc: rekall.plugins.windows.filescan.PSScan-class.html
layout: plugin
module: rekall.plugins.windows.filescan
title: psscan
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
