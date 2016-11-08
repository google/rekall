---
abstract: Pool scanner for _RTL_ATOM_TABLE
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



    * Default: False', sort_by: "Sort by [offset | atom | refcount] (type: String)\n\
    \n\n* Valid Choices:\n    - atom\n    - refcount\n    - offset\n\n\n* Default:\
    \ offset", verbosity: 'An integer reflecting the amount of desired output: 0 =
    quiet, 10 = noisy. (type: IntParser)



    * Default: 1', win32k_profile: Force this profile to be used for Win32k.}
class_name: AtomScan
epydoc: rekall.plugins.windows.gui.atoms.AtomScan-class.html
layout: plugin
module: rekall.plugins.windows.gui.atoms
title: atomscan
---
