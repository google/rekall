---
abstract: Runs a signature scans against physical, kernel or process memory.
args: {eprocess: 'Kernel addresses of eprocess structs. (type: ArrayIntParser)



    * Default: ', method: "Method to list processes. (type: ChoiceArray)\n\n\n* Valid\
    \ Choices:\n    - PsActiveProcessHead\n    - CSRSS\n    - PspCidTable\n    - Sessions\n\
    \    - Handles\n\n\n* Default: PsActiveProcessHead, CSRSS, PspCidTable, Sessions,\
    \ Handles", pids: 'One or more pids of processes to select. (type: ArrayIntParser)



    * Default: ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    ', scan_kernel: 'If specified we scan the kernel address space. (type: Boolean)



    * Default: False', scan_physical: 'If specified we scan the physcial address space.
    (type: Boolean)



    * Default: False', signature: The signature(s) to scan for. Format is 000102*0506*AAFF}
class_name: WinSigScan
epydoc: rekall.plugins.windows.malware.sigscan.WinSigScan-class.html
layout: plugin
module: rekall.plugins.windows.malware.sigscan
title: sigscan
---
