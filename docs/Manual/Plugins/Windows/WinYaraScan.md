---
abstract: Scan using yara signatures.
args: {binary_string: 'A binary string (encoded as hex) to search for. e.g. 000102[1-200]0506
    (type: String)

    ', context: 'Context to print after the hit. (type: IntParser)



    * Default: 64', eprocess: 'Kernel addresses of eprocess structs. (type: ArrayIntParser)



    * Default: ', hits: 'Quit after finding this many hits. (type: IntParser)



    * Default: 10', limit: 'The length of data to search in each selected region.
    (type: IntParser)



    * Default: 18446744073709551616', method: "Method to list processes. (type: ChoiceArray)\n\
    \n\n* Valid Choices:\n    - PsActiveProcessHead\n    - CSRSS\n    - PspCidTable\n\
    \    - Sessions\n    - Handles\n\n\n* Default: PsActiveProcessHead, CSRSS, PspCidTable,\
    \ Sessions, Handles", pids: 'One or more pids of processes to select. (type: ArrayIntParser)



    * Default: ', pre_context: 'Context to print before the hit. (type: IntParser)



    * Default: 0', proc_regex: 'A regex to select a process by name. (type: RegEx)

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



    * Default: False', string: 'A verbatim string to search for. (type: String)

    ', verbosity: 'An integer reflecting the amount of desired output: 0 = quiet,
    10 = noisy. (type: IntParser)



    * Default: 1', yara_expression: 'If provided we scan for this yara expression.
    (type: String)

    ', yara_file: 'The yara signature file to read. (type: String)

    '}
class_name: WinYaraScan
epydoc: rekall.plugins.windows.malware.yarascan.WinYaraScan-class.html
layout: plugin
module: rekall.plugins.windows.malware.yarascan
title: yarascan
---
