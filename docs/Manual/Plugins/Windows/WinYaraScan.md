---
abstract: Scan using yara signatures.
args: {binary_string: 'A binary string (encoded as hex) to search for. e.g. 000102[1-200]0506',
  context: 'Context to print after the hit. (type: IntParser)



    * Default: 64', eprocess: 'Kernel addresses of eprocess structs. (type: ArrayIntParser)

    ', hits: 'Quit after finding this many hits. (type: IntParser)



    * Default: 100000000.0', limit: 'The length of data to search.


    * Default: 18446744073709551616', method: "Method to list processes. (type: ChoiceArray)\n\
    \n\n* Valid Choices:\n    - PsActiveProcessHead\n    - CSRSS\n    - PspCidTable\n\
    \    - Sessions\n    - Handles\n\n\n* Default: PsActiveProcessHead, CSRSS, PspCidTable,\
    \ Sessions, Handles", phys_eprocess: 'Physical addresses of eprocess structs.
    (type: ArrayIntParser)

    ', pid: 'One or more pids of processes to select. (type: ArrayIntParser)

    ', pre_context: 'Context to print before the hit. (type: IntParser)



    * Default: 0', proc_regex: 'A regex to select a process by name. (type: RegEx)

    ', scan_physical: 'If specified we scan the physcial address space. Note that
    by default we scan the address space of the specified processes (or if no process
    selectors are specified, the default AS). (type: Boolean)



    * Default: False', start: 'Start searching from this offset. (type: IntParser)



    * Default: 0', string: A verbatim string to search for., yara_expression: If provided
    we scan for this yara expression., yara_file: The yara signature file to read.}
class_name: WinYaraScan
epydoc: rekall.plugins.windows.malware.yarascan.WinYaraScan-class.html
layout: plugin
module: rekall.plugins.windows.malware.yarascan
title: yarascan
---
