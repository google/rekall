---
abstract: Scan using yara signatures.
args: {binary_string: 'A binary string (encoded as hex) to search for. e.g. 000102[1-200]0506',
  context: 'Context to print after the hit. (type: IntParser)



    * Default: 64', hits: 'Quit after finding this many hits. (type: IntParser)



    * Default: 100000000.0', limit: 'The length of data to search.


    * Default: 18446744073709551616', method: "Method to list processes (Default uses\
    \ all methods).\n\n* Valid Choices:\n    - allproc\n    - dead_procs\n    - tasks\n\
    \    - pidhash\n    - pgrphash\n", phys_proc: 'Physical addresses of proc structs.
    (type: ArrayIntParser)

    ', pid: 'One or more pids of processes to select. (type: ArrayIntParser)

    ', pre_context: 'Context to print before the hit. (type: IntParser)



    * Default: 0', proc: 'Kernel addresses of proc structs. (type: ArrayIntParser)

    ', proc_regex: A regex to select a process by name., scan_physical: 'If specified
    we scan the physcial address space. Note that by default we scan the address space
    of the specified processes (or if no process selectors are specified, the default
    AS). (type: Boolean)



    * Default: False', start: 'Start searching from this offset. (type: IntParser)



    * Default: 0', string: A verbatim string to search for., yara_expression: If provided
    we scan for this yara expression., yara_file: The yara signature file to read.}
class_name: DarwinYaraScan
epydoc: rekall.plugins.darwin.yarascan.DarwinYaraScan-class.html
layout: plugin
module: rekall.plugins.darwin.yarascan
title: yarascan
---
