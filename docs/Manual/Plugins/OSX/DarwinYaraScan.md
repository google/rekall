---
abstract: Scan using yara signatures.
args: {binary_string: 'A binary string (encoded as hex) to search for. e.g. 000102[1-200]0506
    (type: String)

    ', context: 'Context to print after the hit. (type: IntParser)



    * Default: 64', hits: 'Quit after finding this many hits. (type: IntParser)



    * Default: 10', pids: 'One or more pids of processes to select. (type: ArrayIntParser)

    ', pre_context: 'Context to print before the hit. (type: IntParser)



    * Default: 0', proc: 'Kernel addresses of proc structs. (type: ArrayIntParser)

    ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    ', scan_kernel: 'Scan the entire kernel address space. (type: Boolean)



    * Default: False', scan_physical: 'Scan the physical address space only. (type:
    Boolean)



    * Default: False', scan_process_memory: 'Scan all of process memory. Uses process
    selectors to narrow down selections. (type: Boolean)



    * Default: False', string: 'A verbatim string to search for. (type: String)

    ', yara_expression: 'If provided we scan for this yara expression. (type: String)

    ', yara_file: 'The yara signature file to read. (type: String)

    '}
class_name: DarwinYaraScan
epydoc: rekall.plugins.darwin.yarascan.DarwinYaraScan-class.html
layout: plugin
module: rekall.plugins.darwin.yarascan
title: yarascan
---
