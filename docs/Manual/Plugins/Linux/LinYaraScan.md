---
abstract: Scan using yara signatures.
args: {binary_string: 'A binary string (encoded as hex) to search for. e.g. 000102[1-200]0506',
  context: 'Context to print after the hit. (type: IntParser)



    * Default: 64', hits: 'Quit after finding this many hits. (type: IntParser)



    * Default: 100000000.0', limit: 'The length of data to search.


    * Default: 18446744073709551616', method: "Method to list processes (Default uses\
    \ all methods). (type: ChoiceArray)\n\n\n* Valid Choices:\n    - InitTask\n\n\n\
    * Default: InitTask", phys_task: 'Physical addresses of task structs. (type: ArrayIntParser)

    ', pid: 'One or more pids of processes to select. (type: ArrayIntParser)

    ', pre_context: 'Context to print before the hit. (type: IntParser)



    * Default: 0', proc_regex: A regex to select a process by name., scan_physical: 'If
    specified we scan the physcial address space. Note that by default we scan the
    address space of the specified processes (or if no process selectors are specified,
    the default AS). (type: Boolean)



    * Default: False', start: 'Start searching from this offset. (type: IntParser)



    * Default: 0', string: A verbatim string to search for., task: 'Kernel addresses
    of task structs. (type: ArrayIntParser)

    ', task_head: 'Use this as the first task to follow the list. (type: IntParser)

    ', yara_expression: If provided we scan for this yara expression., yara_file: The
    yara signature file to read.}
class_name: LinYaraScan
epydoc: rekall.plugins.linux.yarascan.LinYaraScan-class.html
layout: plugin
module: rekall.plugins.linux.yarascan
title: yarascan
---
