---
abstract: Dumps the memory map for linux tasks.
args: {all: 'Use the entire range of address space. (type: Boolean)



    * Default: False', coalesce: 'Merge contiguous pages into larger ranges. (type:
    Boolean)



    * Default: False', method: "Method to list processes (Default uses all methods).\
    \ (type: ChoiceArray)\n\n\n* Valid Choices:\n    - InitTask\n\n\n* Default: InitTask",
  pids: 'One or more pids of processes to select. (type: ArrayIntParser)

    ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    ', task: 'Kernel addresses of task structs. (type: ArrayIntParser)

    '}
class_name: LinMemMap
epydoc: rekall.plugins.linux.pslist.LinMemMap-class.html
layout: plugin
module: rekall.plugins.linux.pslist
title: memmap
---
