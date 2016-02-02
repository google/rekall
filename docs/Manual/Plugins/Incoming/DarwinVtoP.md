---
abstract: Describe virtual to physical translation on darwin platforms.
args: {method: "Method to list processes (Default uses all methods).\n\n* Valid Choices:\n\
    \    - allproc\n    - dead_procs\n    - tasks\n    - pidhash\n    - pgrphash\n",
  phys_proc: 'Physical addresses of proc structs. (type: ArrayIntParser)

    ', pid: 'One or more pids of processes to select. (type: ArrayIntParser)

    ', proc: 'Kernel addresses of proc structs. (type: ArrayIntParser)

    ', proc_regex: A regex to select a process by name., virtual_address: 'The Virtual
    Address to examine. (type: SymbolAddress)

    '}
class_name: DarwinVtoP
epydoc: rekall.plugins.darwin.misc.DarwinVtoP-class.html
layout: plugin
module: rekall.plugins.darwin.misc
title: vtop
---
