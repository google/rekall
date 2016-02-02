---
abstract: Describe virtual to physical translation on Linux platforms.
args: {method: "Method to list processes (Default uses all methods). (type: ChoiceArray)\n\
    \n\n* Valid Choices:\n    - InitTask\n\n\n* Default: InitTask", phys_task: 'Physical
    addresses of task structs. (type: ArrayIntParser)

    ', pid: 'One or more pids of processes to select. (type: ArrayIntParser)

    ', proc_regex: A regex to select a process by name., task: 'Kernel addresses of
    task structs. (type: ArrayIntParser)

    ', task_head: 'Use this as the first task to follow the list. (type: IntParser)

    ', virtual_address: 'The Virtual Address to examine. (type: SymbolAddress)

    '}
class_name: LinVtoP
epydoc: rekall.plugins.linux.misc.LinVtoP-class.html
layout: plugin
module: rekall.plugins.linux.misc
title: vtop
---
