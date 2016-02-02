---
abstract: Find hidden processes comparing various process listings.
args: {method: "Method to list processes (Default uses all methods). (type: ChoiceArray)\n\
    \n\n* Valid Choices:\n    - InitTask\n    - PidHashTable\n\n\n* Default: InitTask,\
    \ PidHashTable", phys_task: 'Physical addresses of task structs. (type: ArrayIntParser)

    ', pid: 'One or more pids of processes to select. (type: ArrayIntParser)

    ', proc_regex: A regex to select a process by name., task: 'Kernel addresses of
    task structs. (type: ArrayIntParser)

    ', task_head: 'Use this as the first task to follow the list. (type: IntParser)

    '}
class_name: LinuxPsxView
epydoc: rekall.plugins.linux.psxview.LinuxPsxView-class.html
layout: plugin
module: rekall.plugins.linux.psxview
title: psxview
---

