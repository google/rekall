---
abstract: "Gathers active tasks by walking the task_struct->task list.\n\n    It does\
  \ not display the swapper process. If the DTB column is blank, the\n    item is\
  \ likely a kernel thread.\n    "
args: {method: "Method to list processes (Default uses all methods). (type: ChoiceArray)\n\
    \n\n* Valid Choices:\n    - InitTask\n\n\n* Default: InitTask", phys_task: 'Physical
    addresses of task structs. (type: ArrayIntParser)

    ', pid: 'One or more pids of processes to select. (type: ArrayIntParser)

    ', proc_regex: A regex to select a process by name., task: 'Kernel addresses of
    task structs. (type: ArrayIntParser)

    ', task_head: 'Use this as the first task to follow the list. (type: IntParser)

    '}
class_name: LinuxPsList
epydoc: rekall.plugins.linux.pslist.LinuxPsList-class.html
layout: plugin
module: rekall.plugins.linux.pslist
title: pslist
---
