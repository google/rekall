---
abstract: A cc plugin for windows.
args: {method: "Method to list processes (Default uses all methods).\n\n* Valid Choices:\n\
    \    - allproc\n    - dead_procs\n    - tasks\n    - pidhash\n    - pgrphash\n",
  phys_proc: 'Physical addresses of proc structs. (type: ArrayIntParser)

    ', pid: 'One or more pids of processes to select. (type: ArrayIntParser)

    ', proc: 'Kernel addresses of proc structs. (type: ArrayIntParser)

    ', proc_regex: A regex to select a process by name.}
class_name: DarwinSetProcessContext
epydoc: rekall.plugins.darwin.misc.DarwinSetProcessContext-class.html
layout: plugin
module: rekall.plugins.darwin.misc
title: cc
---
