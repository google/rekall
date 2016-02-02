---
abstract: Resolves a physical address to a virtual addrress in a process.
args: {method: "Method to list processes (Default uses all methods).\n\n* Valid Choices:\n\
    \    - allproc\n    - dead_procs\n    - tasks\n    - pidhash\n    - pgrphash\n",
  offsets: 'A list of physical offsets to resolve. (type: ArrayIntParser)

    ', phys_proc: 'Physical addresses of proc structs. (type: ArrayIntParser)

    ', pid: 'One or more pids of processes to select. (type: ArrayIntParser)

    ', proc: 'Kernel addresses of proc structs. (type: ArrayIntParser)

    ', proc_regex: A regex to select a process by name.}
class_name: DarwinPas2Vas
epydoc: rekall.plugins.darwin.pas2kas.DarwinPas2Vas-class.html
layout: plugin
module: rekall.plugins.darwin.pas2kas
title: pas2vas
---
