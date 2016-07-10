---
abstract: Resolves a physical address to a virtual addrress in a process.
args: {method: "Method to list processes (Default uses all methods). (type: ChoiceArray)\n\
    \n\n* Valid Choices:\n    - InitTask\n\n\n* Default: InitTask", offsets: 'A list
    of physical offsets to resolve. (type: ArrayIntParser)

    ', pids: 'One or more pids of processes to select. (type: ArrayIntParser)

    ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    ', task: 'Kernel addresses of task structs. (type: ArrayIntParser)

    '}
class_name: LinPas2Vas
epydoc: rekall.plugins.linux.pas2kas.LinPas2Vas-class.html
layout: plugin
module: rekall.plugins.linux.pas2kas
title: pas2vas
---
