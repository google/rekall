---
abstract: A cc plugin for windows.
args: {method: "Method to list processes (Default uses all methods). (type: ChoiceArray)\n\
    \n\n* Valid Choices:\n    - InitTask\n\n\n* Default: InitTask", pids: 'One or
    more pids of processes to select. (type: ArrayIntParser)

    ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    ', task: 'Kernel addresses of task structs. (type: ArrayIntParser)

    '}
class_name: LinuxSetProcessContext
epydoc: rekall.plugins.linux.misc.LinuxSetProcessContext-class.html
layout: plugin
module: rekall.plugins.linux.misc
title: cc
---
