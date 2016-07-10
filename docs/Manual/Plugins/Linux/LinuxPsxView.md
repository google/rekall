---
abstract: Find hidden processes comparing various process listings.
args: {method: "Method to list processes. (type: ChoiceArray)\n\n\n* Valid Choices:\n\
    \    - InitTask\n    - PidHashTable\n\n\n* Default: InitTask, PidHashTable", pids: 'One
    or more pids of processes to select. (type: ArrayIntParser)

    ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    ', task: 'Kernel addresses of task structs. (type: ArrayIntParser)

    '}
class_name: LinuxPsxView
epydoc: rekall.plugins.linux.psxview.LinuxPsxView-class.html
layout: plugin
module: rekall.plugins.linux.psxview
title: psxview
---

