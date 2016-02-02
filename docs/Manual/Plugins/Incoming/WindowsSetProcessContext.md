---
abstract: A cc plugin for windows.
args: {eprocess: 'Kernel addresses of eprocess structs. (type: ArrayIntParser)

    ', method: "Method to list processes. (type: ChoiceArray)\n\n\n* Valid Choices:\n\
    \    - PsActiveProcessHead\n    - CSRSS\n    - PspCidTable\n    - Sessions\n \
    \   - Handles\n\n\n* Default: PsActiveProcessHead, CSRSS, PspCidTable, Sessions,\
    \ Handles", phys_eprocess: 'Physical addresses of eprocess structs. (type: ArrayIntParser)

    ', pid: 'One or more pids of processes to select. (type: ArrayIntParser)

    ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    '}
class_name: WindowsSetProcessContext
epydoc: rekall.plugins.windows.misc.WindowsSetProcessContext-class.html
layout: plugin
module: rekall.plugins.windows.misc
title: cc
---
