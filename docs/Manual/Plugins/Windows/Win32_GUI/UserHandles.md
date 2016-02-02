---
abstract: Dump the USER handle tables
args: {eprocess: 'Kernel addresses of eprocess structs. (type: ArrayIntParser)

    ', free: 'Also include free handles. (type: Boolean)



    * Default: False', method: "Method to list processes. (type: ChoiceArray)\n\n\n\
    * Valid Choices:\n    - PsActiveProcessHead\n    - CSRSS\n    - PspCidTable\n\
    \    - Sessions\n    - Handles\n\n\n* Default: PsActiveProcessHead, CSRSS, PspCidTable,\
    \ Sessions, Handles", phys_eprocess: 'Physical addresses of eprocess structs.
    (type: ArrayIntParser)

    ', pid: 'One or more pids of processes to select. (type: ArrayIntParser)

    ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    ', type: Filter handle type by this Regular Expression., win32k_profile: Force
    this profile to be used for Win32k.}
class_name: UserHandles
epydoc: rekall.plugins.windows.gui.userhandles.UserHandles-class.html
layout: plugin
module: rekall.plugins.windows.gui.userhandles
title: userhandles
---
