---
abstract: Dump the USER handle tables
args: {eprocess: 'Kernel addresses of eprocess structs. (type: ArrayIntParser)



    * Default: ', free: 'Also include free handles. (type: Boolean)

    ', method: "Method to list processes. (type: ChoiceArray)\n\n\n* Valid Choices:\n\
    \    - PsActiveProcessHead\n    - CSRSS\n    - PspCidTable\n    - Sessions\n \
    \   - Handles\n\n\n* Default: PsActiveProcessHead, CSRSS, PspCidTable, Sessions,\
    \ Handles", pids: 'One or more pids of processes to select. (type: ArrayIntParser)



    * Default: ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    ', type: 'Filter handle type by this Regular Expression. (type: RegEx)



    * Default: .', verbosity: 'An integer reflecting the amount of desired output:
    0 = quiet, 10 = noisy. (type: IntParser)



    * Default: 1', win32k_profile: Force this profile to be used for Win32k.}
class_name: UserHandles
epydoc: rekall.plugins.windows.gui.userhandles.UserHandles-class.html
layout: plugin
module: rekall.plugins.windows.gui.userhandles
title: userhandles
---
