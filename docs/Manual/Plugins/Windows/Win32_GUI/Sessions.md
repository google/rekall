---
abstract: "List details on _MM_SESSION_SPACE (user logon sessions).\n\n    Windows\
  \ uses sessions in order to separate processes. Sessions are used to\n    separate\
  \ the address spaces of windows processes.\n\n    Note that this plugin traverses\
  \ the ProcessList member of the session object\n    to list the processes - yet\
  \ another list _EPROCESS objects are on.\n    "
args: {eprocess: 'Kernel addresses of eprocess structs. (type: ArrayIntParser)



    * Default: ', method: "Method to list processes. (type: ChoiceArray)\n\n\n* Valid\
    \ Choices:\n    - PsActiveProcessHead\n    - CSRSS\n    - PspCidTable\n    - Sessions\n\
    \    - Handles\n\n\n* Default: PsActiveProcessHead, CSRSS, PspCidTable, Sessions,\
    \ Handles", pids: 'One or more pids of processes to select. (type: ArrayIntParser)



    * Default: ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    ', verbosity: 'An integer reflecting the amount of desired output: 0 = quiet,
    10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: Sessions
epydoc: rekall.plugins.windows.gui.sessions.Sessions-class.html
layout: plugin
module: rekall.plugins.windows.gui.sessions
title: sessions
---
