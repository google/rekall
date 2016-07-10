---
abstract: "Inspect each page in the VAD and report its status.\n\n    This allows\
  \ us to see the address translation status of each page in the\n    VAD.\n    "
args: {end: 'Stop reading at this offset. (type: IntParser)



    * Default: 9223372036854775808', eprocess: 'Kernel addresses of eprocess structs.
    (type: ArrayIntParser)



    * Default: ', method: "Method to list processes. (type: ChoiceArray)\n\n\n* Valid\
    \ Choices:\n    - PsActiveProcessHead\n    - CSRSS\n    - PspCidTable\n    - Sessions\n\
    \    - Handles\n\n\n* Default: PsActiveProcessHead, CSRSS, PspCidTable, Sessions,\
    \ Handles", pids: 'One or more pids of processes to select. (type: ArrayIntParser)



    * Default: ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    ', start: 'Start reading from this page. (type: IntParser)



    * Default: 0', verbosity: 'An integer reflecting the amount of desired output:
    0 = quiet, 10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: VADMap
epydoc: rekall.plugins.windows.vadinfo.VADMap-class.html
layout: plugin
module: rekall.plugins.windows.vadinfo
title: vadmap
---

