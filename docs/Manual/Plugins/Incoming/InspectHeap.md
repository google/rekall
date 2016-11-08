---
abstract: "Inspect the process heap.\n\n    This prints a lot of interesting facts\
  \ about the process heap. It is also\n    the foundation to many other plugins which\
  \ find things in the process heaps.\n\n    NOTE: Currently we only support Windows\
  \ 7 64 bit.\n    "
args: {eprocess: 'Kernel addresses of eprocess structs. (type: ArrayIntParser)



    * Default: ', free: 'Also show freed chunks. (type: Boolean)

    ', heaps: 'Only show these heaps (default show all) (type: ArrayIntParser)

    ', method: "Method to list processes. (type: ChoiceArray)\n\n\n* Valid Choices:\n\
    \    - PsActiveProcessHead\n    - CSRSS\n    - PspCidTable\n    - Sessions\n \
    \   - Handles\n\n\n* Default: PsActiveProcessHead, CSRSS, PspCidTable, Sessions,\
    \ Handles", pids: 'One or more pids of processes to select. (type: ArrayIntParser)



    * Default: ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    ', verbosity: 'An integer reflecting the amount of desired output: 0 = quiet,
    10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: InspectHeap
epydoc: rekall.plugins.windows.heap_analysis.InspectHeap-class.html
layout: plugin
module: rekall.plugins.windows.heap_analysis
title: inspect_heap
---
