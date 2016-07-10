---
abstract: "Dump files from memory.\n\n    The interface is loosely based on the Volatility\
  \ plugin of the same name,\n    although the implementation is quite different.\n\
  \    "
args: {dump_dir: 'Path suitable for dumping files. (type: String)

    ', eprocess: 'Kernel addresses of eprocess structs. (type: ArrayIntParser)



    * Default: ', file_objects: 'Kernel addresses of _FILE_OBJECT structs. (type:
    ArrayIntParser)

    ', method: "Method to list processes. (type: ChoiceArray)\n\n\n* Valid Choices:\n\
    \    - PsActiveProcessHead\n    - CSRSS\n    - PspCidTable\n    - Sessions\n \
    \   - Handles\n\n\n* Default: PsActiveProcessHead, CSRSS, PspCidTable, Sessions,\
    \ Handles", pids: 'One or more pids of processes to select. (type: ArrayIntParser)



    * Default: ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    '}
class_name: DumpFiles
epydoc: rekall.plugins.windows.cache.DumpFiles-class.html
layout: plugin
module: rekall.plugins.windows.cache
title: dumpfiles
---

