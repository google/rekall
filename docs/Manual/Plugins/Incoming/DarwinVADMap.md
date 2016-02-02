---
abstract: "Inspect each page in the VAD and report its status.\n\n    This allows\
  \ us to see the address translation status of each page in the\n    VAD.\n    "
args: {end: 'Stop reading at this offset. (type: IntParser)



    * Default: 9223372036854775808', method: "Method to list processes (Default uses\
    \ all methods).\n\n* Valid Choices:\n    - allproc\n    - dead_procs\n    - tasks\n\
    \    - pidhash\n    - pgrphash\n", phys_proc: 'Physical addresses of proc structs.
    (type: ArrayIntParser)

    ', pid: 'One or more pids of processes to select. (type: ArrayIntParser)

    ', proc: 'Kernel addresses of proc structs. (type: ArrayIntParser)

    ', proc_regex: A regex to select a process by name., start: 'Start reading from
    this page. (type: IntParser)



    * Default: 0', verbosity: 'An integer reflecting the amount of desired output:
    0 = quiet, 10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: DarwinVADMap
epydoc: rekall.plugins.darwin.maps.DarwinVADMap-class.html
layout: plugin
module: rekall.plugins.darwin.maps
title: vadmap
---
