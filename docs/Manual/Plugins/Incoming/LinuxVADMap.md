---
abstract: "Inspect each page in the VAD and report its status.\n\n    This allows\
  \ us to see the address translation status of each page in the\n    VAD.\n    "
args: {end: 'Stop reading at this offset. (type: IntParser)



    * Default: 9223372036854775808', method: "Method to list processes (Default uses\
    \ all methods). (type: ChoiceArray)\n\n\n* Valid Choices:\n    - InitTask\n\n\n\
    * Default: InitTask", pids: 'One or more pids of processes to select. (type: ArrayIntParser)

    ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    ', start: 'Start reading from this page. (type: IntParser)



    * Default: 0', task: 'Kernel addresses of task structs. (type: ArrayIntParser)

    ', verbosity: 'An integer reflecting the amount of desired output: 0 = quiet,
    10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: LinuxVADMap
epydoc: rekall.plugins.linux.proc_maps.LinuxVADMap-class.html
layout: plugin
module: rekall.plugins.linux.proc_maps
title: vadmap
---
