---
abstract: "Walks open files of each proc and collects the fileproc.\n\n    This is\
  \ the same algorithm as lsof, but aimed at just collecting the\n    fileprocs, without\
  \ doing anything with them, or sorting.\n    "
args: {pids: 'One or more pids of processes to select. (type: ArrayIntParser)

    ', proc: 'Kernel addresses of proc structs. (type: ArrayIntParser)

    ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    ', verbosity: 'An integer reflecting the amount of desired output: 0 = quiet,
    10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: DarwinHandles
epydoc: rekall.plugins.darwin.lsof.DarwinHandles-class.html
layout: plugin
module: rekall.plugins.darwin.lsof
title: handles
---
