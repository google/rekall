---
abstract: "Walks open files of each proc and collects the fileproc.\n\n    This is\
  \ the same algorithm as lsof, but aimed at just collecting the\n    fileprocs, without\
  \ doing anything with them, or sorting.\n    "
args: {phys_proc: 'Physical addresses of proc structs. (type: ArrayIntParser)

    ', pid: 'One or more pids of processes to select. (type: ArrayIntParser)

    ', proc: 'Kernel addresses of proc structs. (type: ArrayIntParser)

    ', proc_regex: A regex to select a process by name.}
class_name: DarwinHandles
epydoc: rekall.plugins.darwin.lsof.DarwinHandles-class.html
layout: plugin
module: rekall.plugins.darwin.lsof
title: handles
---
