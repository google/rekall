---
abstract: "A mixin for plugins which require a valid kernel address space.\n\n   \
  \     Args:\n          dtb: A potential dtb to be used.\n        "
args: {pids: 'One or more pids of processes to select. (type: ArrayIntParser)

    ', proc: 'Kernel addresses of proc structs. (type: ArrayIntParser)

    ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    '}
class_name: DarwinPsxView
epydoc: rekall.plugins.darwin.processes.DarwinPsxView-class.html
layout: plugin
module: rekall.plugins.darwin.processes
title: psxview
---
