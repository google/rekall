---
abstract: "Filters processes by parameters.\n\n        Args:\n           phys_proc_struct:\
  \ One or more proc structs or offsets defined in\n              the physical AS.\n\
  \n           pid: A single pid.\n        "
args: {phys_proc: 'Physical addresses of proc structs. (type: ArrayIntParser)

    ', pid: 'One or more pids of processes to select. (type: ArrayIntParser)

    ', proc: 'Kernel addresses of proc structs. (type: ArrayIntParser)

    ', proc_regex: A regex to select a process by name.}
class_name: DarwinPsxView
epydoc: rekall.plugins.darwin.processes.DarwinPsxView-class.html
layout: plugin
module: rekall.plugins.darwin.processes
title: psxview
---
