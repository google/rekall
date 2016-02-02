---
abstract: Dump the VMA memory for a process.
args: {dump_dir: 'Path suitable for dumping files. (Default: Use current directory)',
  method: "Method to list processes (Default uses all methods). (type: ChoiceArray)\n\
    \n\n* Valid Choices:\n    - InitTask\n\n\n* Default: InitTask", phys_task: 'Physical
    addresses of task structs. (type: ArrayIntParser)

    ', pid: 'One or more pids of processes to select. (type: ArrayIntParser)

    ', proc_regex: A regex to select a process by name., task: 'Kernel addresses of
    task structs. (type: ArrayIntParser)

    ', task_head: 'Use this as the first task to follow the list. (type: IntParser)

    '}
class_name: LinVadDump
epydoc: rekall.plugins.linux.proc_maps.LinVadDump-class.html
layout: plugin
module: rekall.plugins.linux.proc_maps
title: vaddump
---
