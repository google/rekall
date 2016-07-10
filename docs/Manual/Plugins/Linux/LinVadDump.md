---
abstract: Dump the VMA memory for a process.
args: {dump_dir: 'Path suitable for dumping files. (type: String)

    ', method: "Method to list processes (Default uses all methods). (type: ChoiceArray)\n\
    \n\n* Valid Choices:\n    - InitTask\n\n\n* Default: InitTask", pids: 'One or
    more pids of processes to select. (type: ArrayIntParser)

    ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    ', task: 'Kernel addresses of task structs. (type: ArrayIntParser)

    '}
class_name: LinVadDump
epydoc: rekall.plugins.linux.proc_maps.LinVadDump-class.html
layout: plugin
module: rekall.plugins.linux.proc_maps
title: vaddump
---
