---
abstract: Dump the VMA memory for a process.
args: {dump_dir: 'Path suitable for dumping files. (type: String)

    ', pids: 'One or more pids of processes to select. (type: ArrayIntParser)

    ', proc: 'Kernel addresses of proc structs. (type: ArrayIntParser)

    ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    '}
class_name: DarwinVadDump
epydoc: rekall.plugins.darwin.processes.DarwinVadDump-class.html
layout: plugin
module: rekall.plugins.darwin.processes
title: vaddump
---
