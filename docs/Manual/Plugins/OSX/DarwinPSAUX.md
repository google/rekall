---
abstract: List processes with their commandline.
args: {phys_proc: 'Physical addresses of proc structs. (type: ArrayIntParser)

    ', pid: 'One or more pids of processes to select. (type: ArrayIntParser)

    ', proc: 'Kernel addresses of proc structs. (type: ArrayIntParser)

    ', proc_regex: A regex to select a process by name.}
class_name: DarwinPSAUX
epydoc: rekall.plugins.darwin.processes.DarwinPSAUX-class.html
layout: plugin
module: rekall.plugins.darwin.processes
title: psaux
---
