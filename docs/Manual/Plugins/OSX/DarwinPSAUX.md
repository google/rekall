---
abstract: List processes with their commandline.
args: {pids: 'One or more pids of processes to select. (type: ArrayIntParser)

    ', proc: 'Kernel addresses of proc structs. (type: ArrayIntParser)

    ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    ', verbosity: 'An integer reflecting the amount of desired output: 0 = quiet,
    10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: DarwinPSAUX
epydoc: rekall.plugins.darwin.processes.DarwinPSAUX-class.html
layout: plugin
module: rekall.plugins.darwin.processes
title: psaux
---
