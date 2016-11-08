---
abstract: Describe virtual to physical translation on darwin platforms.
args: {pids: 'One or more pids of processes to select. (type: ArrayIntParser)

    ', proc: 'Kernel addresses of proc structs. (type: ArrayIntParser)

    ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    ', verbosity: 'An integer reflecting the amount of desired output: 0 = quiet,
    10 = noisy. (type: IntParser)



    * Default: 1', virtual_address: 'The Virtual Address to examine. (type: SymbolAddress)

    '}
class_name: DarwinVtoP
epydoc: rekall.plugins.darwin.misc.DarwinVtoP-class.html
layout: plugin
module: rekall.plugins.darwin.misc
title: vtop
---
