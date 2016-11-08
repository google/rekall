---
abstract: Resolves a physical address to a virtual addrress in a process.
args: {offsets: 'A list of physical offsets to resolve. (type: ArrayIntParser)

    ', pids: 'One or more pids of processes to select. (type: ArrayIntParser)

    ', proc: 'Kernel addresses of proc structs. (type: ArrayIntParser)

    ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    ', verbosity: 'An integer reflecting the amount of desired output: 0 = quiet,
    10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: DarwinPas2Vas
epydoc: rekall.plugins.darwin.pas2kas.DarwinPas2Vas-class.html
layout: plugin
module: rekall.plugins.darwin.pas2kas
title: pas2vas
---
