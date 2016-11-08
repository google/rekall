---
abstract: Runs a signature scans against physical, kernel or process memory.
args: {pids: 'One or more pids of processes to select. (type: ArrayIntParser)

    ', proc: 'Kernel addresses of proc structs. (type: ArrayIntParser)

    ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    ', scan_kernel: 'If specified we scan the kernel address space. (type: Boolean)



    * Default: False', scan_physical: 'If specified we scan the physcial address space.
    (type: Boolean)



    * Default: False', signature: The signature(s) to scan for. Format is 000102*0506*AAFF,
  verbosity: 'An integer reflecting the amount of desired output: 0 = quiet, 10 =
    noisy. (type: IntParser)



    * Default: 1'}
class_name: DarwinSigScan
epydoc: rekall.plugins.darwin.sigscan.DarwinSigScan-class.html
layout: plugin
module: rekall.plugins.darwin.sigscan
title: sigscan
---
