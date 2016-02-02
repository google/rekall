---
abstract: Runs a signature scans against physical, kernel or process memory.
args: {method: "Method to list processes (Default uses all methods). (type: ChoiceArray)\n\
    \n\n* Valid Choices:\n    - InitTask\n\n\n* Default: InitTask", phys_task: 'Physical
    addresses of task structs. (type: ArrayIntParser)

    ', pid: 'One or more pids of processes to select. (type: ArrayIntParser)

    ', proc_regex: A regex to select a process by name., scan_kernel: 'If specified
    we scan the kernel address space. (type: Boolean)



    * Default: False', scan_physical: 'If specified we scan the physcial address space.
    (type: Boolean)



    * Default: False', signature: The signature(s) to scan for. Format is 000102*0506*AAFF,
  task: 'Kernel addresses of task structs. (type: ArrayIntParser)

    ', task_head: 'Use this as the first task to follow the list. (type: IntParser)

    '}
class_name: LinuxSigScan
epydoc: rekall.plugins.linux.sigscan.LinuxSigScan-class.html
layout: plugin
module: rekall.plugins.linux.sigscan
title: sigscan
---
