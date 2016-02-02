---
abstract: "Scan the bash process for history.\n\n    Based on original algorithm by\
  \ Andrew Case.\n    "
args: {method: "Method to list processes (Default uses all methods). (type: ChoiceArray)\n\
    \n\n* Valid Choices:\n    - InitTask\n\n\n* Default: InitTask", phys_task: 'Physical
    addresses of task structs. (type: ArrayIntParser)

    ', pid: 'One or more pids of processes to select. (type: ArrayIntParser)

    ', proc_regex: A regex to select a process by name., scan_entire_address_space: 'Scan
    the entire process address space, not only the heap. (type: Boolean)



    * Default: False', task: 'Kernel addresses of task structs. (type: ArrayIntParser)

    ', task_head: 'Use this as the first task to follow the list. (type: IntParser)

    '}
class_name: BashHistory
epydoc: rekall.plugins.linux.bash.BashHistory-class.html
layout: plugin
module: rekall.plugins.linux.bash
title: bash
---

The Bourne Again Shell maintains a history a history of all commands that
have been executed in the current session in memory. `bash` is a plugin that
provides a chronologically ordered list of commands executed by each bash
process, grouped by pid.


### Notes

* Only commands executed in each bash session are stored in memory. So if
you're looking for commands for exitted bash sessions you may be more lucky
by looking at the disk .bash_history file if logging wasn't disabled.

### Sample output

```
Windows7_VMware(Win7x64+Ubuntu686,Ubuntu64)_VBox(XPSP3x86).ram 12:27:35> bash
-----------------------------------------------------------------------> bash()
   Pid Name                 Timestamp                Command
------ -------------------- ------------------------ --------------------
  1335 bash                 2014-03-04 17:16:31+0000 uname -a
```
