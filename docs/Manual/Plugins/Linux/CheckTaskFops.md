---
abstract: Check open files in tasks for f_ops modifications.
args: {all: 'Specify to see all the fops, even if they are known. (type: Boolean)

    ', method: "Method to list processes (Default uses all methods). (type: ChoiceArray)\n\
    \n\n* Valid Choices:\n    - InitTask\n\n\n* Default: InitTask", pids: 'One or
    more pids of processes to select. (type: ArrayIntParser)

    ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    ', task: 'Kernel addresses of task structs. (type: ArrayIntParser)

    '}
class_name: CheckTaskFops
epydoc: rekall.plugins.linux.check_fops.CheckTaskFops-class.html
layout: plugin
module: rekall.plugins.linux.check_fops
title: check_task_fops
---

`check_task_fops` checks the file operations pointers of each running process'
open files. Rootkits may hook these function pointers in order to control
operation of specific tasks.

In order to determine if an operation pointer is hooked, rekall checks that the
pointer resides within a known module or the kernel image.

If a pointer is found outside of these bounds, it will be reported.

### Notes
 * To obtain a list of all checked function pointers, use the `--all`
   parameter.

### Sample output

Expect blank output on clean systems.

```
pmem 15:44:30> check_task_fops
-------------> check_proc_fops()
   DirEntry    Path                                               Member                  Address     Module              
-------------- -------------------------------------------------- -------------------- -------------- --------------------
pmem 15:44:35> 
```
