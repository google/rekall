
---
layout: plugin
title: check_task_fops
abstract: |
    Check open files in tasks for f_ops modifications.

epydoc: rekall.plugins.linux.check_fops.CheckTaskFops-class.html
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
