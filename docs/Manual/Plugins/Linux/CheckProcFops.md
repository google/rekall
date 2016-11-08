---
abstract: Checks the proc filesystem for hooked f_ops.
args: {all: 'Specify to see all the fops, even if they are known. (type: Boolean)

    ', verbosity: 'An integer reflecting the amount of desired output: 0 = quiet,
    10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: CheckProcFops
epydoc: rekall.plugins.linux.check_fops.CheckProcFops-class.html
layout: plugin
module: rekall.plugins.linux.check_fops
title: check_proc_fops
---

`check_proc_fops` checks the file operations pointers of each open file in the
proc filesystem. Some rootkits hook these operations in order to implement
process hiding.

In order to determine if an operation pointer is hooked, rekall checks that the
pointer resides within a known module or the kernel image.

If a pointer is found outside of these bounds, it will be reported.

### Notes
 * To obtain a list of all checked function pointers, use the `--all`
   parameter.

### Sample output

Expect blank output on clean systems.

```
pmem 15:44:30> check_proc_fops
-------------> check_proc_fops()
   DirEntry    Path                                               Member                  Address     Module              
-------------- -------------------------------------------------- -------------------- -------------- --------------------
pmem 15:44:35> 
```
