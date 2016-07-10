---
abstract: 'Scan for driver objects _DRIVER_OBJECT '
args: {eprocess: 'Kernel addresses of eprocess structs. (type: ArrayIntParser)



    * Default: ', method: "Method to list processes. (type: ChoiceArray)\n\n\n* Valid\
    \ Choices:\n    - PsActiveProcessHead\n    - CSRSS\n    - PspCidTable\n    - Sessions\n\
    \    - Handles\n\n\n* Default: PsActiveProcessHead, CSRSS, PspCidTable, Sessions,\
    \ Handles", pids: 'One or more pids of processes to select. (type: ArrayIntParser)



    * Default: ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    ', scan_kernel: 'Scan the entire kernel address space. (type: Boolean)



    * Default: False', scan_kernel_code: 'Scan the kernel image and loaded drivers.
    (type: Boolean)



    * Default: False', scan_kernel_nonpaged_pool: 'Scan the kernel non-paged pool.
    (type: Boolean)



    * Default: False', scan_kernel_paged_pool: 'Scan the kernel paged pool. (type:
    Boolean)



    * Default: False', scan_kernel_session_pools: 'Scan session pools for all processes.
    (type: Boolean)



    * Default: False', scan_physical: 'Scan the physical address space only. (type:
    Boolean)



    * Default: False', scan_process_memory: 'Scan all of process memory. Uses process
    selectors to narrow down selections. (type: Boolean)



    * Default: False'}
class_name: DriverScan
epydoc: rekall.plugins.windows.filescan.DriverScan-class.html
layout: plugin
module: rekall.plugins.windows.filescan
title: driverscan
---

To find **_DRIVER_OBJECT**s in physical memory using pool tag scanning, use this
plugin. This is another way to locate kernel modules, although not all kernel
modules have an associated **_DRIVER_OBJECT**.

The usual way for malware to enter Ring 0 is via loading a kernel driver of some
sort. A malicious kernel driver is a strong indication that malware is running
in Ring 0.

### Notes

1. Like other pool scanning plugins, this plugin may produce false positives
   since it essentially carves **_DRIVER_OBJECT** structures out of memory. On
   the other hand, this plugin may reveal drivers which have been unloaded.

### Sample output


```
win8.1.raw 16:17:29> driverscan
-------------------> driverscan()
    Offset(P)    #Ptr #Hnd     Start           Size      Service Key          Name         Driver Name
- -------------- ---- ---- -------------- -------------- -------------------- ------------ -----------
...
  0x00003e569c60    3    0 0xf80000b14000        0x10000 pcw                  pcw          \Driver\pcw
  0x00003e569e60    3    0 0xf80000aeb000        0x29000 VBoxGuest            VBoxGuest    \Driver\VBoxGuest
  0x00003e59e590   17    0 0xf80000c26000       0x118000 NDIS                 NDIS         \Driver\NDIS
  0x00003e5a1060    8    0 0xf80000ec5000       0x27f000 Tcpip                Tcpip        \Driver\Tcpip
  0x00003eb8d870    3    0 0xf800025ca000        0x10000 pmem                 pmem         \Driver\pmem
  0x00003f066e60    3    0 0xf80001c69000         0xe000 monitor              monitor      \Driver\monitor
....
```

