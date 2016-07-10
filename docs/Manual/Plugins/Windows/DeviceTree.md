---
abstract: Show device tree.
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
class_name: DeviceTree
epydoc: rekall.plugins.windows.malware.devicetree.DeviceTree-class.html
layout: plugin
module: rekall.plugins.windows.malware.devicetree
title: devicetree
---


Windows uses a layered driver architecture, or driver chain so that multiple
drivers can inspect or respond to an IRP. Rootkits often insert drivers (or
devices) into this chain for filtering purposes (to hide files, hide network
connections, steal keystrokes or mouse movements). The devicetree plugin shows
the relationship of a driver object to its devices (by walking
_DRIVER_OBJECT.DeviceObject.NextDevice) and any attached devices
(_DRIVER_OBJECT.DeviceObject.AttachedDevice).


### Notes

In the current implementation this plugin uses scanning methods to locate the
driver and device objects. This is an inefficient method which is also
susceptible to false positives and active subversion. We are working on
converting this plugin to use the [object_tree](ObjectTree.html) plugin to
directly parse kernel driver structures.

### Sample output

```
[snip]
DRV 0x2bb31060 \Driver\winpmem
---| DEV 0xfa80019ba060 pmem FILE_DEVICE_UNKNOWN
DRV 0x2bb36600 \Driver\TermDD
---| DEV 0xfa80019ff040 - FILE_DEVICE_8042_PORT
------| ATT 0xfa80019ff980 - - \Driver\mouclass FILE_DEVICE_MOUSE
---| DEV 0xfa80019e2040 - FILE_DEVICE_8042_PORT
------| ATT 0xfa80019e2960 - - \Driver\kbdclass FILE_DEVICE_KEYBOARD
[snip]
```

In the above we can see that the winpmem driver has a device called "pmem". We
also can see the mouse and keyboard drivers attached to the terminal services
driver.
