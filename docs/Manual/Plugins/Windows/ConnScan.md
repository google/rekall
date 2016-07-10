---
abstract: " Scan Physical memory for _TCPT_OBJECT objects (tcp connections)\n    "
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



    * Default: False', tcpip_guid: Force this profile to be used for tcpip.}
class_name: ConnScan
epydoc: rekall.plugins.windows.connscan.ConnScan-class.html
layout: plugin
module: rekall.plugins.windows.connscan
title: connscan
---


Similar to the [connections](Connections.html) plugin, this plugin searches from
_TCP_OBJECT structs. However, it employs pool scanning techniques.


### Notes

1. This plugin only works on versions of winsows prior to Win7.

2. Since the plugin may recover freed pool memory, the data may have been
   overwritten. This might produce garbage results for terminated connections.


### Sample output.

Note the nonsensical connection for local address *3.0.48.2* and the incorrect
pid number below.

```
xp-laptop-2005-06-25.img 23:00:29> connscan
---------------------------------> connscan()
Offset(P)  Local Address             Remote Address                   Pid
---------- ------------------------- ------------------------- ----------
0x01370e70 192.168.2.7:1115          207.126.123.29:80               1916
0x01ed1a50 3.0.48.2:17985            66.179.81.245:20084       4287933200
0x01f0e358 192.168.2.7:1164          66.179.81.247:80                 944
0x01f11e70 192.168.2.7:1082          205.161.7.134:80                2392
0x01f35cd0 192.168.2.7:1086          199.239.137.200:80              1916
0x01f88e70 192.168.2.7:1162          170.224.8.51:80                 1916
0x020869b0 127.0.0.1:1055            127.0.0.1:1056                  2160
```