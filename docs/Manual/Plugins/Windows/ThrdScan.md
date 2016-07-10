---
abstract: Scan physical memory for _ETHREAD objects
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
class_name: ThrdScan
epydoc: rekall.plugins.windows.modscan.ThrdScan-class.html
layout: plugin
module: rekall.plugins.windows.modscan
title: thrdscan
---

Pool scanning is a technique for discovering kernel data structures based on
signatures. It is essentially the memory forensic equivalent of carving. The
**thrdscan** plugin carves for **_KTHREAD** structures in memory.

By default the plugin scans in the physical address space. Any hits are resolved
into the virtual address space by following the lists. If **scan_in_kernel** is
specified, the scanning occurs in kernel space.

### Notes

1. Like other pool scanning plugins, this plugin may produce false positives
   since it essentially carves **_KTHREAD** structures out of memory. On the
   other hand, this plugin may reveal files which have been closed or freed.

2. The plugin displays the physical address of the **_KTHREAD** found. It may be
   possible to derive their virtual address using the [ptov](PtoV.html)
   plugin. Alternatively, specify the *scan_in_kernel* option, to ensure
   scanning occurs in the kernel address space.

3. This plugin is the pool scanning variant of the [threads](Threads.html) plugin.

### Sample output

The below is an example of running **thrdscan** over a windows system. Note that
we can still see exited threads. Rekall resolves the start address of the thread
(i.e. the function which started running in this thread). This helps to identify
what the thread is supposed to be doing.

```
win8.1.raw 18:52:26> thrdscan
  Offset(P)       PID    TID Start Address  Create Time              Exit Time                Process          Symbol
-------------- ------ ------ -------------- ------------------------ ------------------------ ---------------- ------
0x0000001ab080   2332   3976 0x7ff87f35b5c0 -                        -                        svchost.exe      \Windows\System32\ntdll.dll!TpPostWork+0x4a0
0x000000230880   2392   3212 0x7ff6670fd0bc -                        2014-01-24 21:18:44+0000 VBoxTray.exe     \Windows\System32\VBoxTray.exe!+0xd0bc
0x00000025e080   3644   1068 0x7ff7a4831070 -                        -                        conhost.exe      \Windows\System32\conhost.exe!+0x1070
0x000000261080    880   2440 0x7ff866dbaf44 -                        -                        svchost.exe      \Windows\System32\wuaueng.dll!+0x3af44
0x000000261880    880   3512 0x7ff87f35b5c0 -                        -                        svchost.exe      \Windows\System32\ntdll.dll!TpPostWork+0x4a0
0x0000002d6080   3644   3688 0x7ff7a4833060 -                        -                        conhost.exe      \Windows\System32\conhost.exe!+0x3060
0x0000002e1080    976   3932 0x7ff877104924 -                        2014-01-24 21:18:37+0000 svchost.exe      \Windows\System32\sysmain.dll!+0x94924
0x0000002e1880    880   3324 0x7ff87f35b5c0 -                        -                        svchost.exe      \Windows\System32\ntdll.dll!TpPostWork+0x4a0
0x00000035d080    880   1752 0x7ff866dbaf44 -                        -                        svchost.exe      \Windows\System32\wuaueng.dll!+0x3af44
0x000000558080    880   3524 0x7ff87f35b5c0 -                        -                        svchost.exe      \Windows\System32\ntdll.dll!TpPostWork+0x4a0
0x000000613080    880   3496 0x7ff866dbaf44 -                        -                        svchost.exe      \Windows\System32\wuaueng.dll!+0x3af44
0x000000613880   3400   3648 0x7ff87f35b5c0 -                        -                        MpCmdRun.exe     \Windows\System32\ntdll.dll!TpPostWork+0x4a0
0x000000668080    880   3524 0x7ff87f35b5c0 -                        -                        svchost.exe      \Windows\System32\ntdll.dll!TpPostWork+0x4a0
0x0000006c0080    880   3692 0x7ff8733911b0 -                        -                        svchost.exe      \Windows\System32\aelupsvc.dll!+0x11b0
0x0000006ce080    880   3180 0x7ff866d81f3c -                        -                        svchost.exe      \Windows\System32\wuaueng.dll!+0x1f3c
0x000002bd2080    880   3736 0x7ff866dbaf44 -                        -                        svchost.exe      \Windows\System32\wuaueng.dll!+0x3af44
0x00000370a080    976   3932 0x7ff877104924 -                        2014-01-24 21:18:37+0000 svchost.exe      \Windows\System32\sysmain.dll!+0x94924
0x00000370a880    880   3324 0x7ff87f35b5c0 -                        -                        svchost.exe      \Windows\System32\ntdll.dll!TpPostWork+0x4a0
0x000004eef080    880   3692 0x7ff8733911b0 -                        -                        svchost.exe      \Windows\System32\aelupsvc.dll!+0x11b0
0x0000051a4874 2124654 30318413 0xffe800000000 -                        -                        ----------------
0x000005d8a080    880   3692 0x7ff8733911b0 -                        -                        svchost.exe      \Windows\System32\aelupsvc.dll!+0x11b0
0x000009f5d080   2332   3928 0x7ff87f35b5c0 -                        -                        svchost.exe      \Windows\System32\ntdll.dll!TpPostWork+0x4a0
0x00000cbde080   2392   3880 0x7ff6670fd0bc -                        2014-01-24 21:18:24+0000 VBoxTray.exe     \Windows\System32\VBoxTray.exe!+0xd0bc
0x00000dbdb080   2392   4084 0x7ff6670fd0bc -                        2014-01-24 21:19:27+0000 VBoxTray.exe     \Windows\System32\VBoxTray.exe!+0xd0bc
0x00000f345080    880   1532 0x7ff866dbaf44 -                        -                        svchost.exe      \Windows\System32\wuaueng.dll!+0x3af44
0x00000f345880    880   2932 0x7ff87f35b5c0 -                        -                        svchost.exe      \Windows\System32\ntdll.dll!TpPostWork+0x4a0
0x00000f413080      4   3176 0xf802d3613418 -                        -                        System           nt!MiStoreEvictThread
```