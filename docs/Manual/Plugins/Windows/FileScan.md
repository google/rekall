---
abstract: " Scan Physical memory for _FILE_OBJECT pool allocations\n    "
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
class_name: FileScan
epydoc: rekall.plugins.windows.filescan.FileScan-class.html
layout: plugin
module: rekall.plugins.windows.filescan
title: filescan
---


To find FILE_OBJECTs in physical memory using pool tag scanning, use the
filescan command. This will find open files even if a rootkit is hiding the
files on disk and if the rootkit hooks some API functions to hide the open
handles on a live system.

The plugin also resolves back the **_FILE_OBJECT** into the ownning
process. This works only if the **_FILE_OBJECT** is actually in use (it does not
work for closed files).

### Notes

1. Like other pool scanning plugins, this plugin may produce false positives
   since it essentially carves **_FILE_OBJECT** structures out of memory. On the
   other hand, this plugin may reveal files which have been closed or freed.

2. When inspecting the output, the **#Hnd** column indicates the number of
   handles to this **_FILE_OBJECT**.  Objects in use will have a non zero value
   here and are likely to not be freed.

3. The plugin displays the physical address of the **_FILE_OBJECT** found. It
   may be possible to derive their virtual address using the [ptov](PtoV.html)
   plugin. Alternatively, specify the *scan_in_kernel* option, to ensure
   scanning occurs in the kernel address space.


### Sample output

```
win8.1.raw 16:55:44> filescan scan_in_kernel=True
-------------------> filescan(scan_in_kernel=True)
      Offset       #Ptr #Hnd Access     Owner      Owner Pid Owner Name       Name
- -------------- ------ ---- ------ -------------- --------- ---------------- ----
  0xe000000421e0     17   0 RW-rwd -------------- ---- ---------------- \$Directory
  0xe00000057d70     14   0 R--rwd -------------- ---- ---------------- \Windows\System32\AuthBroker.dll
  0xe000000599d0  32758   1 R--rw- 0xe00000074580    4 System           \Windows\CSC\v2.0.6
  0xe000000686e0     19   0 RW-rwd -------------- ---- ---------------- \$Directory
  0xe0000006a1f0     19   0 RW-rwd -------------- ---- ---------------- \$Directory
  0xe0000006b5a0     16   0 R--r-d -------------- ---- ---------------- \Windows\Fonts\modern.fon
  0xe0000006d8c0      4   0 R--r-d -------------- ---- ---------------- \Windows\System32\negoexts.dll
  0xe0000006dc40     16   0 R--r-- -------------- ---- ---------------- \Windows\Fonts\meiryob.ttc
  0xe0000006e1f0  29617   1 ------ 0xe0000204a900 2628 winpmem_1.5.2.   \Connect
  0xe0000006edd0     16   0 R--rwd -------------- ---- ---------------- \Windows\System32\msctf.dll
  0xe00000079270     16   0 R--r-- -------------- ---- ---------------- \Windows\Cursors\aero_up.cur
  0xe0000007abc0     12   0 R--rwd -------------- ---- ---------------- \Windows\System32\puiobj.dll
  0xe0000007ba90     18   0 RW-rwd -------------- ---- ---------------- \$Directory
  0xe0000007e070      3   0 R--r-- -------------- ---- ---------------- \Windows\Fonts\segoeui.ttf
  0xe0000007e360      4   0 RW-rwd -------------- ---- ---------------- \$ConvertToNonresident
  0xe0000007e890      7   0 R--r-d -------------- ---- ---------------- \Windows\System32\usbmon.dll
  0xe0000007f360  32768   1 R--r-d 0xe000000ce080  432 wininit.exe      \Windows\System32\en-GB\user32.dll.mui
  0xe0000007f980      4   0 R--r-d -------------- ---- ---------------- \Windows\System32\KBDUK.DLL
  0xe000000b1d90     17   0 RW-rwd -------------- ---- ---------------- \$Directory
  0xe000000b1f20      5   0 R--r-d -------------- ---- ---------------- \Windows\System32\AppXDeploymentServer.dll
  0xe000000b4610     12   0 R--rwd -------------- ---- ---------------- \Windows\SysWOW64\winmmbase.dll
  0xe000000b6820      1   1 RWD--- 0xe00000074580    4 System           \Windows\System32\config\RegBack\SECURITY
  0xe000000b6a50  32766   1 RW---- 0xe00000074580    4 System           \Windows\System32\config\SECURITY.LOG2
```