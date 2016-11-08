---
abstract: 'Scan for mutant objects _KMUTANT '
args: {eprocess: 'Kernel addresses of eprocess structs. (type: ArrayIntParser)



    * Default: ', limit: 'The length of data to search in each selected region. (type:
    IntParser)



    * Default: 18446744073709551616', method: "Method to list processes. (type: ChoiceArray)\n\
    \n\n* Valid Choices:\n    - PsActiveProcessHead\n    - CSRSS\n    - PspCidTable\n\
    \    - Sessions\n    - Handles\n\n\n* Default: PsActiveProcessHead, CSRSS, PspCidTable,\
    \ Sessions, Handles", pids: 'One or more pids of processes to select. (type: ArrayIntParser)



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



    * Default: False', verbosity: 'An integer reflecting the amount of desired output:
    0 = quiet, 10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: MutantScan
epydoc: rekall.plugins.windows.filescan.MutantScan-class.html
layout: plugin
module: rekall.plugins.windows.filescan
title: mutantscan
---

This plugin uses pool scanning techniques to find **_KMUTANT** objects.

Mutants implement a "named semaphore" in windows. This is used by malware to
ensure only a single copy of the malware is running at the same time. By
analyzing the name of the Mutant that a specific malware strand is using it is
possible to tell immediately if the malware is running on the machine.

For more information, see Andreas Schuster's [Searching for Mutants](http://computer.forensikblog.de/en/2009/04/searching_for_mutants.html).

### Notes

1. Like other pool scanning plugins, this plugin may produce false positives
   since it essentially carves **_KMUTANT** structures out of memory.

2. It is more efficient to search for named mutants using the
   [object_tree](ObjectTree.html) plugin - since it does not use pool scanning
   techniques.

3. When inspecting the output, the **#Hnd** column indicates the number of
   handles to this **_KMUTANT**.  Objects in use will have a non zero value here
   and are likely to not be freed.


### Sample output

```
win8.1.raw 23:46:56> mutantscan scan_in_kernel=1
-------------------> mutantscan(scan_in_kernel=1)
    Offset(P)      #Ptr #Hnd Signal     Thread           CID Name
- -------------- ------ ---- ------ -------------- --------- ----
  0xe0000007f810      3  2 1    0x000000000000           C::Users:test:AppData:Local:Microsoft:Windows:Explorer:thumbcache_sr.db!dfMaintainer
  0xe0000007f8d0      3  2 1    0x000000000000           C::Users:test:AppData:Local:Microsoft:Windows:Explorer:thumbcache_1600.db!dfMaintainer
  0xe000000b8d00  32722  1 1    0x000000000000           BcdSyncMutant
  0xe00000624240  32769  1 0    0xe00000624700  556:1396 F659A567-8ACB-4E4A-92A7-5C2DD1884F72
  0xe000006f4a60  32768  1 0    0xe000006dc080 2332:2460 Instance2:  ESENT Performance Data Schema Version 255
  0xe00001253080  32768  1 0    0xe000007fd080  880:3144 Instance3:  ESENT Performance Data Schema Version 255
  0xe00001262360      2  1 1    0x000000000000           ARC_AppRepSettings_Mutex
  0xe00001272530      5  4 1    0x000000000000           C::Users:test:AppData:Local:Microsoft:Windows:Explorer:iconcache_1024.db!dfMaintainer
  0xe000012725f0      5  4 1    0x000000000000           C::Users:test:AppData:Local:Microsoft:Windows:Explorer:iconcache_256.db!dfMaintainer
  0xe000012726b0      5  4 1    0x000000000000           C::Users:test:AppData:Local:Microsoft:Windows:Explorer:iconcache_96.db!dfMaintainer
  0xe00001272770      5  4 1    0x000000000000           C::Users:test:AppData:Local:Microsoft:Windows:Explorer:iconcache_48.db!dfMaintainer
  0xe00001272ac0 131007  4 1    0x000000000000           C::Users:test:AppData:Local:Microsoft:Windows:Explorer:iconcache_32.db!dfMaintainer
  0xe0000128e1e0 131005  4 1    0x000000000000           C::Users:test:AppData:Local:Microsoft:Windows:Explorer:iconcache_16.db!dfMaintainer
  0xe0000129a2c0  32734  1 1    0x000000000000           SmartScreen_AppRepSettings_Mutex
  0xe000012c7950 131061  4 1    0x000000000000           C::Users:test:AppData:Local:Microsoft:Windows:Explorer:iconcache_idx.db!IconCacheInit
  0xe000012c7a10      5  4 1    0x000000000000           C::Users:test:AppData:Local:Microsoft:Windows:Explorer:iconcache_wide_alternate.db!dfMaintainer
  0xe000012c7ad0      5  4 1    0x000000000000           C::Users:test:AppData:Local:Microsoft:Windows:Explorer:iconcache_exif.db!dfMaintainer
  0xe000012c7b90      5  4 1    0x000000000000           C::Users:test:AppData:Local:Microsoft:Windows:Explorer:iconcache_wide.db!dfMaintainer
  0xe000012c7c50      5  4 1    0x000000000000           C::Users:test:AppData:Local:Microsoft:Windows:Explorer:iconcache_sr.db!dfMaintainer
...
```
