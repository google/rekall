---
abstract: Enumerate pool tag usage statistics.
args: {}
class_name: PoolTracker
epydoc: rekall.plugins.windows.pool.PoolTracker-class.html
layout: plugin
module: rekall.plugins.windows.pool
title: pool_tracker
---

The Windows kernel allocates memory from a shared pool. In order to track memory
leaks and to aid in debugging, pool allocations typically have fixed tags
indicating the component which allocated the memory. For example, in windows 8,
allocating an _EPROCESS struct will result in a pool allocation with a tag of
`Proc`.

To aid in debugging, Windows tracks pool allocation in a special table found by
the symbol **PoolTrackTable**. This table can show the total number of
allocation and deallocations associated with a particular pool tag.

From a forensic point of view, this information can be useful to assess the
number of outstanding allocations. For example we can see how many live
processes we expect to be preset.

### Notes

1. Just because the process is terminated does not mean the _EPROCESS structure
   is immediately deallocated. Windows might keep these structures alive for
   some time for various reasons. A discrepancy here is at best a hint that
   something does'nt add up.

### Sample output

```
win8.1.raw 15:29:07> pool_tracker
Tag              NP Alloc   NP Bytes              P Alloc    P Bytes
---- -------------------- ---------- -------------------- ----------
 DMV                1 (0)          0                0 (0)          0
8042                6 (4)       4048               12 (0)          0
ACPI                4 (0)          0                0 (0)          0
AFGp                1 (0)          0                0 (0)          0
ALPC           3211 (770)     434240                0 (0)          0
ARFT                0 (0)          0              151 (3)        192
AcpA                2 (2)        160                0 (0)          0
AcpB                0 (0)          0              121 (0)          0
...
Pprl                0 (0)          0                3 (0)          0
Ppsu                0 (0)          0           1394 (223)      18512
Prcr                5 (4)       5440               13 (0)          0
Proc             137 (48)      91328                0 (0)          0
PsFn              136 (0)          0                0 (0)          0
...

win8.1.raw 15:36:40> pslist
-------------------> pslist()
  Offset (V)   Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                    Exit
-------------- -------------------- ------ ------ ------ -------- ------ ------ ------------------------ ------------------------
DEBUG:root:Listed 48 processes using PsActiveProcessHead
DEBUG:root:Listed 43 processes using CSRSS
DEBUG:root:Listed 47 processes using PspCidTable
DEBUG:root:Listed 45 processes using Sessions
DEBUG:root:Listed 45 processes using Handles
...
```

In the above example we see that there are 48 outstanding *_EPROCESS* objects
and there are 48 members in the **PsActiveProcessHead** list.
