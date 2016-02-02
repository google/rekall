---
abstract: List processes for windows.
args: {eprocess: 'Kernel addresses of eprocess structs. (type: ArrayIntParser)

    ', method: "Method to list processes. (type: ChoiceArray)\n\n\n* Valid Choices:\n\
    \    - PsActiveProcessHead\n    - CSRSS\n    - PspCidTable\n    - Sessions\n \
    \   - Handles\n\n\n* Default: PsActiveProcessHead, CSRSS, PspCidTable, Sessions,\
    \ Handles", phys_eprocess: 'Physical addresses of eprocess structs. (type: ArrayIntParser)

    ', pid: 'One or more pids of processes to select. (type: ArrayIntParser)

    ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    '}
class_name: WinPsList
epydoc: rekall.plugins.windows.taskmods.WinPsList-class.html
layout: plugin
module: rekall.plugins.windows.taskmods
title: pslist
---

The **pslist** plugin list all the processes on windows using a variety of
methods. Since it is required by all plugins which has process selectors, this
plugin will, by default, list processes using all methods.

The output of this plugin is typically cached in the session, so the first time
it is run there might be a slight delay while all methods are used, but
subsequent invokations should be almost instant.

Currently the following process listing methods are used:

* PsActiveProcessHead: This method follows the doubly linked list found by the
  symbol **PsActiveProcessHead**. It is the simplest and fastest method for
  listing processes, but it is easily subverted by simply removing an _EPROCESS
  struct from this list.

* CSRSS: The client-server runtime service is responsible for monitoring all
  running processes. It therefore maintains open handles to running
  processes. This method locates the `csrss.exe` process and enumerates its
  handle table finding all handles to processes. Note that this will not
  typically find the csrss.exe proces itself, nor system processes which were
  started before it.

* PspCidTable: The PspCidTable is a handle table for process and thread client
  IDs [Ref](http://uninformed.org/index.cgi?v=3&a=7&p=6). The process's pid is
  the index into this table. This method enumerates the table in order to find
  all processes. (Note a rootkit can easily remove a process from this table).

* Sessions: This enumerates all the processes in all windows sessions
  (**SessionProcessLinks** member of **_MM_SESSION_SPACE** struct).

* Handles: The enumerates all handle tables (Which are found on a list from the
  symbol **HandleTableListHead**) and collects their owning process (The
  **QuotaProcess** member).

### Sample output

```
  Offset (V)   Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                    Exit
-------------- -------------------- ------ ------ ------ -------- ------ ------ ------------------------ ------------------------
DEBUG:root:Listed 48 processes using PsActiveProcessHead
DEBUG:root:Listed 43 processes using CSRSS
DEBUG:root:Listed 47 processes using PspCidTable
DEBUG:root:Listed 45 processes using Sessions
DEBUG:root:Listed 45 processes using Handles
0xe00000074580 System                    4      0     97 -------- ------  False 2014-01-24 22:07:24+0000 -
0xe00001499040 smss.exe                292      4      2 -------- ------  False 2014-01-24 22:07:24+0000 -
0xe0000212c900 svchost.exe             372    528     15 --------      0  False 2014-01-24 21:07:51+0000 -
0xe00001be1280 csrss.exe               380    372      8 --------      0  False 2014-01-24 22:07:32+0000 -
0xe000000ce080 wininit.exe             432    372      1 --------      0  False 2014-01-24 22:07:32+0000 -
0xe000000d9280 csrss.exe               440    424      9 --------      1  False 2014-01-24 22:07:32+0000 -
```