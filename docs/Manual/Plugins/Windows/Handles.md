---
abstract: Print list of open handles for each process
args: {eprocess: 'Kernel addresses of eprocess structs. (type: ArrayIntParser)



    * Default: ', method: "Method to list processes. (type: ChoiceArray)\n\n\n* Valid\
    \ Choices:\n    - PsActiveProcessHead\n    - CSRSS\n    - PspCidTable\n    - Sessions\n\
    \    - Handles\n\n\n* Default: PsActiveProcessHead, CSRSS, PspCidTable, Sessions,\
    \ Handles", named_only: 'Output only handles with a name . (type: Boolean)

    ', object_types: 'Types of objects to show. (type: ArrayStringParser)

    ', pids: 'One or more pids of processes to select. (type: ArrayIntParser)



    * Default: ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    ', verbosity: 'An integer reflecting the amount of desired output: 0 = quiet,
    10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: Handles
epydoc: rekall.plugins.windows.handles.Handles-class.html
layout: plugin
module: rekall.plugins.windows.handles
title: handles
---

This plugin displays the handle table of processes. The handle table in the
process stores securable kernel objects.

When a user mode process obtains a securable kernel object, they receive a
handle to it - i.e. an integer which is the location in the handle table, rather
than the raw kernel level pointer. User processes then use the handle to operate
of the kernel level object. For example, if a process opens a file the
**_FILE_OBJECT** will be stored in the handle table, and the userspace code will
receive the offset into the handle table.

This plugin is especially useful to find all resources that are opened by a user
space program, such as open files, registry keys etc. In fact any of the objects
shown by the [object_types](ObjectTypes.html) plugin are stored in the handle
table as can be seen by this module.

All the usual process selectors are supported. Additionally, it is possible to
filter the output by using a comma separated list of handle types (as can be
seen by the [object_types](ObjectTypes.html) plugin.


### Sample output

In the following output we see the winpmem acquisition tool's handle table. Note
that it has an open file to the raw device *\Device\pmem* and the output file of
*\Device\HarddiskVolume2\temp\win8.1.raw*.

```
win8.1.raw 18:00:43> handles proc_regex="winpmem"
-------------------> handles(proc_regex="winpmem")
  Offset (V)      Pid     Handle         Access     Type             Details
-------------- ------ -------------- -------------- ---------------- -------
0xe00001f82f20   2628            0x4       0x12019f File             \Device\ConDrv\Reference
0xe00001d17e00   2628           0x10       0x100020 File             \Device\HarddiskVolume2\Windows
0xe00001f546b0   2628           0x18       0x12019f File             \Device\ConDrv\Input
0xe00001eef800   2628           0x1c       0x12019f File             \Device\ConDrv\Output
0xe00001eef800   2628           0x20       0x12019f File             \Device\ConDrv\Output
0xe00001d0db80   2628           0x24       0x100020 File             \Device\HarddiskVolume2\temp
0xe0000006e1f0   2628           0x28       0x12019f File             \Device\ConDrv\Connect
0xe00000637480   2628           0x30       0x1f0001 ALPC Port
0xe000006bd290   2628           0x34       0x1f0003 Event
0xe00001ed6060   2628           0x38            0x1 WaitCompletionPacket
0xe00001ecd080   2628           0x3c       0x1f0003 IoCompletion
0xe00001ec7060   2628           0x40        0xf00ff TpWorkerFactory
0xe00000778320   2628           0x44       0x100002 IRTimer
0xe00001ecfb80   2628           0x48            0x1 WaitCompletionPacket
0xe00001a629d0   2628           0x4c       0x100002 IRTimer
0xe00001ec8f90   2628           0x50            0x1 WaitCompletionPacket
0xe00002048970   2628           0x54          0x804 EtwRegistration
0xe0000077dd00   2628           0x58       0x100003 Semaphore
0xe00001d1b340   2628           0x5c       0x100001 File             \Device\CNG
0xe000006b82c0   2628           0x60       0x100003 Semaphore
0xe00001d0c6e0   2628           0x64       0x120196 File             \Device\HarddiskVolume2\temp\win8.1.raw
0xe000007db2f0   2628           0x74       0x1f0003 Event
0xe000023eda60   2628           0x78          0x804 EtwRegistration
0xe000024c56c0   2628           0x7c          0x804 EtwRegistration
0xe00001f803e0   2628           0x80          0x804 EtwRegistration
0xe00000813330   2628           0x84       0x1f0003 Event
0xe00001254440   2628           0x88       0x1fffff Thread           TID 3420 PID 2628
0xe0000061ebb0   2628           0x8c       0x1f0001 ALPC Port
0xe00001d0c340   2628           0x90       0x12019f File             \Device\pmem
```