---
abstract: "Print kernel timers and associated module DPCs.\n\n    Ref:\n    http://computer.forensikblog.de/en/2011/10/timers-and-times.html\n\
  \    "
args: {}
class_name: Timers
epydoc: rekall.plugins.windows.malware.timers.Timers-class.html
layout: plugin
module: rekall.plugins.windows.malware.timers
title: timers
---

The windows kernel has a mechanism for drivers to schedule Deferred Procedure
Calls (DPCs) wither periodically or in a future time. This mechanism is useful
for malware which wants to remain persistant, but not necessarily run at all
times (This reduces the malware's footprint).

The kernel uses **_KTIMER** objects to keep track of these DPCs. Depending on
the exact OS version, the timers are arranged in slightly different data
structures:

* On Window XP there is a symbol **KiTimerTableListHead** which enumerates all
  timer hash tables.

* On windows 7, the timer list is at **_KPCR.PrcbData.TimerTable.TimerEntries**.

Since Windows 7, PatchGuard was introduced. This uses the timer table to
schedule periodic runs. Microsoft felt it was necessary to protect PatchGuard by
obfuscating all DPC pointers in the timer table. This unfortunately also
obfuscates all other timers, including ones possibly used by malware.

Rekall is able to de-obfuscate these DPC address and resolve them back to their
correct module. Rekall will also indicate when the timer is due to go off.

### Sample output

```
win8.1.raw 22:25:53> timers
Table     Offset     DueTime(H) DueTime              Period(ms)   Signaled    Routine     Module
----- -------------- ---------- -------------------- ---------- ---------- -------------- --------------------
2   0xe00001a58708 0x0000000001f0df8a92 2014-01-24 21:21:14+0000       1000        Yes 0xf80000298480 wdf01000 + 0x8480
8   0xf802d32ecd00 0x0000000001c789ad30 2014-01-24 21:20:05+0000          0          - 0xf802d311b194 nt!CcScanDpc
9   0xf802d32bcce0 0x0000010c0d9d767529 2015-01-01 00:00:00+0000          0          - 0xf802d32467b4 nt!ExpNextYearDpcRoutine
9   0xf802d32ac920 0x0000000001e478b3c5 2014-01-24 21:20:53+0000          0          - 0xf802d3116abc nt!CmpLazyFlushDpcRoutine
13  0xf80002146660 0x0000000001f3302411 2014-01-24 21:21:18+0000      43348        Yes 0xf80002140c44 bowser + 0x3c44
15  0xf8000072e320 0x00000000c877502ee7 2014-01-25 21:02:20+0000          0          - 0xf80000719230 storport + 0x23230
17  0xf800024cbb28 0x0000000001fdfb093c 2014-01-24 21:21:36+0000      28348        Yes 0xf800024af550 tunnel + 0x1550
18  0xe0000127ff40 0x0000000002f06baf46 2014-01-24 21:28:23+0000          0          - 0xf80000b31394 volsnap + 0x2394
21  0xe0000137bb40 0x0000000001f0df8a92 2014-01-24 21:21:14+0000       1000        Yes 0xf8000194a860 usbport + 0x2860
24  0xe00000203b88 0x0000000002534bd8cd 2014-01-24 21:23:59+0000          0          - 0xf80001a930a4 battc + 0x10a4
38  0xe00001493278 0x0000000001f1249ec9 2014-01-24 21:21:14+0000          0          - 0xf80000c2ac30 ndis + 0x4c30
38  0xe00002327228 0x00000000024c651b42 2014-01-24 21:23:47+0000     944848          - 0xf8000249cbb4 mslldp + 0x4bb4
38  0xe000013f7ef8 0x00000000324d602123 2014-01-25 03:07:25+0000   21600000          - 0xf80001491cf0 dxgkrnl + 0x19cf0
38  0xf802d32ea250 0x0000000001d163bc04 2014-01-24 21:20:21+0000      60000        Yes 0xf802d3116bac nt!IopIrpStackProfilerTimer
40  0xf80000e981c0 0x0000000002840a55a8 2014-01-24 21:25:21+0000          0          - 0xf80000e94c9c mup + 0x1c9c
```