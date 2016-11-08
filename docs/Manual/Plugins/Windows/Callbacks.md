---
abstract: "Enumerate callback routines.\n\n    This plugin just enumerates installed\
  \ callback routines from various\n    sources. It does not scan for them.\n\n  \
  \  This plugin is loosely based on the original Volatility plugin of the same\n\
  \    name but much expanded using new information.\n\n    Reference:\n    <http://www.codemachine.com/notes.html>\n\
  \    "
args: {verbosity: 'An integer reflecting the amount of desired output: 0 = quiet,
    10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: Callbacks
epydoc: rekall.plugins.windows.malware.callbacks.Callbacks-class.html
layout: plugin
module: rekall.plugins.windows.malware.callbacks
title: callbacks
---

The Windows kernel has a facility to register callbacks for certain events. This
is often misused by malware in order to gain persistence. The `callbacks` plugin
enumerates these callbacks.

Since Rekall has an address resolver, we can often say more about what exists at
each of the callback locations. Normally Rekall only tracks the profile for
certain binaries (such as the kernel).

In the below example the callbacks plugins resolves the address of kernel
symbols precisely since it has the kernel profile loaded. Other symbols are give
approximately as their distance from the module's export table.

Suppose we want to verify what is the callback in the "wdf01000" driver. We can
instruct the address resolver to download the profile from the Microsoft symbol
server. Once the profile is downloaded, Rekall can determine the exact function
name registered (wdf01000!FxpBugCheckCallback).


```text
[1] win7.elf 00:59:59> callbacks
---------------------> callbacks()
                Type                     Offset        Callback                          Symbol                       Details
------------------------------------ -------------- -------------- -------------------------------------------------- -------
nt!PspLoadImageNotifyRoutine         0xf8000283e4a0 0xf800029acb68 nt!EtwpTraceLoadImage
nt!PspCreateProcessNotifyRoutine     0xf8000283e720 0xf8000265af28 nt!ViCreateProcessCallback
nt!PspCreateProcessNotifyRoutine     0xf8000283e728 0xf88001211330 ksecdd!AcceptSecurityContext+0x230
nt!PspCreateProcessNotifyRoutine     0xf8000283e730 0xf8800112b910 cng!SystemPrng+0x6a0
nt!PspCreateProcessNotifyRoutine     0xf8000283e738 0xf8800164c390 tcpip!CreateProcessNotifyRoutineEx
nt!PspCreateProcessNotifyRoutine     0xf8000283e740 0xf88000d01b94 ci!CiFreePolicyInfo+0xce84
nt!KeBugCheckCallbackListHead        0xfa80019c3ea0 0xf880014548f0 ndis!NdisGetSharedDataAlignment+0x10               Ndis min
nt!KeBugCheckCallbackListHead        0xfa80019a4ea0 0xf880014548f0 ndis!NdisGetSharedDataAlignment+0x10               Ndis min
nt!KeBugCheckCallbackListHead        0xfa80019a1ea0 0xf880014548f0 ndis!NdisGetSharedDataAlignment+0x10               Ndis min
nt!KeBugCheckCallbackListHead        0xf80002c25400 0xf80002c0eef4 hal!HalQueryMaximumProcessorCount+0x54c            ACPI x64
nt!KeBugCheckReasonCallbackListHead  0xfa80026549f8 0xf88000efd054 wdf01000+0x7a054                                   PEAUTH
nt!KeBugCheckReasonCallbackListHead  0xfa8000927f88 0xf88000efd054 wdf01000+0x7a054                                   monitor

[1] win7.elf 02:04:35> address_resolver "wdf01000"
---------------------> address_resolver("wdf01000") |
 Trying to fetch http://msdl.microsoft.com/download/symbols/wdf01000.pdb/99521C1B360441A9A1EAECC9E5087A251/wdf01000.pd_
 Trying to fetch http://msdl.microsoft.com/download/symbols/wdf01000.pdb/99521C1B360441A9A1EAECC9E5087A251/wdf01000.pd_
Extracting cabinet: /tmp/tmpnOmJvR/wdf01000.pd_
  extracting Wdf01000.pdb

All done, no errors.
                Out<1> Plugin: address_resolver

1] win7.elf 02:05:08> callbacks
---------------------> callbacks()
                Type                     Offset        Callback                          Symbol                       Details
------------------------------------ -------------- -------------- -------------------------------------------------- -------
nt!PspLoadImageNotifyRoutine         0xf8000283e4a0 0xf800029acb68 nt!EtwpTraceLoadImage
nt!PspCreateProcessNotifyRoutine     0xf8000283e720 0xf8000265af28 nt!ViCreateProcessCallback
nt!PspCreateProcessNotifyRoutine     0xf8000283e728 0xf88001211330 ksecdd!AcceptSecurityContext+0x230
nt!PspCreateProcessNotifyRoutine     0xf8000283e730 0xf8800112b910 cng!SystemPrng+0x6a0
nt!PspCreateProcessNotifyRoutine     0xf8000283e738 0xf8800164c390 tcpip!CreateProcessNotifyRoutineEx
nt!PspCreateProcessNotifyRoutine     0xf8000283e740 0xf88000d01b94 ci!CiFreePolicyInfo+0xce84
nt!KeBugCheckCallbackListHead        0xfa80019c3ea0 0xf880014548f0 ndis!NdisGetSharedDataAlignment+0x10               Ndis min
nt!KeBugCheckCallbackListHead        0xfa80019a4ea0 0xf880014548f0 ndis!NdisGetSharedDataAlignment+0x10               Ndis min
nt!KeBugCheckCallbackListHead        0xfa80019a1ea0 0xf880014548f0 ndis!NdisGetSharedDataAlignment+0x10               Ndis min
nt!KeBugCheckCallbackListHead        0xf80002c25400 0xf80002c0eef4 hal!HalQueryMaximumProcessorCount+0x54c            ACPI x64
nt!KeBugCheckReasonCallbackListHead  0xfa80026549f8 0xf88000efd054 wdf01000!FxpBugCheckCallback                       PEAUTH
nt!KeBugCheckReasonCallbackListHead  0xfa8000927f88 0xf88000efd054 wdf01000!FxpBugCheckCallback                       monitor
nt!KeBugCheckReasonCallbackListHead  0xfa80021f54b0 0xf88003edaf40 mouhid+0x3f40                                      mouhid


```
