---
layout: plugin
title: ssdt
abstract: |
  Enumerate the SSDT.

epydoc: rekall.plugins.windows.ssdt.WinSSDT-class.html
args:

---

The System Service Descritor Table is the main interface to the kernel from user
space. In the past, malware used to install hook in this SSDT in order to
intercept userspace->kernel calls. In more recent versions of Windows, Microsoft
has implemented **PatchGuard** specifically to prevent these kinds of
hooks. Therefore, its very rare to see these kinds of hooks any more.

The **ssdt** plugin enumerates the the SSDT table and resolves the addresses
back to the names of the functions. Windows has two SSDTs - one for the kernel
and one for the GUI subsystem (win32k driver).

An intalled ssdt hook will appear as a function in a different module (or an
unknown module).

### Sample output

```
win7.elf 15:35:25> ssdt
************ Table 0 @ 0xf80002691b00 ************
    Entry          Target     Symbol
-------------- -------------- ------
           0x0 0xf80002aa2190 nt!NtMapUserPhysicalPagesScatter
           0x1 0xf80002988a00 nt!NtWaitForSingleObject
           0x2 0xf80002688dd0 nt!NtCallbackReturn
           0x3 0xf800029abb10 nt!NtReadFile
           0x4 0xf800029a9bb0 nt!NtDeviceIoControlFile
           0x5 0xf800029a4ee0 nt!NtWriteFile
           0x6 0xf8000294adc0 nt!NtRemoveIoCompletion
           0x7 0xf80002947f10 nt!NtReleaseSemaphore
           0x8 0xf8000299fda0 nt!NtReplyWaitReceivePort
           0x9 0xf80002a71e20 nt!NtReplyPort
...
         0x18c 0xf8000297a92c nt!NtWaitForKeyedEvent
         0x18d 0xf800026a1010 nt!NtWaitForWorkViaWorkerFactory
         0x18e 0xf80002ab0b00 nt!NtWaitHighEventPair
         0x18f 0xf80002ab0b90 nt!NtWaitLowEventPair
         0x190 0xf80002678fc4 nt!NtWorkerFactoryWorkerReady
************ Table 1 @ 0xf960001a1c00 ************
    Entry          Target     Symbol
-------------- -------------- ------
           0x0 0xf96000195580 win32k!NtUserGetThreadState
           0x1 0xf96000192630 win32k!NtUserPeekMessage
           0x2 0xf960001a3c6c win32k!NtUserCallOneParam
           0x3 0xf960001b1dd0 win32k!NtUserGetKeyState
           0x4 0xf960001ab1ac win32k!NtUserInvalidateRect
           0x5 0xf960001a3e70 win32k!NtUserCallNoParam
           0x6 0xf9600019b5a0 win32k!NtUserGetMessage
           0x7 0xf9600017fbec win32k!NtUserMessageCall
...
         0x334 0xf96000153b80 win32k!NtUserValidateHandleSecure
         0x335 0xf960001acd9c win32k!NtUserWaitForInputIdle
         0x336 0xf960001a6304 win32k!NtUserWaitForMsgAndEvent
         0x337 0xf960001acef0 win32k!NtUserWindowFromPhysicalPoint
         0x338 0xf960001ae06c win32k!NtUserYieldTask
         0x339 0xf960001a6b84 win32k!NtUserSetClassLongPtr
         0x33a 0xf96000181ca0 win32k!NtUserSetWindowLongPtr
```