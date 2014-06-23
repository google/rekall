---
layout: plugin
title: psxview
abstract: |
  Find hidden processes with various process listings

epydoc: rekall.plugins.windows.malware.psxview.PsXview-class.html
args:
  pid: 'One or more pids of processes to select.'
  eprocess: 'Kernel addresses of eprocess structs.'
  phys_eprocess: 'Physical addresses of eprocess structs.'
  proc_regex: 'A regex to select a process by name.'
  method: 'Method to list processes (Default uses all methods).'

---

Rekall implements a number of methods for discovering processes. Malware
attempts to hide processes by making them harder to detect. In order to easily
see which method reveals which process, the **psxview** plugin lists all
processes and the methods that reveals them.

### Notes

1. Some processes are not seen by some methods and this is normal:

   * If a process is only seen by **psscan** it might have already
     exited. PSScan has the ability to see already freed **_EPROCESS** objects.

   * The **csrss.exe** is normally not seen using the **CSRSS** method (which
     enumerates process handles in the **csrss.exe** process itself).

   * The **System** process does not belong to any session, hence does not
     appear in the list. That process also has no handles and so is not seen
     using the *Handles* method.

### Sample output

```
win7.elf 14:55:22> psxview
  Offset(V)    Name                    PID CSRSS Handles PSScan PsActiveProcessHead PspCidTable Sessions Thrdproc
-------------- -------------------- ------ ----- ------- ------ ------------------- ----------- -------- --------
0xfa80008959e0 System                    4 False False   True   True                True        False    True
0xfa80024f85d0 svchost.exe             236 True  True    True   True                True        True     True
0xfa8001994310 smss.exe                272 False True    True   True                True        False    True
0xfa8002259060 csrss.exe               348 False True    True   True                True        True     True
0xfa8000901060 wininit.exe             384 True  True    True   True                True        True     True
0xfa8000900420 csrss.exe               396 False True    True   True                True        True     True
0xfa8002282710 winlogon.exe            436 True  True    True   True                True        True     True
0xfa800206d5f0 services.exe            480 True  True    True   True                True        True     True
0xfa800183ab30 lsass.exe               496 True  True    True   True                True        True     True
0xfa800239db30 lsm.exe                 504 True  True    True   True                True        True     True
0xfa80028a1640 WmiPrvSE.exe            592 True  True    True   True                True        True     True
0xfa80023f6770 svchost.exe             608 True  True    True   True                True        True     True
0xfa8002522b30 svchost.exe             624 True  True    True   True                True        True     True
0xfa8001903060 VBoxService.ex          664 True  True    True   True                True        True     True
0xfa800242a350 svchost.exe             716 True  True    True   True                True        True     True
0xfa80024589e0 svchost.exe             768 True  True    True   True                True        True     True
0xfa80024a8790 svchost.exe             872 True  True    True   True                True        True     True
0xfa80024aab30 svchost.exe             932 True  True    True   True                True        True     True
0xfa800252bb30 spoolsv.exe            1056 True  True    True   True                True        True     True
0xfa80025b4060 svchost.exe            1092 True  True    True   True                True        True     True
0xfa8002635810 svchost.exe            1192 True  True    True   True                True        True     True
0xfa8001fd9060 sppsvc.exe             1256 True  True    True   True                True        True     True
0xfa800269b950 wlms.exe               1304 True  True    True   True                True        True
```