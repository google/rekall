---
layout: default
menuitem: FAQ
title: Frequently Asked Questions (FAQ).
---

# Frequently Asked Questions (FAQ).

<div id="profile"></div>

#### Rekall fails with "Unable to load profile from any repository". What gives?

Rekall requires accurate profiles to operate. This is similar to the way the
windows kernel debugger works - in order to analyse a windows image, the kernel
debugger needs to obtain debugging symbols from the microsoft debugging server.

To generate a profile file for an image, simple use the **fetch_pdb** and
**parse_pdb** plugins. For example, suppose you have a memory image which you
are not quite sure what exact version of Windows it is.

1. The first step is to figure out the precise version of the windows kernel
   this image has. We do this by scanning for the GUID of the **ntoskrnl.exe**
   process from the image itself.

2. We then fetch the debugging symbols (pdb file) for this kernel from
   Microsoft's debug symbols.

3. Finally we convert the pdb file into Rekall's own json format.

```
$ rekal -f ~/images/win7.elf version_scan | grep ntkrnl
0x0000027bb5fc f8e2a8b5c9b74bf4a6e4a48f180099942 ntkrnlmp.pdb

$ rekal fetch_pdb --dump-dir . --filename ntkrnlmp.pdb --guid f8e2a8b5c9b74bf4a6e4a48f180099942
Trying to fetch http://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/F8E2A8B5C9B74BF4A6E4A48F180099942/ntkrnlmp.pd_
Received 2675077 bytes
Extracting cabinet: ./ntkrnlmp.pd_
 extracting ntkrnlmp.pdb

All done, no errors.

$ rekal parse_pdb -f ntkrnlmp.pdb --output ntkrnlmp.json --profile_class Win7x64
$ rekal --profile ./ntkrnlmp.json -f ~/images/win7.elf pslist
 Offset (V)   Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                    Exit
-------------- -------------------- ------ ------ ------ -------- ------ ------ ------------------------ ------------------------
0xfa80008959e0 System                    4      0     84      511 ------  False 2012-10-01 21:39:51+0000 -
0xfa8001994310 smss.exe                272      4      2       29 ------  False 2012-10-01 21:39:51+0000 -
0xfa8002259060 csrss.exe               348    340      9      436      0  False 2012-10-01 21:39:57+0000 -
0xfa8000901060 wininit.exe             384    340      3       75      0  False 2012-10-01 21:39:57+0000 -
0xfa8000900420 csrss.exe               396    376      8      192      1  False 2012-10-01 21:39:57+0000 -
....
```

The same technique can be used to generate symbols for other profiles which
might be needed - for example **tcpip.pdb** or **win32k.pdb**.



