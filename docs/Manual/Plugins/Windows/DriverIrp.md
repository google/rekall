---
layout: plugin
title: driverirp
abstract: |
  Driver IRP hook detection

epydoc: rekall.plugins.windows.malware.devicetree.DriverIrp-class.html
args:
  regex: 'Analyze drivers matching REGEX'
  verbosity: 'Add more output.'
  address_space: ''
  scan_in_kernel: 'Scan in the kernel address space'

---


Windows drivers export a table of functions called the IRP **MajorFunction**
table. In that table, the driver installs function handlers to handle verious
types of requests from userspace. A common way to hook a legitimate driver is to
replace these function pointers with a malicious function.

Many drivers forward their IRP functions to other drivers for legitimate
purposes, so detecting hooked IRP functions based on containing modules is not a
good method. Instead, we print everything and let you be the judge. The command
also checks for Inline hooks of IRP functions and optionally prints a
disassembly of the instructions at the IRP address (pass --verbosity to enable
this).

This command outputs information for all drivers, unless you specify a regular
expression filter.

### Notes

In the current implementation this plugin uses scanning methods to locate the
driver and device objects. This is an inefficient method which is also
susceptible to false positives and active subversion. We are working on
converting this plugin to use the [object_tree](ObjectTree.html) plugin to
directly parse kernel driver structures.


### Sample output

In the below we see that the pmem driver handles the **IRP_MJ_CREATE**,
**IRP_MJ_CLOSE**, **IRP_MJ_READ** and **IRP_MJ_DEVICE_CONTROL** IRP types.

```
win8.1.raw 16:15:36> driverirp regex="pmem"
-------------------> driverirp(regex="pmem")
**************************************************
DriverName: pmem
DriverStart: 0xf800025ca000
DriverSize: 0x10000
DriverStartIo: 0x0
   - Func Name                              Func Addr    Module
---- ------------------------------------ -------------- ------
   0 IRP_MJ_CREATE                        0xf800025cb210 \??\C:\Users\test\AppData\Local\Temp\pmeA86F.tmp
   1 IRP_MJ_CREATE_NAMED_PIPE             0xf802d31131b8 \SystemRoot\system32\ntoskrnl.exe
   2 IRP_MJ_CLOSE                         0xf800025cb270 \??\C:\Users\test\AppData\Local\Temp\pmeA86F.tmp
   3 IRP_MJ_READ                          0xf800025cbfa0 \??\C:\Users\test\AppData\Local\Temp\pmeA86F.tmp
   4 IRP_MJ_WRITE                         0xf802d31131b8 \SystemRoot\system32\ntoskrnl.exe
   5 IRP_MJ_QUERY_INFORMATION             0xf802d31131b8 \SystemRoot\system32\ntoskrnl.exe
   6 IRP_MJ_SET_INFORMATION               0xf802d31131b8 \SystemRoot\system32\ntoskrnl.exe
   7 IRP_MJ_QUERY_EA                      0xf802d31131b8 \SystemRoot\system32\ntoskrnl.exe
   8 IRP_MJ_SET_EA                        0xf802d31131b8 \SystemRoot\system32\ntoskrnl.exe
   9 IRP_MJ_FLUSH_BUFFERS                 0xf802d31131b8 \SystemRoot\system32\ntoskrnl.exe
  10 IRP_MJ_QUERY_VOLUME_INFORMATION      0xf802d31131b8 \SystemRoot\system32\ntoskrnl.exe
  11 IRP_MJ_SET_VOLUME_INFORMATION        0xf802d31131b8 \SystemRoot\system32\ntoskrnl.exe
  12 IRP_MJ_DIRECTORY_CONTROL             0xf802d31131b8 \SystemRoot\system32\ntoskrnl.exe
  13 IRP_MJ_FILE_SYSTEM_CONTROL           0xf802d31131b8 \SystemRoot\system32\ntoskrnl.exe
  14 IRP_MJ_DEVICE_CONTROL                0xf800025cb300 \??\C:\Users\test\AppData\Local\Temp\pmeA86F.tmp
  15 IRP_MJ_INTERNAL_DEVICE_CONTROL       0xf802d31131b8 \SystemRoot\system32\ntoskrnl.exe
  16 IRP_MJ_SHUTDOWN                      0xf802d31131b8 \SystemRoot\system32\ntoskrnl.exe
  17 IRP_MJ_LOCK_CONTROL                  0xf802d31131b8 \SystemRoot\system32\ntoskrnl.exe
  18 IRP_MJ_CLEANUP                       0xf802d31131b8 \SystemRoot\system32\ntoskrnl.exe
  19 IRP_MJ_CREATE_MAILSLOT               0xf802d31131b8 \SystemRoot\system32\ntoskrnl.exe
  20 IRP_MJ_QUERY_SECURITY                0xf802d31131b8 \SystemRoot\system32\ntoskrnl.exe
  21 IRP_MJ_SET_SECURITY                  0xf802d31131b8 \SystemRoot\system32\ntoskrnl.exe
  22 IRP_MJ_POWER                         0xf802d31131b8 \SystemRoot\system32\ntoskrnl.exe
  23 IRP_MJ_SYSTEM_CONTROL                0xf802d31131b8 \SystemRoot\system32\ntoskrnl.exe
  24 IRP_MJ_DEVICE_CHANGE                 0xf802d31131b8 \SystemRoot\system32\ntoskrnl.exe
  25 IRP_MJ_QUERY_QUOTA                   0xf802d31131b8 \SystemRoot\system32\ntoskrnl.exe
  26 IRP_MJ_SET_QUOTA                     0xf802d31131b8 \SystemRoot\system32\ntoskrnl.exe
  27 IRP_MJ_PNP                           0xf802d31131b8 \SystemRoot\system32\ntoskrnl.exe
```