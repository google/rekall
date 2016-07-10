---
abstract: Print list of loaded kernel modules.
args: {name_regex: 'Filter module names by this regex. (type: RegEx)

    '}
class_name: Modules
epydoc: rekall.plugins.windows.modules.Modules-class.html
layout: plugin
module: rekall.plugins.windows.modules
title: modules
---

To view the list of kernel drivers loaded on the system, use the modules
command. This walks the doubly-linked list of **_LDR_DATA_TABLE_ENTRY**
structures pointed to by **PsLoadedModuleList**.

It cannot find hidden/unlinked kernel drivers, however [modscan](ModScan.html)
serves that purpose. Also, since this plugin uses list walking techniques, you
typically can assume that the order the modules are displayed in the output is
the order they were loaded on the system.

### Notes

1. The Base address is the location where the kernel module's PE header is
   mapped. For example you can examine information about the module's IAT/EAT
   using the [peinfo](PEInfo.html) plugin, providing the base address.


### Sample output

```
win8.1.raw 23:35:19> modules
-------------------> modules()
  Offset (V)   Name                      Base           Size      File
-------------- -------------------- -------------- -------------- ----
0xe00000057620 ntoskrnl.exe         0xf802d3019000       0x781000 \SystemRoot\system32\ntoskrnl.exe
0xe00000057530 hal.dll              0xf802d379a000        0x6f000 \SystemRoot\system32\hal.dll
0xe000000557c0 storahci.sys         0xf800006d9000        0x1d000 \SystemRoot\System32\drivers\storahci.sys
0xe0000149ade0 mssmbios.sys         0xf800018c4000         0xc000 \SystemRoot\System32\drivers\mssmbios.sys
0xe000013871e0 Npfs.SYS             0xf800008ba000        0x14000 \SystemRoot\System32\Drivers\Npfs.SYS
0xe00000055d50 volmgrx.sys          0xf80000393000        0x5f000 \SystemRoot\System32\drivers\volmgrx.sys
0xe00002145a50 lltdio.sys           0xf80001c9b000        0x14000 \SystemRoot\system32\DRIVERS\lltdio.sys
0xe00000055e40 volmgr.sys           0xf8000045d000        0x15000 \SystemRoot\System32\drivers\volmgr.sys
0xe00000054950 fwpkclnt.sys         0xf80001144000        0x6c000 \SystemRoot\System32\drivers\fwpkclnt.sys
0xe00000054c60 NETIO.SYS            0xf80000d3e000        0x79000 \SystemRoot\system32\drivers\NETIO.SYS
0xe000014b3500 kbdclass.sys         0xf80001a1f000        0x10000 \SystemRoot\System32\drivers\kbdclass.sys
0xe00001339b50 drmk.sys             0xf80001c00000        0x1c000 \SystemRoot\system32\drivers\drmk.sys
0xe00000054b70 ksecpkg.sys          0xf80000db7000        0x34000 \SystemRoot\System32\Drivers\ksecpkg.sys
0xe00000054100 CLASSPNP.SYS         0xf80000800000        0x56000 \SystemRoot\System32\drivers\CLASSPNP.SYS
```