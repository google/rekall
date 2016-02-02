---
abstract: Scan Physical memory for _LDR_DATA_TABLE_ENTRY objects.
args: {scan_in_kernel: 'Scan in the kernel address space (type: Boolean)



    * Default: False'}
class_name: ModScan
epydoc: rekall.plugins.windows.modscan.ModScan-class.html
layout: plugin
module: rekall.plugins.windows.modscan
title: modscan
---

The modscan command finds LDR_DATA_TABLE_ENTRY structures by scanning physical
memory for pool tags. This can pick up previously unloaded drivers and drivers
that have been hidden/unlinked by rootkits.


### Notes

1. Like other pool scanning plugins, this plugin may produce false positives
   since it essentially carves **_LDR_DATA_TABLE_ENTRY** structures out of
   memory. On the other hand, this plugin may reveal files which have been
   closed or freed.

### Sample output

In this example we can identify the pmem driver which was loaded from a
temporary location.

```
win8.1.raw 23:27:24> modscan
-------------------> modscan()
  Offset(P)    Name                      Base           Size      File
-------------- -------------------- -------------- -------------- ----
0x000001ce507e                      0x20c483483824     0xebc08b44
0x00003ce163b0 mrxsmb.sys           0xf80002174000        0x6d000 \SystemRoot\system32\DRIVERS\mrxsmb.sys
0x00003ce17610 mrxsmb20.sys         0xf80002000000        0x39000 \SystemRoot\system32\DRIVERS\mrxsmb20.sys
0x00003ce1e830 mpsdrv.sys           0xf8000215d000        0x17000 \SystemRoot\System32\drivers\mpsdrv.sys
0x00003ce4cf30 Ndu.sys              0xf800022cd000        0x1d000 \SystemRoot\system32\drivers\Ndu.sys
0x00003ce4df20 mrxsmb10.sys         0xf80002282000        0x4b000 \SystemRoot\system32\DRIVERS\mrxsmb10.sys
0x00003ce80170 peauth.sys           0xf800022ea000        0xa9000 \SystemRoot\system32\drivers\peauth.sys
0x00003ce8b010 srvnet.sys           0xf8000239e000        0x43000 \SystemRoot\System32\DRIVERS\srvnet.sys
0x00003ce8bc20 secdrv.SYS           0xf80002393000         0xb000 \SystemRoot\System32\Drivers\secdrv.SYS
0x00003ceae280 tcpipreg.sys         0xf800023e1000        0x12000 \SystemRoot\System32\drivers\tcpipreg.sys
0x00003ceae520 srv2.sys             0xf800024ec000        0xad000 \SystemRoot\System32\DRIVERS\srv2.sys
0x00003cec9ee0                      0x665602050006            0x0
0x00003ceede60 srv.sys              0xf80002400000        0x98000 \SystemRoot\System32\DRIVERS\srv.sys
0x00003cf44eb0 mslldp.sys           0xf80002498000        0x16000 \SystemRoot\system32\DRIVERS\mslldp.sys
0x00003d144160 rspndr.sys           0xf80001caf000        0x18000 \SystemRoot\system32\DRIVERS\rspndr.sys
0x00003d145a50 lltdio.sys           0xf80001c9b000        0x14000 \SystemRoot\system32\DRIVERS\lltdio.sys
0x00003d18c850 HTTP.sys             0xf80002043000        0xfa000 \SystemRoot\system32\drivers\HTTP.sys
0x00003d29b010 pmeA86F.tmp          0xf800025ca000        0x10000 \??\C:\Users\test\AppData\Local\Temp\pmeA86F.tmp
0x00003d655520 HdAudio.sys          0xf80001d45000        0x66000 \SystemRoot\system32\drivers\HdAudio.sys
0x00003d6593e0 tunnel.sys           0xf800024ae000        0x2d000 \SystemRoot\system32\DRIVERS\tunnel.sys
```